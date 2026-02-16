#!/bin/bash

# Configuration
MIN_HASHRATE=500
ADDRESS="bc1qca9673x0335xss274yuz8uaz5nryhkgy0nrpyu"
URL="stratum+tcp://public-pool.io:3333"
THREADS=$(nproc)
STATS_FILE="miner_stats.log"
BLOCKS_FILE="blocks.log"  # New file for block solved logs

# Globals to track difficulty stats
best_diff=0
total_diff=0
share_count=0
block_count=0  # New counter for blocks

run_miner() {
    echo "Starting miner with $THREADS threads..."
    stdbuf -oL ./cpuminer -a sha256d -o "$URL" -u "$ADDRESS" -p x -t "$THREADS" 2>&1 | while read -r line; do
        echo "$line"

        # --- Block solved detection ---
        if [[ "$line" == *"BLOCK SOLVED"* ]]; then
            block_count=$((block_count + 1))
            # Extract diff if present, e.g. "BLOCK SOLVED (diff 123.45)"
            block_diff=$(echo "$line" | sed -n 's/.*BLOCK SOLVED.*(diff \([0-9.]*\)).*/\1/p')
            if [[ -z "$block_diff" ]]; then
                block_diff="unknown"
            fi
            timestamp=$(date '+%Y-%m-%d %H:%M:%S')
            block_log="BLOCK SOLVED #${block_count} diff=${block_diff}"
            echo "🎉 ${block_log} 🎉"
            printf '%s | %s\n' "$timestamp" "$block_log" >> "$BLOCKS_FILE"
            continue
        fi

        # --- Hashrate watchdog (your existing logic) ---
        if [[ "$line" == *"CPU #"* ]] && [[ "$line" == *"kH/s"* ]]; then
            current_rate=$(echo "$line" | sed -n 's/.*: \([0-9.]*\) kH\/s.*/\1/p' | cut -d. -f1)
            if [[ "$current_rate" =~ ^[0-9]+$ ]]; then
                if [ "$current_rate" -lt "$MIN_HASHRATE" ]; then
                    echo "--- WATCHDOG: Hashrate $current_rate kH/s dropped below $MIN_HASHRATE! ---"
                    pkill -P $$ cpuminer
                    break
                fi
            fi
        fi

        # --- Difficulty tracking: look for accepted lines with diff ---
        if [[ "$line" == *"accepted:"* ]] && [[ "$line" == *"(diff "* ]]; then
            # Extract the diff value between "(diff " and ")"
            diff_val=$(echo "$line" | sed -n 's/.*(diff \([0-9.]*\)).*/\1/p')

            if [[ "$diff_val" =~ ^[0-9.]+$ ]]; then
                # Use bc for floating point arithmetic
                # Update best
                cmp=$(echo "$diff_val > $best_diff" | bc -l)
                if [[ "$cmp" -eq 1 ]]; then
                    best_diff="$diff_val"
                fi

                # Update running sum and count
                total_diff=$(echo "$total_diff + $diff_val" | bc -l)
                share_count=$((share_count + 1))

                # Compute average
                avg_diff=$(echo "scale=6; $total_diff / $share_count" | bc -l)

                # Timestamped log line
                timestamp=$(date '+%Y-%m-%d %H:%M:%S')
                printf '%s diff=%s best=%s avg=%s count=%d\n' \
                    "$timestamp" \
                    "$diff_val" "$best_diff" "$avg_diff" "$share_count" >> "$STATS_FILE"
            fi
        fi
    done
}

while true; do
    run_miner
    echo "Restarting miner in 5 seconds..."
    sleep 5
done
