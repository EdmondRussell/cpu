#!/bin/bash

# Configuration
MIN_HASHRATE=500
ADDRESS="bc1qca9673x0335xss274yuz8uaz5nryhkgy0nrpyu"
URL="stratum+tcp://public-pool.io:3333"
THREADS=$(nproc)
STATS_FILE="miner_stats.log"

# Globals to track difficulty stats
best_diff=0
total_diff=0
share_count=0

run_miner() {
    echo "Starting miner with $THREADS threads..."
    stdbuf -oL ./cpuminer -a sha256d -o "$URL" -u "$ADDRESS" -p x -t "$THREADS" 2>&1 | while read -r line; do
        echo "$line"

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
                printf '%s diff=%s best=%s avg=%s count=%d\n' \
                    "$(date '+%Y-%m-%d %H:%M:%S')" \
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
