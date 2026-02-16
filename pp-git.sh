#!/bin/bash

# Configuration
MIN_HASHRATE=500
ADDRESS="bc1qca9673x0335xss274yuz8uaz5nryhkgy0nrpyu"
URL="stratum+tcp://public-pool.io:3333"
THREADS=$(nproc)

# NEW: Worker name and stats file (unique per machine)
WORKER_NAME="${HOSTNAME}_$(date +%Y%m%d_%H%M)"  # e.g., raspberrypi_20260216_1048
STATS_FILE="cpu_${WORKER_NAME}.log"  # Unique: cpu_raspberrypi_20260216_1048.log

# Globals to track difficulty stats
best_diff=0
total_diff=0
share_count=0
blocks_solved=0

run_miner() {
    echo "Starting $WORKER_NAME miner with $THREADS threads..."
    echo "Logging stats to $STATS_FILE"
    stdbuf -oL ./cpuminer -a sha256d -o "$URL" -u "${ADDRESS}.${WORKER_NAME}" -p x -t "$THREADS" 2>&1 | while read -r line; do
        echo "$line"

        # --- Hashrate watchdog ---
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

        # --- Difficulty tracking: accepted lines ---
        if [[ "$line" == *"accepted:"* ]] && [[ "$line" == *"(diff "* ]]; then
            diff_val=$(echo "$line" | sed -n 's/.*(diff \([0-9.]*\)).*/\1/p')
            if [[ "$diff_val" =~ ^[0-9]+(\.[0-9]+)?$ ]] && [[ -n "$diff_val" ]]; then
                cmp=$(echo "$diff_val > $best_diff" | bc -l 2>/dev/null)
                if [[ "$cmp" == "1" ]]; then
                    best_diff="$diff_val"
                fi
                total_diff=$(echo "$total_diff + $diff_val" | bc -l 2>/dev/null)
                share_count=$((share_count + 1))
                avg_diff=$(echo "scale=6; $total_diff / $share_count" | bc -l 2>/dev/null)
                printf '%s diff=%s best=%s avg=%s count=%d worker=%s\n' \
                    "$(date '+%Y-%m-%d %H:%M:%S')" \
                    "$diff_val" "$best_diff" "$avg_diff" "$share_count" "$WORKER_NAME" >> "$STATS_FILE"
            fi
        fi

        # NEW: Block solved capture
        if [[ "$line" == *"BLOCK SOLVED"* ]] || [[ "$line" == *"Block solved"* ]]; then
            blocks_solved=$((blocks_solved + 1))
            printf '%s *** BLOCK SOLVED *** worker=%s total_blocks=%d ***\n' \
                "$(date '+%Y-%m-%d %H:%M:%S')" "$WORKER_NAME" "$blocks_solved" >> "$STATS_FILE"
            # Also log full line for context
            printf '%s BLOCK LINE: %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$line" >> "$STATS_FILE"
        fi
    done
}

while true; do
    run_miner
    echo "Restarting $WORKER_NAME in 5 seconds..."
    sleep 5
done
