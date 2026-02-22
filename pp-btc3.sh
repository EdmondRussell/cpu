#!/bin/bash
# Configuration
MIN_HASHRATE=500
ADDRESS="bc1qca9673x0335xss274yuz8uaz5nryhkgy0nrpyu"
URL="stratum+tcp://public-pool.io:3333"
THREADS=$(nproc)
STATS_FILE="miner_stats.log"
BLOCKS_FILE="blocks.log"
LAST_LOG_FILE="/tmp/miner_last_log.ts"
SILENCE_TIMEOUT=180  # 3 minutes in seconds

# Globals to track difficulty stats
best_diff=0
total_diff=0
share_count=0
block_count=0

# Background watchdog: restarts miner if no log output for SILENCE_TIMEOUT seconds
start_silence_watchdog() {
    local miner_pid=$1
    (
        while true; do
            sleep 10
            if [[ ! -f "$LAST_LOG_FILE" ]]; then
                date +%s > "$LAST_LOG_FILE"
                continue
            fi
            last_ts=$(cat "$LAST_LOG_FILE")
            now=$(date +%s)
            elapsed=$(( now - last_ts ))
            if [[ "$elapsed" -ge "$SILENCE_TIMEOUT" ]]; then
                echo "--- WATCHDOG: No log output for ${elapsed}s (limit ${SILENCE_TIMEOUT}s). Killing miner. ---"
                # Kill the whole process group of the miner pipeline
                pkill -P "$miner_pid" cpuminer 2>/dev/null
                kill "$miner_pid" 2>/dev/null
                exit 0
            fi
        done
    ) &
    echo $!  # Return watchdog PID
}

run_miner() {
    echo "Starting miner with $THREADS threads..."

    # Initialize the last-log timestamp
    date +%s > "$LAST_LOG_FILE"

    # Start the miner in background so we can get its PID
    stdbuf -oL ./cpuminer -a sha256d -o "$URL" -u "$ADDRESS" -p x -t "$THREADS" 2>&1 | (
        while read -r line; do
            echo "$line"
            # Touch the last-log timestamp on any output
            date +%s > "$LAST_LOG_FILE"

            # --- Block solved detection ---
            if [[ "$line" == *"BLOCK SOLVED"* ]]; then
                block_count=$((block_count + 1))
                block_diff=$(echo "$line" | sed -n 's/.*BLOCK SOLVED.*(diff \([0-9.]*\)).*/\1/p')
                [[ -z "$block_diff" ]] && block_diff="unknown"
                timestamp=$(date '+%Y-%m-%d %H:%M:%S')
                block_log="BLOCK SOLVED #${block_count} diff=${block_diff}"
                echo "🎉 ${block_log} 🎉"
                printf '%s | %s\n' "$timestamp" "$block_log" >> "$BLOCKS_FILE"
                continue
            fi

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

            # --- Difficulty tracking ---
            if [[ "$line" == *"accepted:"* ]] && [[ "$line" == *"(diff "* ]]; then
                diff_val=$(echo "$line" | sed -n 's/.*(diff \([0-9.]*\)).*/\1/p')
                if [[ "$diff_val" =~ ^[0-9.]+$ ]]; then
                    cmp=$(echo "$diff_val > $best_diff" | bc -l)
                    [[ "$cmp" -eq 1 ]] && best_diff="$diff_val"
                    total_diff=$(echo "$total_diff + $diff_val" | bc -l)
                    share_count=$((share_count + 1))
                    avg_diff=$(echo "scale=6; $total_diff / $share_count" | bc -l)
                    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
                    printf '%s diff=%s best=%s avg=%s count=%d\n' \
                        "$timestamp" "$diff_val" "$best_diff" "$avg_diff" "$share_count" >> "$STATS_FILE"
                fi
            fi
        done
    ) &
    local pipeline_pid=$!

    # Start silence watchdog, passing the pipeline PID
    local watchdog_pid
    watchdog_pid=$(start_silence_watchdog "$pipeline_pid")

    # Wait for the miner pipeline to finish
    wait "$pipeline_pid"

    # Clean up watchdog when miner exits for any reason
    kill "$watchdog_pid" 2>/dev/null
    rm -f "$LAST_LOG_FILE"
}

while true; do
    run_miner
    echo "Restarting miner in 5 seconds..."
    sleep 5
done
