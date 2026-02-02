#!/bin/bash

# Configuration
MIN_HASHRATE=500
ADDRESS="bc1qca9673x0335xss274yuz8uaz5nryhkgy0nrpyu"
URL="stratum+tcp://public-pool.io:3333"
THREADS=$(nproc)

run_miner() {
    echo "Starting miner with $THREADS threads..."
    # We use 'stdbuf' to prevent output buffering
    stdbuf -oL ./cpuminer -a sha256d -o "$URL" -u "$ADDRESS" -p x -t "$THREADS" 2>&1 | while read -r line; do
        echo "$line"
        
        # Check if line contains "CPU #" and "kH/s"
        if [[ "$line" == *"CPU #"* ]] && [[ "$line" == *"kH/s"* ]]; then
            # Extract the number specifically between the colon and 'kH/s'
            # This handles strings like "[timestamp] CPU #1: 6941 kH/s"
            current_rate=$(echo "$line" | sed -n 's/.*: \([0-9.]*\) kH\/s.*/\1/p' | cut -d. -f1)
            
            # Ensure current_rate is a valid number before comparing
            if [[ "$current_rate" =~ ^[0-9]+$ ]]; then
                if [ "$current_rate" -lt "$MIN_HASHRATE" ]; then
                    echo "--- WATCHDOG: Hashrate $current_rate kH/s dropped below $MIN_HASHRATE! ---"
                    # Kill the miner process group
                    pkill -P $$ cpuminer
                    break
                fi
            fi
        fi
    done
}

while true; do
    run_miner
    echo "Restarting miner in 5 seconds..."
    sleep 5
done
