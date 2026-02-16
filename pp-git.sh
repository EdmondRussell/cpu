#!/bin/bash

# Configuration
MIN_HASHRATE=500
ADDRESS="bc1qca9673x0335xss274yuz8uaz5nryhkgy0nrpyu"
URL="stratum+tcp://public-pool.io:3333"
THREADS=$(nproc)

# Worker name and stats file (unique per machine/run)
WORKER_NAME="${HOSTNAME}_$(date +%Y%m%d_%H%M)"  # e.g., raspberrypi_20260216_1110
STATS_FILE="cpu_${WORKER_NAME}.log"

# Globals to track stats
best_diff=0
total_diff=0
share_count=0
blocks_solved=0

# GitHub upload function (requires GITHUB_TOKEN env var + jq)
upload_to_github() {
    local log_file="$1"
    local repo="EdmondRussell/workers"
    local branch="main"
    local path="logs/$(basename "$log_file")"
    local commit_msg="Auto-upload from ${WORKER_NAME}: $(date)"

    if [[ -z "$GITHUB_TOKEN" ]]; then
        echo "No GITHUB_TOKEN, skipping GitHub upload"
        return 0
    fi

    local content_b64
    content_b64=$(base64 -w 0 "$log_file")

    local exists_sha
    exists_sha=$(curl -s -H "Authorization: token $GITHUB_TOKEN" \
        "https://api.github.com/repos/$repo/contents/$path" | jq -r '.sha // empty')

    if [[ "$exists_sha" != "null" && -n "$exists_sha" ]]; then
        curl -s -X PUT -H "Authorization: token $GITHUB_TOKEN" \
            -H "Content-Type: application/json" \
            -d "{\"message\": \"$commit_msg\", \"committer\": {\"name\": \"${WORKER_NAME}\", \"email\": \"miner@example.com\"}, \"content\": \"$content_b64\", \"sha\": \"$exists_sha\", \"branch\": \"$branch\"}" \
            "https://api.github.com/repos/$repo/contents/$path" >/dev/null
        echo "Updated $path on GitHub"
    else
        curl -s -X PUT -H "Authorization: token $GITHUB_TOKEN" \
            -H "Content-Type: application/json" \
            -d "{\"message\": \"$commit_msg\", \"committer\": {\"name\": \"${WORKER_NAME}\", \"email\": \"miner@example.com\"}, \"content\": \"$content_b64\", \"branch\": \"$branch\"}" \
            "https://api.github.com/repos/$repo/contents/$path" >/dev/null
        echo "Created $path on GitHub"
    fi
}

run_miner() {
    echo "Starting $WORKER_NAME miner with $THREADS threads..."
    echo "Logging to $STATS_FILE"
    stdbuf -oL ./cpuminer -a sha256d -o "$URL" -u "${ADDRESS}.${WORKER_NAME}" -p x -t "$THREADS" 2>&1 | while read -r line; do
        echo "$line"

        # Hashrate watchdog
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

        # Accepted diff tracking
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

        # Block solved capture
        if [[ "$line" == *"BLOCK SOLVED"* ]] || [[ "$line" == *"Block solved"* ]]; then
            blocks_solved=$((blocks_solved + 1))
            printf '%s *** BLOCK SOLVED *** worker=%s total_blocks=%d ***\n' \
                "$(date '+%Y-%m-%d %H:%M:%S')" "$WORKER_NAME" "$blocks_solved" >> "$STATS_FILE"
            printf '%s BLOCK LINE: %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$line" >> "$STATS_FILE"
        fi
    done
    # Upload to GitHub on restart
    [[ -f "$STATS_FILE" && -s "$STATS_FILE" ]] && upload_to_github "$STATS_FILE"
}

while true; do
    run_miner
    echo "Restarting $WORKER_NAME in 5 seconds..."
    sleep 5
done
