#!/bin/bash
# Usage: ./run_attack.sh <scenario_name> <command...>
SESSION_ID="sess_$(date +%Y%m%d_%H%M%S)_$RANDOM"
SCENARIO="$1"
shift
LOGFILE=~/Desktop/governed-ai-soc/data/collection_log.csv

echo "[$SESSION_ID] Starting scenario: $SCENARIO"
echo "[$SESSION_ID] Command: $*"
START=$(date -Iseconds)

"$@"

END=$(date -Iseconds)
echo "$START,$END,$SCENARIO,$SESSION_ID,\"$*\"" >> "$LOGFILE"
echo "[$SESSION_ID] Done. Logged to $LOGFILE"
