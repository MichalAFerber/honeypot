#!/bin/sh
# Summarize a JSONL event log. Usage: scripts/daily-summary.sh [events.jsonl]
set -eu
LOG=${1:-/var/log/honeypot/events.jsonl}
if [ ! -f "$LOG" ]; then
    echo "no log at $LOG" >&2
    exit 1
fi

echo "== events =="
wc -l < "$LOG"

echo "== by service =="
jq -r '.svc' "$LOG" | sort | uniq -c | sort -rn

echo "== by event =="
jq -r '.event' "$LOG" | sort | uniq -c | sort -rn

echo "== top source IPs =="
jq -r '.src' "$LOG" | sed 's/:[0-9]*$//' | sort | uniq -c | sort -rn | head -20

echo "== credentials =="
jq -r 'select(.event=="password") | [.svc,.src,.user,.pass] | @tsv' "$LOG" | head -50

echo "== telnet/ftp commands =="
jq -r 'select(.event=="command") | [.svc,.src,.data] | @tsv' "$LOG" | head -50
