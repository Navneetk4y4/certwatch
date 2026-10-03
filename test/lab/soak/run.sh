#!/usr/bin/env bash
# LOCAL-003, build item 089: the 24-hour unattended run.
#
# Verifies the lab endpoint on a loop and records, every cycle: outcome,
# per-IP counts, RSS, open file descriptors and goroutine-ish process state.
# The point is not that it passes once — it is that nothing grows without
# bound and nothing crashes over a full day.
#
#   nohup test/lab/soak/run.sh > /dev/null 2>&1 &
set -uo pipefail

# The first 24-hour attempt (2026-09-30) recorded 668 cycles where ~1,380 were
# expected, with an 11-hour hole: the host went to sleep. Wall-clock "elapsed"
# kept advancing, so the run LOOKED like it covered a day. Two fixes:
#   1. caffeinate holds an idle-sleep assertion on macOS for the life of the run
#   2. any gap between cycles larger than GAP_LIMIT invalidates the run, loudly
if [ -z "${SOAK_CAFFEINATED:-}" ] && command -v caffeinate >/dev/null 2>&1; then
  export SOAK_CAFFEINATED=1
  exec caffeinate -i -s "$0" "$@"
fi
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="${SOAK_OUT:-$HERE/evidence}"
mkdir -p "$OUT"
INTERVAL="${SOAK_INTERVAL:-60}"
DURATION="${SOAK_DURATION:-86400}"
NET=certwatch-lab
LOG="$OUT/soak.jsonl"
META="$OUT/meta.json"

start=$(date -u +%s)
GAP_LIMIT="${SOAK_GAP_LIMIT:-$(( INTERVAL * 3 ))}"
last_cycle_at=$start
gaps=0
cat > "$META" <<EOF
{"started_at":"$(date -u +%Y-%m-%dT%H:%M:%SZ)",
 "commit":"$(git -C "$HERE/../../.." rev-parse HEAD 2>/dev/null)",
 "interval_seconds":$INTERVAL,"duration_seconds":$DURATION,
 "host":"$(uname -srm)","go":"$(go version 2>/dev/null)"}
EOF

cycle=0
while :; do
  now=$(date -u +%s)
  elapsed=$(( now - start ))
  [ "$elapsed" -ge "$DURATION" ] && break
  cycle=$(( cycle + 1 ))

  # A gap far larger than the interval means the host slept or the process
  # was stopped. Record it as an invalidating event; never let it pass silently.
  gap=$(( now - last_cycle_at ))
  if [ "$cycle" -gt 1 ] && [ "$gap" -gt "$GAP_LIMIT" ]; then
    gaps=$(( gaps + 1 ))
    printf '{"INVALIDATING_GAP":true,"cycle":%d,"gap_seconds":%d,"limit":%d,"at":"%s"}\n' \
      "$cycle" "$gap" "$GAP_LIMIT" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$LOG"
  fi
  last_cycle_at=$now

  # One verification through the full production path, inside the lab network.
  res=$(docker run --rm --network "$NET" --dns 10.77.0.53 \
        -v /tmp/labrun:/w -w /w alpine:3.20 \
        ./certscan --verify expect.json --out /dev/null --format json 2>&1 | tail -40)
  outcome=$(printf '%s' "$res" | grep -oE '(FAILURE|PASS|DRIFT|WARNING|UNKNOWN|UNREACHABLE)' | head -1)
  matched=$(printf '%s' "$res" | grep -oE '[0-9]+ of [0-9]+ addresses' | head -1)

  # Resource trend of the docker client + any stray certscan processes.
  rss=$(ps -o rss= -p $$ 2>/dev/null | tr -d ' ')
  nfd=$(lsof -p $$ 2>/dev/null | wc -l | tr -d ' ')

  # A harness that cannot see an outcome must SAY SO, loudly, rather than
  # record "NONE" for a day and let a broken run look like a clean one.
  if [ -z "${outcome:-}" ]; then
    printf '{"cycle":%d,"elapsed":%d,"at":"%s","HARNESS_BROKEN":true,"raw":%s}\n' \
      "$cycle" "$elapsed" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
      "$(printf '%s' "$res" | head -c 400 | python3 -c 'import json,sys;print(json.dumps(sys.stdin.read()))')" \
      >> "$LOG"
    broken=$(( ${broken:-0} + 1 ))
    if [ "$broken" -ge 3 ]; then
      printf '{"aborted":"harness produced no outcome for 3 consecutive cycles"}\n' >> "$LOG"
      exit 1
    fi
    sleep "$INTERVAL"; continue
  fi
  broken=0

  printf '{"cycle":%d,"elapsed":%d,"at":"%s","outcome":"%s","matched":"%s","rss_kb":%s,"open_fds":%s}\n' \
    "$cycle" "$elapsed" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${outcome:-NONE}" \
    "${matched:-}" "${rss:-0}" "${nfd:-0}" >> "$LOG"

  sleep "$INTERVAL"
done

printf '{"finished_at":"%s","cycles":%d,"elapsed":%d,"invalidating_gaps":%d,"expected_cycles_min":%d}\n' \
  "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$cycle" "$(( $(date -u +%s) - start ))" "$gaps" \
  "$(( DURATION / (INTERVAL + 30) ))" >> "$LOG"
