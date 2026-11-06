#!/usr/bin/env bash
# Day 1 lab health check. Read-only: it only inspects, it changes nothing.
# Adjust the variables below to match your lab, or export them before running.

SPLUNK_URL="${SPLUNK_URL:-http://localhost:8000}"
SHUFFLE_URL="${SHUFFLE_URL:-http://localhost:3001}"
EVE_EDGE="${EVE_EDGE:-/var/log/suricata/eve.json}"
EVE_INTERNAL="${EVE_INTERNAL:-}"        # optional second sensor path
VICTIM_AUTH_LOG="${VICTIM_AUTH_LOG:-/var/log/auth.log}"

pass=0; fail=0
ok()   { echo "[ OK ] $1"; pass=$((pass+1)); }
bad()  { echo "[FAIL] $1"; fail=$((fail+1)); }
warn() { echo "[WARN] $1"; }

echo "== Docker =="
if command -v docker >/dev/null 2>&1; then
  ok "docker installed"
  state=$(docker info --format '{{.Swarm.LocalNodeState}}' 2>/dev/null)
  [ "$state" = "active" ] && ok "swarm active" || warn "swarm state: ${state:-unknown} (fine if you use plain compose)"
  echo "--- running containers ---"
  docker ps --format '  {{.Names}}\t{{.Status}}' 2>/dev/null
  for name in splunk suricata shuffle; do
    docker ps --format '{{.Names}}' 2>/dev/null | grep -qi "$name" \
      && ok "container matching '$name' is running" \
      || bad "no running container matching '$name'"
  done
else
  bad "docker not found on this host"
fi

echo; echo "== HTTP endpoints =="
for pair in "Splunk|$SPLUNK_URL" "Shuffle|$SHUFFLE_URL"; do
  n="${pair%%|*}"; u="${pair##*|}"
  code=$(curl -s -o /dev/null -m 5 -w '%{http_code}' "$u" 2>/dev/null)
  case "$code" in
    2*|3*|401|403) ok "$n reachable at $u (HTTP $code)";;
    *) bad "$n not reachable at $u (HTTP ${code:-none})";;
  esac
done

echo; echo "== Log files =="
check_file() {
  [ -z "$2" ] && return
  if [ -r "$2" ]; then
    age=$(( $(date +%s) - $(stat -c %Y "$2") ))
    ok "$1 readable: $2 (last modified ${age}s ago)"
  else
    bad "$1 not readable: $2"
  fi
}
check_file "Suricata edge eve.json" "$EVE_EDGE"
check_file "Suricata internal eve.json" "$EVE_INTERNAL"
check_file "Victim auth log" "$VICTIM_AUTH_LOG"

echo; echo "== Result: $pass ok, $fail failed =="
[ "$fail" -eq 0 ] && echo "Lab looks ready for Day 2." || echo "Fix the failures first. If a rebuild is needed, Day 2 takes two days."
exit "$fail"
