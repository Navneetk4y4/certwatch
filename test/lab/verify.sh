#!/usr/bin/env bash
# Assert every lab fixture serves what it is supposed to serve.
#
# Runs INSIDE the lab network. On macOS a Docker bridge address is not routable
# from the host, so anything that talks to the lab must run as a container on
# the same network. That is not a workaround; it is also closer to how the
# collector actually runs — inside the customer's network, not outside it.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
NET=certwatch-lab
fail=0
ok()   { printf "  \033[32mPASS\033[0m %s\n" "$1"; }
bad()  { printf "  \033[31mFAIL\033[0m %s\n" "$1"; fail=$((fail+1)); }

# alpine has no openssl binary; alpine/openssl does. Using plain alpine made
# fp_of return an empty string for every address, and the comparison below then
# reported PASS because empty equals empty. A fixture check that cannot fail is
# worse than no check, so fp_of now refuses to return empty.
innet()  { docker run --rm --network "$NET" --dns 10.77.0.53 -v /tmp/labrun:/w -w /w alpine:3.20 "$@"; }
inssl()  { docker run --rm --network "$NET" --dns 10.77.0.53 --entrypoint sh alpine/openssl:3.3.2 "$@"; }

fp_of() { # $1=addr $2=sni -> 16 hex chars, or the literal string NONE
  local out
  out=$(inssl -c "echo | openssl s_client -connect $1:8443 -servername $2 2>/dev/null \
    | openssl x509 -noout -fingerprint -sha256 2>/dev/null" \
    | cut -d= -f2 | tr -d ':\r\n' | tr 'A-Z' 'a-z' | cut -c1-16)
  # Never return empty: two empty strings compare equal, which turns a dead
  # fixture into a passing assertion.
  if [ ${#out} -ne 16 ]; then echo "NONE"; else echo "$out"; fi
}

echo "== lab fixtures =="
POOL=$(fp_of 10.77.0.11 lab.internal.test)
[ "$POOL" != "NONE" ] && ok "web-a serves a certificate ($POOL)" || bad "web-a served nothing"
for ip in 10.77.0.12 10.77.0.13; do
  GOT=$(fp_of $ip lab.internal.test)
  if [ "$GOT" = "NONE" ]; then bad "$ip served nothing"
  elif [ "$GOT" = "$POOL" ]; then ok "$ip agrees with the pool"
  else bad "$ip disagrees with the pool (it should agree): $GOT vs $POOL"; fi
done
DIV=$(fp_of 10.77.0.14 lab.internal.test)
if [ "$DIV" = "NONE" ]; then bad "web-divergent served nothing"
elif [ "$DIV" = "$POOL" ]; then bad "web-divergent does not diverge — the partial-rollout fixture is broken"
else ok "web-divergent serves a DIFFERENT certificate ($DIV)"; fi

echo "== DNS =="
N=$(innet sh -c 'nslookup lab.internal.test 10.77.0.53 2>/dev/null | grep -c "^Address:"')
[ "${N:-0}" -ge 4 ] && ok "lab.internal.test resolves to multiple addresses" \
  || bad "multi-A record missing (got ${N:-0})"

echo "== draining backend (GAP-2) =="
innet sh -c 'nc -z -w2 10.77.0.30 8443' >/dev/null 2>&1 \
  && bad "web-draining accepted a connection; it must refuse" \
  || ok "web-draining refuses TCP"

echo "== metadata decoy (S14) =="
TOUCHES=$(docker compose -f test/lab/docker-compose.yml exec -T imds-decoy \
  sh -c 'wc -l < /data/imds.jsonl' 2>/dev/null | tr -d ' \r')
echo "     decoy has recorded ${TOUCHES:-?} inbound connection(s) this run"

echo
[ "$fail" -eq 0 ] && echo "lab-verify: ALL FIXTURES OK" || echo "lab-verify: $fail FAILURE(S)"
exit $fail
