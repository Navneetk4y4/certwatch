#!/usr/bin/env bash
# Divergence lab — the controlled experiment for competitive testing.
#
# Builds the exact scenario the remaining commercial hypothesis turns on:
#
#     lab.internal.test
#          |-- 10.99.0.1:8443  -> certificate A   (the "expected" one)
#          `-- 10.99.0.2:8443  -> certificate B   (a "stale" one)
#
# A hostname-level monitor connects once, gets whichever address answers, and
# reports healthy. A per-IP verifier reports the divergence.
#
# WHY 10.99.x AND NOT 127.0.0.x: certscan refuses loopback unconditionally
# (threat T3 — a scanner that can be pointed at loopback or link-local is a
# credential-theft primitive). 10.99.x is RFC1918, which is the address space
# the product exists to scan. The alias lives on lo0 so no real interface is
# touched and nothing is exposed off this machine.
#
# REQUIRES sudo for the interface aliases only. Everything else is unprivileged.
#
#   ./setup.sh          create the lab
#   ./setup.sh teardown remove it
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOST="lab.internal.test"
IP_A="10.99.0.1"
IP_B="10.99.0.2"
PORT=8443

teardown() {
  echo "tearing down..."
  pkill -f "divergence-backend" 2>/dev/null || true
  if [[ "$(uname)" == "Darwin" ]]; then
    sudo ifconfig lo0 -alias "$IP_A" 2>/dev/null || true
    sudo ifconfig lo0 -alias "$IP_B" 2>/dev/null || true
  else
    sudo ip addr del "$IP_A/32" dev lo 2>/dev/null || true
    sudo ip addr del "$IP_B/32" dev lo 2>/dev/null || true
  fi
  rm -rf "$DIR/certs"
  echo "done"
}

if [[ "${1:-}" == "teardown" ]]; then teardown; exit 0; fi

echo "== 1. interface aliases (needs sudo) =="
if [[ "$(uname)" == "Darwin" ]]; then
  sudo ifconfig lo0 alias "$IP_A" netmask 255.255.255.255
  sudo ifconfig lo0 alias "$IP_B" netmask 255.255.255.255
else
  sudo ip addr add "$IP_A/32" dev lo 2>/dev/null || true
  sudo ip addr add "$IP_B/32" dev lo 2>/dev/null || true
fi
echo "   $IP_A and $IP_B aliased"

echo "== 2. two DIFFERENT certificates for the SAME hostname =="
mkdir -p "$DIR/certs"
for n in a b; do
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout "$DIR/certs/$n.key" -out "$DIR/certs/$n.crt" \
    -days 90 -nodes -subj "/CN=$HOST" \
    -addext "subjectAltName=DNS:$HOST" 2>/dev/null
done
echo "   certificate A: $(openssl x509 -in "$DIR/certs/a.crt" -noout -fingerprint -sha256 | cut -d= -f2 | tr -d : | tr 'A-Z' 'a-z' | cut -c1-16)"
echo "   certificate B: $(openssl x509 -in "$DIR/certs/b.crt" -noout -fingerprint -sha256 | cut -d= -f2 | tr -d : | tr 'A-Z' 'a-z' | cut -c1-16)"

echo "== 3. /etc/hosts entry (needs sudo) =="
if ! grep -q "$HOST" /etc/hosts 2>/dev/null; then
  echo "$IP_A $HOST" | sudo tee -a /etc/hosts >/dev/null
  echo "   added: $IP_A $HOST"
  echo "   NOTE: /etc/hosts gives ONE address. For a true multi-A test you need a"
  echo "         resolver that returns both — see dnsmasq note in README.md."
else
  echo "   already present"
fi

echo "== 4. starting backends =="
( exec -a divergence-backend-a \
  openssl s_server -accept "$IP_A:$PORT" -cert "$DIR/certs/a.crt" -key "$DIR/certs/a.key" -quiet \
  >/dev/null 2>&1 ) &
( exec -a divergence-backend-b \
  openssl s_server -accept "$IP_B:$PORT" -cert "$DIR/certs/b.crt" -key "$DIR/certs/b.key" -quiet \
  >/dev/null 2>&1 ) &
sleep 1

echo "== 5. verifying =="
for ip in "$IP_A" "$IP_B"; do
  fp=$(echo | openssl s_client -connect "$ip:$PORT" -servername "$HOST" 2>/dev/null \
       | openssl x509 -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2 | tr -d : | tr 'A-Z' 'a-z' | cut -c1-16)
  echo "   $ip:$PORT serves $fp"
done

cat <<EOF

LAB READY.

  hostname : $HOST
  member A : $IP_A:$PORT   (expected certificate)
  member B : $IP_B:$PORT   (stale certificate -- the partial-rollout case)

A hostname-level monitor sees ONE of these and reports healthy.
A per-IP verifier sees BOTH and reports the divergence.

Next: test each product against it. See README.md in this directory.
Teardown: ./setup.sh teardown
EOF
