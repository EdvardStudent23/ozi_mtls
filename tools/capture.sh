#!/usr/bin/env bash
# Reproduce the two demo pcaps used in the report.
#   captures/mtls_tls13.pcapng — Python mTLS, TLS 1.3 (default)
#   captures/mtls_tls12.pcapng — openssl s_server/s_client, TLS 1.2 forced
#
# On macOS loopback capture works on lo0 with `access_bpf` group membership
# (no sudo needed if ChmodBPF is installed via Wireshark).

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PKI="$ROOT/pki"
OUT="$ROOT/captures"
IFACE="${IFACE:-lo0}"
PORT=8443

[[ -f "$PKI/server.pem" ]] || { echo "ERROR: PKI missing. Run: bash $PKI/gen_pki.sh"; exit 2; }
command -v tshark >/dev/null || { echo "ERROR: tshark not installed (brew install wireshark)"; exit 2; }
mkdir -p "$OUT"

free_port() {
  lsof -nP -iTCP:"$PORT" -sTCP:LISTEN 2>/dev/null | awk 'NR>1{print $2}' | xargs -r kill 2>/dev/null || true
  sleep 0.3
}

wait_listen() {
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    (echo > /dev/tcp/127.0.0.1/"$PORT") 2>/dev/null && return 0
    sleep 0.2
  done
  echo "ERROR: server didn't open $PORT"; return 1
}

# ---------- Capture 1: TLS 1.3 via Python ----------
free_port
echo "[1/2] capturing TLS 1.3 mTLS via python3 server.py + client.py"
PCAP1="$OUT/mtls_tls13.pcapng"
tshark -i "$IFACE" -f "tcp port $PORT" -w "$PCAP1" >/dev/null 2>&1 &
TSH=$!; sleep 1
python3 -u "$ROOT/server.py" >/tmp/srv1.log 2>&1 &
SRV=$!
wait_listen
python3 "$ROOT/client.py" >/tmp/cli1.log 2>&1 || true
sleep 0.5
kill "$SRV" 2>/dev/null || true; wait "$SRV" 2>/dev/null || true
sleep 0.3
kill "$TSH" 2>/dev/null || true; wait "$TSH" 2>/dev/null || true
echo "    -> $PCAP1 ($(stat -f %z "$PCAP1") bytes)"

# ---------- Capture 2: TLS 1.2 via openssl ----------
free_port
echo "[2/2] capturing TLS 1.2 mTLS via openssl s_server/s_client"
PCAP2="$OUT/mtls_tls12.pcapng"
tshark -i "$IFACE" -f "tcp port $PORT" -w "$PCAP2" >/dev/null 2>&1 &
TSH=$!; sleep 1
openssl s_server -accept "$PORT" -quiet \
  -cert "$PKI/server.pem" -key "$PKI/server.key" \
  -CAfile "$PKI/rootCA.pem" -Verify 1 \
  -tls1_2 >/tmp/srv2.log 2>&1 &
SRV=$!
wait_listen
echo "hello from openssl mtls client" | \
  openssl s_client -connect 127.0.0.1:"$PORT" -quiet \
    -cert "$PKI/client.pem" -key "$PKI/client.key" \
    -CAfile "$PKI/rootCA.pem" -tls1_2 >/tmp/cli2.log 2>&1 || true
sleep 0.5
kill "$SRV" 2>/dev/null || true; wait "$SRV" 2>/dev/null || true
sleep 0.3
kill "$TSH" 2>/dev/null || true; wait "$TSH" 2>/dev/null || true
echo "    -> $PCAP2 ($(stat -f %z "$PCAP2") bytes)"

echo
echo "Done. Inspect with:"
echo "  tshark -r $PCAP2 -Y 'tls.handshake.type == 13' -V"
echo "  tshark -r $PCAP1 -Y 'tls.handshake'"
