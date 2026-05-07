#!/usr/bin/env bash
# Negative-path checks for the mTLS server.
# Demonstrates that all three failure modes are correctly rejected.
#
# Prerequisite: server.py must be running in another terminal:
#   python3 server.py

set -u
HOST=127.0.0.1
PORT=8443
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PKI="$ROOT/pki"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

if [[ ! -f "$PKI/rootCA.pem" ]]; then
  echo "ERROR: PKI not found. Run: bash $ROOT/pki/gen_pki.sh"
  exit 2
fi

# Fast-fail probe: server reachable?
if ! (echo > /dev/tcp/$HOST/$PORT) 2>/dev/null; then
  echo "ERROR: $HOST:$PORT is not listening. Start server first: python3 $ROOT/server.py"
  exit 2
fi

pass=0
fail=0
report() {
  local label="$1" outcome="$2" out="$3"
  if [[ "$outcome" == "pass" ]]; then
    echo "  PASS: $label"
    pass=$((pass+1))
  else
    echo "  FAIL: $label"
    echo "  ---- s_client output (last 12 lines) ----"
    printf '%s\n' "$out" | tail -n 12 | sed 's/^/    /'
    echo "  -----------------------------------------"
    fail=$((fail+1))
  fi
}

# NB: in TLS 1.3 the rejection alert arrives post-handshake, so `-state` must be
# passed to s_client — otherwise the alert lines are not printed and the
# connection looks "established" in the summary.
REJECT_RE='alert (read|write|number)|handshake.failure|certificate.required|certificate.unknown|bad.certificate|unknown.ca|verify error|expired|SSL_shutdown.*init|alert number (40|42|43|45|46|48|49|116)'

# === [1/3] No client certificate =============================================
echo "[1/3] connection without client cert"
out=$(openssl s_client -connect "$HOST:$PORT" -CAfile "$PKI/rootCA.pem" \
        -state </dev/null 2>&1 || true)
if printf '%s' "$out" | grep -qiE "$REJECT_RE"; then
  report "server rejects client without cert" pass "$out"
else
  report "server rejects client without cert" fail "$out"
fi

# === [2/3] Cert from a rogue (untrusted) CA ==================================
echo
echo "[2/3] connection with cert from rogue CA"
openssl genrsa -out "$TMP/rogueCA.key" 2048 2>/dev/null
openssl req -x509 -new -nodes -sha256 -key "$TMP/rogueCA.key" -days 1 \
  -subj "/CN=Rogue CA" -out "$TMP/rogueCA.pem" 2>/dev/null
openssl genrsa -out "$TMP/rogue.key" 2048 2>/dev/null
openssl req -new -key "$TMP/rogue.key" -subj "/CN=rogue-client" \
  -out "$TMP/rogue.csr" 2>/dev/null
cat > "$TMP/rogue.ext" <<EOF
basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=clientAuth
EOF
openssl x509 -req -in "$TMP/rogue.csr" -sha256 \
  -CA "$TMP/rogueCA.pem" -CAkey "$TMP/rogueCA.key" -CAcreateserial \
  -extfile "$TMP/rogue.ext" -days 1 -out "$TMP/rogue.pem" 2>/dev/null

out=$(openssl s_client -connect "$HOST:$PORT" -CAfile "$PKI/rootCA.pem" \
        -cert "$TMP/rogue.pem" -key "$TMP/rogue.key" \
        -state </dev/null 2>&1 || true)
if printf '%s' "$out" | grep -qiE "$REJECT_RE"; then
  report "server rejects rogue-CA cert" pass "$out"
else
  report "server rejects rogue-CA cert" fail "$out"
fi

# === [3/3] Expired client cert (signed by trusted CA) ========================
echo
echo "[3/3] connection with expired client cert"
openssl genrsa -out "$TMP/expired.key" 2048 2>/dev/null
openssl req -new -key "$TMP/expired.key" -subj "/CN=expired-client" \
  -out "$TMP/expired.csr" 2>/dev/null
cat > "$TMP/expired.ext" <<EOF
basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=clientAuth
EOF

if command -v faketime >/dev/null 2>&1; then
  # Issue a cert that was already valid-until-yesterday by backdating clock.
  faketime '2020-01-01' openssl x509 -req -in "$TMP/expired.csr" -sha256 \
    -CA "$PKI/rootCA.pem" -CAkey "$PKI/rootCA.key" -CAcreateserial \
    -extfile "$TMP/expired.ext" -days 1 -out "$TMP/expired.pem" 2>/dev/null

  out=$(openssl s_client -connect "$HOST:$PORT" -CAfile "$PKI/rootCA.pem" \
          -cert "$TMP/expired.pem" -key "$TMP/expired.key" \
          -state </dev/null 2>&1 || true)
  if printf '%s' "$out" | grep -qiE "expired|$REJECT_RE"; then
    report "server rejects expired cert" pass "$out"
  else
    report "server rejects expired cert" fail "$out"
  fi
else
  echo "  SKIP: 'faketime' not installed (brew install libfaketime). Manual test needed."
fi

echo
echo "=========================================="
echo "  passed: $pass    failed: $fail"
echo "=========================================="
[[ $fail -eq 0 ]]
