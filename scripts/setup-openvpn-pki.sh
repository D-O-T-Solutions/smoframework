#!/bin/bash
# setup-openvpn-pki.sh — Generate OpenVPN PKI without easy-rsa
# Dùng khi easy-rsa không available, tự gen certs với openssl
set -euo pipefail

OUTDIR="${1:-/etc/openvpn}"
CA_PASS="${CA_PASS:-smo-mesh-ca}"

step() { echo "━━━ $1"; }

mkdir -p "$OUTDIR/easy-rsa/pki"

step "Generating CA key and cert"
openssl genrsa -out "$OUTDIR/ca.key" 4096
openssl req -new -x509 -days 3650 -key "$OUTDIR/ca.key" \
    -out "$OUTDIR/ca.crt" -subj "/CN=SMO-Mesh-CA/O=SMO/C=VN"

step "Generating server key and cert"
openssl genrsa -out "$OUTDIR/server.key" 2048
openssl req -new -key "$OUTDIR/server.key" \
    -out "$OUTDIR/server.csr" -subj "/CN=server/O=SMO/C=VN"
openssl x509 -req -days 3650 -in "$OUTDIR/server.csr" \
    -CA "$OUTDIR/ca.crt" -CAkey "$OUTDIR/ca.key" -CAcreateserial \
    -out "$OUTDIR/server.crt"

step "Generating DH parameters"
openssl dhparam -out "$OUTDIR/dh.pem" 2048

step "Generating TLS crypt key"
openvpn --genkey --secret "$OUTDIR/ta.key"

step "Generating client certs"
for CLIENT in local-a local-b; do
    openssl genrsa -out "$OUTDIR/$CLIENT.key" 2048
    openssl req -new -key "$OUTDIR/$CLIENT.key" \
        -out "$OUTDIR/$CLIENT.csr" -subj "/CN=$CLIENT/O=SMO/C=VN"
    openssl x509 -req -days 3650 -in "$OUTDIR/$CLIENT.csr" \
        -CA "$OUTDIR/ca.crt" -CAkey "$OUTDIR/ca.key" -CAcreateserial \
        -out "$OUTDIR/$CLIENT.crt"
    step "Generated $CLIENT cert"
done

step "OpenVPN PKI generated in $OUTDIR"
ls -la "$OUTDIR/"*.crt "$OUTDIR/"*.key "$OUTDIR/"dh.pem "$OUTDIR/"ta.key 2>/dev/null
echo ""
echo "Client certs: $OUTDIR/<local-a|local-b>.crt + .key"
echo "Distribute ca.crt, ta.key, <client>.crt, <client>.key to each local machine"
