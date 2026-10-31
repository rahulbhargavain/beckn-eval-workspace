#!/bin/bash
# Run an ONIX adapter against the stub registry and backend. Needs root (port 443, mount namespace).
# usage: start.sh OUTDIR ONIXDIR   (OUTDIR as made by prepare.py, seen from this machine)
# The host mapping lives in a private mount namespace: /etc/hosts and the system trust store are untouched.
set -e
D=$1; O=$2
mkdir -p "$D/certs"
if [ ! -f "$D/certs/ca.crt" ]; then
  openssl req -x509 -newkey rsa:2048 -nodes -keyout "$D/certs/ca.key" -out "$D/certs/ca.crt" -subj "/CN=onix-eval-throwaway-ca" -days 2 2>/dev/null
  openssl req -newkey rsa:2048 -nodes -keyout "$D/certs/server.key" -out "$D/certs/server.csr" -subj "/CN=fabric.nfh.global" 2>/dev/null
  printf "subjectAltName=DNS:fabric.nfh.global" > "$D/certs/san.ext"
  openssl x509 -req -in "$D/certs/server.csr" -CA "$D/certs/ca.crt" -CAkey "$D/certs/ca.key" -CAcreateserial \
    -out "$D/certs/server.crt" -days 2 -extfile "$D/certs/san.ext" 2>/dev/null
  cat /etc/ssl/certs/ca-certificates.crt "$D/certs/ca.crt" > "$D/certs/bundle.crt"
fi
rm -f "$D/backend.log"
redis-server --port 6379 --save "" --daemonize yes >/dev/null
exec unshare -m -- bash -c '
  cp /etc/hosts '"$D"'/hosts && echo "127.0.0.1 fabric.nfh.global" >> '"$D"'/hosts && mount --bind '"$D"'/hosts /etc/hosts
  python3 '"$(dirname "$0")"'/stubs.py '"$D"' &
  sleep 1
  cd '"$O"'
  SSL_CERT_FILE='"$D"'/certs/bundle.crt exec ./server --config='"$D"'/config.yaml'
