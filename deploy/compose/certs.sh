#!/bin/sh
# Makes the TLS material for the local identity provider: a throwaway CA and a server certificate for
# Dex. The control plane only accepts an https issuer (internal/authn), so the stack needs one, and
# no key may be committed. The CA key is deleted as soon as the certificate is signed. The files live
# in a Docker volume that belongs to this Compose project, and `docker compose down --volumes`
# removes them. The server key is readable by every user of the volume, because Dex runs as another
# user than this script.
set -eu
cd /certs
if [ -f dex.crt ] && [ -f dex.key ] && [ -f ca.pem ]; then
    echo "the certificates exist"
    exit 0
fi

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 365 \
    -subj "/CN=ipso local development CA" \
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign" \
    -keyout ca.key -out ca.pem
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -subj "/CN=dex" -keyout dex.key -out dex.csr
printf '%s\n' \
    "subjectAltName=DNS:dex,DNS:localhost,IP:127.0.0.1" \
    "basicConstraints=critical,CA:FALSE" \
    "extendedKeyUsage=serverAuth" > dex.ext
openssl x509 -req -in dex.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 365 \
    -extfile dex.ext -out dex.crt
rm -f ca.key ca.srl dex.csr dex.ext
chmod 0644 ca.pem dex.crt dex.key
echo "made the certificates"
