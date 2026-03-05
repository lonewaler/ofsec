# TLS Certificates

For local production testing, generate a self-signed cert:

    mkdir -p infra/certs
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
      -keyout infra/certs/ofsec.key \
      -out infra/certs/ofsec.crt \
      -subj "/C=US/ST=Dev/L=Local/O=OfSec/CN=localhost"

For real production, place your certificate authority certs here instead.
Never commit private keys (.key files) to git.
