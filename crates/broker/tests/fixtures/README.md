# TLS test fixtures — NOT SECRET, NOT FOR PRODUCTION

`localhost.pem` and `localhost-key.pem` are a throwaway self-signed
certificate and its **plaintext** private key, committed on purpose so the
broker's TLS tests can bind a real socket without a certificate-minting
dependency at build time. The private key is public: anyone reading this
repository has it. Never point a real broker at these files.

- Subject / issuer: `CN=agentcordon-broker-test` (self-signed)
- SAN: `DNS:localhost`, `IP:127.0.0.1`
- Key: P-256, unencrypted PKCS#8 (`BEGIN PRIVATE KEY`)
- Extended key usage: `serverAuth`; `basicConstraints: CA:FALSE`, so the
  certificate is a valid end-entity and can also be handed to a client as a
  trust anchor (`reqwest::Certificate::from_pem` + `add_root_certificate`).
- Valid for 10 years from 2026-09-04.

Regenerate with the same command that made them:

    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
      -keyout localhost-key.pem -out localhost.pem -days 3650 \
      -subj "/CN=agentcordon-broker-test" \
      -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
      -addext "basicConstraints=critical,CA:FALSE" \
      -addext "keyUsage=critical,digitalSignature,keyAgreement" \
      -addext "extendedKeyUsage=serverAuth"

`CA:FALSE` matters: rustls-webpki refuses a certificate with `CA:TRUE` as an
end-entity (`Error::CaUsedAsEndEntity`), and `serverAuth` is required of the
end-entity, so a certificate missing either will fail the handshake rather
than the assertion the test is making.
