#!/bin/bash

# Create certs directory
mkdir -p certs

echo "Generating self-signed SSL certificates for Kairos Report Engine..."

# Generate a new private key and self-signed certificate valid for 365 days
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout certs/key.pem \
  -out certs/cert.pem \
  -subj "/C=US/ST=State/L=City/O=KairosSec/CN=localhost"

echo ""
echo "Success! Self-signed certificates have been generated:"
echo "  - certs/key.pem  (Private Key)"
echo "  - certs/cert.pem (Certificate)"
echo ""
echo "You can now run Streamlit in production mode on port 443."
echo "Note: Running on port 443 requires root privileges, so start the app with:"
echo "  sudo .venv/bin/streamlit run --server.port 443 --server.headless true --server.sslCertFile certs/cert.pem --server.sslKeyFile certs/key.pem app.py"
