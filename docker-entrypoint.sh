#!/bin/bash
set -e

# Generate self-signed certificates if not present
if [ ! -f /app/certs/cert.pem ] || [ ! -f /app/certs/key.pem ]; then
    echo "No certificates found — generating self-signed SSL certificates..."
    mkdir -p /app/certs
    openssl req -x509 -nodes -days 365 -newkey rsa:4096 \
        -keyout /app/certs/key.pem \
        -out /app/certs/cert.pem \
        -subj "/C=US/ST=State/L=City/O=KairosSec/CN=localhost" 2>/dev/null
    echo "Certificates generated."
fi

mkdir -p /app/data /app/reports

exec streamlit run app.py \
    --server.port 8443 \
    --server.headless true \
    --server.sslCertFile /app/certs/cert.pem \
    --server.sslKeyFile /app/certs/key.pem \
    --browser.gatherUsageStats false
