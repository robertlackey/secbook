#!/bin/bash

# Define the directory path
DIRECTORY=./certs

# Check if the directory exists
if [ ! -d "$DIRECTORY" ]; then
    # If the directory doesn't exist, create it
    mkdir -p "$DIRECTORY"
    echo "Directory created: $DIRECTORY"
else
    echo "Directory already exists: $DIRECTORY"
fi

# Obtain the hostname or IP address of the system
if [ -n "$HOSTNAME" ]; then
    HOST="$HOSTNAME"
else
    HOST="$(hostname -f)"
fi

# Get the IP address of the system
IP=$(hostname -I | awk '{print $1}')

# Generate a private key
openssl genpkey -algorithm RSA -out $DIRECTORY/cert.key

# Generate a configuration file for the certificate
cat <<EOF > $DIRECTORY/cert.cnf
[req]
default_bits = 4096
prompt = no
default_md = sha256
distinguished_name = dn

[dn]
CN = ${HOSTNAME}

[req_ext]
subjectAltName = @alt_names

[alt_names]
DNS.1 = ${HOSTNAME}
IP.1 = ${IP}
EOF

# Generate a CSR (Certificate Signing Request)
openssl req -new -key $DIRECTORY/cert.key -out $DIRECTORY/cert.csr -config $DIRECTORY/cert.cnf

# Generate a self-signed certificate
openssl x509 -req -days 365 -in $DIRECTORY/cert.csr -signkey $DIRECTORY/cert.key -out $DIRECTORY/cert.crt -extensions req_ext -extfile $DIRECTORY/cert.cnf

# Clean up the CSR and configuration file
rm $DIRECTORY/cert.csr $DIRECTORY/cert.cnf

docker-compose --env-file .env.dev up --build -d
