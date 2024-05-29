#!/bin/bash

openssl ecparam -name prime256v1 -genkey -noout -out ca.key
openssl req -x509 -new -nodes -key ca.key -subj "/CN=TestCA/C=MY" -days 730 -out ca.crt
openssl ecparam -name prime256v1 -genkey -noout -out server.key
cat > csr.conf <<EOF
[ req ]
default_bits = 256
prompt = no
default_md = sha256
req_extensions = req_ext
distinguished_name = dn

[ dn ]
C = MY
CN = localhost

[ req_ext ]
keyUsage = keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = localhost
DNS.2 = pkcs11-proxy-server.local
IP.1 = 127.0.0.1

EOF
openssl req -new -key server.key -out server.csr -config csr.conf
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 90 -extfile csr.conf -extensions req_ext
openssl ecparam -name prime256v1 -genkey -noout -out client.key
cat > csrclient.conf <<EOF
[ req ]
default_bits = 256
prompt = no
default_md = sha256
req_extensions = req_ext
distinguished_name = dn

[ dn ]
C = MY
CN = client

[ req_ext ]
keyUsage = keyEncipherment
extendedKeyUsage = clientAuth

EOF
openssl req -new -key client.key -out client.csr -config csrclient.conf
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt -days 90 -extfile csrclient.conf -extensions req_ext