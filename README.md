```bash
export PKCS11_PROXY_URI="localhost:8080"
export PKCS11_MODULE="/usr/lib/softhsm/libsofthsm2.so"

export PKCS11_PROXY_CACERT=$(pwd)/ca.crt
export PKCS11_PROXY_KEY=$(pwd)/server.key
export PKCS11_PROXY_CERT=$(pwd)/server.crt

export PKCS11_PROXY_CACERT=$(pwd)/ca.crt
export PKCS11_PROXY_KEY=$(pwd)/client.key
export PKCS11_PROXY_CERT=$(pwd)/client.crt
```