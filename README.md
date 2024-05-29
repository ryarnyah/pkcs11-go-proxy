# Simple PKCS#11 module proxy over GRPC

Can be used to make a bridge with PKCS#11 windows-only module to use it on linux.

## Usage
### Generate certs
```bash
./generate-keys.sh
```
### Server
```bash
# Bind address
export PKCS11_PROXY_URI="localhost:8080"
# Ca-cert for allowed clients (Optional)
export PKCS11_PROXY_CACERT=$(pwd)/ca.crt
# Server cert & key (Optional)
export PKCS11_PROXY_KEY=$(pwd)/server.key
export PKCS11_PROXY_CERT=$(pwd)/server.crt
# Start server
./pkcs11-proxy-server
```

### Client
```bash
# Dial address of server
export PKCS11_PROXY_URI="localhost:8080"
# Module to use on server (must be present only on server host)
export PKCS11_MODULE="/usr/lib/softhsm/libsofthsm2.so"

# Ca-cert for trusted server (Optional)
export PKCS11_PROXY_CACERT=$(pwd)/ca.crt
# Client cert & key (Optional)
export PKCS11_PROXY_KEY=$(pwd)/client.key
export PKCS11_PROXY_CERT=$(pwd)/client.crt

# Example usage on client
p11tool --provider=$(pwd)/pkcs11-proxy-module.so --generate-random=256
p11tool --provider=$(pwd)/pkcs11-proxy-module.so --list-mechanisms
```

## Build
```bash
sudo apt-get update && sudo apt-get install gcc-multilib curl unzip gcc gcc-mingw-w64 -y
mkdir -p $HOME/protobuf && pushd $HOME/protobuf
curl -o protoc.zip -L 'https://github.com/protocolbuffers/protobuf/releases/download/v27.0/protoc-27.0-linux-x86_64.zip'
unzip protoc.zip
popd
export PATH=$HOME/.local/bin:$HOME/protobuf/bin:$PATH
make dev-dependencies
make
```