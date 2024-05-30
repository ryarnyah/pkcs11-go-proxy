# Simple PKCS#11 module proxy over GRPC

Can be used to make a bridge with PKCS#11 windows-only module to use it on linux.

(Info) You can get small binaries compressed with UPX (prefixed by 's' in releases).

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

### Example usage
```bash
# Install softhsm2
apt-get update
apt-get install -y softhsm2 gnutls-bin curl
# Initialize softhsm2 token
mkdir -p $HOME/.local/softhsm2/tokens
cat > $HOME/.softhsm2.conf <<EOF
# SoftHSM v2 configuration file

directories.tokendir = $HOME/.local/softhsm2/tokens/
objectstore.backend = file

# ERROR, WARNING, INFO, DEBUG
log.level = ERROR

# If CKF_REMOVABLE_DEVICE flag should be set
slots.removable = false

# Enable and disable PKCS#11 mechanisms using slots.mechanisms.
slots.mechanisms = ALL

# If the library should reset the state on fork
library.reset_on_fork = false
EOF
export SOFTHSM2_CONF=$HOME/.softhsm2.conf
softhsm2-util --init-token --slot 0 --label "My token 1" --pin 1234 --so-pin 1234
# Install server
curl -LO https://github.com/ryarnyah/pkcs11-go-proxy/releases/latest/download/spkcs11-proxy-server
chmod +x spkcs11-proxy-server

# Install client
curl -LO https://github.com/ryarnyah/pkcs11-go-proxy/releases/latest/download/spkcs11-proxy-module.so

# Generate tls keys
curl -LO https://github.com/ryarnyah/pkcs11-go-proxy/raw/main/generate-keys.sh
chmod +x generate-keys.sh
./generate-keys.sh

# Launch server
export PKCS11_PROXY_ALLOWED_MODULES="/usr/lib/softhsm/libsofthsm2.so"
export PKCS11_PROXY_URI="localhost:8080"
export PKCS11_PROXY_CACERT=$(pwd)/ca.crt
export PKCS11_PROXY_KEY=$(pwd)/server.key
export PKCS11_PROXY_CERT=$(pwd)/server.crt
./spkcs11-proxy-server &
timeout 22 bash -c 'until printf "" 2>>/dev/null >>/dev/tcp/$0/$1; do sleep 1; done' localhost 8080

# Test client
unset SOFTHSM2_CONF
# For pkcs11mod log
mkdir -p $HOME/.config
export PKCS11_PROXY_URI="localhost:8080"
export PKCS11_PROXY_CACERT=$(pwd)/ca.crt
export PKCS11_PROXY_KEY=$(pwd)/client.key
export PKCS11_PROXY_CERT=$(pwd)/client.crt
export PKCS11_MODULE="/usr/lib/softhsm/libsofthsm2.so"
p11tool --provider=$(pwd)/spkcs11-proxy-module.so --list-mechanisms
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