
all: pkcs11-proxy-module.so pkcs11-proxy-server

clean:
	rm -f pkcs11-proxy-module.so pkcs11-proxy-module.h pkcs11-proxy-server

.PHONY: pkcs11-proxy-server
pkcs11-proxy-server: protoc
	go build -o pkcs11-proxy-server ./cmd/server

.PHONY: pkcs11-proxy-server.exe
pkcs11-proxy-server.exe: protoc
	CGO_ENABLED=1 CC=/usr/bin/x86_64-w64-mingw32-gcc GOOS=windows go build -o pkcs11-proxy-server.exe ./cmd/server

.PHONY: pkcs11-proxy-module.so
pkcs11-proxy-module.so: protoc init
	go build -o pkcs11-proxy-module.so -buildmode=c-shared ./cmd/module

.PHONY: protoc
protoc: 
	protoc -I proto/ \
	--proto_path=${GOPATH}/src \
	--go-grpc_out=pkcs11 \
	--go_out=pkcs11 \
	proto/schema.proto

.PHONY: init
init:
	cd pkcs11mod; go mod init github.com/namecoin/pkcs11mod || true
	cd pkcs11mod; go mod tidy
	cd pkcs11mod; go generate ./...
	cd pkcs11mod; go mod tidy

.PHONY: dev-dependencies
dev-dependencies: ## Install all dev dependencies
	go install -v google.golang.org/protobuf/cmd/protoc-gen-go@v1.27.1
	go install -v google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.1.0
