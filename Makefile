
all: pkcs11-proxy-module.so pkcs11-proxy-module.dll pkcs11-proxy-server pkcs11-proxy-server.exe

clean:
	rm -f *.so *.dll pkcs11-proxy-server* spkcs11-proxy-server*

.PHONY: pkcs11-proxy-server
pkcs11-proxy-server: protoc
	go build -ldflags="-s -w" -buildvcs=false -o pkcs11-proxy-server ./cmd/server

.PHONY: pkcs11-proxy-server.exe
pkcs11-proxy-server.exe: protoc
	CGO_ENABLED=1 CC=/usr/bin/x86_64-w64-mingw32-gcc GOOS=windows go build -ldflags="-s -w" -buildvcs=false -o pkcs11-proxy-server.exe ./cmd/server

.PHONY: pkcs11-proxy-module.so
pkcs11-proxy-module.so: protoc init
	go build -ldflags="-s -w" -o pkcs11-proxy-module.so -buildvcs=false -buildmode=c-shared ./cmd/module

.PHONY: pkcs11-proxy-module.dll
pkcs11-proxy-module.dll: protoc init
	GOOS=windows CGO_ENABLED=1 CC=/usr/bin/x86_64-w64-mingw32-gcc go build -ldflags="-s -w" -o pkcs11-proxy-module.dll -buildvcs=false -buildmode=c-shared ./cmd/module

.PHONY: protoc
protoc: 
	protoc -I proto/ \
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
