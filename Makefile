BASE_PATH := $(PWD)

all: pkcs11-proxy-module.so pkcs11-proxy-module.dll pkcs11-proxy-server pkcs11-proxy-server.exe

clean:
	rm -f *.so *.dll pkcs11-proxy-server* spkcs11-proxy-server*

.PHONY: pre-integration-test
pre-integration-test: init-softhsm2 build-pkcs11test start-pkcs11-proxy-server

.PHONY: integration-test
integration-test: pre-integration-test pkcs11-proxy-module.so
	PKCS11_MODULE=$(BASE_PATH)/.local/softhsm/libsofthsm2.so \
		ext/pkcs11test/pkcs11test -S 0 -u 1234 -o 4321 -m $(BASE_PATH)/pkcs11-proxy-module.so
	$(MAKE) post-integration-test

.PHONY: post-integration-test
post-integration-test: stop-pkcs11-proxy-server

.PHONY: pkcs11-proxy-server
pkcs11-proxy-server: protoc
	go build -ldflags="-s -w" -buildvcs=false -o pkcs11-proxy-server ./cmd/server

.PHONY: pkcs11-proxy-server.exe
pkcs11-proxy-server.exe: protoc
	CGO_ENABLED=1 CC=/usr/bin/x86_64-w64-mingw32-gcc GOOS=windows go build -ldflags="-s -w" -buildvcs=false -o pkcs11-proxy-server.exe ./cmd/server

.PHONY: pkcs11-proxy-module.so
pkcs11-proxy-module.so: protoc
	go build -ldflags="-s -w" -o pkcs11-proxy-module.so -buildvcs=false -buildmode=c-shared ./cmd/module

.PHONY: pkcs11-proxy-module.dll
pkcs11-proxy-module.dll: protoc
	GOOS=windows CGO_ENABLED=1 CC=/usr/bin/x86_64-w64-mingw32-gcc go build -ldflags="-s -w" -o pkcs11-proxy-module.dll -buildvcs=false -buildmode=c-shared ./cmd/module

.PHONY: protoc
protoc: 
	protoc -I proto/ \
	--go-grpc_out=pkg/proto/pkcs11 \
	--go_out=pkg/proto/pkcs11 \
	proto/schema.proto

.PHONY: dev-dependencies
dev-dependencies: ## Install all dev dependencies
	go install -v google.golang.org/protobuf/cmd/protoc-gen-go@v1.27.1
	go install -v google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.1.0

# Tests
.PHONY: build-softhsm2
build-softhsm2:
	cd ext/SoftHSMv2 && ./autogen.sh && ./configure --prefix=$(BASE_PATH)/.local && make -j && make install

.PHONY: start-softhsm2
init-softhsm2: build-softhsm2
	SOFTHSM2_CONF=$(BASE_PATH)/.local/etc/softhsm2.conf $(BASE_PATH)/.local/bin/softhsm2-util --init-token --slot 0 --token pkcs11-proxy-test --label test --pin 1234 --so-pin 4321 || true

.PHONY: build-pkcs11test
build-pkcs11test:
	$(MAKE) -C ext/pkcs11test -j

.PHONY: start-pkcs11-proxy-server
start-pkcs11-proxy-server: pkcs11-proxy-server stop-pkcs11-proxy-server
	PKCS11_PROXY_ACCESS_LOGS=true ./pkcs11-proxy-server &

.PHONY: stop-pkcs11-proxy-server
stop-pkcs11-proxy-server:
	-pkill -f pkcs11-proxy-server