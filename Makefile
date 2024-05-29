
.PHONY: protoc
protoc: 
	protoc -I proto/ \
	--proto_path=${GOPATH}/src \
	--go-grpc_out=pkcs11 \
	--go_out=pkcs11 \
	proto/schema.proto

.PHONY: dev-dependencies
dev-dependencies: ## Install all dev dependencies
	go install -v google.golang.org/protobuf/cmd/protoc-gen-go@v1.27.1
	go install -v google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.1.0
