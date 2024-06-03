module github.com/ryarnyah/pkcs11-go-proxy

go 1.22.3

require (
	github.com/miekg/pkcs11 v1.1.1
	github.com/namecoin/pkcs11mod v0.0.1
	google.golang.org/grpc v1.64.0
	google.golang.org/protobuf v1.34.1
)

require (
	golang.org/x/net v0.23.0 // indirect
	golang.org/x/sys v0.18.0 // indirect
	golang.org/x/text v0.14.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20240318140521-94a12d6c2237 // indirect
)

replace github.com/namecoin/pkcs11mod => ./pkcs11mod
