package main

/*
#cgo linux LDFLAGS: -ldl
#cgo darwin LDFLAGS: -ldl
#cgo openbsd LDFLAGS:
#cgo freebsd LDFLAGS: -ldl
*/

// #include <stdlib.h>
// #include <stdio.h>
// #include <string.h>
// #include <unistd.h>
// #include "pkcs11go.h"
import "C"
import (
	"context"
	"fmt"
	"os"

	p11 "github.com/ryarnyah/pkcs11-go-proxy/pkcs11"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

var client p11.PKCS11Client
var ctx uint64

func init() {
	conn, err := grpc.Dial(os.Getenv("PKCS11_PROXY_URI"), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		panic(fmt.Errorf("unable to connect to pkcs11 proxy using env PKCS11_PROXY_URI %s: %s", os.Getenv("PKCS11_PROXY_URI"), err))
	}
	client := p11.NewPKCS11Client(conn)
	response, err := client.New(context.Background(), &p11.NewRequest{
		Module: os.Getenv("PKCS11_MODULE"),
	})
	if err != nil {
		panic(err)
	}
	ctx := response.Ctx
	fmt.Printf("Context initialized with %d\n", ctx)
}

//export C_Initialize
func C_Initialize(pInitArgs C.CK_VOID_PTR) C.CK_RV {
	response, _ := client.Initialize(context.Background(), &p11.InitializeRequest{
		Ctx: ctx,
	})
	return C.CK_RV(response.Error)
}

func main() {}
