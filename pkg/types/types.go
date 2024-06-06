package types

import (
	pkcs11 "github.com/ryarnyah/pkcs11-go-proxy/pkg/proto/pkcs11"
)

func UintToUint64(d []uint) []uint64 {
	res := make([]uint64, len(d))
	for i, a := range d {
		res[i] = uint64(a)
	}
	return res
}

func uint64ToUint(d []uint64) []uint {
	res := make([]uint, len(d))
	for i, a := range d {
		res[i] = uint(a)
	}
	return res
}

func ObjectHandlesToUint64(d []pkcs11.ObjectHandle) []uint64 {
	res := make([]uint64, len(d))
	for i, a := range d {
		res[i] = uint64(a)
	}
	return res
}

func uint64ToObjectHandles(d []uint64) []pkcs11.ObjectHandle {
	res := make([]pkcs11.ObjectHandle, len(d))
	for i, a := range d {
		res[i] = pkcs11.ObjectHandle(a)
	}
	return res
}
