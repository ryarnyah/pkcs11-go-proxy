package module

/*
#include "../pkcs11/pkcs11go.h"

static inline void SetIndex(CK_ULONG_PTR array, CK_ULONG i, CK_ULONG val) {
	array[i] = val;
}
static inline CK_ATTRIBUTE_PTR IndexAttributePtr(CK_ATTRIBUTE_PTR array, CK_ULONG i) {
	return &(array[i]);
}
// Copied verbatim from miekg/pkcs11 pkcs11.go
static inline CK_VOID_PTR getAttributePval(CK_ATTRIBUTE_PTR a) {
	return a->pValue;
}
static inline CK_VOID_PTR getMechanismParam(CK_MECHANISM_PTR m) {
	return m->pParameter;
}

static inline CK_VOID_PTR getOAEPSourceData(CK_RSA_PKCS_OAEP_PARAMS_PTR params) {
	return params->pSourceData;
}
*/
import "C"

import (
	"errors"
	"unsafe"

	"github.com/ryarnyah/pkcs11-go-proxy/pkg/proto/pkcs11"
)

func contains(s []uint64, e uint64) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

// toMechanism converts from a C pointer to a *pkcs11.Mechanism.
// It doesn't free the input object.
func toMechanism(pMechanism C.CK_MECHANISM_PTR) *pkcs11.Mechanism {
	if contains(pkcs11.KnownMechanisms, uint64(pMechanism.mechanism)) && uint64(pMechanism.ulParameterLen) > 0 {
		return &pkcs11.Mechanism{
			Mechanism: uint64(pMechanism.mechanism),
			Parameter: C.GoBytes(unsafe.Pointer(C.getMechanismParam(pMechanism)), C.int(pMechanism.ulParameterLen)),
		}
	}
	return &pkcs11.Mechanism{
		Mechanism: uint64(pMechanism.mechanism),
	}
}

// fromObjectHandleList converts from a []pkcs11.ObjectHandle to a C style array.
func fromObjectHandleList(goList []pkcs11.ObjectHandle, cList C.CK_ULONG_PTR, goSize uint64) {
	for i := 0; uint64(i) < goSize; i++ {
		C.SetIndex(cList, C.CK_ULONG(i), C.CK_ULONG(goList[i]))
	}
}

// fromTemplate converts from a []*pkcs11.Attribute to a C style array that
// already contains a template as is passed to C_GetAttributeValue.
func fromTemplate(template []*pkcs11.Attribute, clist C.CK_ATTRIBUTE_PTR) error {
	l1 := make([]C.CK_ATTRIBUTE_PTR, len(template))
	for i := 0; i < len(l1); i++ {
		l1[i] = C.IndexAttributePtr(clist, C.CK_ULONG(i))
	}

	bufferTooSmall := false

	for i, x := range template {
		c := l1[i]
		if x.Value == nil {
			// CKR_ATTRIBUTE_TYPE_INVALID or CKR_ATTRIBUTE_SENSITIVE
			c.ulValueLen = C.CK_UNAVAILABLE_INFORMATION

			continue
		}

		cLen := C.CK_ULONG(uint64(len(x.Value)))

		switch {
		case C.getAttributePval(c) == nil:
			c.ulValueLen = cLen
		case c.ulValueLen >= cLen:
			buf := unsafe.Pointer(C.getAttributePval(c))

			// Adapted from solution 3 of https://stackoverflow.com/a/35675259
			goBuf := (*[1 << 30]byte)(buf)
			copy(goBuf[:], x.Value)

			c.ulValueLen = cLen
		default:
			c.ulValueLen = C.CK_UNAVAILABLE_INFORMATION
			bufferTooSmall = true
		}
	}

	if bufferTooSmall {
		return pkcs11.Error(pkcs11.CKR_BUFFER_TOO_SMALL)
	}

	return nil
}

// toTemplate converts from a C style array to a []*pkcs11.Attribute.
// It doesn't free the input array.
func toTemplate(clist C.CK_ATTRIBUTE_PTR, size C.CK_ULONG) []*pkcs11.Attribute {
	l1 := make([]C.CK_ATTRIBUTE_PTR, int(size))
	for i := 0; i < len(l1); i++ {
		l1[i] = C.IndexAttributePtr(clist, C.CK_ULONG(i))
	}
	// defer C.free(unsafe.Pointer(clist)) // Removed compared to miekg implementation since it's not desired here
	l2 := make([]*pkcs11.Attribute, int(size))

	for i, c := range l1 {
		x := new(pkcs11.Attribute)
		x.Type = uint64(c._type)

		//nolint:wsl // Ignore commented-out miekg line
		if int(c.ulValueLen) != -1 {
			buf := unsafe.Pointer(C.getAttributePval(c))
			x.Value = C.GoBytes(buf, C.int(c.ulValueLen))
			// C.free(buf) // Removed compared to miekg implementation since it's not desired here
		}

		l2[i] = x
	}

	return l2
}

// fromMechanismList converts from a []*pkcs11.Mechanism to a C style array of
// mechanism types.
func fromMechanismList(goList []*pkcs11.Mechanism, cList C.CK_ULONG_PTR, goSize uint64) {
	for i := 0; uint64(i) < goSize; i++ {
		C.SetIndex(cList, C.CK_ULONG(i), C.CK_ULONG(goList[i].Mechanism))
	}
}

// fromList converts from a []uint to a C style array.
func fromList(goList []uint64, cList C.CK_ULONG_PTR, goSize uint64) {
	for i := 0; uint64(i) < goSize; i++ {
		C.SetIndex(cList, C.CK_ULONG(i), C.CK_ULONG(goList[i]))
	}
}

// fromCBBool converts a CK_BBOOL to a bool.
func fromCBBool(x C.CK_BBOOL) bool {
	// Any nonzero value means true, and zero means false.
	return x != C.CK_FALSE
}

func fromError(e error) C.CK_RV {
	if e == nil {
		return C.CKR_OK
	}

	var pe pkcs11.Error
	if !errors.As(e, &pe) {
		// This error doesn't map to a PKCS#11 error code.  Return a generic
		// "function failed" error instead.
		pe = pkcs11.Error(pkcs11.CKR_FUNCTION_FAILED)
	}

	return C.CK_RV(pe)
}
