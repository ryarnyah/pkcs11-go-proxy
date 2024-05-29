package pkg

import (
	"github.com/miekg/pkcs11"
	p11 "github.com/ryarnyah/pkcs11-go-proxy/pkcs11"
)

func UintToUint32(d []uint) []uint32 {
	res := make([]uint32, len(d))
	for i, a := range d {
		res[i] = uint32(a)
	}
	return res
}

func Uint32ToUint(d []uint32) []uint {
	res := make([]uint, len(d))
	for i, a := range d {
		res[i] = uint(a)
	}
	return res
}

func ObjectHandlesToUint32(d []pkcs11.ObjectHandle) []uint32 {
	res := make([]uint32, len(d))
	for i, a := range d {
		res[i] = uint32(a)
	}
	return res
}

func Uint32ToObjectHandles(d []uint32) []pkcs11.ObjectHandle {
	res := make([]pkcs11.ObjectHandle, len(d))
	for i, a := range d {
		res[i] = pkcs11.ObjectHandle(a)
	}
	return res
}

func VersionToVersion(v pkcs11.Version) *p11.Version {
	return &p11.Version{
		MajorMinor: []byte{v.Major, v.Minor},
	}
}

func AttributeToAttribute(a *pkcs11.Attribute) *p11.Attribute {
	return &p11.Attribute{
		Type:  uint32(a.Type),
		Value: a.Value,
	}
}

func AttributesToAttributes(a []*pkcs11.Attribute) []*p11.Attribute {
	res := make([]*p11.Attribute, len(a))
	for i, a := range a {
		res[i] = AttributeToAttribute(a)
	}
	return res
}

func ReverseAttributeToAttribute(a *p11.Attribute) *pkcs11.Attribute {
	return &pkcs11.Attribute{
		Type:  uint(a.Type),
		Value: a.Value,
	}
}

func ReverseAttributesToAttributes(a []*p11.Attribute) []*pkcs11.Attribute {
	res := make([]*pkcs11.Attribute, len(a))
	for i, a := range a {
		res[i] = ReverseAttributeToAttribute(a)
	}
	return res
}

func MechanismToMechanism(m *pkcs11.Mechanism) *p11.Mechanism {
	return &p11.Mechanism{
		Mechanism: uint32(m.Mechanism),
		Parameter: m.Parameter,
		// TODO generator
	}
}

func ReverseMechanismToMechanism(m *p11.Mechanism) *pkcs11.Mechanism {
	return &pkcs11.Mechanism{
		Mechanism: uint(m.Mechanism),
		Parameter: m.Parameter,
		// TODO generator
	}
}

func MechanismsToMechanisms(m []*pkcs11.Mechanism) []*p11.Mechanism {
	res := make([]*p11.Mechanism, len(m))
	for i, a := range m {
		res[i] = MechanismToMechanism(a)
	}
	return res
}

func ReverseMechanismsToMechanisms(m []*p11.Mechanism) []*pkcs11.Mechanism {
	res := make([]*pkcs11.Mechanism, len(m))
	for i, a := range m {
		res[i] = ReverseMechanismToMechanism(a)
	}
	return res
}
