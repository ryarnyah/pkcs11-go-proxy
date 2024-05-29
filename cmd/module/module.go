package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"io/ioutil"
	"log"
	"os"

	"github.com/miekg/pkcs11"
	"github.com/namecoin/pkcs11mod"
	p11 "github.com/ryarnyah/pkcs11-go-proxy/pkcs11"
	"github.com/ryarnyah/pkcs11-go-proxy/pkg"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

type backend struct {
	client p11.PKCS11Client
	ctx    string
}

func (b *backend) Initialize() error {
	_, err := b.client.Initialize(context.Background(), &p11.InitializeRequest{Ctx: b.ctx})
	return err
}
func (b *backend) Finalize() error {
	_, err := b.client.Finalize(context.Background(), &p11.FinalizeRequest{Ctx: b.ctx})
	return err
}
func (b *backend) GetInfo() (pkcs11.Info, error) {
	response, err := b.client.GetInfo(context.Background(), &p11.GetInfoRequest{Ctx: b.ctx})
	return pkcs11.Info{
		CryptokiVersion: pkcs11.Version{
			Major: response.GetInfo().GetCryptokiVersion().GetMajorMinor()[0],
			Minor: response.GetInfo().GetCryptokiVersion().GetMajorMinor()[1],
		},
		ManufacturerID:     response.GetInfo().GetManufacturerID(),
		Flags:              uint(response.GetInfo().GetFlags()),
		LibraryDescription: response.GetInfo().GetLibraryDescription(),
		LibraryVersion: pkcs11.Version{
			Major: response.GetInfo().GetLibraryVersion().GetMajorMinor()[0],
			Minor: response.GetInfo().GetLibraryVersion().GetMajorMinor()[1],
		},
	}, err
}
func (b *backend) GetSlotList(tokenPresent bool) ([]uint, error) {
	response, err := b.client.GetSlotList(context.Background(), &p11.GetSlotListRequest{
		Ctx:          b.ctx,
		TokenPresent: tokenPresent,
	})
	return pkg.Uint32ToUint(response.GetSlotIds()), err
}
func (b *backend) GetSlotInfo(slotID uint) (pkcs11.SlotInfo, error) {
	response, err := b.client.GetSlotInfo(context.Background(), &p11.GetSlotInfoRequest{
		Ctx:    b.ctx,
		SlotId: uint32(slotID),
	})
	return pkcs11.SlotInfo{
		SlotDescription: response.GetInfo().GetSlotDescription(),
		ManufacturerID:  response.GetInfo().GetManufacturerID(),
		Flags:           uint(response.GetInfo().GetFlags()),
		HardwareVersion: pkcs11.Version{
			Major: response.GetInfo().GetHardwareVersion().GetMajorMinor()[0],
			Minor: response.GetInfo().GetHardwareVersion().GetMajorMinor()[1],
		},
		FirmwareVersion: pkcs11.Version{
			Major: response.GetInfo().GetFirmwareVersion().GetMajorMinor()[0],
			Minor: response.GetInfo().GetFirmwareVersion().GetMajorMinor()[1],
		},
	}, err
}
func (b *backend) GetTokenInfo(slotID uint) (pkcs11.TokenInfo, error) {
	response, err := b.client.GetTokenInfo(context.Background(), &p11.GetTokenInfoRequest{
		Ctx:    b.ctx,
		SlotId: uint32(slotID),
	})
	return pkcs11.TokenInfo{
		Label:              response.GetInfo().GetLabel(),
		ManufacturerID:     response.GetInfo().GetManufacturerID(),
		Model:              response.GetInfo().GetModel(),
		SerialNumber:       response.GetInfo().GetSerialNumber(),
		Flags:              uint(response.GetInfo().GetFlags()),
		MaxSessionCount:    uint(response.GetInfo().GetMaxSessionCount()),
		SessionCount:       uint(response.GetInfo().GetSessionCount()),
		MaxRwSessionCount:  uint(response.GetInfo().GetMaxRwSessionCount()),
		RwSessionCount:     uint(response.GetInfo().GetRwSessionCount()),
		MaxPinLen:          uint(response.GetInfo().GetMaxPinLen()),
		MinPinLen:          uint(response.GetInfo().GetMinPinLen()),
		TotalPublicMemory:  uint(response.GetInfo().GetTotalPublicMemory()),
		FreePublicMemory:   uint(response.GetInfo().GetFreePublicMemory()),
		TotalPrivateMemory: uint(response.GetInfo().GetTotalPrivateMemory()),
		FreePrivateMemory:  uint(response.GetInfo().GetFreePrivateMemory()),
		HardwareVersion: pkcs11.Version{
			Major: response.GetInfo().GetHardwareVersion().GetMajorMinor()[0],
			Minor: response.GetInfo().GetHardwareVersion().GetMajorMinor()[1],
		},
		FirmwareVersion: pkcs11.Version{
			Major: response.GetInfo().GetFirmwareVersion().GetMajorMinor()[0],
			Minor: response.GetInfo().GetFirmwareVersion().GetMajorMinor()[1],
		},
		UTCTime: response.GetInfo().GetUTCTime(),
	}, err
}
func (b *backend) GetMechanismList(slotID uint) ([]*pkcs11.Mechanism, error) {
	response, err := b.client.GetMechanismList(context.Background(), &p11.GetMechanismListRequest{
		Ctx:    b.ctx,
		SlotId: uint32(slotID),
	})
	return pkg.ReverseMechanismsToMechanisms(response.GetMechanisms()), err
}
func (b *backend) GetMechanismInfo(slotID uint, m []*pkcs11.Mechanism) (pkcs11.MechanismInfo, error) {
	response, err := b.client.GetMechanismInfo(context.Background(), &p11.GetMechanismInfoRequest{
		Ctx:        b.ctx,
		SlotId:     uint32(slotID),
		Mechanisms: pkg.MechanismsToMechanisms(m),
	})
	return pkcs11.MechanismInfo{
		MinKeySize: uint(response.GetInfo().GetMinKeySize()),
		MaxKeySize: uint(response.GetInfo().GetMaxKeySize()),
		Flags:      uint(response.GetInfo().GetFlags()),
	}, err
}
func (b *backend) InitPIN(handle pkcs11.SessionHandle, pin string) error {
	_, err := b.client.InitPIN(context.Background(), &p11.InitPINRequest{
		Ctx:           b.ctx,
		SessionHandle: uint32(handle),
		Pin:           pin,
	})
	return err
}
func (b *backend) SetPIN(handle pkcs11.SessionHandle, oldPin string, newPin string) error {
	_, err := b.client.SetPIN(context.Background(), &p11.SetPINRequest{
		Ctx:           b.ctx,
		SessionHandle: uint32(handle),
		OldPin:        oldPin,
		NewPin:        newPin,
	})
	return err
}
func (b *backend) OpenSession(slotID uint, flags uint) (pkcs11.SessionHandle, error) {
	response, err := b.client.OpenSession(context.Background(), &p11.OpenSessionRequest{
		Ctx:    b.ctx,
		SlotId: uint32(slotID),
		Flags:  uint32(flags),
	})
	return pkcs11.SessionHandle(uint(response.GetSessionHandle())), err
}
func (b *backend) CloseSession(handle pkcs11.SessionHandle) error {
	_, err := b.client.CloseSession(context.Background(), &p11.CloseSessionRequest{
		Ctx:           b.ctx,
		SessionHandle: uint32(handle),
	})
	return err
}
func (b *backend) CloseAllSessions(slotID uint) error {
	_, err := b.client.CloseAllSessions(context.Background(), &p11.CloseAllSessionsRequest{
		Ctx:    b.ctx,
		SlotId: uint32(slotID),
	})
	return err
}
func (b *backend) GetSessionInfo(handle pkcs11.SessionHandle) (pkcs11.SessionInfo, error) {
	response, err := b.client.GetSessionInfo(context.Background(), &p11.GetSessionInfoRequest{
		Ctx:           b.ctx,
		SessionHandle: uint32(handle),
	})
	return pkcs11.SessionInfo{
		SlotID:      uint(response.GetInfo().GetSlotID()),
		State:       uint(response.GetInfo().GetState()),
		Flags:       uint(response.GetInfo().GetFlags()),
		DeviceError: uint(response.GetInfo().GetDeviceError()),
	}, err
}
func (b *backend) GetOperationState(handle pkcs11.SessionHandle) ([]byte, error) {
	response, err := b.client.GetOperationState(context.Background(), &p11.GetOperationStateRequest{
		Ctx:           b.ctx,
		SessionHandle: uint32(handle),
	})
	return response.GetState(), err
}
func (b *backend) SetOperationState(handle pkcs11.SessionHandle, state []byte, encryptKeyHandle pkcs11.ObjectHandle, authKeyHandle pkcs11.ObjectHandle) error {
	_, err := b.client.SetOperationState(context.Background(), &p11.SetOperationStateRequest{
		Ctx:           b.ctx,
		SessionHandle: uint32(handle),
		State:         state,
		EncryptKey:    uint32(encryptKeyHandle),
		AuthKey:       uint32(authKeyHandle),
	})
	return err
}
func (b *backend) Login(handle pkcs11.SessionHandle, userType uint, pin string) error {
	_, err := b.client.Login(context.Background(), &p11.LoginRequest{
		Ctx:           b.ctx,
		SessionHandle: uint32(handle),
		UserType:      uint32(userType),
		Pin:           pin,
	})
	return err
}
func (b *backend) Logout(handle pkcs11.SessionHandle) error {
	_, err := b.client.Logout(context.Background(), &p11.LogoutRequest{
		Ctx:           b.ctx,
		SessionHandle: uint32(handle),
	})
	return err
}
func (b *backend) CreateObject(handle pkcs11.SessionHandle, a []*pkcs11.Attribute) (pkcs11.ObjectHandle, error) {
	response, err := b.client.CreateObject(context.Background(), &p11.CreateObjectRequest{
		Ctx:           b.ctx,
		SessionHandle: uint32(handle),
		Attributes:    pkg.AttributesToAttributes(a),
	})
	return pkcs11.ObjectHandle(response.GetHandleId()), err
}
func (b *backend) CopyObject(handle pkcs11.SessionHandle, handleID pkcs11.ObjectHandle, a []*pkcs11.Attribute) (pkcs11.ObjectHandle, error) {
	response, err := b.client.CopyObject(context.Background(), &p11.CopyObjectRequest{
		Ctx:           b.ctx,
		SessionHandle: uint32(handle),
		HandleId:      uint32(handleID),
		Attributes:    pkg.AttributesToAttributes(a),
	})
	return pkcs11.ObjectHandle(response.GetHandleId()), err
}
func (b *backend) DestroyObject(handle pkcs11.SessionHandle, handleID pkcs11.ObjectHandle) error {
	_, err := b.client.DestroyObject(context.Background(), &p11.DestroyObjectRequest{
		Ctx:           b.ctx,
		SessionHandle: uint32(handle),
		HandleId:      uint32(handleID),
	})
	return err
}
func (b *backend) GetObjectSize(handle pkcs11.SessionHandle, handleID pkcs11.ObjectHandle) (uint, error) {
	response, err := b.client.GetObjectSize(context.Background(), &p11.GetObjectSizeRequest{
		Ctx:           b.ctx,
		SessionHandle: uint32(handle),
		HandleId:      uint32(handleID),
	})
	return uint(response.GetSize()), err
}
func (b *backend) GetAttributeValue(handle pkcs11.SessionHandle, handleID pkcs11.ObjectHandle, a []*pkcs11.Attribute) ([]*pkcs11.Attribute, error) {
	response, err := b.client.GetAttributeValue(context.Background(), &p11.GetAttributeValueRequest{
		Ctx:           b.ctx,
		SessionHandle: uint32(handle),
		HandleId:      uint32(handleID),
		Attributes:    pkg.AttributesToAttributes(a),
	})
	return pkg.ReverseAttributesToAttributes(response.GetAttributes()), err
}
func (b *backend) SetAttributeValue(handle pkcs11.SessionHandle, handleID pkcs11.ObjectHandle, a []*pkcs11.Attribute) error {
	_, err := b.client.SetAttributeValue(context.Background(), &p11.SetAttributeValueRequest{
		Ctx:           b.ctx,
		SessionHandle: uint32(handle),
		HandleId:      uint32(handleID),
		Attributes:    pkg.AttributesToAttributes(a),
	})
	return err
}
func (b *backend) FindObjectsInit(handle pkcs11.SessionHandle, a []*pkcs11.Attribute) error {
	_, err := b.client.FindObjectsInit(context.Background(), &p11.FindObjectsInitRequest{
		Ctx:           b.ctx,
		SessionHandle: uint32(handle),
		Attributes:    pkg.AttributesToAttributes(a),
	})
	return err
}
func (b *backend) FindObjects(handle pkcs11.SessionHandle, max int) ([]pkcs11.ObjectHandle, bool, error) {
	response, err := b.client.FindObjects(context.Background(), &p11.FindObjectsRequest{
		Ctx:           b.ctx,
		SessionHandle: uint32(handle),
		Max:           uint32(max),
	})
	return pkg.Uint32ToObjectHandles(response.GetHandleIds()), response.GetHasMore(), err
}
func (b *backend) FindObjectsFinal(handle pkcs11.SessionHandle) error {
	_, err := b.client.FindObjectsFinal(context.Background(), &p11.FindObjectsFinalRequest{
		Ctx:           b.ctx,
		SessionHandle: uint32(handle),
	})
	return err
}
func (b *backend) EncryptInit(handle pkcs11.SessionHandle, m []*pkcs11.Mechanism, handleID pkcs11.ObjectHandle) error {
	_, err := b.client.EncryptInit(context.Background(), &p11.EncryptInitRequest{
		Ctx:           b.ctx,
		SessionHandle: uint32(handle),
		Mechanisms:    pkg.MechanismsToMechanisms(m),
		HandleId:      uint32(handleID),
	})
	return err
}
func (b *backend) Encrypt(handle pkcs11.SessionHandle, plain []byte) ([]byte, error) {
	response, err := b.client.Encrypt(context.Background(), &p11.EncryptRequest{
		Ctx:           b.ctx,
		SessionHandle: uint32(handle),
		Plain:         plain,
	})
	return response.GetEncrypted(), err
}
func (b *backend) EncryptUpdate(handle pkcs11.SessionHandle, plain []byte) ([]byte, error) {
	response, err := b.client.EncryptUpdate(context.Background(), &p11.EncryptUpdateRequest{
		Ctx:           b.ctx,
		SessionHandle: uint32(handle),
		Message:       plain,
	})
	return response.GetEncrypted(), err
}
func (b *backend) EncryptFinal(handle pkcs11.SessionHandle) ([]byte, error) {
	response, err := b.client.EncryptFinal(context.Background(), &p11.EncryptFinalRequest{
		Ctx:           b.ctx,
		SessionHandle: uint32(handle),
	})
	return response.GetEncrypted(), err
}
func (b *backend) DecryptInit(handle pkcs11.SessionHandle, m []*pkcs11.Mechanism, handleID pkcs11.ObjectHandle) error {
	_, err := b.client.DecryptInit(context.Background(), &p11.DecryptInitRequest{
		Ctx:           b.ctx,
		SessionHandle: uint32(handle),
		Mechanisms:    pkg.MechanismsToMechanisms(m),
		HandleId:      uint32(handleID),
	})
	return err
}
func (b *backend) Decrypt(handle pkcs11.SessionHandle, encrypted []byte) ([]byte, error) {
	response, err := b.client.Decrypt(context.Background(), &p11.DecryptRequest{
		Ctx:           b.ctx,
		SessionHandle: uint32(handle),
		Encrypted:     encrypted,
	})
	return response.GetPlain(), err
}
func (b *backend) DecryptUpdate(handle pkcs11.SessionHandle, encrypted []byte) ([]byte, error) {
	response, err := b.client.DecryptUpdate(context.Background(), &p11.DecryptUpdateRequest{
		Ctx:           b.ctx,
		SessionHandle: uint32(handle),
		Encrypted:     encrypted,
	})
	return response.GetPlain(), err
}
func (b *backend) DecryptFinal(handle pkcs11.SessionHandle) ([]byte, error) {
	response, err := b.client.DecryptFinal(context.Background(), &p11.DecryptFinalRequest{
		Ctx:           b.ctx,
		SessionHandle: uint32(handle),
	})
	return response.GetPlain(), err
}
func (b *backend) DigestInit(handle pkcs11.SessionHandle, m []*pkcs11.Mechanism) error {
	_, err := b.client.DigestInit(context.Background(), &p11.DigestInitRequest{
		Ctx:           b.ctx,
		SessionHandle: uint32(handle),
		Mechanisms:    pkg.MechanismsToMechanisms(m),
	})
	return err
}
func (b *backend) Digest(handle pkcs11.SessionHandle, data []byte) ([]byte, error) {
	response, err := b.client.Digest(context.Background(), &p11.DigestRequest{
		Ctx:           b.ctx,
		SessionHandle: uint32(handle),
		Message:       data,
	})
	return response.GetHashed(), err
}
func (b *backend) DigestUpdate(handle pkcs11.SessionHandle, data []byte) error {
	_, err := b.client.DigestUpdate(context.Background(), &p11.DigestUpdateRequest{
		Ctx:           b.ctx,
		SessionHandle: uint32(handle),
		Message:       data,
	})
	return err
}
func (b *backend) DigestKey(handle pkcs11.SessionHandle, handleID pkcs11.ObjectHandle) error {
	_, err := b.client.DigestKey(context.Background(), &p11.DigestKeyRequest{
		Ctx:           b.ctx,
		SessionHandle: uint32(handle),
		HandleId:      uint32(handleID),
	})
	return err
}
func (b *backend) DigestFinal(handle pkcs11.SessionHandle) ([]byte, error) {
	response, err := b.client.DigestFinal(context.Background(), &p11.DigestFinalRequest{
		Ctx:           b.ctx,
		SessionHandle: uint32(handle),
	})
	return response.GetHashed(), err
}
func (b *backend) SignInit(handle pkcs11.SessionHandle, m []*pkcs11.Mechanism, handleID pkcs11.ObjectHandle) error {
	_, err := b.client.SignInit(context.Background(), &p11.SignInitRequest{
		Ctx:           b.ctx,
		SessionHandle: uint32(handle),
		Mechanisms:    pkg.MechanismsToMechanisms(m),
		HandleId:      uint32(handleID),
	})
	return err
}
func (b *backend) Sign(handle pkcs11.SessionHandle, data []byte) ([]byte, error) {
	response, err := b.client.Sign(context.Background(), &p11.SignRequest{
		Ctx:           b.ctx,
		SessionHandle: uint32(handle),
		Message:       data,
	})
	return response.GetSignature(), err
}
func (b *backend) SignUpdate(handle pkcs11.SessionHandle, data []byte) error {
	_, err := b.client.Sign(context.Background(), &p11.SignRequest{
		Ctx:           b.ctx,
		SessionHandle: uint32(handle),
		Message:       data,
	})
	return err
}
func (b *backend) SignFinal(handle pkcs11.SessionHandle) ([]byte, error) {
	response, err := b.client.SignFinal(context.Background(), &p11.SignFinalRequest{
		Ctx:           b.ctx,
		SessionHandle: uint32(handle),
	})
	return response.GetSignature(), err
}
func (b *backend) SignRecoverInit(handle pkcs11.SessionHandle, m []*pkcs11.Mechanism, handleID pkcs11.ObjectHandle) error {
	_, err := b.client.SignRecoverInit(context.Background(), &p11.SignRecoverInitRequest{
		Ctx:           b.ctx,
		SessionHandle: uint32(handle),
		Mechanisms:    pkg.MechanismsToMechanisms(m),
		HandleId:      uint32(handleID),
	})
	return err
}
func (b *backend) SignRecover(handle pkcs11.SessionHandle, data []byte) ([]byte, error) {
	response, err := b.client.SignRecover(context.Background(), &p11.SignRecoverRequest{
		Ctx:           b.ctx,
		SessionHandle: uint32(handle),
		Message:       data,
	})
	return response.GetSignature(), err
}
func (b *backend) VerifyInit(handle pkcs11.SessionHandle, m []*pkcs11.Mechanism, handleID pkcs11.ObjectHandle) error {
	_, err := b.client.VerifyInit(context.Background(), &p11.VerifyInitRequest{
		Ctx:           b.ctx,
		SessionHandle: uint32(handle),
		Mechanisms:    pkg.MechanismsToMechanisms(m),
		HandleId:      uint32(handleID),
	})
	return err
}
func (b *backend) Verify(handle pkcs11.SessionHandle, message []byte, sig []byte) error {
	_, err := b.client.Verify(context.Background(), &p11.VerifyRequest{
		Ctx:           b.ctx,
		SessionHandle: uint32(handle),
		Message:       message,
		Signature:     sig,
	})
	return err
}
func (b *backend) VerifyUpdate(handle pkcs11.SessionHandle, message []byte) error {
	_, err := b.client.Verify(context.Background(), &p11.VerifyRequest{
		Ctx:           b.ctx,
		SessionHandle: uint32(handle),
		Message:       message,
	})
	return err
}
func (b *backend) VerifyFinal(handle pkcs11.SessionHandle, sig []byte) error {
	_, err := b.client.VerifyFinal(context.Background(), &p11.VerifyFinalRequest{
		Ctx:           b.ctx,
		SessionHandle: uint32(handle),
		Signature:     sig,
	})
	return err
}
func (b *backend) VerifyRecoverInit(handle pkcs11.SessionHandle, m []*pkcs11.Mechanism, handleID pkcs11.ObjectHandle) error {
	_, err := b.client.VerifyRecoverInit(context.Background(), &p11.VerifyRecoverInitRequest{
		Ctx:           b.ctx,
		SessionHandle: uint32(handle),
		Mechanisms:    pkg.MechanismsToMechanisms(m),
		HandleId:      uint32(handleID),
	})
	return err
}
func (b *backend) VerifyRecover(handle pkcs11.SessionHandle, sig []byte) ([]byte, error) {
	response, err := b.client.VerifyRecover(context.Background(), &p11.VerifyRecoverRequest{
		Ctx:           b.ctx,
		SessionHandle: uint32(handle),
		Signature:     sig,
	})
	return response.GetData(), err
}
func (b *backend) DigestEncryptUpdate(handle pkcs11.SessionHandle, data []byte) ([]byte, error) {
	response, err := b.client.DigestEncryptUpdate(context.Background(), &p11.DigestEncryptUpdateRequest{
		Ctx:           b.ctx,
		SessionHandle: uint32(handle),
		Message:       data,
	})
	return response.GetHashed(), err
}
func (b *backend) DecryptDigestUpdate(handle pkcs11.SessionHandle, message []byte) ([]byte, error) {
	response, err := b.client.DecryptDigestUpdate(context.Background(), &p11.DecryptDigestUpdateRequest{
		Ctx:           b.ctx,
		SessionHandle: uint32(handle),
		Message:       message,
	})
	return response.GetEncrypted(), err
}
func (b *backend) SignEncryptUpdate(handle pkcs11.SessionHandle, message []byte) ([]byte, error) {
	response, err := b.client.SignEncryptUpdate(context.Background(), &p11.SignEncryptUpdateRequest{
		Ctx:           b.ctx,
		SessionHandle: uint32(handle),
		Message:       message,
	})
	return response.GetSignature(), err
}
func (b *backend) DecryptVerifyUpdate(handle pkcs11.SessionHandle, message []byte) ([]byte, error) {
	response, err := b.client.DecryptVerifyUpdate(context.Background(), &p11.DecryptVerifyUpdateRequest{
		Ctx:           b.ctx,
		SessionHandle: uint32(handle),
		Encrypted:     message,
	})
	return response.GetPlain(), err
}
func (b *backend) GenerateKey(handle pkcs11.SessionHandle, m []*pkcs11.Mechanism, a []*pkcs11.Attribute) (pkcs11.ObjectHandle, error) {
	response, err := b.client.GenerateKey(context.Background(), &p11.GenerateKeyRequest{
		Ctx:           b.ctx,
		SessionHandle: uint32(handle),
		Mechanisms:    pkg.MechanismsToMechanisms(m),
		Attributes:    pkg.AttributesToAttributes(a),
	})
	return pkcs11.ObjectHandle(response.GetHandleId()), err
}
func (b *backend) GenerateKeyPair(handle pkcs11.SessionHandle, m []*pkcs11.Mechanism, pkeyA []*pkcs11.Attribute, keyA []*pkcs11.Attribute) (pkcs11.ObjectHandle, pkcs11.ObjectHandle, error) {
	response, err := b.client.GenerateKeyPair(context.Background(), &p11.GenerateKeyPairRequest{
		Ctx:               b.ctx,
		SessionHandle:     uint32(handle),
		Mechanisms:        pkg.MechanismsToMechanisms(m),
		PublicAttributes:  pkg.AttributesToAttributes(pkeyA),
		PrivateAttributes: pkg.AttributesToAttributes(keyA),
	})
	return pkcs11.ObjectHandle(response.GetPublicKeyHandleId()), pkcs11.ObjectHandle(response.GetPrivateKeyHandleId()), err
}
func (b *backend) WrapKey(handle pkcs11.SessionHandle, m []*pkcs11.Mechanism, wrappingHandleID pkcs11.ObjectHandle, handleID pkcs11.ObjectHandle) ([]byte, error) {
	response, err := b.client.WrapKey(context.Background(), &p11.WrapKeyRequest{
		Ctx:              b.ctx,
		SessionHandle:    uint32(handle),
		Mechanisms:       pkg.MechanismsToMechanisms(m),
		WrappingHandleId: uint32(wrappingHandleID),
		HandleId:         uint32(handleID),
	})
	return response.GetWrappedKey(), err
}
func (b *backend) UnwrapKey(handle pkcs11.SessionHandle, m []*pkcs11.Mechanism, handleID pkcs11.ObjectHandle, wrappedKey []byte, a []*pkcs11.Attribute) (pkcs11.ObjectHandle, error) {
	response, err := b.client.UnwrapKey(context.Background(), &p11.UnwrapKeyRequest{
		Ctx:              b.ctx,
		SessionHandle:    uint32(handle),
		Mechanisms:       pkg.MechanismsToMechanisms(m),
		WrappingHandleId: uint32(handleID),
		WrappedKey:       wrappedKey,
		Attributes:       pkg.AttributesToAttributes(a),
	})
	return pkcs11.ObjectHandle(response.GetHandleId()), err
}
func (b *backend) DeriveKey(handle pkcs11.SessionHandle, m []*pkcs11.Mechanism, handleID pkcs11.ObjectHandle, a []*pkcs11.Attribute) (pkcs11.ObjectHandle, error) {
	response, err := b.client.DeriveKey(context.Background(), &p11.DeriveKeyRequest{
		Ctx:           b.ctx,
		SessionHandle: uint32(handle),
		Mechanisms:    pkg.MechanismsToMechanisms(m),
		HandleId:      uint32(handleID),
		Attributes:    pkg.AttributesToAttributes(a),
	})
	return pkcs11.ObjectHandle(response.GetHandleId()), err
}
func (b *backend) SeedRandom(handle pkcs11.SessionHandle, seed []byte) error {
	_, err := b.client.SeedRandom(context.Background(), &p11.SeedRandomRequest{
		Ctx:           b.ctx,
		SessionHandle: uint32(handle),
		Seed:          seed,
	})
	return err
}
func (b *backend) GenerateRandom(handle pkcs11.SessionHandle, length int) ([]byte, error) {
	response, err := b.client.GenerateRandom(context.Background(), &p11.GenerateRandomRequest{
		Ctx:           b.ctx,
		SessionHandle: uint32(handle),
		Length:        uint32(length),
	})
	return response.GetData(), err
}
func (b *backend) WaitForSlotEvent(flags uint) chan pkcs11.SlotEvent {
	c := make(chan pkcs11.SlotEvent)
	stream, err := b.client.WaitForSlotEvent(context.Background(), &p11.WaitForSlotEventRequest{
		Ctx:   b.ctx,
		Flags: uint32(flags),
	})
	if err != nil {
		close(c)
	}
	if err == nil {
		go func() {
			defer close(c)
			for {
				resp, err := stream.Recv()
				if err == io.EOF {
					return
				}
				if err != nil {
					return
				}
				c <- pkcs11.SlotEvent{
					SlotID: uint(resp.GetSlotID()),
				}
			}
		}()
	}
	return c
}

func init() {
	c := insecure.NewCredentials()
	if os.Getenv("PKCS11_PROXY_KEY") != "" && os.Getenv("PKCS11_PROXY_CERT") != "" {
		// Load the server certificate and its key
		serverCert, err := tls.LoadX509KeyPair(os.Getenv("PKCS11_PROXY_CERT"), os.Getenv("PKCS11_PROXY_KEY"))
		if err != nil {
			log.Fatalf("Failed to load server certificate and key. %s.", err)
		}
		var certPool *x509.CertPool
		if os.Getenv("PKCS11_PROXY_CACERT") != "" {
			// Load the CA certificate
			trustedCert, err := ioutil.ReadFile(os.Getenv("PKCS11_PROXY_CACERT"))
			if err != nil {
				log.Fatalf("Failed to load trusted certificate. %s.", err)
			}

			// Put the CA certificate to certificate pool
			certPool = x509.NewCertPool()
			if !certPool.AppendCertsFromPEM(trustedCert) {
				log.Fatalf("Failed to append trusted certificate to certificate pool. %s.", err)
			}
		}
		sni := "pkcs11-proxy-server.local"
		if os.Getenv("PKCS11_PROXY_SNI") != "" {
			sni = os.Getenv("PKCS11_PROXY_SNI")
		}
		// Create the TLS configuration
		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{serverCert},
			RootCAs:      certPool,
			ClientCAs:    certPool,
			MinVersion:   tls.VersionTLS13,
			MaxVersion:   tls.VersionTLS13,
			ServerName:   sni,
		}

		// Create a new TLS credentials based on the TLS configuration
		c = credentials.NewTLS(tlsConfig)
	}
	conn, err := grpc.Dial(os.Getenv("PKCS11_PROXY_URI"), grpc.WithTransportCredentials(c))
	if err != nil {
		log.Fatalf("unable to connect to pkcs11 proxy using env PKCS11_PROXY_URI %s: %s", os.Getenv("PKCS11_PROXY_URI"), err)
	}
	client := p11.NewPKCS11Client(conn)
	response, err := client.New(context.Background(), &p11.NewRequest{
		Module: os.Getenv("PKCS11_MODULE"),
	})
	if err != nil {
		log.Fatal(err)
	}
	pkcs11mod.SetBackend(&backend{
		ctx:    response.Ctx,
		client: client,
	})
}

func main() {}
