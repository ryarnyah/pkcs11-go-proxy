package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"log"
	"os"

	"github.com/ryarnyah/pkcs11-go-proxy/pkg/module"
	"github.com/ryarnyah/pkcs11-go-proxy/pkg/proto/pkcs11"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

type backend struct {
	client pkcs11.PKCS11Client
	ctx    string
}

func (b *backend) Initialize() error {
	_, err := b.client.Initialize(context.Background(), &pkcs11.InitializeRequest{Ctx: b.ctx})
	return err
}
func (b *backend) Finalize() error {
	_, err := b.client.Finalize(context.Background(), &pkcs11.FinalizeRequest{Ctx: b.ctx})
	return err
}
func (b *backend) GetInfo() (pkcs11.Info, error) {
	response, err := b.client.GetInfo(context.Background(), &pkcs11.GetInfoRequest{Ctx: b.ctx})
	if err != nil {
		return pkcs11.Info{}, err
	}
	return pkcs11.Info{
		CryptokiVersion:    response.GetInfo().GetCryptokiVersion(),
		ManufacturerID:     response.GetInfo().GetManufacturerID(),
		Flags:              response.GetInfo().GetFlags(),
		LibraryDescription: response.GetInfo().GetLibraryDescription(),
		LibraryVersion:     response.GetInfo().GetLibraryVersion(),
	}, nil
}
func (b *backend) GetSlotList(tokenPresent bool) ([]uint64, error) {
	response, err := b.client.GetSlotList(context.Background(), &pkcs11.GetSlotListRequest{
		Ctx:          b.ctx,
		TokenPresent: tokenPresent,
	})
	return response.GetSlotIds(), err
}
func (b *backend) GetSlotInfo(slotID uint64) (pkcs11.SlotInfo, error) {
	response, err := b.client.GetSlotInfo(context.Background(), &pkcs11.GetSlotInfoRequest{
		Ctx:    b.ctx,
		SlotId: uint64(slotID),
	})
	if err != nil {
		return pkcs11.SlotInfo{}, err
	}
	return pkcs11.SlotInfo{
		SlotDescription: response.GetInfo().GetSlotDescription(),
		ManufacturerID:  response.GetInfo().GetManufacturerID(),
		Flags:           response.GetInfo().GetFlags(),
		HardwareVersion: response.GetInfo().GetHardwareVersion(),
		FirmwareVersion: response.GetInfo().GetFirmwareVersion(),
	}, nil
}
func (b *backend) GetTokenInfo(slotID uint64) (pkcs11.TokenInfo, error) {
	response, err := b.client.GetTokenInfo(context.Background(), &pkcs11.GetTokenInfoRequest{
		Ctx:    b.ctx,
		SlotId: uint64(slotID),
	})
	if err != nil {
		return pkcs11.TokenInfo{}, err
	}
	return pkcs11.TokenInfo{
		Label:              response.GetInfo().GetLabel(),
		ManufacturerID:     response.GetInfo().GetManufacturerID(),
		Model:              response.GetInfo().GetModel(),
		SerialNumber:       response.GetInfo().GetSerialNumber(),
		Flags:              response.GetInfo().GetFlags(),
		MaxSessionCount:    response.GetInfo().GetMaxSessionCount(),
		SessionCount:       response.GetInfo().GetSessionCount(),
		MaxRwSessionCount:  response.GetInfo().GetMaxRwSessionCount(),
		RwSessionCount:     response.GetInfo().GetRwSessionCount(),
		MaxPinLen:          response.GetInfo().GetMaxPinLen(),
		MinPinLen:          response.GetInfo().GetMinPinLen(),
		TotalPublicMemory:  response.GetInfo().GetTotalPublicMemory(),
		FreePublicMemory:   response.GetInfo().GetFreePublicMemory(),
		TotalPrivateMemory: response.GetInfo().GetTotalPrivateMemory(),
		FreePrivateMemory:  response.GetInfo().GetFreePrivateMemory(),
		HardwareVersion:    response.GetInfo().GetHardwareVersion(),
		FirmwareVersion:    response.GetInfo().GetFirmwareVersion(),
		UTCTime:            response.GetInfo().GetUTCTime(),
	}, nil
}
func (b *backend) GetMechanismList(slotID uint64) ([]*pkcs11.Mechanism, error) {
	response, err := b.client.GetMechanismList(context.Background(), &pkcs11.GetMechanismListRequest{
		Ctx:    b.ctx,
		SlotId: uint64(slotID),
	})
	return response.GetMechanisms(), err
}
func (b *backend) GetMechanismInfo(slotID uint64, m []*pkcs11.Mechanism) (pkcs11.MechanismInfo, error) {
	response, err := b.client.GetMechanismInfo(context.Background(), &pkcs11.GetMechanismInfoRequest{
		Ctx:        b.ctx,
		SlotId:     uint64(slotID),
		Mechanisms: m,
	})
	if err != nil {
		return pkcs11.MechanismInfo{}, err
	}
	return pkcs11.MechanismInfo{
		MinKeySize: response.GetInfo().GetMinKeySize(),
		MaxKeySize: response.GetInfo().GetMaxKeySize(),
		Flags:      response.GetInfo().GetFlags(),
	}, nil
}
func (b *backend) InitPIN(handle pkcs11.SessionHandle, pin string) error {
	_, err := b.client.InitPIN(context.Background(), &pkcs11.InitPINRequest{
		Ctx:           b.ctx,
		SessionHandle: uint64(handle),
		Pin:           pin,
	})
	return err
}
func (b *backend) SetPIN(handle pkcs11.SessionHandle, oldPin string, newPin string) error {
	_, err := b.client.SetPIN(context.Background(), &pkcs11.SetPINRequest{
		Ctx:           b.ctx,
		SessionHandle: uint64(handle),
		OldPin:        oldPin,
		NewPin:        newPin,
	})
	return err
}
func (b *backend) OpenSession(slotID uint64, flags uint64) (pkcs11.SessionHandle, error) {
	response, err := b.client.OpenSession(context.Background(), &pkcs11.OpenSessionRequest{
		Ctx:    b.ctx,
		SlotId: uint64(slotID),
		Flags:  uint64(flags),
	})
	return pkcs11.SessionHandle(response.GetSessionHandle()), err
}
func (b *backend) CloseSession(handle pkcs11.SessionHandle) error {
	_, err := b.client.CloseSession(context.Background(), &pkcs11.CloseSessionRequest{
		Ctx:           b.ctx,
		SessionHandle: uint64(handle),
	})
	return err
}
func (b *backend) CloseAllSessions(slotID uint64) error {
	_, err := b.client.CloseAllSessions(context.Background(), &pkcs11.CloseAllSessionsRequest{
		Ctx:    b.ctx,
		SlotId: uint64(slotID),
	})
	return err
}
func (b *backend) GetSessionInfo(handle pkcs11.SessionHandle) (pkcs11.SessionInfo, error) {
	response, err := b.client.GetSessionInfo(context.Background(), &pkcs11.GetSessionInfoRequest{
		Ctx:           b.ctx,
		SessionHandle: uint64(handle),
	})
	if err != nil {
		return pkcs11.SessionInfo{}, err
	}
	return pkcs11.SessionInfo{
		SlotID:      response.GetInfo().GetSlotID(),
		State:       response.GetInfo().GetState(),
		Flags:       response.GetInfo().GetFlags(),
		DeviceError: response.GetInfo().GetDeviceError(),
	}, nil
}
func (b *backend) GetOperationState(handle pkcs11.SessionHandle) ([]byte, error) {
	response, err := b.client.GetOperationState(context.Background(), &pkcs11.GetOperationStateRequest{
		Ctx:           b.ctx,
		SessionHandle: uint64(handle),
	})
	return response.GetState(), err
}
func (b *backend) SetOperationState(handle pkcs11.SessionHandle, state []byte, encryptKeyHandle pkcs11.ObjectHandle, authKeyHandle pkcs11.ObjectHandle) error {
	_, err := b.client.SetOperationState(context.Background(), &pkcs11.SetOperationStateRequest{
		Ctx:           b.ctx,
		SessionHandle: uint64(handle),
		State:         state,
		EncryptKey:    uint64(encryptKeyHandle),
		AuthKey:       uint64(authKeyHandle),
	})
	return err
}
func (b *backend) Login(handle pkcs11.SessionHandle, userType uint64, pin string) error {
	_, err := b.client.Login(context.Background(), &pkcs11.LoginRequest{
		Ctx:           b.ctx,
		SessionHandle: uint64(handle),
		UserType:      uint64(userType),
		Pin:           pin,
	})
	return err
}
func (b *backend) Logout(handle pkcs11.SessionHandle) error {
	_, err := b.client.Logout(context.Background(), &pkcs11.LogoutRequest{
		Ctx:           b.ctx,
		SessionHandle: uint64(handle),
	})
	return err
}
func (b *backend) CreateObject(handle pkcs11.SessionHandle, a []*pkcs11.Attribute) (pkcs11.ObjectHandle, error) {
	response, err := b.client.CreateObject(context.Background(), &pkcs11.CreateObjectRequest{
		Ctx:           b.ctx,
		SessionHandle: uint64(handle),
		Attributes:    a,
	})
	return pkcs11.ObjectHandle(response.GetHandleId()), err
}
func (b *backend) CopyObject(handle pkcs11.SessionHandle, handleID pkcs11.ObjectHandle, a []*pkcs11.Attribute) (pkcs11.ObjectHandle, error) {
	response, err := b.client.CopyObject(context.Background(), &pkcs11.CopyObjectRequest{
		Ctx:           b.ctx,
		SessionHandle: uint64(handle),
		HandleId:      uint64(handleID),
		Attributes:    a,
	})
	return pkcs11.ObjectHandle(response.GetHandleId()), err
}
func (b *backend) DestroyObject(handle pkcs11.SessionHandle, handleID pkcs11.ObjectHandle) error {
	_, err := b.client.DestroyObject(context.Background(), &pkcs11.DestroyObjectRequest{
		Ctx:           b.ctx,
		SessionHandle: uint64(handle),
		HandleId:      uint64(handleID),
	})
	return err
}
func (b *backend) GetObjectSize(handle pkcs11.SessionHandle, handleID pkcs11.ObjectHandle) (uint64, error) {
	response, err := b.client.GetObjectSize(context.Background(), &pkcs11.GetObjectSizeRequest{
		Ctx:           b.ctx,
		SessionHandle: uint64(handle),
		HandleId:      uint64(handleID),
	})
	return response.GetSize(), err
}
func (b *backend) GetAttributeValue(handle pkcs11.SessionHandle, handleID pkcs11.ObjectHandle, a []*pkcs11.Attribute) ([]*pkcs11.Attribute, error) {
	response, err := b.client.GetAttributeValue(context.Background(), &pkcs11.GetAttributeValueRequest{
		Ctx:           b.ctx,
		SessionHandle: uint64(handle),
		HandleId:      uint64(handleID),
		Attributes:    a,
	})
	return response.GetAttributes(), err
}
func (b *backend) SetAttributeValue(handle pkcs11.SessionHandle, handleID pkcs11.ObjectHandle, a []*pkcs11.Attribute) error {
	_, err := b.client.SetAttributeValue(context.Background(), &pkcs11.SetAttributeValueRequest{
		Ctx:           b.ctx,
		SessionHandle: uint64(handle),
		HandleId:      uint64(handleID),
		Attributes:    a,
	})
	return err
}
func (b *backend) FindObjectsInit(handle pkcs11.SessionHandle, a []*pkcs11.Attribute) error {
	_, err := b.client.FindObjectsInit(context.Background(), &pkcs11.FindObjectsInitRequest{
		Ctx:           b.ctx,
		SessionHandle: uint64(handle),
		Attributes:    a,
	})
	return err
}
func (b *backend) FindObjects(handle pkcs11.SessionHandle, max int) ([]pkcs11.ObjectHandle, bool, error) {
	response, err := b.client.FindObjects(context.Background(), &pkcs11.FindObjectsRequest{
		Ctx:           b.ctx,
		SessionHandle: uint64(handle),
		Max:           uint64(max),
	})
	return response.GetHandleIds(), response.GetHasMore(), err
}
func (b *backend) FindObjectsFinal(handle pkcs11.SessionHandle) error {
	_, err := b.client.FindObjectsFinal(context.Background(), &pkcs11.FindObjectsFinalRequest{
		Ctx:           b.ctx,
		SessionHandle: uint64(handle),
	})
	return err
}
func (b *backend) EncryptInit(handle pkcs11.SessionHandle, m []*pkcs11.Mechanism, handleID pkcs11.ObjectHandle) error {
	_, err := b.client.EncryptInit(context.Background(), &pkcs11.EncryptInitRequest{
		Ctx:           b.ctx,
		SessionHandle: uint64(handle),
		Mechanisms:    m,
		HandleId:      uint64(handleID),
	})
	return err
}
func (b *backend) Encrypt(handle pkcs11.SessionHandle, plain []byte) ([]byte, error) {
	response, err := b.client.Encrypt(context.Background(), &pkcs11.EncryptRequest{
		Ctx:           b.ctx,
		SessionHandle: uint64(handle),
		Plain:         plain,
	})
	return response.GetEncrypted(), err
}
func (b *backend) EncryptUpdate(handle pkcs11.SessionHandle, plain []byte) ([]byte, error) {
	response, err := b.client.EncryptUpdate(context.Background(), &pkcs11.EncryptUpdateRequest{
		Ctx:           b.ctx,
		SessionHandle: uint64(handle),
		Message:       plain,
	})
	return response.GetEncrypted(), err
}
func (b *backend) EncryptFinal(handle pkcs11.SessionHandle) ([]byte, error) {
	response, err := b.client.EncryptFinal(context.Background(), &pkcs11.EncryptFinalRequest{
		Ctx:           b.ctx,
		SessionHandle: uint64(handle),
	})
	return response.GetEncrypted(), err
}
func (b *backend) DecryptInit(handle pkcs11.SessionHandle, m []*pkcs11.Mechanism, handleID pkcs11.ObjectHandle) error {
	_, err := b.client.DecryptInit(context.Background(), &pkcs11.DecryptInitRequest{
		Ctx:           b.ctx,
		SessionHandle: uint64(handle),
		Mechanisms:    m,
		HandleId:      uint64(handleID),
	})
	return err
}
func (b *backend) Decrypt(handle pkcs11.SessionHandle, encrypted []byte) ([]byte, error) {
	response, err := b.client.Decrypt(context.Background(), &pkcs11.DecryptRequest{
		Ctx:           b.ctx,
		SessionHandle: uint64(handle),
		Encrypted:     encrypted,
	})
	return response.GetPlain(), err
}
func (b *backend) DecryptUpdate(handle pkcs11.SessionHandle, encrypted []byte) ([]byte, error) {
	response, err := b.client.DecryptUpdate(context.Background(), &pkcs11.DecryptUpdateRequest{
		Ctx:           b.ctx,
		SessionHandle: uint64(handle),
		Encrypted:     encrypted,
	})
	return response.GetPlain(), err
}
func (b *backend) DecryptFinal(handle pkcs11.SessionHandle) ([]byte, error) {
	response, err := b.client.DecryptFinal(context.Background(), &pkcs11.DecryptFinalRequest{
		Ctx:           b.ctx,
		SessionHandle: uint64(handle),
	})
	return response.GetPlain(), err
}
func (b *backend) DigestInit(handle pkcs11.SessionHandle, m []*pkcs11.Mechanism) error {
	_, err := b.client.DigestInit(context.Background(), &pkcs11.DigestInitRequest{
		Ctx:           b.ctx,
		SessionHandle: uint64(handle),
		Mechanisms:    m,
	})
	return err
}
func (b *backend) Digest(handle pkcs11.SessionHandle, data []byte) ([]byte, error) {
	response, err := b.client.Digest(context.Background(), &pkcs11.DigestRequest{
		Ctx:           b.ctx,
		SessionHandle: uint64(handle),
		Message:       data,
	})
	return response.GetHashed(), err
}
func (b *backend) DigestUpdate(handle pkcs11.SessionHandle, data []byte) error {
	_, err := b.client.DigestUpdate(context.Background(), &pkcs11.DigestUpdateRequest{
		Ctx:           b.ctx,
		SessionHandle: uint64(handle),
		Message:       data,
	})
	return err
}
func (b *backend) DigestKey(handle pkcs11.SessionHandle, handleID pkcs11.ObjectHandle) error {
	_, err := b.client.DigestKey(context.Background(), &pkcs11.DigestKeyRequest{
		Ctx:           b.ctx,
		SessionHandle: uint64(handle),
		HandleId:      uint64(handleID),
	})
	return err
}
func (b *backend) DigestFinal(handle pkcs11.SessionHandle) ([]byte, error) {
	response, err := b.client.DigestFinal(context.Background(), &pkcs11.DigestFinalRequest{
		Ctx:           b.ctx,
		SessionHandle: uint64(handle),
	})
	return response.GetHashed(), err
}
func (b *backend) SignInit(handle pkcs11.SessionHandle, m []*pkcs11.Mechanism, handleID pkcs11.ObjectHandle) error {
	_, err := b.client.SignInit(context.Background(), &pkcs11.SignInitRequest{
		Ctx:           b.ctx,
		SessionHandle: uint64(handle),
		Mechanisms:    m,
		HandleId:      uint64(handleID),
	})
	return err
}
func (b *backend) Sign(handle pkcs11.SessionHandle, data []byte) ([]byte, error) {
	response, err := b.client.Sign(context.Background(), &pkcs11.SignRequest{
		Ctx:           b.ctx,
		SessionHandle: uint64(handle),
		Message:       data,
	})
	return response.GetSignature(), err
}
func (b *backend) SignUpdate(handle pkcs11.SessionHandle, data []byte) error {
	_, err := b.client.Sign(context.Background(), &pkcs11.SignRequest{
		Ctx:           b.ctx,
		SessionHandle: uint64(handle),
		Message:       data,
	})
	return err
}
func (b *backend) SignFinal(handle pkcs11.SessionHandle) ([]byte, error) {
	response, err := b.client.SignFinal(context.Background(), &pkcs11.SignFinalRequest{
		Ctx:           b.ctx,
		SessionHandle: uint64(handle),
	})
	return response.GetSignature(), err
}
func (b *backend) SignRecoverInit(handle pkcs11.SessionHandle, m []*pkcs11.Mechanism, handleID pkcs11.ObjectHandle) error {
	_, err := b.client.SignRecoverInit(context.Background(), &pkcs11.SignRecoverInitRequest{
		Ctx:           b.ctx,
		SessionHandle: uint64(handle),
		Mechanisms:    m,
		HandleId:      uint64(handleID),
	})
	return err
}
func (b *backend) SignRecover(handle pkcs11.SessionHandle, data []byte) ([]byte, error) {
	response, err := b.client.SignRecover(context.Background(), &pkcs11.SignRecoverRequest{
		Ctx:           b.ctx,
		SessionHandle: uint64(handle),
		Message:       data,
	})
	return response.GetSignature(), err
}
func (b *backend) VerifyInit(handle pkcs11.SessionHandle, m []*pkcs11.Mechanism, handleID pkcs11.ObjectHandle) error {
	_, err := b.client.VerifyInit(context.Background(), &pkcs11.VerifyInitRequest{
		Ctx:           b.ctx,
		SessionHandle: uint64(handle),
		Mechanisms:    m,
		HandleId:      uint64(handleID),
	})
	return err
}
func (b *backend) Verify(handle pkcs11.SessionHandle, message []byte, sig []byte) error {
	_, err := b.client.Verify(context.Background(), &pkcs11.VerifyRequest{
		Ctx:           b.ctx,
		SessionHandle: uint64(handle),
		Message:       message,
		Signature:     sig,
	})
	return err
}
func (b *backend) VerifyUpdate(handle pkcs11.SessionHandle, message []byte) error {
	_, err := b.client.Verify(context.Background(), &pkcs11.VerifyRequest{
		Ctx:           b.ctx,
		SessionHandle: uint64(handle),
		Message:       message,
	})
	return err
}
func (b *backend) VerifyFinal(handle pkcs11.SessionHandle, sig []byte) error {
	_, err := b.client.VerifyFinal(context.Background(), &pkcs11.VerifyFinalRequest{
		Ctx:           b.ctx,
		SessionHandle: uint64(handle),
		Signature:     sig,
	})
	return err
}
func (b *backend) VerifyRecoverInit(handle pkcs11.SessionHandle, m []*pkcs11.Mechanism, handleID pkcs11.ObjectHandle) error {
	_, err := b.client.VerifyRecoverInit(context.Background(), &pkcs11.VerifyRecoverInitRequest{
		Ctx:           b.ctx,
		SessionHandle: uint64(handle),
		Mechanisms:    m,
		HandleId:      uint64(handleID),
	})
	return err
}
func (b *backend) VerifyRecover(handle pkcs11.SessionHandle, sig []byte) ([]byte, error) {
	response, err := b.client.VerifyRecover(context.Background(), &pkcs11.VerifyRecoverRequest{
		Ctx:           b.ctx,
		SessionHandle: uint64(handle),
		Signature:     sig,
	})
	return response.GetData(), err
}
func (b *backend) DigestEncryptUpdate(handle pkcs11.SessionHandle, data []byte) ([]byte, error) {
	response, err := b.client.DigestEncryptUpdate(context.Background(), &pkcs11.DigestEncryptUpdateRequest{
		Ctx:           b.ctx,
		SessionHandle: uint64(handle),
		Message:       data,
	})
	return response.GetHashed(), err
}
func (b *backend) DecryptDigestUpdate(handle pkcs11.SessionHandle, message []byte) ([]byte, error) {
	response, err := b.client.DecryptDigestUpdate(context.Background(), &pkcs11.DecryptDigestUpdateRequest{
		Ctx:           b.ctx,
		SessionHandle: uint64(handle),
		Message:       message,
	})
	return response.GetEncrypted(), err
}
func (b *backend) SignEncryptUpdate(handle pkcs11.SessionHandle, message []byte) ([]byte, error) {
	response, err := b.client.SignEncryptUpdate(context.Background(), &pkcs11.SignEncryptUpdateRequest{
		Ctx:           b.ctx,
		SessionHandle: uint64(handle),
		Message:       message,
	})
	return response.GetSignature(), err
}
func (b *backend) DecryptVerifyUpdate(handle pkcs11.SessionHandle, message []byte) ([]byte, error) {
	response, err := b.client.DecryptVerifyUpdate(context.Background(), &pkcs11.DecryptVerifyUpdateRequest{
		Ctx:           b.ctx,
		SessionHandle: uint64(handle),
		Encrypted:     message,
	})
	return response.GetPlain(), err
}
func (b *backend) GenerateKey(handle pkcs11.SessionHandle, m []*pkcs11.Mechanism, a []*pkcs11.Attribute) (pkcs11.ObjectHandle, error) {
	response, err := b.client.GenerateKey(context.Background(), &pkcs11.GenerateKeyRequest{
		Ctx:           b.ctx,
		SessionHandle: uint64(handle),
		Mechanisms:    m,
		Attributes:    a,
	})
	return pkcs11.ObjectHandle(response.GetHandleId()), err
}
func (b *backend) GenerateKeyPair(handle pkcs11.SessionHandle, m []*pkcs11.Mechanism, pkeyA []*pkcs11.Attribute, keyA []*pkcs11.Attribute) (pkcs11.ObjectHandle, pkcs11.ObjectHandle, error) {
	response, err := b.client.GenerateKeyPair(context.Background(), &pkcs11.GenerateKeyPairRequest{
		Ctx:               b.ctx,
		SessionHandle:     uint64(handle),
		Mechanisms:        m,
		PublicAttributes:  pkeyA,
		PrivateAttributes: keyA,
	})
	return pkcs11.ObjectHandle(response.GetPublicKeyHandleId()), pkcs11.ObjectHandle(response.GetPrivateKeyHandleId()), err
}
func (b *backend) WrapKey(handle pkcs11.SessionHandle, m []*pkcs11.Mechanism, wrappingHandleID pkcs11.ObjectHandle, handleID pkcs11.ObjectHandle) ([]byte, error) {
	response, err := b.client.WrapKey(context.Background(), &pkcs11.WrapKeyRequest{
		Ctx:              b.ctx,
		SessionHandle:    uint64(handle),
		Mechanisms:       m,
		WrappingHandleId: uint64(wrappingHandleID),
		HandleId:         uint64(handleID),
	})
	return response.GetWrappedKey(), err
}
func (b *backend) UnwrapKey(handle pkcs11.SessionHandle, m []*pkcs11.Mechanism, handleID pkcs11.ObjectHandle, wrappedKey []byte, a []*pkcs11.Attribute) (pkcs11.ObjectHandle, error) {
	response, err := b.client.UnwrapKey(context.Background(), &pkcs11.UnwrapKeyRequest{
		Ctx:              b.ctx,
		SessionHandle:    uint64(handle),
		Mechanisms:       m,
		WrappingHandleId: uint64(handleID),
		WrappedKey:       wrappedKey,
		Attributes:       a,
	})
	return pkcs11.ObjectHandle(response.GetHandleId()), err
}
func (b *backend) DeriveKey(handle pkcs11.SessionHandle, m []*pkcs11.Mechanism, handleID pkcs11.ObjectHandle, a []*pkcs11.Attribute) (pkcs11.ObjectHandle, error) {
	response, err := b.client.DeriveKey(context.Background(), &pkcs11.DeriveKeyRequest{
		Ctx:           b.ctx,
		SessionHandle: uint64(handle),
		Mechanisms:    m,
		HandleId:      uint64(handleID),
		Attributes:    a,
	})
	return pkcs11.ObjectHandle(response.GetHandleId()), err
}
func (b *backend) SeedRandom(handle pkcs11.SessionHandle, seed []byte) error {
	_, err := b.client.SeedRandom(context.Background(), &pkcs11.SeedRandomRequest{
		Ctx:           b.ctx,
		SessionHandle: uint64(handle),
		Seed:          seed,
	})
	return err
}
func (b *backend) GenerateRandom(handle pkcs11.SessionHandle, length int) ([]byte, error) {
	response, err := b.client.GenerateRandom(context.Background(), &pkcs11.GenerateRandomRequest{
		Ctx:           b.ctx,
		SessionHandle: uint64(handle),
		Length:        uint64(length),
	})
	return response.GetData(), err
}
func (b *backend) WaitForSlotEvent(flags uint64) (uint64, error) {
	response, err := b.client.WaitForSlotEvent(context.Background(), &pkcs11.WaitForSlotEventRequest{
		Ctx:   b.ctx,
		Flags: uint64(flags),
	})
	if err != nil {
		return 0, err
	}
	return response.GetSlotID(), nil
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
			trustedCert, err := os.ReadFile(os.Getenv("PKCS11_PROXY_CACERT"))
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
	errHandler := func(ctx context.Context, method string, req, resp interface{}, info *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		err := invoker(ctx, method, req, resp, info, opts...)
		if err != nil {
			s := status.Convert(err)
			if s != nil {
				code := s.Code()
				if code == codes.Unknown {
					code = codes.Code(pkcs11.CKR_FUNCTION_FAILED)
				}
				err = pkcs11.Error(code)
			}
		}
		return err
	}
	conn, err := grpc.NewClient(os.Getenv("PKCS11_PROXY_URI"), grpc.WithTransportCredentials(c), grpc.WithUnaryInterceptor(errHandler))
	if err != nil {
		log.Fatalf("unable to connect to pkcs11 proxy using env PKCS11_PROXY_URI %s: %s", os.Getenv("PKCS11_PROXY_URI"), err)
	}
	client := pkcs11.NewPKCS11Client(conn)
	response, err := client.New(context.Background(), &pkcs11.NewRequest{
		Module: os.Getenv("PKCS11_MODULE"),
	})
	if err != nil {
		log.Fatal(err)
	}
	module.SetBackend(&backend{
		ctx:    response.Ctx,
		client: client,
	})
}

func main() {}
