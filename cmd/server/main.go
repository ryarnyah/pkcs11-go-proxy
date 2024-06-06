package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log"
	"net"
	"os"
	"slices"
	"strings"

	"github.com/ryarnyah/pkcs11-go-proxy/pkg/proto/pkcs11"
	"github.com/ryarnyah/pkcs11-go-proxy/pkg/server"
	"github.com/ryarnyah/pkcs11-go-proxy/pkg/types"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

// ErrCtxNotFound raised when context can't be found.
var ErrCtxNotFound = errors.New("context not found")

// ErrModuleNotAllowed raised when module is not allowlist.
var ErrModuleNotAllowed = errors.New("module not allowed")

type pkcs11Server struct {
	ctxs map[string]*server.Ctx

	allowedModules []string
	pkcs11.UnimplementedPKCS11Server
}

// New creates a new context and initializes the module/library for use.
func (m *pkcs11Server) New(ctx context.Context, in *pkcs11.NewRequest) (*pkcs11.NewResponse, error) {
	if len(m.allowedModules) > 0 && !slices.Contains(m.allowedModules, in.GetModule()) {
		return nil, ErrModuleNotAllowed
	}
	c, ok := m.ctxs[in.GetModule()]
	if ok {
		c.Finalize()
		c.Destroy()
		delete(m.ctxs, in.GetModule())
	}
	p := server.New(in.GetModule())
	m.ctxs[in.GetModule()] = p
	return &pkcs11.NewResponse{
		Ctx: in.GetModule(),
	}, nil
}

// Destroy unloads the module/library and frees any remaining memory.
func (m *pkcs11Server) Destroy(ctx context.Context, in *pkcs11.DestroyRequest) (*pkcs11.EmptyResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	c.Destroy()
	delete(m.ctxs, in.GetCtx())
	return &pkcs11.EmptyResponse{}, nil
}

// Initialize initializes the Cryptoki library.
func (m *pkcs11Server) Initialize(ctx context.Context, in *pkcs11.InitializeRequest) (*pkcs11.InitializeResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	err := c.Initialize()
	return &pkcs11.InitializeResponse{}, err
}

// Finalize indicates that an application is done with the Cryptoki library.
func (m *pkcs11Server) Finalize(ctx context.Context, in *pkcs11.FinalizeRequest) (*pkcs11.FinalizeResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	err := c.Finalize()
	return &pkcs11.FinalizeResponse{}, err
}

// GetInfo returns general information about Cryptoki.
func (m *pkcs11Server) GetInfo(ctx context.Context, in *pkcs11.GetInfoRequest) (*pkcs11.GetInfoResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	info, err := c.GetInfo()
	if err != nil {
		return &pkcs11.GetInfoResponse{}, err
	}
	return &pkcs11.GetInfoResponse{
		Info: &pkcs11.Info{
			CryptokiVersion:    info.CryptokiVersion,
			ManufacturerID:     info.ManufacturerID,
			Flags:              uint64(info.Flags),
			LibraryDescription: info.LibraryDescription,
			LibraryVersion:     info.LibraryVersion,
		},
	}, err
}

// GetSlotList obtains a list of slots in the system.
func (m *pkcs11Server) GetSlotList(ctx context.Context, in *pkcs11.GetSlotListRequest) (*pkcs11.GetSlotListResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	slots, err := c.GetSlotList(in.GetTokenPresent())
	if err != nil {
		return &pkcs11.GetSlotListResponse{}, err
	}
	return &pkcs11.GetSlotListResponse{
		SlotIds: slots,
	}, err
}

// GetSlotInfo obtains information about a particular slot in the system.
func (m *pkcs11Server) GetSlotInfo(ctx context.Context, in *pkcs11.GetSlotInfoRequest) (*pkcs11.GetSlotInfoResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	info, err := c.GetSlotInfo(uint(in.GetSlotId()))
	if err != nil {
		return &pkcs11.GetSlotInfoResponse{}, err
	}
	return &pkcs11.GetSlotInfoResponse{
		Info: &pkcs11.SlotInfo{
			SlotDescription: info.SlotDescription,
			ManufacturerID:  info.ManufacturerID,
			Flags:           uint64(info.Flags),
			HardwareVersion: info.HardwareVersion,
			FirmwareVersion: info.FirmwareVersion,
		},
	}, err
}

// GetTokenInfo obtains information about a particular token
// in the system.
func (m *pkcs11Server) GetTokenInfo(ctx context.Context, in *pkcs11.GetTokenInfoRequest) (*pkcs11.GetTokenInfoResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	info, err := c.GetTokenInfo(uint(in.GetSlotId()))
	if err != nil {
		return &pkcs11.GetTokenInfoResponse{}, err
	}

	return &pkcs11.GetTokenInfoResponse{
		Info: &pkcs11.TokenInfo{
			Label:              info.Label,
			ManufacturerID:     info.ManufacturerID,
			Model:              info.Model,
			SerialNumber:       info.SerialNumber,
			Flags:              uint64(info.Flags),
			MaxSessionCount:    uint64(info.MaxSessionCount),
			SessionCount:       uint64(info.SessionCount),
			MaxRwSessionCount:  uint64(info.MaxRwSessionCount),
			RwSessionCount:     uint64(info.RwSessionCount),
			MaxPinLen:          uint64(info.MaxPinLen),
			MinPinLen:          uint64(info.MinPinLen),
			TotalPublicMemory:  uint64(info.TotalPublicMemory),
			FreePublicMemory:   uint64(info.FreePublicMemory),
			TotalPrivateMemory: uint64(info.TotalPrivateMemory),
			FreePrivateMemory:  uint64(info.FreePrivateMemory),
			HardwareVersion:    info.HardwareVersion,
			FirmwareVersion:    info.FirmwareVersion,
			UTCTime:            info.UTCTime,
		},
	}, err
}

// GetMechanismList obtains a list of mechanism types supported by a token.
func (m *pkcs11Server) GetMechanismList(ctx context.Context, in *pkcs11.GetMechanismListRequest) (*pkcs11.GetMechanismListResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	mechanisms, err := c.GetMechanismList(uint(in.GetSlotId()))
	if err != nil {
		return &pkcs11.GetMechanismListResponse{}, err
	}

	return &pkcs11.GetMechanismListResponse{
		Mechanisms: mechanisms,
	}, err
}

// GetMechanismInfo obtains information about a particular
// mechanism possibly supported by a token.
func (m *pkcs11Server) GetMechanismInfo(ctx context.Context, in *pkcs11.GetMechanismInfoRequest) (*pkcs11.GetMechanismInfoResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	info, err := c.GetMechanismInfo(uint(in.GetSlotId()), in.GetMechanisms())
	if err != nil {
		return &pkcs11.GetMechanismInfoResponse{}, err
	}

	return &pkcs11.GetMechanismInfoResponse{
		Info: &pkcs11.MechanismInfo{
			MinKeySize: uint64(info.MinKeySize),
			MaxKeySize: uint64(info.MaxKeySize),
			Flags:      uint64(info.Flags),
		},
	}, err
}

// InitToken initializes a token. The label must be 32 characters
// long, it is blank padded if it is not. If it is longer it is capped
// to 32 characters.
func (m *pkcs11Server) InitToken(ctx context.Context, in *pkcs11.InitTokenRequest) (*pkcs11.InitTokenResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	err := c.InitToken(uint(in.GetSlotId()), in.GetPin(), in.GetLabel())
	return &pkcs11.InitTokenResponse{}, err
}

// InitPIN initializes the normal user's PIN.
func (m *pkcs11Server) InitPIN(ctx context.Context, in *pkcs11.InitPINRequest) (*pkcs11.InitPINResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	err := c.InitPIN(in.GetSessionHandle(), in.GetPin())
	return &pkcs11.InitPINResponse{}, err
}

// SetPIN modifies the PIN of the user who is logged in.
func (m *pkcs11Server) SetPIN(ctx context.Context, in *pkcs11.SetPINRequest) (*pkcs11.SetPINResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	err := c.SetPIN(in.GetSessionHandle(), in.GetOldPin(), in.GetOldPin())
	return &pkcs11.SetPINResponse{}, err
}

// OpenSession opens a session between an application and a token.
func (m *pkcs11Server) OpenSession(ctx context.Context, in *pkcs11.OpenSessionRequest) (*pkcs11.OpenSessionResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	handle, err := c.OpenSession(uint(in.GetSlotId()), uint(in.GetFlags()))
	if err != nil {
		return &pkcs11.OpenSessionResponse{}, err
	}

	return &pkcs11.OpenSessionResponse{
		SessionHandle: uint64(handle),
	}, err
}

// CloseSession closes a session between an application and a token.
func (m *pkcs11Server) CloseSession(ctx context.Context, in *pkcs11.CloseSessionRequest) (*pkcs11.CloseSessionResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	err := c.CloseSession(in.GetSessionHandle())
	if err != nil {
		return &pkcs11.CloseSessionResponse{}, err
	}

	return &pkcs11.CloseSessionResponse{}, err
}

// CloseAllSessions closes all sessions with a token.
func (m *pkcs11Server) CloseAllSessions(ctx context.Context, in *pkcs11.CloseAllSessionsRequest) (*pkcs11.CloseAllSessionsResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	err := c.CloseAllSessions(uint(in.GetSlotId()))
	if err != nil {
		return &pkcs11.CloseAllSessionsResponse{}, err
	}

	return &pkcs11.CloseAllSessionsResponse{}, err
}

// GetSessionInfo obtains information about the session.
func (m *pkcs11Server) GetSessionInfo(ctx context.Context, in *pkcs11.GetSessionInfoRequest) (*pkcs11.GetSessionInfoResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	info, err := c.GetSessionInfo(in.GetSessionHandle())
	if err != nil {
		return &pkcs11.GetSessionInfoResponse{}, err
	}

	return &pkcs11.GetSessionInfoResponse{
		Info: &pkcs11.SessionInfo{
			SlotID:      uint64(info.SlotID),
			State:       uint64(info.State),
			Flags:       uint64(info.Flags),
			DeviceError: uint64(info.DeviceError),
		},
	}, err
}

// GetOperationState obtains the state of the cryptographic operation in a
// session.
func (m *pkcs11Server) GetOperationState(ctx context.Context, in *pkcs11.GetOperationStateRequest) (*pkcs11.GetOperationStateResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	state, err := c.GetOperationState(in.GetSessionHandle())
	if err != nil {
		return &pkcs11.GetOperationStateResponse{}, err
	}

	return &pkcs11.GetOperationStateResponse{
		State: state,
	}, err
}

// SetOperationState restores the state of the cryptographic operation in a
// session.
func (m *pkcs11Server) SetOperationState(ctx context.Context, in *pkcs11.SetOperationStateRequest) (*pkcs11.SetOperationStateResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	err := c.SetOperationState(in.GetSessionHandle(), in.GetState(), in.GetEncryptKey(), in.GetAuthKey())
	return &pkcs11.SetOperationStateResponse{}, err
}

// Login logs a user into a token.
func (m *pkcs11Server) Login(ctx context.Context, in *pkcs11.LoginRequest) (*pkcs11.LoginResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	err := c.Login(in.GetSessionHandle(), uint(in.GetUserType()), in.GetPin())
	return &pkcs11.LoginResponse{}, err
}

// Logout logs a user out from a token.
func (m *pkcs11Server) Logout(ctx context.Context, in *pkcs11.LogoutRequest) (*pkcs11.LogoutResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	err := c.Logout(in.GetSessionHandle())
	return &pkcs11.LogoutResponse{}, err
}

// CreateObject creates a new object.
func (m *pkcs11Server) CreateObject(ctx context.Context, in *pkcs11.CreateObjectRequest) (*pkcs11.CreateObjectResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	handleID, err := c.CreateObject(in.GetSessionHandle(), in.GetAttributes())
	if err != nil {
		return &pkcs11.CreateObjectResponse{}, err
	}
	return &pkcs11.CreateObjectResponse{
		HandleId: uint64(handleID),
	}, err
}

// CopyObject copies an object, creating a new object for the copy.
func (m *pkcs11Server) CopyObject(ctx context.Context, in *pkcs11.CopyObjectRequest) (*pkcs11.CopyObjectResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	handleID, err := c.CopyObject(in.GetSessionHandle(), in.GetHandleId(), in.GetAttributes())
	if err != nil {
		return &pkcs11.CopyObjectResponse{}, err
	}

	return &pkcs11.CopyObjectResponse{
		HandleId: uint64(handleID),
	}, err
}

// DestroyObject destroys an object.
func (m *pkcs11Server) DestroyObject(ctx context.Context, in *pkcs11.DestroyObjectRequest) (*pkcs11.DestroyObjectResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	err := c.DestroyObject(in.GetSessionHandle(), in.GetHandleId())
	return &pkcs11.DestroyObjectResponse{}, err
}

// GetObjectSize gets the size of an object in bytes.
func (m *pkcs11Server) GetObjectSize(ctx context.Context, in *pkcs11.GetObjectSizeRequest) (*pkcs11.GetObjectSizeResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	size, err := c.GetObjectSize(in.GetSessionHandle(), in.GetHandleId())
	if err != nil {
		return &pkcs11.GetObjectSizeResponse{}, err
	}

	return &pkcs11.GetObjectSizeResponse{
		Size: uint64(size),
	}, err
}

// GetAttributeValue obtains the value of one or more object attributes.
func (m *pkcs11Server) GetAttributeValue(ctx context.Context, in *pkcs11.GetAttributeValueRequest) (*pkcs11.GetAttributeValueResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	attributes, err := c.GetAttributeValue(in.GetSessionHandle(), in.GetHandleId(), in.GetAttributes())
	if err != nil {
		return &pkcs11.GetAttributeValueResponse{}, err
	}

	return &pkcs11.GetAttributeValueResponse{
		Attributes: attributes,
	}, err
}

// SetAttributeValue modifies the value of one or more object attributes
func (m *pkcs11Server) SetAttributeValue(ctx context.Context, in *pkcs11.SetAttributeValueRequest) (*pkcs11.SetAttributeValueResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	err := c.SetAttributeValue(in.GetSessionHandle(), in.GetHandleId(), in.GetAttributes())
	return &pkcs11.SetAttributeValueResponse{}, err
}

// FindObjectsInit initializes a search for token and session
// objects that match a template.
func (m *pkcs11Server) FindObjectsInit(ctx context.Context, in *pkcs11.FindObjectsInitRequest) (*pkcs11.FindObjectsInitResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	err := c.FindObjectsInit(in.GetSessionHandle(), in.GetAttributes())
	return &pkcs11.FindObjectsInitResponse{}, err
}

// FindObjects continues a search for token and session
// objects that match a template, obtaining additional object
// handles. Calling the function repeatedly may yield additional results until
// an empty slice is returned.
//
// The returned boolean value is deprecated and should be ignored.
func (m *pkcs11Server) FindObjects(ctx context.Context, in *pkcs11.FindObjectsRequest) (*pkcs11.FindObjectsResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	handles, hasMore, err := c.FindObjects(in.GetSessionHandle(), int(in.GetMax()))
	if err != nil {
		return &pkcs11.FindObjectsResponse{}, err
	}

	return &pkcs11.FindObjectsResponse{
		HandleIds: types.ObjectHandlesToUint64(handles),
		HasMore:   hasMore,
	}, err
}

// FindObjectsFinal finishes a search for token and session objects.
func (m *pkcs11Server) FindObjectsFinal(ctx context.Context, in *pkcs11.FindObjectsFinalRequest) (*pkcs11.FindObjectsFinalResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	err := c.FindObjectsFinal(in.GetSessionHandle())
	return &pkcs11.FindObjectsFinalResponse{}, err
}

// EncryptInit initializes an encryption operation.
func (m *pkcs11Server) EncryptInit(ctx context.Context, in *pkcs11.EncryptInitRequest) (*pkcs11.EncryptInitResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	err := c.EncryptInit(in.GetSessionHandle(), in.GetMechanisms(), in.GetHandleId())
	return &pkcs11.EncryptInitResponse{}, err
}

// Encrypt encrypts single-part data.
func (m *pkcs11Server) Encrypt(ctx context.Context, in *pkcs11.EncryptRequest) (*pkcs11.EncryptResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	encrypted, err := c.Encrypt(in.GetSessionHandle(), in.GetPlain())
	if err != nil {
		return &pkcs11.EncryptResponse{}, err
	}
	log.Println(len(encrypted))

	return &pkcs11.EncryptResponse{
		Encrypted: encrypted,
	}, err
}

// EncryptUpdate continues a multiple-part encryption operation.
func (m *pkcs11Server) EncryptUpdate(ctx context.Context, in *pkcs11.EncryptUpdateRequest) (*pkcs11.EncryptUpdateResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	encrypted, err := c.EncryptUpdate(in.GetSessionHandle(), in.GetMessage())
	if err != nil {
		return &pkcs11.EncryptUpdateResponse{}, err
	}

	return &pkcs11.EncryptUpdateResponse{
		Encrypted: encrypted,
	}, err
}

// EncryptFinal finishes a multiple-part encryption operation.
func (m *pkcs11Server) EncryptFinal(ctx context.Context, in *pkcs11.EncryptFinalRequest) (*pkcs11.EncryptFinalResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	encrypted, err := c.EncryptFinal(in.GetSessionHandle())
	if err != nil {
		return &pkcs11.EncryptFinalResponse{}, err
	}

	return &pkcs11.EncryptFinalResponse{
		Encrypted: encrypted,
	}, err
}

// DecryptInit initializes a decryption operation.
func (m *pkcs11Server) DecryptInit(ctx context.Context, in *pkcs11.DecryptInitRequest) (*pkcs11.DecryptInitResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	err := c.DecryptInit(in.GetSessionHandle(), in.GetMechanisms(), in.GetHandleId())
	return &pkcs11.DecryptInitResponse{}, err
}

// Decrypt decrypts encrypted data in a single part.
func (m *pkcs11Server) Decrypt(ctx context.Context, in *pkcs11.DecryptRequest) (*pkcs11.DecryptResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	plain, err := c.Decrypt(in.GetSessionHandle(), in.GetEncrypted())
	if err != nil {
		return &pkcs11.DecryptResponse{}, err
	}

	return &pkcs11.DecryptResponse{
		Plain: plain,
	}, err
}

// DecryptUpdate continues a multiple-part decryption operation.
func (m *pkcs11Server) DecryptUpdate(ctx context.Context, in *pkcs11.DecryptUpdateRequest) (*pkcs11.DecryptUpdateResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	plain, err := c.DecryptUpdate(in.GetSessionHandle(), in.GetEncrypted())
	if err != nil {
		return &pkcs11.DecryptUpdateResponse{}, err
	}

	return &pkcs11.DecryptUpdateResponse{
		Plain: plain,
	}, err
}

// DecryptFinal finishes a multiple-part decryption operation.
func (m *pkcs11Server) DecryptFinal(ctx context.Context, in *pkcs11.DecryptFinalRequest) (*pkcs11.DecryptFinalResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	plain, err := c.DecryptFinal(in.GetSessionHandle())
	if err != nil {
		return &pkcs11.DecryptFinalResponse{}, err
	}

	return &pkcs11.DecryptFinalResponse{
		Plain: plain,
	}, err
}

// DigestInit initializes a message-digesting operation.
func (m *pkcs11Server) DigestInit(ctx context.Context, in *pkcs11.DigestInitRequest) (*pkcs11.DigestInitResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	err := c.DigestInit(in.GetSessionHandle(), in.GetMechanisms())
	return &pkcs11.DigestInitResponse{}, err
}

// Digest digests message in a single part.
func (m *pkcs11Server) Digest(ctx context.Context, in *pkcs11.DigestRequest) (*pkcs11.DigestResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	hashed, err := c.Digest(in.GetSessionHandle(), in.GetMessage())
	if err != nil {
		return &pkcs11.DigestResponse{}, err
	}

	return &pkcs11.DigestResponse{
		Hashed: hashed,
	}, err
}

// DigestUpdate continues a multiple-part message-digesting operation.
func (m *pkcs11Server) DigestUpdate(ctx context.Context, in *pkcs11.DigestUpdateRequest) (*pkcs11.DigestUpdateResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	err := c.DigestUpdate(in.GetSessionHandle(), in.GetMessage())
	return &pkcs11.DigestUpdateResponse{}, err
}

// DigestKey continues a multi-part message-digesting
// operation, by digesting the value of a secret key as part of
// the data already digested.
func (m *pkcs11Server) DigestKey(ctx context.Context, in *pkcs11.DigestKeyRequest) (*pkcs11.DigestKeyResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	err := c.DigestKey(in.GetSessionHandle(), in.GetHandleId())
	return &pkcs11.DigestKeyResponse{}, err
}

// DigestFinal finishes a multiple-part message-digesting operation.
func (m *pkcs11Server) DigestFinal(ctx context.Context, in *pkcs11.DigestFinalRequest) (*pkcs11.DigestFinalResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	hashed, err := c.DigestFinal(in.GetSessionHandle())
	if err != nil {
		return &pkcs11.DigestFinalResponse{}, err
	}

	return &pkcs11.DigestFinalResponse{
		Hashed: hashed,
	}, err
}

// SignInit initializes a signature (private key encryption)
// operation, where the signature is (will be) an appendix to
// the data, and plaintext cannot be recovered from the signature.
func (m *pkcs11Server) SignInit(ctx context.Context, in *pkcs11.SignInitRequest) (*pkcs11.SignInitResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	err := c.SignInit(in.GetSessionHandle(), in.GetMechanisms(), in.GetHandleId())
	return &pkcs11.SignInitResponse{}, err
}

// Sign signs (encrypts with private key) data in a single part, where the
// signature is (will be) an appendix to the data, and plaintext cannot be
// recovered from the signature.
func (m *pkcs11Server) Sign(ctx context.Context, in *pkcs11.SignRequest) (*pkcs11.SignResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	signature, err := c.Sign(in.GetSessionHandle(), in.GetMessage())
	if err != nil {
		return &pkcs11.SignResponse{}, err
	}

	return &pkcs11.SignResponse{
		Signature: signature,
	}, err
}

// SignUpdate continues a multiple-part signature operation,
// where the signature is (will be) an appendix to the data,
// and plaintext cannot be recovered from the signature.
func (m *pkcs11Server) SignUpdate(ctx context.Context, in *pkcs11.SignUpdateRequest) (*pkcs11.SignUpdateResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	err := c.SignUpdate(in.GetSessionHandle(), in.GetMessage())
	return &pkcs11.SignUpdateResponse{}, err
}

// SignFinal finishes a multiple-part signature operation returning the
// signature.
func (m *pkcs11Server) SignFinal(ctx context.Context, in *pkcs11.SignFinalRequest) (*pkcs11.SignFinalResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	signature, err := c.SignFinal(in.GetSessionHandle())
	if err != nil {
		return &pkcs11.SignFinalResponse{}, err
	}

	return &pkcs11.SignFinalResponse{
		Signature: signature,
	}, err
}

// SignRecoverInit initializes a signature operation, where the data can be
// recovered from the signature.
func (m *pkcs11Server) SignRecoverInit(ctx context.Context, in *pkcs11.SignRecoverInitRequest) (*pkcs11.SignRecoverInitResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	err := c.SignRecoverInit(in.GetSessionHandle(), in.GetMechanisms(), in.GetHandleId())
	return &pkcs11.SignRecoverInitResponse{}, err
}

// SignRecover signs data in a single operation, where the data can be
// recovered from the signature.
func (m *pkcs11Server) SignRecover(ctx context.Context, in *pkcs11.SignRecoverRequest) (*pkcs11.SignRecoverResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	signature, err := c.SignRecover(in.GetSessionHandle(), in.GetMessage())
	if err != nil {
		return &pkcs11.SignRecoverResponse{}, err
	}

	return &pkcs11.SignRecoverResponse{
		Signature: signature,
	}, err
}

// VerifyInit initializes a verification operation, where the
// signature is an appendix to the data, and plaintext cannot
// be recovered from the signature (e.g. DSA).
func (m *pkcs11Server) VerifyInit(ctx context.Context, in *pkcs11.VerifyInitRequest) (*pkcs11.VerifyInitResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	err := c.VerifyInit(in.GetSessionHandle(), in.GetMechanisms(), in.GetHandleId())
	return &pkcs11.VerifyInitResponse{}, err
}

// Verify verifies a signature in a single-part operation,
// where the signature is an appendix to the data, and plaintext
// cannot be recovered from the signature.
func (m *pkcs11Server) Verify(ctx context.Context, in *pkcs11.VerifyRequest) (*pkcs11.VerifyResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	err := c.Verify(in.GetSessionHandle(), in.GetMessage(), in.GetSignature())
	return &pkcs11.VerifyResponse{}, err
}

// VerifyUpdate continues a multiple-part verification
// operation, where the signature is an appendix to the data,
// and plaintext cannot be recovered from the signature.
func (m *pkcs11Server) VerifyUpdate(ctx context.Context, in *pkcs11.VerifyUpdateRequest) (*pkcs11.VerifyUpdateResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	err := c.VerifyUpdate(in.GetSessionHandle(), in.GetMessage())
	return &pkcs11.VerifyUpdateResponse{}, err
}

// VerifyFinal finishes a multiple-part verification
// operation, checking the signature.
func (m *pkcs11Server) VerifyFinal(ctx context.Context, in *pkcs11.VerifyFinalRequest) (*pkcs11.VerifyFinalResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	err := c.VerifyFinal(in.GetSessionHandle(), in.GetSignature())
	return &pkcs11.VerifyFinalResponse{}, err
}

// VerifyRecoverInit initializes a signature verification
// operation, where the data is recovered from the signature.
func (m *pkcs11Server) VerifyRecoverInit(ctx context.Context, in *pkcs11.VerifyRecoverInitRequest) (*pkcs11.VerifyRecoverInitResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	err := c.VerifyRecoverInit(in.GetSessionHandle(), in.GetMechanisms(), in.GetHandleId())
	return &pkcs11.VerifyRecoverInitResponse{}, err
}

// VerifyRecover verifies a signature in a single-part
// operation, where the data is recovered from the signature.
func (m *pkcs11Server) VerifyRecover(ctx context.Context, in *pkcs11.VerifyRecoverRequest) (*pkcs11.VerifyRecoverResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	data, err := c.VerifyRecover(in.GetSessionHandle(), in.GetSignature())
	if err != nil {
		return &pkcs11.VerifyRecoverResponse{}, err
	}

	return &pkcs11.VerifyRecoverResponse{
		Data: data,
	}, err
}

// DigestEncryptUpdate continues a multiple-part digesting and encryption
// operation.
func (m *pkcs11Server) DigestEncryptUpdate(ctx context.Context, in *pkcs11.DigestEncryptUpdateRequest) (*pkcs11.DigestEncryptUpdateResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	data, err := c.DigestEncryptUpdate(in.GetSessionHandle(), in.GetMessage())
	if err != nil {
		return &pkcs11.DigestEncryptUpdateResponse{}, err
	}

	return &pkcs11.DigestEncryptUpdateResponse{
		Hashed: data,
	}, err
}

// DecryptDigestUpdate continues a multiple-part decryption and digesting
// operation.
func (m *pkcs11Server) DecryptDigestUpdate(ctx context.Context, in *pkcs11.DecryptDigestUpdateRequest) (*pkcs11.DecryptDigestUpdateResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	data, err := c.DecryptDigestUpdate(in.GetSessionHandle(), in.GetMessage())
	if err != nil {
		return &pkcs11.DecryptDigestUpdateResponse{}, err
	}

	return &pkcs11.DecryptDigestUpdateResponse{
		Encrypted: data,
	}, err
}

// SignEncryptUpdate continues a multiple-part signing and encryption
// operation.
func (m *pkcs11Server) SignEncryptUpdate(ctx context.Context, in *pkcs11.SignEncryptUpdateRequest) (*pkcs11.SignEncryptUpdateResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	data, err := c.SignEncryptUpdate(in.GetSessionHandle(), in.GetMessage())
	if err != nil {
		return &pkcs11.SignEncryptUpdateResponse{}, err
	}

	return &pkcs11.SignEncryptUpdateResponse{
		Signature: data,
	}, err
}

// DecryptVerifyUpdate continues a multiple-part decryption and verify
// operation.
func (m *pkcs11Server) DecryptVerifyUpdate(ctx context.Context, in *pkcs11.DecryptVerifyUpdateRequest) (*pkcs11.DecryptVerifyUpdateResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	data, err := c.DecryptVerifyUpdate(in.GetSessionHandle(), in.GetEncrypted())
	if err != nil {
		return &pkcs11.DecryptVerifyUpdateResponse{}, err
	}

	return &pkcs11.DecryptVerifyUpdateResponse{
		Plain: data,
	}, err
}

// GenerateKey generates a secret key, creating a new key object.
func (m *pkcs11Server) GenerateKey(ctx context.Context, in *pkcs11.GenerateKeyRequest) (*pkcs11.GenerateKeyResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	handleID, err := c.GenerateKey(in.GetSessionHandle(), in.GetMechanisms(), in.GetAttributes())
	if err != nil {
		return &pkcs11.GenerateKeyResponse{}, err
	}

	return &pkcs11.GenerateKeyResponse{
		HandleId: uint64(handleID),
	}, err
}

// GenerateKeyPair generates a public-key/private-key pair creating new key
// objects.
func (m *pkcs11Server) GenerateKeyPair(ctx context.Context, in *pkcs11.GenerateKeyPairRequest) (*pkcs11.GenerateKeyPairResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	handleID, phandleID, err := c.GenerateKeyPair(in.GetSessionHandle(),
		in.GetMechanisms(),
		in.GetPublicAttributes(),
		in.GetPrivateAttributes())
	if err != nil {
		return &pkcs11.GenerateKeyPairResponse{}, err
	}

	return &pkcs11.GenerateKeyPairResponse{
		PublicKeyHandleId:  uint64(handleID),
		PrivateKeyHandleId: uint64(phandleID),
	}, err
}

// WrapKey wraps (i.e., encrypts) a key.
func (m *pkcs11Server) WrapKey(ctx context.Context, in *pkcs11.WrapKeyRequest) (*pkcs11.WrapKeyResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	wrapped, err := c.WrapKey(in.GetSessionHandle(),
		in.GetMechanisms(),
		in.GetWrappingHandleId(),
		in.GetHandleId())
	if err != nil {
		return &pkcs11.WrapKeyResponse{}, err
	}

	return &pkcs11.WrapKeyResponse{
		WrappedKey: wrapped,
	}, err
}

// UnwrapKey unwraps (decrypts) a wrapped key, creating a new key object.
func (m *pkcs11Server) UnwrapKey(ctx context.Context, in *pkcs11.UnwrapKeyRequest) (*pkcs11.UnwrapKeyResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	unwrapped, err := c.UnwrapKey(in.GetSessionHandle(),
		in.GetMechanisms(),
		in.GetWrappingHandleId(),
		in.GetWrappedKey(),
		in.GetAttributes())
	if err != nil {
		return &pkcs11.UnwrapKeyResponse{}, err
	}

	return &pkcs11.UnwrapKeyResponse{
		HandleId: uint64(unwrapped),
	}, err
}

// DeriveKey derives a key from a base key, creating a new key object.
func (m *pkcs11Server) DeriveKey(ctx context.Context, in *pkcs11.DeriveKeyRequest) (*pkcs11.DeriveKeyResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	unwrapped, err := c.DeriveKey(in.GetSessionHandle(),
		in.GetMechanisms(),
		in.GetHandleId(),
		in.GetAttributes())
	if err != nil {
		return &pkcs11.DeriveKeyResponse{}, err
	}

	return &pkcs11.DeriveKeyResponse{
		HandleId: uint64(unwrapped),
	}, err
}

// SeedRandom mixes additional seed material into the token's
// random number generator.
func (m *pkcs11Server) SeedRandom(ctx context.Context, in *pkcs11.SeedRandomRequest) (*pkcs11.SeedRandomResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	err := c.SeedRandom(in.GetSessionHandle(), in.GetSeed())
	return &pkcs11.SeedRandomResponse{}, err
}

// GenerateRandom generates random data.
func (m *pkcs11Server) GenerateRandom(ctx context.Context, in *pkcs11.GenerateRandomRequest) (*pkcs11.GenerateRandomResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	random, err := c.GenerateRandom(in.GetSessionHandle(), int(in.GetLength()))
	if err != nil {
		return &pkcs11.GenerateRandomResponse{}, err
	}

	return &pkcs11.GenerateRandomResponse{
		Data: random,
	}, err
}

// WaitForSlotEvent returns a channel which returns a slot event
// (token insertion, removal, etc.) when it occurs.
func (m *pkcs11Server) WaitForSlotEvent(ctx context.Context, in *pkcs11.WaitForSlotEventRequest) (*pkcs11.WaitForSlotEventResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return &pkcs11.WaitForSlotEventResponse{}, ErrCtxNotFound
	}
	slotID, err := c.WaitForSlotEvent(uint(in.GetFlags()))
	if err != nil {
		return &pkcs11.WaitForSlotEventResponse{}, err
	}
	return &pkcs11.WaitForSlotEventResponse{
		SlotID: slotID,
	}, nil
}

func main() {
	listener, err := net.Listen("tcp", os.Getenv("PKCS11_PROXY_URI"))
	if err != nil {
		panic(err)
	}

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
		// Create the TLS configuration
		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{serverCert},
			RootCAs:      certPool,
			ClientCAs:    certPool,
			MinVersion:   tls.VersionTLS13,
			MaxVersion:   tls.VersionTLS13,
			ClientAuth:   tls.RequireAndVerifyClientCert,
		}

		// Create a new TLS credentials based on the TLS configuration
		c = credentials.NewTLS(tlsConfig)
	}

	allowedModules := []string{}
	if os.Getenv("PKCS11_PROXY_ALLOWED_MODULES") != "" {
		allowedModules = strings.Split(os.Getenv("PKCS11_PROXY_ALLOWED_MODULES"), ";")
	}

	errHandler := func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		resp, err := handler(ctx, req)
		if err != nil {
			var pe pkcs11.Error
			if errors.As(err, &pe) {
				err = status.Error(codes.Code(pe), err.Error())
			}
			log.Printf("method %q failed: %s", info.FullMethod, err)
		}
		if os.Getenv("PKCS11_PROXY_ACCESS_LOGS") != "" {
			log.Printf("LOG (%q) [%+v] -> [%+v] (%s)", info.FullMethod, req, resp, err)
		}
		return resp, err
	}
	s := grpc.NewServer(grpc.Creds(c), grpc.UnaryInterceptor(errHandler))
	server := &pkcs11Server{
		ctxs:           make(map[string]*server.Ctx, 0),
		allowedModules: allowedModules,
	}
	pkcs11.RegisterPKCS11Server(s, server)
	if err := s.Serve(listener); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
