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

	"github.com/miekg/pkcs11"
	p11 "github.com/ryarnyah/pkcs11-go-proxy/pkcs11"
	"github.com/ryarnyah/pkcs11-go-proxy/pkg"
	grpc "google.golang.org/grpc"
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
	ctxs map[string]*pkcs11.Ctx

	allowedModules []string
	p11.UnimplementedPKCS11Server
}

// New creates a new context and initializes the module/library for use.
func (m *pkcs11Server) New(ctx context.Context, in *p11.NewRequest) (*p11.NewResponse, error) {
	if len(m.allowedModules) > 0 && !slices.Contains(m.allowedModules, in.GetModule()) {
		return nil, ErrModuleNotAllowed
	}
	c, ok := m.ctxs[in.GetModule()]
	if ok {
		c.Finalize()
		c.Destroy()
		delete(m.ctxs, in.GetModule())
	}
	p := pkcs11.New(in.GetModule())
	m.ctxs[in.GetModule()] = p
	return &p11.NewResponse{
		Ctx: in.GetModule(),
	}, nil
}

// Destroy unloads the module/library and frees any remaining memory.
func (m *pkcs11Server) Destroy(ctx context.Context, in *p11.DestroyRequest) (*p11.EmptyResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	c.Destroy()
	delete(m.ctxs, in.GetCtx())
	return &p11.EmptyResponse{}, nil
}

// Initialize initializes the Cryptoki library.
func (m *pkcs11Server) Initialize(ctx context.Context, in *p11.InitializeRequest) (*p11.InitializeResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	err := c.Initialize()
	return &p11.InitializeResponse{}, err
}

// Finalize indicates that an application is done with the Cryptoki library.
func (m *pkcs11Server) Finalize(ctx context.Context, in *p11.FinalizeRequest) (*p11.FinalizeResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	err := c.Finalize()
	return &p11.FinalizeResponse{}, err
}

// GetInfo returns general information about Cryptoki.
func (m *pkcs11Server) GetInfo(ctx context.Context, in *p11.GetInfoRequest) (*p11.GetInfoResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	info, err := c.GetInfo()
	if err != nil {
		return &p11.GetInfoResponse{}, err
	}
	return &p11.GetInfoResponse{
		Info: &p11.Info{
			CryptokiVersion:    pkg.VersionToVersion(info.CryptokiVersion),
			ManufacturerID:     info.ManufacturerID,
			Flags:              uint64(info.Flags),
			LibraryDescription: info.LibraryDescription,
			LibraryVersion:     pkg.VersionToVersion(info.LibraryVersion),
		},
	}, err
}

// GetSlotList obtains a list of slots in the system.
func (m *pkcs11Server) GetSlotList(ctx context.Context, in *p11.GetSlotListRequest) (*p11.GetSlotListResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	slots, err := c.GetSlotList(in.GetTokenPresent())
	if err != nil {
		return &p11.GetSlotListResponse{}, err
	}
	return &p11.GetSlotListResponse{
		SlotIds: pkg.UintToUint32(slots),
	}, err
}

// GetSlotInfo obtains information about a particular slot in the system.
func (m *pkcs11Server) GetSlotInfo(ctx context.Context, in *p11.GetSlotInfoRequest) (*p11.GetSlotInfoResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	info, err := c.GetSlotInfo(uint(in.GetSlotId()))
	if err != nil {
		return &p11.GetSlotInfoResponse{}, err
	}
	return &p11.GetSlotInfoResponse{
		Info: &p11.SlotInfo{
			SlotDescription: info.SlotDescription,
			ManufacturerID:  info.ManufacturerID,
			Flags:           uint32(info.Flags),
			HardwareVersion: pkg.VersionToVersion(info.HardwareVersion),
			FirmwareVersion: pkg.VersionToVersion(info.FirmwareVersion),
		},
	}, err
}

// GetTokenInfo obtains information about a particular token
// in the system.
func (m *pkcs11Server) GetTokenInfo(ctx context.Context, in *p11.GetTokenInfoRequest) (*p11.GetTokenInfoResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	info, err := c.GetTokenInfo(uint(in.GetSlotId()))
	if err != nil {
		return &p11.GetTokenInfoResponse{}, err
	}

	return &p11.GetTokenInfoResponse{
		Info: &p11.TokenInfo{
			Label:              info.Label,
			ManufacturerID:     info.ManufacturerID,
			Model:              info.Model,
			SerialNumber:       info.SerialNumber,
			Flags:              uint32(info.Flags),
			MaxSessionCount:    uint32(info.MaxSessionCount),
			SessionCount:       uint32(info.SessionCount),
			MaxRwSessionCount:  uint32(info.MaxRwSessionCount),
			RwSessionCount:     uint32(info.RwSessionCount),
			MaxPinLen:          uint32(info.MaxPinLen),
			MinPinLen:          uint32(info.MinPinLen),
			TotalPublicMemory:  uint32(info.TotalPublicMemory),
			FreePublicMemory:   uint32(info.FreePublicMemory),
			TotalPrivateMemory: uint32(info.TotalPrivateMemory),
			FreePrivateMemory:  uint32(info.FreePrivateMemory),
			HardwareVersion:    pkg.VersionToVersion(info.HardwareVersion),
			FirmwareVersion:    pkg.VersionToVersion(info.FirmwareVersion),
			UTCTime:            info.UTCTime,
		},
	}, err
}

// GetMechanismList obtains a list of mechanism types supported by a token.
func (m *pkcs11Server) GetMechanismList(ctx context.Context, in *p11.GetMechanismListRequest) (*p11.GetMechanismListResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	mechanisms, err := c.GetMechanismList(uint(in.GetSlotId()))
	if err != nil {
		return &p11.GetMechanismListResponse{}, err
	}

	return &p11.GetMechanismListResponse{
		Mechanisms: pkg.MechanismsToMechanisms(mechanisms),
	}, err
}

// GetMechanismInfo obtains information about a particular
// mechanism possibly supported by a token.
func (m *pkcs11Server) GetMechanismInfo(ctx context.Context, in *p11.GetMechanismInfoRequest) (*p11.GetMechanismInfoResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	info, err := c.GetMechanismInfo(uint(in.GetSlotId()), pkg.ReverseMechanismsToMechanisms(in.GetMechanisms()))
	if err != nil {
		return &p11.GetMechanismInfoResponse{}, err
	}

	return &p11.GetMechanismInfoResponse{
		Info: &p11.MechanismInfo{
			MinKeySize: uint32(info.MinKeySize),
			MaxKeySize: uint32(info.MaxKeySize),
			Flags:      uint32(info.Flags),
		},
	}, err
}

// InitToken initializes a token. The label must be 32 characters
// long, it is blank padded if it is not. If it is longer it is capped
// to 32 characters.
func (m *pkcs11Server) InitToken(ctx context.Context, in *p11.InitTokenRequest) (*p11.InitTokenResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	err := c.InitToken(uint(in.GetSlotId()), in.GetPin(), in.GetLabel())
	return &p11.InitTokenResponse{}, err
}

// InitPIN initializes the normal user's PIN.
func (m *pkcs11Server) InitPIN(ctx context.Context, in *p11.InitPINRequest) (*p11.InitPINResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	err := c.InitPIN(pkcs11.SessionHandle(in.GetSessionHandle()), in.GetPin())
	return &p11.InitPINResponse{}, err
}

// SetPIN modifies the PIN of the user who is logged in.
func (m *pkcs11Server) SetPIN(ctx context.Context, in *p11.SetPINRequest) (*p11.SetPINResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	err := c.SetPIN(pkcs11.SessionHandle(in.GetSessionHandle()), in.GetOldPin(), in.GetOldPin())
	return &p11.SetPINResponse{}, err
}

// OpenSession opens a session between an application and a token.
func (m *pkcs11Server) OpenSession(ctx context.Context, in *p11.OpenSessionRequest) (*p11.OpenSessionResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	handle, err := c.OpenSession(uint(in.GetSlotId()), uint(in.GetFlags()))
	if err != nil {
		return &p11.OpenSessionResponse{}, err
	}

	return &p11.OpenSessionResponse{
		SessionHandle: uint32(handle),
	}, err
}

// CloseSession closes a session between an application and a token.
func (m *pkcs11Server) CloseSession(ctx context.Context, in *p11.CloseSessionRequest) (*p11.CloseSessionResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	err := c.CloseSession(pkcs11.SessionHandle(in.GetSessionHandle()))
	if err != nil {
		return &p11.CloseSessionResponse{}, err
	}

	return &p11.CloseSessionResponse{}, err
}

// CloseAllSessions closes all sessions with a token.
func (m *pkcs11Server) CloseAllSessions(ctx context.Context, in *p11.CloseAllSessionsRequest) (*p11.CloseAllSessionsResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	err := c.CloseAllSessions(uint(in.GetSlotId()))
	if err != nil {
		return &p11.CloseAllSessionsResponse{}, err
	}

	return &p11.CloseAllSessionsResponse{}, err
}

// GetSessionInfo obtains information about the session.
func (m *pkcs11Server) GetSessionInfo(ctx context.Context, in *p11.GetSessionInfoRequest) (*p11.GetSessionInfoResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	info, err := c.GetSessionInfo(pkcs11.SessionHandle(in.GetSessionHandle()))
	if err != nil {
		return &p11.GetSessionInfoResponse{}, err
	}

	return &p11.GetSessionInfoResponse{
		Info: &p11.SessionInfo{
			SlotID:      uint32(info.SlotID),
			State:       uint32(info.State),
			Flags:       uint32(info.Flags),
			DeviceError: uint32(info.DeviceError),
		},
	}, err
}

// GetOperationState obtains the state of the cryptographic operation in a
// session.
func (m *pkcs11Server) GetOperationState(ctx context.Context, in *p11.GetOperationStateRequest) (*p11.GetOperationStateResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	state, err := c.GetOperationState(pkcs11.SessionHandle(in.GetSessionHandle()))
	if err != nil {
		return &p11.GetOperationStateResponse{}, err
	}

	return &p11.GetOperationStateResponse{
		State: state,
	}, err
}

// SetOperationState restores the state of the cryptographic operation in a
// session.
func (m *pkcs11Server) SetOperationState(ctx context.Context, in *p11.SetOperationStateRequest) (*p11.SetOperationStateResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	err := c.SetOperationState(pkcs11.SessionHandle(in.GetSessionHandle()), in.GetState(), pkcs11.ObjectHandle(in.GetEncryptKey()), pkcs11.ObjectHandle(in.GetAuthKey()))
	return &p11.SetOperationStateResponse{}, err
}

// Login logs a user into a token.
func (m *pkcs11Server) Login(ctx context.Context, in *p11.LoginRequest) (*p11.LoginResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	err := c.Login(pkcs11.SessionHandle(in.GetSessionHandle()), uint(in.GetUserType()), in.GetPin())
	return &p11.LoginResponse{}, err
}

// Logout logs a user out from a token.
func (m *pkcs11Server) Logout(ctx context.Context, in *p11.LogoutRequest) (*p11.LogoutResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	err := c.Logout(pkcs11.SessionHandle(in.GetSessionHandle()))
	return &p11.LogoutResponse{}, err
}

// CreateObject creates a new object.
func (m *pkcs11Server) CreateObject(ctx context.Context, in *p11.CreateObjectRequest) (*p11.CreateObjectResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	handleID, err := c.CreateObject(pkcs11.SessionHandle(in.GetSessionHandle()), pkg.ReverseAttributesToAttributes(in.GetAttributes()))
	if err != nil {
		return &p11.CreateObjectResponse{}, err
	}
	return &p11.CreateObjectResponse{
		HandleId: uint32(handleID),
	}, err
}

// CopyObject copies an object, creating a new object for the copy.
func (m *pkcs11Server) CopyObject(ctx context.Context, in *p11.CopyObjectRequest) (*p11.CopyObjectResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	handleID, err := c.CopyObject(pkcs11.SessionHandle(in.GetSessionHandle()), pkcs11.ObjectHandle(in.GetHandleId()), pkg.ReverseAttributesToAttributes(in.GetAttributes()))
	if err != nil {
		return &p11.CopyObjectResponse{}, err
	}

	return &p11.CopyObjectResponse{
		HandleId: uint32(handleID),
	}, err
}

// DestroyObject destroys an object.
func (m *pkcs11Server) DestroyObject(ctx context.Context, in *p11.DestroyObjectRequest) (*p11.DestroyObjectResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	err := c.DestroyObject(pkcs11.SessionHandle(in.GetSessionHandle()), pkcs11.ObjectHandle(in.GetHandleId()))
	return &p11.DestroyObjectResponse{}, err
}

// GetObjectSize gets the size of an object in bytes.
func (m *pkcs11Server) GetObjectSize(ctx context.Context, in *p11.GetObjectSizeRequest) (*p11.GetObjectSizeResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	size, err := c.GetObjectSize(pkcs11.SessionHandle(in.GetSessionHandle()), pkcs11.ObjectHandle(in.GetHandleId()))
	if err != nil {
		return &p11.GetObjectSizeResponse{}, err
	}

	return &p11.GetObjectSizeResponse{
		Size: uint32(size),
	}, err
}

// GetAttributeValue obtains the value of one or more object attributes.
func (m *pkcs11Server) GetAttributeValue(ctx context.Context, in *p11.GetAttributeValueRequest) (*p11.GetAttributeValueResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	attributes, err := c.GetAttributeValue(pkcs11.SessionHandle(in.GetSessionHandle()), pkcs11.ObjectHandle(in.GetHandleId()), pkg.ReverseAttributesToAttributes(in.GetAttributes()))
	if err != nil {
		return &p11.GetAttributeValueResponse{}, err
	}

	return &p11.GetAttributeValueResponse{
		Attributes: pkg.AttributesToAttributes(attributes),
	}, err
}

// SetAttributeValue modifies the value of one or more object attributes
func (m *pkcs11Server) SetAttributeValue(ctx context.Context, in *p11.SetAttributeValueRequest) (*p11.SetAttributeValueResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	err := c.SetAttributeValue(pkcs11.SessionHandle(in.GetSessionHandle()), pkcs11.ObjectHandle(in.GetHandleId()), pkg.ReverseAttributesToAttributes(in.GetAttributes()))
	return &p11.SetAttributeValueResponse{}, err
}

// FindObjectsInit initializes a search for token and session
// objects that match a template.
func (m *pkcs11Server) FindObjectsInit(ctx context.Context, in *p11.FindObjectsInitRequest) (*p11.FindObjectsInitResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	err := c.FindObjectsInit(pkcs11.SessionHandle(in.GetSessionHandle()), pkg.ReverseAttributesToAttributes(in.GetAttributes()))
	return &p11.FindObjectsInitResponse{}, err
}

// FindObjects continues a search for token and session
// objects that match a template, obtaining additional object
// handles. Calling the function repeatedly may yield additional results until
// an empty slice is returned.
//
// The returned boolean value is deprecated and should be ignored.
func (m *pkcs11Server) FindObjects(ctx context.Context, in *p11.FindObjectsRequest) (*p11.FindObjectsResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	handles, hasMore, err := c.FindObjects(pkcs11.SessionHandle(in.GetSessionHandle()), int(in.GetMax()))
	if err != nil {
		return &p11.FindObjectsResponse{}, err
	}

	return &p11.FindObjectsResponse{
		HandleIds: pkg.ObjectHandlesToUint32(handles),
		HasMore:   hasMore,
	}, err
}

// FindObjectsFinal finishes a search for token and session objects.
func (m *pkcs11Server) FindObjectsFinal(ctx context.Context, in *p11.FindObjectsFinalRequest) (*p11.FindObjectsFinalResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	err := c.FindObjectsFinal(pkcs11.SessionHandle(in.GetSessionHandle()))
	return &p11.FindObjectsFinalResponse{}, err
}

// EncryptInit initializes an encryption operation.
func (m *pkcs11Server) EncryptInit(ctx context.Context, in *p11.EncryptInitRequest) (*p11.EncryptInitResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	err := c.EncryptInit(pkcs11.SessionHandle(in.GetSessionHandle()), pkg.ReverseMechanismsToMechanisms(in.GetMechanisms()), pkcs11.ObjectHandle(in.GetHandleId()))
	return &p11.EncryptInitResponse{}, err
}

// Encrypt encrypts single-part data.
func (m *pkcs11Server) Encrypt(ctx context.Context, in *p11.EncryptRequest) (*p11.EncryptResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	encrypted, err := c.Encrypt(pkcs11.SessionHandle(in.GetSessionHandle()), in.GetPlain())
	if err != nil {
		return &p11.EncryptResponse{}, err
	}

	return &p11.EncryptResponse{
		Encrypted: encrypted,
	}, err
}

// EncryptUpdate continues a multiple-part encryption operation.
func (m *pkcs11Server) EncryptUpdate(ctx context.Context, in *p11.EncryptUpdateRequest) (*p11.EncryptUpdateResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	encrypted, err := c.EncryptUpdate(pkcs11.SessionHandle(in.GetSessionHandle()), in.GetMessage())
	if err != nil {
		return &p11.EncryptUpdateResponse{}, err
	}

	return &p11.EncryptUpdateResponse{
		Encrypted: encrypted,
	}, err
}

// EncryptFinal finishes a multiple-part encryption operation.
func (m *pkcs11Server) EncryptFinal(ctx context.Context, in *p11.EncryptFinalRequest) (*p11.EncryptFinalResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	encrypted, err := c.EncryptFinal(pkcs11.SessionHandle(in.GetSessionHandle()))
	if err != nil {
		return &p11.EncryptFinalResponse{}, err
	}

	return &p11.EncryptFinalResponse{
		Encrypted: encrypted,
	}, err
}

// DecryptInit initializes a decryption operation.
func (m *pkcs11Server) DecryptInit(ctx context.Context, in *p11.DecryptInitRequest) (*p11.DecryptInitResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	err := c.DecryptInit(pkcs11.SessionHandle(in.GetSessionHandle()), pkg.ReverseMechanismsToMechanisms(in.GetMechanisms()), pkcs11.ObjectHandle(in.GetHandleId()))
	return &p11.DecryptInitResponse{}, err
}

// Decrypt decrypts encrypted data in a single part.
func (m *pkcs11Server) Decrypt(ctx context.Context, in *p11.DecryptRequest) (*p11.DecryptResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	plain, err := c.Decrypt(pkcs11.SessionHandle(in.GetSessionHandle()), in.GetEncrypted())
	if err != nil {
		return &p11.DecryptResponse{}, err
	}

	return &p11.DecryptResponse{
		Plain: plain,
	}, err
}

// DecryptUpdate continues a multiple-part decryption operation.
func (m *pkcs11Server) DecryptUpdate(ctx context.Context, in *p11.DecryptUpdateRequest) (*p11.DecryptUpdateResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	plain, err := c.DecryptUpdate(pkcs11.SessionHandle(in.GetSessionHandle()), in.GetEncrypted())
	if err != nil {
		return &p11.DecryptUpdateResponse{}, err
	}

	return &p11.DecryptUpdateResponse{
		Plain: plain,
	}, err
}

// DecryptFinal finishes a multiple-part decryption operation.
func (m *pkcs11Server) DecryptFinal(ctx context.Context, in *p11.DecryptFinalRequest) (*p11.DecryptFinalResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	plain, err := c.DecryptFinal(pkcs11.SessionHandle(in.GetSessionHandle()))
	if err != nil {
		return &p11.DecryptFinalResponse{}, err
	}

	return &p11.DecryptFinalResponse{
		Plain: plain,
	}, err
}

// DigestInit initializes a message-digesting operation.
func (m *pkcs11Server) DigestInit(ctx context.Context, in *p11.DigestInitRequest) (*p11.DigestInitResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	err := c.DigestInit(pkcs11.SessionHandle(in.GetSessionHandle()), pkg.ReverseMechanismsToMechanisms(in.GetMechanisms()))
	return &p11.DigestInitResponse{}, err
}

// Digest digests message in a single part.
func (m *pkcs11Server) Digest(ctx context.Context, in *p11.DigestRequest) (*p11.DigestResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	hashed, err := c.Digest(pkcs11.SessionHandle(in.GetSessionHandle()), in.GetMessage())
	if err != nil {
		return &p11.DigestResponse{}, err
	}

	return &p11.DigestResponse{
		Hashed: hashed,
	}, err
}

// DigestUpdate continues a multiple-part message-digesting operation.
func (m *pkcs11Server) DigestUpdate(ctx context.Context, in *p11.DigestUpdateRequest) (*p11.DigestUpdateResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	err := c.DigestUpdate(pkcs11.SessionHandle(in.GetSessionHandle()), in.GetMessage())
	return &p11.DigestUpdateResponse{}, err
}

// DigestKey continues a multi-part message-digesting
// operation, by digesting the value of a secret key as part of
// the data already digested.
func (m *pkcs11Server) DigestKey(ctx context.Context, in *p11.DigestKeyRequest) (*p11.DigestKeyResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	err := c.DigestKey(pkcs11.SessionHandle(in.GetSessionHandle()), pkcs11.ObjectHandle(in.GetHandleId()))
	return &p11.DigestKeyResponse{}, err
}

// DigestFinal finishes a multiple-part message-digesting operation.
func (m *pkcs11Server) DigestFinal(ctx context.Context, in *p11.DigestFinalRequest) (*p11.DigestFinalResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	hashed, err := c.DigestFinal(pkcs11.SessionHandle(in.GetSessionHandle()))
	if err != nil {
		return &p11.DigestFinalResponse{}, err
	}

	return &p11.DigestFinalResponse{
		Hashed: hashed,
	}, err
}

// SignInit initializes a signature (private key encryption)
// operation, where the signature is (will be) an appendix to
// the data, and plaintext cannot be recovered from the signature.
func (m *pkcs11Server) SignInit(ctx context.Context, in *p11.SignInitRequest) (*p11.SignInitResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	err := c.SignInit(pkcs11.SessionHandle(in.GetSessionHandle()), pkg.ReverseMechanismsToMechanisms(in.GetMechanisms()), pkcs11.ObjectHandle(in.GetHandleId()))
	return &p11.SignInitResponse{}, err
}

// Sign signs (encrypts with private key) data in a single part, where the
// signature is (will be) an appendix to the data, and plaintext cannot be
// recovered from the signature.
func (m *pkcs11Server) Sign(ctx context.Context, in *p11.SignRequest) (*p11.SignResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	signature, err := c.Sign(pkcs11.SessionHandle(in.GetSessionHandle()), in.GetMessage())
	if err != nil {
		return &p11.SignResponse{}, err
	}

	return &p11.SignResponse{
		Signature: signature,
	}, err
}

// SignUpdate continues a multiple-part signature operation,
// where the signature is (will be) an appendix to the data,
// and plaintext cannot be recovered from the signature.
func (m *pkcs11Server) SignUpdate(ctx context.Context, in *p11.SignUpdateRequest) (*p11.SignUpdateResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	err := c.SignUpdate(pkcs11.SessionHandle(in.GetSessionHandle()), in.GetMessage())
	return &p11.SignUpdateResponse{}, err
}

// SignFinal finishes a multiple-part signature operation returning the
// signature.
func (m *pkcs11Server) SignFinal(ctx context.Context, in *p11.SignFinalRequest) (*p11.SignFinalResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	signature, err := c.SignFinal(pkcs11.SessionHandle(in.GetSessionHandle()))
	if err != nil {
		return &p11.SignFinalResponse{}, err
	}

	return &p11.SignFinalResponse{
		Signature: signature,
	}, err
}

// SignRecoverInit initializes a signature operation, where the data can be
// recovered from the signature.
func (m *pkcs11Server) SignRecoverInit(ctx context.Context, in *p11.SignRecoverInitRequest) (*p11.SignRecoverInitResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	err := c.SignRecoverInit(pkcs11.SessionHandle(in.GetSessionHandle()), pkg.ReverseMechanismsToMechanisms(in.GetMechanisms()), pkcs11.ObjectHandle(in.GetHandleId()))
	return &p11.SignRecoverInitResponse{}, err
}

// SignRecover signs data in a single operation, where the data can be
// recovered from the signature.
func (m *pkcs11Server) SignRecover(ctx context.Context, in *p11.SignRecoverRequest) (*p11.SignRecoverResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	signature, err := c.SignRecover(pkcs11.SessionHandle(in.GetSessionHandle()), in.GetMessage())
	if err != nil {
		return &p11.SignRecoverResponse{}, err
	}

	return &p11.SignRecoverResponse{
		Signature: signature,
	}, err
}

// VerifyInit initializes a verification operation, where the
// signature is an appendix to the data, and plaintext cannot
// be recovered from the signature (e.g. DSA).
func (m *pkcs11Server) VerifyInit(ctx context.Context, in *p11.VerifyInitRequest) (*p11.VerifyInitResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	err := c.VerifyInit(pkcs11.SessionHandle(in.GetSessionHandle()), pkg.ReverseMechanismsToMechanisms(in.GetMechanisms()), pkcs11.ObjectHandle(in.GetHandleId()))
	return &p11.VerifyInitResponse{}, err
}

// Verify verifies a signature in a single-part operation,
// where the signature is an appendix to the data, and plaintext
// cannot be recovered from the signature.
func (m *pkcs11Server) Verify(ctx context.Context, in *p11.VerifyRequest) (*p11.VerifyResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	err := c.Verify(pkcs11.SessionHandle(in.GetSessionHandle()), in.GetMessage(), in.GetSignature())
	return &p11.VerifyResponse{}, err
}

// VerifyUpdate continues a multiple-part verification
// operation, where the signature is an appendix to the data,
// and plaintext cannot be recovered from the signature.
func (m *pkcs11Server) VerifyUpdate(ctx context.Context, in *p11.VerifyUpdateRequest) (*p11.VerifyUpdateResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	err := c.VerifyUpdate(pkcs11.SessionHandle(in.GetSessionHandle()), in.GetMessage())
	return &p11.VerifyUpdateResponse{}, err
}

// VerifyFinal finishes a multiple-part verification
// operation, checking the signature.
func (m *pkcs11Server) VerifyFinal(ctx context.Context, in *p11.VerifyFinalRequest) (*p11.VerifyFinalResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	err := c.VerifyFinal(pkcs11.SessionHandle(in.GetSessionHandle()), in.GetSignature())
	return &p11.VerifyFinalResponse{}, err
}

// VerifyRecoverInit initializes a signature verification
// operation, where the data is recovered from the signature.
func (m *pkcs11Server) VerifyRecoverInit(ctx context.Context, in *p11.VerifyRecoverInitRequest) (*p11.VerifyRecoverInitResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	err := c.VerifyRecoverInit(pkcs11.SessionHandle(in.GetSessionHandle()), pkg.ReverseMechanismsToMechanisms(in.GetMechanisms()), pkcs11.ObjectHandle(in.GetHandleId()))
	return &p11.VerifyRecoverInitResponse{}, err
}

// VerifyRecover verifies a signature in a single-part
// operation, where the data is recovered from the signature.
func (m *pkcs11Server) VerifyRecover(ctx context.Context, in *p11.VerifyRecoverRequest) (*p11.VerifyRecoverResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	data, err := c.VerifyRecover(pkcs11.SessionHandle(in.GetSessionHandle()), in.GetSignature())
	if err != nil {
		return &p11.VerifyRecoverResponse{}, err
	}

	return &p11.VerifyRecoverResponse{
		Data: data,
	}, err
}

// DigestEncryptUpdate continues a multiple-part digesting and encryption
// operation.
func (m *pkcs11Server) DigestEncryptUpdate(ctx context.Context, in *p11.DigestEncryptUpdateRequest) (*p11.DigestEncryptUpdateResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	data, err := c.DigestEncryptUpdate(pkcs11.SessionHandle(in.GetSessionHandle()), in.GetMessage())
	if err != nil {
		return &p11.DigestEncryptUpdateResponse{}, err
	}

	return &p11.DigestEncryptUpdateResponse{
		Hashed: data,
	}, err
}

// DecryptDigestUpdate continues a multiple-part decryption and digesting
// operation.
func (m *pkcs11Server) DecryptDigestUpdate(ctx context.Context, in *p11.DecryptDigestUpdateRequest) (*p11.DecryptDigestUpdateResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	data, err := c.DecryptDigestUpdate(pkcs11.SessionHandle(in.GetSessionHandle()), in.GetMessage())
	if err != nil {
		return &p11.DecryptDigestUpdateResponse{}, err
	}

	return &p11.DecryptDigestUpdateResponse{
		Encrypted: data,
	}, err
}

// SignEncryptUpdate continues a multiple-part signing and encryption
// operation.
func (m *pkcs11Server) SignEncryptUpdate(ctx context.Context, in *p11.SignEncryptUpdateRequest) (*p11.SignEncryptUpdateResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	data, err := c.SignEncryptUpdate(pkcs11.SessionHandle(in.GetSessionHandle()), in.GetMessage())
	if err != nil {
		return &p11.SignEncryptUpdateResponse{}, err
	}

	return &p11.SignEncryptUpdateResponse{
		Signature: data,
	}, err
}

// DecryptVerifyUpdate continues a multiple-part decryption and verify
// operation.
func (m *pkcs11Server) DecryptVerifyUpdate(ctx context.Context, in *p11.DecryptVerifyUpdateRequest) (*p11.DecryptVerifyUpdateResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	data, err := c.DecryptVerifyUpdate(pkcs11.SessionHandle(in.GetSessionHandle()), in.GetEncrypted())
	if err != nil {
		return &p11.DecryptVerifyUpdateResponse{}, err
	}

	return &p11.DecryptVerifyUpdateResponse{
		Plain: data,
	}, err
}

// GenerateKey generates a secret key, creating a new key object.
func (m *pkcs11Server) GenerateKey(ctx context.Context, in *p11.GenerateKeyRequest) (*p11.GenerateKeyResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	handleID, err := c.GenerateKey(pkcs11.SessionHandle(in.GetSessionHandle()), pkg.ReverseMechanismsToMechanisms(in.GetMechanisms()), pkg.ReverseAttributesToAttributes(in.GetAttributes()))
	if err != nil {
		return &p11.GenerateKeyResponse{}, err
	}

	return &p11.GenerateKeyResponse{
		HandleId: uint32(handleID),
	}, err
}

// GenerateKeyPair generates a public-key/private-key pair creating new key
// objects.
func (m *pkcs11Server) GenerateKeyPair(ctx context.Context, in *p11.GenerateKeyPairRequest) (*p11.GenerateKeyPairResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	handleID, phandleID, err := c.GenerateKeyPair(pkcs11.SessionHandle(in.GetSessionHandle()),
		pkg.ReverseMechanismsToMechanisms(in.GetMechanisms()),
		pkg.ReverseAttributesToAttributes(in.GetPublicAttributes()),
		pkg.ReverseAttributesToAttributes(in.GetPrivateAttributes()))
	if err != nil {
		return &p11.GenerateKeyPairResponse{}, err
	}

	return &p11.GenerateKeyPairResponse{
		PublicKeyHandleId:  uint32(handleID),
		PrivateKeyHandleId: uint32(phandleID),
	}, err
}

// WrapKey wraps (i.e., encrypts) a key.
func (m *pkcs11Server) WrapKey(ctx context.Context, in *p11.WrapKeyRequest) (*p11.WrapKeyResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	wrapped, err := c.WrapKey(pkcs11.SessionHandle(in.GetSessionHandle()),
		pkg.ReverseMechanismsToMechanisms(in.GetMechanisms()),
		pkcs11.ObjectHandle(in.GetWrappingHandleId()),
		pkcs11.ObjectHandle(in.GetHandleId()))
	if err != nil {
		return &p11.WrapKeyResponse{}, err
	}

	return &p11.WrapKeyResponse{
		WrappedKey: wrapped,
	}, err
}

// UnwrapKey unwraps (decrypts) a wrapped key, creating a new key object.
func (m *pkcs11Server) UnwrapKey(ctx context.Context, in *p11.UnwrapKeyRequest) (*p11.UnwrapKeyResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	unwrapped, err := c.UnwrapKey(pkcs11.SessionHandle(in.GetSessionHandle()),
		pkg.ReverseMechanismsToMechanisms(in.GetMechanisms()),
		pkcs11.ObjectHandle(in.GetWrappingHandleId()),
		in.GetWrappedKey(),
		pkg.ReverseAttributesToAttributes(in.GetAttributes()))
	if err != nil {
		return &p11.UnwrapKeyResponse{}, err
	}

	return &p11.UnwrapKeyResponse{
		HandleId: uint32(unwrapped),
	}, err
}

// DeriveKey derives a key from a base key, creating a new key object.
func (m *pkcs11Server) DeriveKey(ctx context.Context, in *p11.DeriveKeyRequest) (*p11.DeriveKeyResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	unwrapped, err := c.DeriveKey(pkcs11.SessionHandle(in.GetSessionHandle()),
		pkg.ReverseMechanismsToMechanisms(in.GetMechanisms()),
		pkcs11.ObjectHandle(in.GetHandleId()),
		pkg.ReverseAttributesToAttributes(in.GetAttributes()))
	if err != nil {
		return &p11.DeriveKeyResponse{}, err
	}

	return &p11.DeriveKeyResponse{
		HandleId: uint32(unwrapped),
	}, err
}

// SeedRandom mixes additional seed material into the token's
// random number generator.
func (m *pkcs11Server) SeedRandom(ctx context.Context, in *p11.SeedRandomRequest) (*p11.SeedRandomResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	err := c.SeedRandom(pkcs11.SessionHandle(in.GetSessionHandle()), in.GetSeed())
	return &p11.SeedRandomResponse{}, err
}

// GenerateRandom generates random data.
func (m *pkcs11Server) GenerateRandom(ctx context.Context, in *p11.GenerateRandomRequest) (*p11.GenerateRandomResponse, error) {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return nil, ErrCtxNotFound
	}
	random, err := c.GenerateRandom(pkcs11.SessionHandle(in.GetSessionHandle()), int(in.GetLength()))
	if err != nil {
		return &p11.GenerateRandomResponse{}, err
	}

	return &p11.GenerateRandomResponse{
		Data: random,
	}, err
}

// WaitForSlotEvent returns a channel which returns a slot event
// (token insertion, removal, etc.) when it occurs.
func (m *pkcs11Server) WaitForSlotEvent(in *p11.WaitForSlotEventRequest, event p11.PKCS11_WaitForSlotEventServer) error {
	c, ok := m.ctxs[in.GetCtx()]
	if !ok {
		return ErrCtxNotFound
	}
	stream := c.WaitForSlotEvent(uint(in.GetFlags()))
	for c := range stream {
		event.SendMsg(&p11.SlotEvent{
			SlotID: uint32(c.SlotID),
		})
	}
	return nil
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
		ctxs:           make(map[string]*pkcs11.Ctx, 0),
		allowedModules: allowedModules,
	}
	p11.RegisterPKCS11Server(s, server)
	if err := s.Serve(listener); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
