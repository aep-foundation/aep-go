package agent

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"sync"
	"time"

	aep "github.com/aep-foundation/aep-go"
)

type AssertionSigner func(context.Context, aep.ClientAssertionClaims, []aep.SigningAlgorithm) (string, error)

type ServiceIdentity struct {
	AgentDID          string
	IdentityMethod    aep.IdentityMethod
	ServiceDID        string
	SigningAlgorithms []aep.SigningAlgorithm
	Metadata          map[string]string
}

type IdentityRequest struct {
	Inspect    aep.InspectDocument
	ServiceDID string
	ServiceURL *url.URL
}

type IdentityProvider interface {
	GetOrCreateIdentity(context.Context, IdentityRequest) (ServiceIdentity, error)
	SignerFor(context.Context, ServiceIdentity) (AssertionSigner, error)
}

type IdentityStore interface {
	FindIdentity(context.Context, string) (*ServiceIdentity, error)
	SaveIdentity(context.Context, ServiceIdentity) error
}

type OperationKey struct {
	Command      aep.Command
	CredentialID string
	GrantType    aep.GrantType
	ServiceDID   string
	ServiceURL   string
}

type IdempotencyKeyProvider interface {
	CreateKey(context.Context, OperationKey) (string, error)
}

type CredentialRecord struct {
	CredentialID string
	ExpiresAt    time.Time
	GrantType    aep.GrantType
	IssuedAt     time.Time
	Payload      json.RawMessage
	ServiceDID   string
	ServiceURL   string
}

type CredentialStore interface {
	DeleteCredential(context.Context, string, string) error
	FindCredential(context.Context, string, string) (*CredentialRecord, error)
	ListCredentials(context.Context, string) ([]CredentialRecord, error)
	SaveCredential(context.Context, CredentialRecord) error
}

type InspectCacheEntry struct {
	CacheControl string
	CachedAt     time.Time
	ETag         string
	FinalURL     string
	LastModified string
	Document     aep.InspectDocument
}

type InspectCache interface {
	DeleteInspect(context.Context, string) error
	FindInspect(context.Context, string) (*InspectCacheEntry, error)
	SaveInspect(context.Context, string, InspectCacheEntry) error
}

type Options struct {
	AllowInsecureLoopback bool
	AssertionLifetime     time.Duration
	Clock                 func() time.Time
	CommandHTTPClient     *http.Client
	CredentialStore       CredentialStore
	HTTPClient            *http.Client
	IdentityProvider      IdentityProvider
	IdentityStore         IdentityStore
	IdempotencyKeys       IdempotencyKeyProvider
	InspectCache          InspectCache
	InspectHTTPClient     *http.Client
	JTI                   func() (string, error)
	MaximumResponseBytes  int64
	RequestTimeout        time.Duration
}

type Client struct {
	allowInsecureLoopback bool
	assertionLifetime     time.Duration
	clock                 func() time.Time
	commandHTTPClient     *http.Client
	credentialStore       CredentialStore
	identityProvider      IdentityProvider
	identityMu            sync.Mutex
	identityStore         IdentityStore
	idempotencyKeys       IdempotencyKeyProvider
	inspectCache          InspectCache
	inspectHTTPClient     *http.Client
	jti                   func() (string, error)
	maximumResponseBytes  int64
	requestTimeout        time.Duration
}

type Inspection struct {
	CacheControl string
	Document     aep.InspectDocument
	ETag         string
	FinalURL     *url.URL
	InspectURL   *url.URL
	LastModified string
	ServiceURL   *url.URL
}

func (inspection Inspection) CommandURL(command aep.Command) (*url.URL, error) {
	path, err := aep.CommandPathFromInspect(inspection.Document, command)
	if err != nil {
		return nil, err
	}
	return inspection.ServiceURL.Parse(path)
}

type CommandResult[T any] struct {
	Body   T
	Status int
	URL    *url.URL
}

type EnrollOptions struct {
	Claims         *aep.ClaimValues
	IdempotencyKey string
}

type GrantOptions struct {
	GrantType           aep.GrantType
	IdempotencyKey      string
	PreferredGrantTypes []aep.GrantType
	RequestedScopes     []string
}

type GrantResult struct {
	Credential aep.BuiltInGrantResponse
	GrantType  aep.GrantType
	Raw        json.RawMessage
}

type RevokeOptions struct {
	AllGrantTypes  bool
	CredentialID   string
	GrantType      aep.GrantType
	IdempotencyKey string
}

type WaitOptions struct {
	Interval time.Duration
	Timeout  time.Duration
}

type AuthenticationOptions struct {
	Carrier             aep.ProtectedResourceCarrier
	ClientAssertionOnly bool
	CredentialID        string
	GrantType           aep.GrantType
	Resource            *url.URL
}

type Session struct {
	client       *Client
	identity     *ServiceIdentity
	identityMu   sync.Mutex
	inspectionMu sync.Mutex
	serviceURL   *url.URL
}

type CommandError struct {
	Problem *aep.ProblemDetails
	Status  int
	Text    string
}

func (err *CommandError) Error() string { return err.Text }

type EnrollmentStateError struct {
	Status aep.AgentStatus
}

func (err *EnrollmentStateError) Error() string {
	return "AEP Agent identity did not become active: " + string(err.Status)
}

type InspectErrorCode string

const (
	InspectAborted                 InspectErrorCode = "aborted"
	InspectHTTPError               InspectErrorCode = "http_error"
	InspectInvalidJSON             InspectErrorCode = "invalid_json"
	InspectInvalidMediaType        InspectErrorCode = "invalid_media_type"
	InspectInvalidRedirect         InspectErrorCode = "invalid_redirect"
	InspectResponseTooLarge        InspectErrorCode = "response_too_large"
	InspectServiceIdentityMismatch InspectErrorCode = "service_identity_mismatch"
	InspectValidationFailed        InspectErrorCode = "validation_failed"
)

type InspectError struct {
	Cause  error
	Code   InspectErrorCode
	Status int
	Text   string
}

func (err *InspectError) Error() string { return err.Text }

func (err *InspectError) Unwrap() error { return err.Cause }

var ErrNoCompatibleGrantType = errors.New("AEP Service does not advertise a compatible grant type")
var ErrNoAuthenticationMethod = errors.New("AEP Service does not advertise a compatible protected-resource authentication method")
