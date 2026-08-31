package platform

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	aep "github.com/aep-foundation/aep-go"
)

const (
	DIDMediaType        = "application/did+json"
	HostedIdentityDraft = "draft-kavian-aep-platform-hosted-identity-01"
	WellKnownPath       = "/.well-known/aep-platform"
)

type ManagedAgentStatus string

const (
	ManagedAgentActive     ManagedAgentStatus = "active"
	ManagedAgentRevoked    ManagedAgentStatus = "revoked"
	ManagedAgentSuspended  ManagedAgentStatus = "suspended"
	ManagedAgentTerminated ManagedAgentStatus = "terminated"
)

type DiscoveryDocument struct {
	AEPVersion string             `json:"aep_version"`
	Endpoints  DiscoveryEndpoints `json:"endpoints"`
	HTTP       DiscoveryHTTP      `json:"http"`
	Identity   DiscoveryIdentity  `json:"identity"`
	Platform   DiscoveryPlatform  `json:"platform"`
	Signing    DiscoverySigning   `json:"signing"`
}

type DiscoveryEndpoints struct {
	HostedVerification string `json:"hosted_verification,omitempty"`
	Lifecycle          string `json:"lifecycle"`
	List               string `json:"list"`
	Provision          string `json:"provision"`
	Sign               string `json:"sign"`
}

type DiscoveryHTTP struct {
	EndpointBase string `json:"endpoint_base"`
}

type DiscoveryIdentity struct {
	DIDMethods     []string `json:"did_methods"`
	DIDURLTemplate string   `json:"did_url_template"`
}

type DiscoveryPlatform struct {
	DID                string `json:"did,omitempty"`
	HostedVerification bool   `json:"hosted_verification"`
	Name               string `json:"name"`
}

type DiscoverySigning struct {
	Algorithms             []aep.SigningAlgorithm `json:"algorithms"`
	DefaultLifetimeSeconds string                 `json:"default_lifetime_seconds"`
}

type AgentIdentity struct {
	AgentDID          string                 `json:"agent_did"`
	AgentIdentityID   string                 `json:"agent_identity_id"`
	CreatedAt         string                 `json:"created_at"`
	DIDDocumentURL    string                 `json:"did_document_url"`
	KeyID             string                 `json:"key_id"`
	ServiceDID        string                 `json:"service_did"`
	SigningAlgorithms []aep.SigningAlgorithm `json:"signing_algorithms"`
	Status            ManagedAgentStatus     `json:"status"`
	UpdatedAt         string                 `json:"updated_at"`
}

type AgentIdentityListResponse struct {
	Count string          `json:"count"`
	Data  []AgentIdentity `json:"data"`
	Total string          `json:"total"`
}

type ProvisionRequest struct {
	ServiceDID string `json:"service_did"`
}

type LifecycleRequest struct {
	Status ManagedAgentStatus `json:"status"`
}

type SignRequest struct {
	JWTID           string                     `json:"jti"`
	LifetimeSeconds string                     `json:"lifetime_seconds,omitempty"`
	Operation       aep.AssertionOperation     `json:"op"`
	PlatformContext map[string]json.RawMessage `json:"platform_context,omitempty"`
	Resource        string                     `json:"resource,omitempty"`
	ServiceDID      string                     `json:"service_did"`
}

type SignStatus string

const (
	SignCompleted SignStatus = "completed"
	SignPending   SignStatus = "pending"
)

type SignResponse struct {
	AgentDID          string                     `json:"agent_did,omitempty"`
	ClientAssertion   string                     `json:"client_assertion,omitempty"`
	ExpiresAt         string                     `json:"expires_at,omitempty"`
	IssuedAt          string                     `json:"issued_at,omitempty"`
	JWTID             string                     `json:"jti,omitempty"`
	PlatformContext   map[string]json.RawMessage `json:"platform_context,omitempty"`
	RetryAfterSeconds string                     `json:"retry_after_seconds,omitempty"`
	ServiceDID        string                     `json:"service_did,omitempty"`
	Status            SignStatus                 `json:"status"`
}

type VerificationRequest struct {
	ClientAssertion string                 `json:"client_assertion"`
	Operation       aep.AssertionOperation `json:"op"`
	Resource        string                 `json:"resource,omitempty"`
	ServiceDID      string                 `json:"service_did"`
}

type VerificationResponse struct {
	AgentDID        string                 `json:"agent_did,omitempty"`
	AgentIdentityID string                 `json:"agent_identity_id,omitempty"`
	Operation       aep.AssertionOperation `json:"op,omitempty"`
	Reason          string                 `json:"reason"`
	ServiceDID      string                 `json:"service_did"`
	Status          ManagedAgentStatus     `json:"status,omitempty"`
	Verified        bool                   `json:"verified"`
}

type DIDVerificationMethod struct {
	Controller   string          `json:"controller"`
	ID           string          `json:"id"`
	PublicKeyJWK json.RawMessage `json:"publicKeyJwk"`
	Type         string          `json:"type"`
}

type DIDDocument struct {
	Context              []string                `json:"@context"`
	AssertionMethod      []string                `json:"assertionMethod,omitempty"`
	Authentication       []string                `json:"authentication,omitempty"`
	CapabilityInvocation []string                `json:"capabilityInvocation,omitempty"`
	ID                   string                  `json:"id"`
	VerificationMethod   []DIDVerificationMethod `json:"verificationMethod"`
}

type Result[Body any] struct {
	Body        Body
	ContentType string
	Headers     http.Header
	Problem     *aep.ProblemDetails
	Status      int
}

type RequestContext struct {
	Authorization  string
	IdempotencyKey string
	Now            time.Time
	Principal      string
	RequestID      string
}

type IdentityRecord struct {
	AgentDID          string
	AgentDIDID        string
	AgentIdentityID   string
	CreatedAt         time.Time
	DIDDocumentURL    string
	KeyID             string
	Principal         string
	ServiceDID        string
	SigningAlgorithms []aep.SigningAlgorithm
	Status            ManagedAgentStatus
	UpdatedAt         time.Time
}

type IdentityListQuery struct {
	Descending bool
	Limit      int
	Offset     int
	ServiceDID string
	Status     ManagedAgentStatus
}

type IdentityListResult struct {
	Identities []IdentityRecord
	Total      int
}

type IdentityStore interface {
	FindOrCreateIdentity(context.Context, string, string, func() (IdentityRecord, error)) (IdentityRecord, bool, error)
	FindIdentityByAgentDID(context.Context, string) (*IdentityRecord, error)
	FindIdentityByAgentDIDID(context.Context, string) (*IdentityRecord, error)
	GetIdentity(context.Context, string) (*IdentityRecord, error)
	ListIdentities(context.Context, string, IdentityListQuery) (IdentityListResult, error)
	UpdateIdentity(context.Context, string, ManagedAgentStatus, time.Time) (*IdentityRecord, error)
}

type KeyStore interface {
	CreateKey(context.Context, IdentityRecord) error
	DIDVerificationMethod(context.Context, IdentityRecord) (DIDVerificationMethod, error)
	Sign(context.Context, IdentityRecord, aep.ClientAssertionClaims) (string, error)
	VerificationKey(context.Context, IdentityRecord) (any, error)
}

type ServiceDIDResolver interface {
	ResolveServiceDID(context.Context, string) (bool, error)
}

type AuthorizationOperation string

const (
	AuthorizeGetIdentity    AuthorizationOperation = "get-identity"
	AuthorizeListIdentities AuthorizationOperation = "list-identities"
	AuthorizeProvision      AuthorizationOperation = "provision-identity"
	AuthorizeSign           AuthorizationOperation = "sign"
	AuthorizeUpdateIdentity AuthorizationOperation = "update-identity"
	AuthorizeVerify         AuthorizationOperation = "verify"
)

type AuthorizationRequest struct {
	Identity            *IdentityRecord
	LifecycleRequest    *LifecycleRequest
	ListQuery           *IdentityListQuery
	Operation           AuthorizationOperation
	ProvisionRequest    *ProvisionRequest
	SignRequest         *SignRequest
	VerificationRequest *VerificationRequest
}

type Authorizer interface {
	Authorize(context.Context, AuthorizationRequest, RequestContext) (bool, error)
}

type LifecyclePolicy interface {
	CanSign(context.Context, IdentityRecord, RequestContext) (bool, error)
	CanTransition(context.Context, IdentityRecord, ManagedAgentStatus, RequestContext) (bool, error)
	CanVerify(context.Context, IdentityRecord, RequestContext) (bool, error)
}

type ReplayStore interface {
	ConsumeReplay(context.Context, string, time.Time) (bool, error)
}

type IdempotentOperation string

const (
	IdempotentHostedVerification IdempotentOperation = "hosted_verification"
	IdempotentProvision          IdempotentOperation = "provision"
	IdempotentSign               IdempotentOperation = "sign"
)

type StoredResponse struct {
	Body        json.RawMessage
	ContentType string
	CreatedAt   time.Time
	Headers     http.Header
	Status      int
}

type IdempotencyInput struct {
	IdempotencyKey string
	Operation      IdempotentOperation
	Principal      string
	RequestHash    string
}

type IdempotencyState string

const (
	IdempotencyCreated  IdempotencyState = "created"
	IdempotencyReplayed IdempotencyState = "replayed"
	IdempotencyConflict IdempotencyState = "conflict"
)

type IdempotencyResult struct {
	Response StoredResponse
	State    IdempotencyState
}

type IdempotencyStore interface {
	ExecuteIdempotent(context.Context, IdempotencyInput, func() (StoredResponse, error)) (IdempotencyResult, error)
}

type SignHandlerInput struct {
	Identity IdentityRecord
	Request  SignRequest
}

type SignHandler func(context.Context, SignHandlerInput, RequestContext) (*Result[SignResponse], error)

type DiscoveryOptions struct {
	EndpointBase               string
	HostedVerificationEndpoint string
	LifecycleEndpoint          string
	ListEndpoint               string
	PlatformDID                string
	PlatformName               string
	ProvisionEndpoint          string
	SignEndpoint               string
}

type Options struct {
	AgentDIDIDGenerator func() (string, error)
	Authorizer          Authorizer
	Clock               func() time.Time
	DefaultLifetime     time.Duration
	DIDHost             string
	DIDPathPrefix       string
	DIDURLTemplate      string
	Discovery           DiscoveryOptions
	HostedVerification  bool
	Identifier          func() (string, error)
	IdempotencyStore    IdempotencyStore
	IdentityStore       IdentityStore
	KeyStore            KeyStore
	LifecyclePolicy     LifecyclePolicy
	MaximumLifetime     time.Duration
	ReplayStore         ReplayStore
	ServiceDIDResolver  ServiceDIDResolver
	SignHandler         SignHandler
	SigningAlgorithms   []aep.SigningAlgorithm
}

type Platform struct {
	agentDIDIDGenerator func() (string, error)
	authorizer          Authorizer
	clock               func() time.Time
	defaultLifetime     time.Duration
	didHost             string
	didPathPrefix       string
	didURLTemplate      string
	discovery           DiscoveryDocument
	hostedVerification  bool
	identifier          func() (string, error)
	idempotencyStore    IdempotencyStore
	identityStore       IdentityStore
	keyStore            KeyStore
	lifecyclePolicy     LifecyclePolicy
	maximumLifetime     time.Duration
	replayStore         ReplayStore
	serviceDIDResolver  ServiceDIDResolver
	signHandler         SignHandler
	signingAlgorithms   []aep.SigningAlgorithm
}
