package service

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"time"

	aep "github.com/aep-foundation/aep-go"
)

type Result[Body any] struct {
	Body        Body
	ContentType string
	Headers     http.Header
	Problem     *aep.ProblemDetails
	Status      int
}

type CommandOptions struct {
	ClientAssertion string
	IdempotencyKey  string
}

type AssertionVerificationContext struct {
	AllowInsecureLoopback bool
	ClockTolerance        time.Duration
	CurrentTime           time.Time
	IdempotencyKey        string
	Operation             aep.AssertionOperation
	Resource              string
	ServiceDID            string
	SigningAlgorithms     []aep.SigningAlgorithm
}

type AssertionVerifier func(context.Context, string, AssertionVerificationContext) (aep.ClientAssertionClaims, error)

type ReplayRecord struct {
	ExpiresAt int64
	JWTID     string
	Subject   string
}

type ReplayStore interface {
	ConsumeReplay(context.Context, ReplayRecord, int64) (bool, error)
}

type EnrollmentRecord struct {
	AgentDID            string
	Claims              *aep.ClaimValues
	CreatedAt           time.Time
	EnrollmentID        string
	OwnerActionRequired bool
	RequirementsPending []string
	Since               time.Time
	Status              aep.AgentStatus
	UpdatedAt           time.Time
	VerificationPending []string
}

type EnrollmentStore interface {
	FindEnrollment(context.Context, string) (*EnrollmentRecord, error)
	FindOrCreateEnrollment(context.Context, string, func() (EnrollmentRecord, error)) (EnrollmentRecord, bool, error)
	SaveEnrollment(context.Context, EnrollmentRecord) (EnrollmentRecord, error)
}

type EnrollmentDecision struct {
	OwnerActionRequired bool
	RequirementsPending []string
	Status              aep.EnrollmentStatus
	VerificationPending []string
}

type EnrollmentPolicyContext struct {
	Now time.Time
}

type EnrollmentPolicy interface {
	DecideEnrollment(context.Context, aep.EnrollRequest, EnrollmentPolicyContext) (EnrollmentDecision, error)
}

type IdempotentCommand string

const (
	IdempotentEnroll IdempotentCommand = "enroll"
	IdempotentGrant  IdempotentCommand = "grant"
	IdempotentRevoke IdempotentCommand = "revoke"
)

type StoredResponse struct {
	Body        json.RawMessage
	ContentType string
	CreatedAt   time.Time
	Headers     http.Header
	Status      int
}

type IdempotencyInput struct {
	AgentDID       string
	Command        IdempotentCommand
	IdempotencyKey string
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

type GrantContext struct {
	AgentDID   string
	Enrollment EnrollmentRecord
	GrantType  aep.GrantType
}

type RevokeContext struct {
	AgentDID   string
	Enrollment EnrollmentRecord
	GrantType  aep.GrantType
}

type CredentialAuthenticationInput struct {
	Headers http.Header
	Method  string
	Now     time.Time
	URL     *url.URL
}

type AuthenticatedPrincipal struct {
	AgentDID             string
	AuthenticationKind   AuthenticationKind
	AuthenticationMethod aep.AuthenticationMethod
	CredentialID         string
	GrantType            aep.GrantType
	Scopes               []string
}

type AuthenticationKind string

const (
	AuthenticationKindJWT               AuthenticationKind = "aep-jwt"
	AuthenticationKindSessionCredential AuthenticationKind = "session-credential"
)

type GrantTypeHandler interface {
	Grant(context.Context, aep.GrantRequest, GrantContext) (json.RawMessage, error)
	Revoke(context.Context, aep.RevokeRequest, RevokeContext) error
}

type CredentialAuthenticator interface {
	AuthenticateCredential(context.Context, CredentialAuthenticationInput) (*AuthenticatedPrincipal, error)
}

type CredentialPresentationDetector interface {
	HasCredentialPresentation(context.Context, CredentialAuthenticationInput) (bool, error)
}

type GrantTypeDefinition struct {
	Config    aep.GrantTypeConfig
	GrantType aep.GrantType
	Handler   GrantTypeHandler
}

type ProtectedResourceRequest struct {
	Headers http.Header
	Method  string
	URL     *url.URL
}

type ProblemResponse struct {
	Body        aep.ProblemDetails
	ContentType string
	Headers     http.Header
	Status      int
}

type ProtectedResourceResult struct {
	Authenticated bool
	Principal     *AuthenticatedPrincipal
	Response      *ProblemResponse
}

type ClientAssertionOptions struct {
	AllowInsecureLoopback bool
	ClockSkew             *time.Duration
	MaximumLifetime       time.Duration
}

type clientAssertionOptions struct {
	AllowInsecureLoopback bool
	ClockSkew             time.Duration
	MaximumLifetime       time.Duration
}

type Options struct {
	AuthenticationMethods []aep.AuthenticationMethod
	ClientAssertion       ClientAssertionOptions
	Clock                 func() time.Time
	Claims                *aep.InspectClaims
	EndpointBase          string
	EnrollmentPolicy      EnrollmentPolicy
	EnrollmentStore       EnrollmentStore
	Extensions            []string
	GrantTypes            []GrantTypeDefinition
	Identifier            func() (string, error)
	IdempotencyStore      IdempotencyStore
	IdentityMethods       []aep.IdentityMethod
	InspectURL            *url.URL
	OpenAPI               *aep.OpenAPIReference
	ReplayStore           ReplayStore
	ServiceDID            string
	SigningAlgorithms     []aep.SigningAlgorithm
	Verifier              AssertionVerifier
}

type Service struct {
	authenticationMethods []aep.AuthenticationMethod
	clientAssertion       clientAssertionOptions
	clock                 func() time.Time
	document              aep.InspectDocument
	enrollmentPolicy      EnrollmentPolicy
	enrollmentStore       EnrollmentStore
	grantHandlers         map[aep.GrantType]GrantTypeHandler
	identifier            func() (string, error)
	idempotencyStore      IdempotencyStore
	inspectURL            *url.URL
	replayStore           ReplayStore
	verifier              AssertionVerifier
}
