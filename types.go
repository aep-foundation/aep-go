package aep

import "encoding/json"

type AdditionalMembers map[string]json.RawMessage

type AuthenticationMethod string
type Binding string
type IdentityMethod string

const (
	AuthenticationMethodJWT AuthenticationMethod = "aep-jwt"
	BindingHTTP             Binding              = "http"
	IdentityMethodDIDWeb    IdentityMethod       = "did:web"
)

type Authentication struct {
	Methods    []AuthenticationMethod `json:"methods"`
	Additional AdditionalMembers      `json:"-"`
}

type Bindings struct {
	Supported []Binding `json:"supported"`
}

type InspectClaims struct {
	Required  []ClaimName `json:"required,omitempty"`
	Preferred []ClaimName `json:"preferred,omitempty"`
	Optional  []ClaimName `json:"optional,omitempty"`
}

type Commands struct {
	Supported        []Command                  `json:"supported"`
	GrantTypes       []GrantType                `json:"grant_types,omitempty"`
	GrantTypesConfig map[string]GrantTypeConfig `json:"grant_types_config,omitempty"`
}

type GrantTypeConfig struct {
	SupportsPerCredentialRevoke string            `json:"supports_per_credential_revoke,omitempty"`
	Additional                  AdditionalMembers `json:"-"`
}

type Core struct {
	SigningAlgorithms []SigningAlgorithm `json:"signing_algorithms"`
}

type Extensions struct {
	Supported []string `json:"supported,omitempty"`
}

type OpenAPIPathMatching struct {
	TrailingSlash string            `json:"trailing_slash"`
	Additional    AdditionalMembers `json:"-"`
}

type OpenAPIReference struct {
	URL          string              `json:"url"`
	PathMatching OpenAPIPathMatching `json:"path_matching"`
	Additional   AdditionalMembers   `json:"-"`
}

type HTTPConfiguration struct {
	EndpointBase string            `json:"endpoint_base,omitempty"`
	OpenAPI      *OpenAPIReference `json:"openapi,omitempty"`
}

type Identity struct {
	Methods []IdentityMethod `json:"methods"`
}

type ServiceIdentity struct {
	DID string `json:"did"`
}

type InspectDocument struct {
	AEPVersion     string            `json:"aep_version"`
	Authentication *Authentication   `json:"authentication,omitempty"`
	Bindings       Bindings          `json:"bindings"`
	Claims         *InspectClaims    `json:"claims,omitempty"`
	Commands       Commands          `json:"commands"`
	Core           Core              `json:"core"`
	Extensions     *Extensions       `json:"extensions,omitempty"`
	HTTP           HTTPConfiguration `json:"http"`
	Identity       Identity          `json:"identity"`
	Service        ServiceIdentity   `json:"service"`
	Additional     AdditionalMembers `json:"-"`
}

type ContactAddressPrimary struct {
	City       *string           `json:"city,omitempty"`
	Country    string            `json:"country"`
	FirstName  string            `json:"first_name"`
	LastName   string            `json:"last_name"`
	Line1      string            `json:"line1"`
	Line2      string            `json:"line2,omitempty"`
	Line3      string            `json:"line3,omitempty"`
	Postcode   string            `json:"postcode,omitempty"`
	Region     string            `json:"region,omitempty"`
	Additional AdditionalMembers `json:"-"`
}

type ClaimValues struct {
	ContactAddressPrimary *ContactAddressPrimary `json:"-"`
	ContactEmail          *string                `json:"-"`
	ContactMobile         *string                `json:"-"`
	PersonBirthdate       *string                `json:"-"`
	PersonFirstName       *string                `json:"-"`
	PersonLastName        *string                `json:"-"`
	PersonUsername        *string                `json:"-"`
	Additional            AdditionalMembers      `json:"-"`
}

type EnrollmentStatus string

const (
	EnrollmentActive   EnrollmentStatus = "active"
	EnrollmentPending  EnrollmentStatus = "pending"
	EnrollmentRejected EnrollmentStatus = "rejected"
)

type AgentStatus string

const (
	AgentActive      AgentStatus = "active"
	AgentPending     AgentStatus = "pending"
	AgentRejected    AgentStatus = "rejected"
	AgentSuspended   AgentStatus = "suspended"
	AgentTerminated  AgentStatus = "terminated"
	AgentUnavailable AgentStatus = "unavailable"
)

type EnrollRequest struct {
	AgentDID       string            `json:"agent_did"`
	Claims         *ClaimValues      `json:"claims,omitempty"`
	IdempotencyKey string            `json:"idempotency_key,omitempty"`
	Additional     AdditionalMembers `json:"-"`
}

type EnrollResponse struct {
	Status              EnrollmentStatus  `json:"status"`
	OwnerActionRequired *string           `json:"owner_action_required,omitempty"`
	VerificationPending []string          `json:"verification_pending,omitempty"`
	RequirementsPending []string          `json:"requirements_pending,omitempty"`
	Additional          AdditionalMembers `json:"-"`
}

type StatusResponse struct {
	Status              AgentStatus       `json:"status"`
	OwnerActionRequired *string           `json:"owner_action_required,omitempty"`
	VerificationPending []string          `json:"verification_pending,omitempty"`
	RequirementsPending []string          `json:"requirements_pending,omitempty"`
	Since               string            `json:"since,omitempty"`
	Additional          AdditionalMembers `json:"-"`
}

type GrantRequest struct {
	GrantType       GrantType         `json:"grant_type"`
	RequestedScopes []string          `json:"requested_scopes,omitempty"`
	Additional      AdditionalMembers `json:"-"`
}

type RevokeRequest struct {
	GrantType     GrantType         `json:"grant_type,omitempty"`
	CredentialID  string            `json:"credential_id,omitempty"`
	AllGrantTypes string            `json:"all_grant_types,omitempty"`
	Additional    AdditionalMembers `json:"-"`
}

type RevokeResponse struct{}

type IdempotencyMetadata struct {
	AgentDID       *string           `json:"agent_did,omitempty"`
	IdempotencyKey string            `json:"idempotency_key"`
	FirstBodyHash  *string           `json:"first_body_hash,omitempty"`
	SecondBodyHash *string           `json:"second_body_hash,omitempty"`
	Additional     AdditionalMembers `json:"-"`
}

type OpenAPIAEPSecurityScheme struct {
	AuthenticationMethod AuthenticationMethod `json:"x-aep-authentication-method"`
	Additional           AdditionalMembers    `json:"-"`
}

type ClientAssertionClaims struct {
	Audience   string             `json:"aud"`
	ExpiresAt  int64              `json:"exp"`
	IssuedAt   int64              `json:"iat"`
	Issuer     string             `json:"iss"`
	JWTID      string             `json:"jti"`
	Operation  AssertionOperation `json:"op"`
	Resource   string             `json:"resource,omitempty"`
	Subject    string             `json:"sub"`
	Additional AdditionalMembers  `json:"-"`
}

type ErrorCode string

const (
	ErrorEnrollmentFailed                ErrorCode = "enrollment_failed"
	ErrorInvalidRequest                  ErrorCode = "invalid_request"
	ErrorNotRecognized                   ErrorCode = "not_recognized"
	ErrorIdentitySuspended               ErrorCode = "identity_suspended"
	ErrorIdentityTerminated              ErrorCode = "identity_terminated"
	ErrorIdentityUnavailable             ErrorCode = "identity_unavailable"
	ErrorVerificationPending             ErrorCode = "verification_pending"
	ErrorVerificationTimeout             ErrorCode = "verification_timeout"
	ErrorRequirementsUnmet               ErrorCode = "requirements_unmet"
	ErrorRateLimited                     ErrorCode = "rate_limited"
	ErrorUnsupportedGrantType            ErrorCode = "unsupported_grant_type"
	ErrorIdempotencyConflict             ErrorCode = "idempotency_conflict"
	ErrorAuthenticationRequired          ErrorCode = "authentication_required"
	ErrorUnsupportedAuthenticationMethod ErrorCode = "unsupported_authentication_method"
	ErrorInsufficientScope               ErrorCode = "insufficient_scope"
)

type ProblemDetails struct {
	Type                string            `json:"type"`
	Title               string            `json:"title"`
	Status              int               `json:"status"`
	Detail              string            `json:"detail,omitempty"`
	Instance            string            `json:"instance,omitempty"`
	Code                ErrorCode         `json:"code"`
	OwnerActionRequired *string           `json:"owner_action_required,omitempty"`
	RequirementsPending []string          `json:"requirements_pending,omitempty"`
	VerificationPending []string          `json:"verification_pending,omitempty"`
	Additional          AdditionalMembers `json:"-"`
}

type OAuthBearerGrantResponse struct {
	AccessToken  string   `json:"access_token"`
	CredentialID string   `json:"credential_id"`
	ExpiresAt    string   `json:"expires_at"`
	Scopes       []string `json:"scopes"`
	TokenType    string   `json:"token_type"`
}

type APIKeyGrantResponse struct {
	APIKey       string   `json:"api_key"`
	CredentialID string   `json:"credential_id"`
	ExpiresAt    string   `json:"expires_at"`
	Header       string   `json:"header"`
	Scopes       []string `json:"scopes"`
}

type BasicGrantResponse struct {
	CredentialID string   `json:"credential_id"`
	ExpiresAt    string   `json:"expires_at"`
	Password     string   `json:"password"`
	Realm        *string  `json:"realm,omitempty"`
	Scopes       []string `json:"scopes"`
	Username     string   `json:"username"`
}

type BuiltInGrantResponse interface {
	GrantType() GrantType
}

func (OAuthBearerGrantResponse) GrantType() GrantType { return GrantTypeOAuthBearer }
func (APIKeyGrantResponse) GrantType() GrantType      { return GrantTypeAPIKey }
func (BasicGrantResponse) GrantType() GrantType       { return GrantTypeBasic }

type ProtectedResourceCarrier string

const (
	ProtectedResourceStandard  ProtectedResourceCarrier = "Authorization"
	ProtectedResourceDedicated ProtectedResourceCarrier = "AEP-Authorization"
)

type ProtectedResourceAuthorization struct {
	Carrier     ProtectedResourceCarrier `json:"carrier"`
	Scheme      CredentialScheme         `json:"scheme"`
	Credentials string                   `json:"credentials"`
}

type CredentialScheme string

const (
	CredentialSchemeAEP    CredentialScheme = "AEP"
	CredentialSchemeBearer CredentialScheme = "Bearer"
	CredentialSchemeBasic  CredentialScheme = "Basic"
)
