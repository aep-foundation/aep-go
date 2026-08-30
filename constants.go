package aep

import "time"

const (
	Version                  = "1.0"
	MediaType                = "application/aep+json"
	ProblemMediaType         = "application/problem+json"
	AuthorizationScheme      = "AEP"
	AuthorizationHeader      = "AEP-Authorization"
	WellKnownPath            = "/.well-known/aep"
	DefaultHTTPEndpointBase  = "/aep/"
	MaxAuthenticationMethods = 16
	MaxAssertionLifetime     = 5 * time.Minute
	RecommendedClockSkew     = 30 * time.Second
	DefaultInspectFreshness  = 5 * time.Minute
	MinimumIdempotencyTTL    = time.Hour
)

type Command string

const (
	CommandEnroll  Command = "enroll"
	CommandGrant   Command = "grant"
	CommandInspect Command = "inspect"
	CommandRevoke  Command = "revoke"
	CommandStatus  Command = "status"
)

type AssertionOperation string

const (
	AssertionEnroll       AssertionOperation = "enroll"
	AssertionGrant        AssertionOperation = "grant"
	AssertionRevoke       AssertionOperation = "revoke"
	AssertionStatus       AssertionOperation = "status"
	AssertionAuthenticate AssertionOperation = "authenticate"
)

type SigningAlgorithm string

const (
	SigningAlgorithmEdDSA SigningAlgorithm = "EdDSA"
	SigningAlgorithmES256 SigningAlgorithm = "ES256"
)

type GrantType string

const (
	GrantTypeOAuthBearer GrantType = "oauth-bearer"
	GrantTypeAPIKey      GrantType = "api-key"
	GrantTypeBasic       GrantType = "basic"
)

type ClaimName string

const (
	ClaimContactAddressPrimary ClaimName = "contact.address.primary"
	ClaimContactEmail          ClaimName = "contact.email"
	ClaimContactMobile         ClaimName = "contact.mobile"
	ClaimPersonBirthdate       ClaimName = "person.birthdate"
	ClaimPersonFirstName       ClaimName = "person.first_name"
	ClaimPersonLastName        ClaimName = "person.last_name"
	ClaimPersonUsername        ClaimName = "person.username"
)

var registeredClaimNames = []ClaimName{
	ClaimContactAddressPrimary,
	ClaimContactEmail,
	ClaimContactMobile,
	ClaimPersonBirthdate,
	ClaimPersonFirstName,
	ClaimPersonLastName,
	ClaimPersonUsername,
}

func RegisteredClaims() []ClaimName {
	return append([]ClaimName(nil), registeredClaimNames...)
}
