package aep

import (
	"errors"
	"strings"
)

var commandPaths = map[Command]string{
	CommandEnroll: "enroll",
	CommandGrant:  "grant",
	CommandRevoke: "revoke",
	CommandStatus: "status",
}

func NormalizeEndpointBase(endpointBase string) (string, error) {
	if endpointBase == "" {
		endpointBase = DefaultHTTPEndpointBase
	}
	if !strings.HasPrefix(endpointBase, "/") || strings.HasPrefix(endpointBase, "//") {
		return "", errors.New("AEP endpoint_base must be an origin-relative absolute path")
	}
	if !strings.HasSuffix(endpointBase, "/") {
		endpointBase += "/"
	}
	return endpointBase, nil
}

func CommandPath(command Command, endpointBase string) (string, error) {
	path, ok := commandPaths[command]
	if !ok {
		return "", errors.New("AEP command has no HTTP endpoint path")
	}
	base, err := NormalizeEndpointBase(endpointBase)
	if err != nil {
		return "", err
	}
	return base + path, nil
}

func CommandPathFromInspect(document InspectDocument, command Command) (string, error) {
	return CommandPath(command, document.HTTP.EndpointBase)
}

func ProtectedResourceAuthorizationHeader(carrier ProtectedResourceCarrier) (string, error) {
	switch carrier {
	case "", ProtectedResourceStandard:
		return "Authorization", nil
	case ProtectedResourceDedicated:
		return AuthorizationHeader, nil
	default:
		return "", errors.New("unsupported AEP authorization carrier")
	}
}

func RenderProtectedResourceAuthorization(value ProtectedResourceAuthorization) (string, string, error) {
	// Validation already resolves the carrier, so a header name is available once it returns.
	if err := ValidateProtectedResourceAuthorization(value); err != nil {
		return "", "", err
	}
	header, _ := ProtectedResourceAuthorizationHeader(value.Carrier)
	return header, string(value.Scheme) + " " + value.Credentials, nil
}

func ValidateProtectedResourceAuthorization(value ProtectedResourceAuthorization) error {
	if value.Credentials == "" {
		return &AuthorizationCarrierError{Code: ErrorInvalidRequest, Text: "authorization credentials must not be empty"}
	}
	if !isCredentialToken(value.Credentials) {
		return &AuthorizationCarrierError{Code: ErrorInvalidRequest, Text: "authorization credentials must be visible US-ASCII"}
	}
	if !isCredentialScheme(value.Scheme) {
		return &AuthorizationCarrierError{Code: ErrorInvalidRequest, Text: "unsupported authorization scheme"}
	}
	_, err := ProtectedResourceAuthorizationHeader(value.Carrier)
	return err
}

func ParseProtectedResourceAuthorization(fieldValue string, carrier ProtectedResourceCarrier) (ProtectedResourceAuthorization, error) {
	if carrier == "" {
		carrier = ProtectedResourceStandard
	}
	if _, err := ProtectedResourceAuthorizationHeader(carrier); err != nil {
		return ProtectedResourceAuthorization{}, err
	}
	if carrier == ProtectedResourceDedicated && strings.Contains(fieldValue, ",") {
		return ProtectedResourceAuthorization{}, &AuthorizationCarrierError{Code: ErrorNotRecognized, Text: "the dedicated authorization field is ambiguous"}
	}
	unrecognized := &AuthorizationCarrierError{Code: ErrorNotRecognized, Text: "the authorization presentation was not recognized"}
	separator := strings.IndexAny(fieldValue, " \t")
	if separator < 1 {
		return ProtectedResourceAuthorization{}, unrecognized
	}
	scheme := canonicalCredentialScheme(fieldValue[:separator])
	if scheme == "" {
		return ProtectedResourceAuthorization{}, unrecognized
	}
	// CORE-AUTH-001 spells the separator 1*SP, so repeated spaces are part of the grammar rather
	// than a malformed presentation, and a field value may carry trailing optional whitespace.
	credentials := strings.TrimRight(strings.TrimLeft(fieldValue[separator:], " \t"), " \t")
	if !isCredentialToken(credentials) {
		return ProtectedResourceAuthorization{}, unrecognized
	}
	return ProtectedResourceAuthorization{Carrier: carrier, Scheme: scheme, Credentials: credentials}, nil
}

// isCredentialToken reports whether every byte is visible US-ASCII, the character set the AEP,
// Bearer, and Basic credential grammars share. Rejecting anything else keeps a control character
// or an embedded CRLF out of a value a caller may render back into a request header.
func isCredentialToken(value string) bool {
	if value == "" {
		return false
	}
	for index := 0; index < len(value); index++ {
		if value[index] < 0x21 || value[index] > 0x7e {
			return false
		}
	}
	return true
}

func canonicalCredentialScheme(value string) CredentialScheme {
	switch strings.ToLower(value) {
	case "aep":
		return CredentialSchemeAEP
	case "bearer":
		return CredentialSchemeBearer
	case "basic":
		return CredentialSchemeBasic
	default:
		return ""
	}
}

func isCredentialScheme(value CredentialScheme) bool {
	return value == CredentialSchemeAEP || value == CredentialSchemeBearer || value == CredentialSchemeBasic
}
