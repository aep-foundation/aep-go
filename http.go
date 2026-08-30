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
	if err := ValidateProtectedResourceAuthorization(value); err != nil {
		return "", "", err
	}
	header, err := ProtectedResourceAuthorizationHeader(value.Carrier)
	if err != nil {
		return "", "", err
	}
	return header, string(value.Scheme) + " " + value.Credentials, nil
}

func ValidateProtectedResourceAuthorization(value ProtectedResourceAuthorization) error {
	if value.Credentials == "" {
		return &AuthorizationCarrierError{Code: ErrorInvalidRequest, Text: "authorization credentials must not be empty"}
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
	separator := strings.IndexByte(fieldValue, ' ')
	if separator < 1 || separator == len(fieldValue)-1 || fieldValue[separator+1] == ' ' || fieldValue[separator+1] == '\t' {
		return ProtectedResourceAuthorization{}, &AuthorizationCarrierError{Code: ErrorNotRecognized, Text: "the authorization presentation was not recognized"}
	}
	scheme := canonicalCredentialScheme(fieldValue[:separator])
	if scheme == "" {
		return ProtectedResourceAuthorization{}, &AuthorizationCarrierError{Code: ErrorNotRecognized, Text: "the authorization presentation was not recognized"}
	}
	return ProtectedResourceAuthorization{Carrier: carrier, Scheme: scheme, Credentials: fieldValue[separator+1:]}, nil
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
