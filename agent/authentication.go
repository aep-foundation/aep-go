package agent

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"time"

	aep "github.com/aep-foundation/aep-go"
)

func (session *Session) AuthenticationHeaders(ctx context.Context, options AuthenticationOptions) (http.Header, error) {
	if options.ClientAssertionOnly && (options.CredentialID != "" || options.GrantType != "") {
		return nil, errors.New("AEP credential selection cannot be combined with client-assertion-only authentication")
	}
	inspection, err := session.Inspect(ctx)
	if err != nil {
		return nil, err
	}
	if options.Resource == nil {
		return nil, errors.New("AEP protected-resource authentication requires a resource URL")
	}
	if err := validateProtectedResource(options.Resource, session.serviceURL, session.client.allowInsecureLoopback); err != nil {
		return nil, err
	}
	if _, err := aep.ProtectedResourceAuthorizationHeader(options.Carrier); err != nil {
		return nil, err
	}
	methods := authenticationMethods(inspection.Document)
	if options.GrantType != "" && !containsAuthenticationMethod(methods, aep.AuthenticationMethod(options.GrantType)) {
		return nil, ErrNoAuthenticationMethod
	}
	if !options.ClientAssertionOnly {
		credentialMethods := methods
		if options.CredentialID == "" && options.GrantType == "" {
			if jwtIndex := authenticationMethodIndex(methods, aep.AuthenticationMethodJWT); jwtIndex >= 0 {
				credentialMethods = methods[:jwtIndex]
			}
		}
		if len(credentialMethods) != 0 || options.CredentialID != "" || options.GrantType != "" {
			record, findErr := session.findCredential(ctx, inspection.Document.Service.DID, credentialMethods, options)
			if findErr != nil {
				return nil, findErr
			}
			if record != nil {
				return credentialHeaders(*record, options.Carrier)
			}
			if options.CredentialID != "" || options.GrantType != "" {
				return nil, errors.New("requested AEP credential was not found")
			}
		}
	}
	if !containsAuthenticationMethod(methods, aep.AuthenticationMethodJWT) {
		return nil, ErrNoAuthenticationMethod
	}
	identity, err := session.resolveIdentity(ctx, inspection)
	if err != nil {
		return nil, err
	}
	signer, err := session.client.signerFor(ctx, identity)
	if err != nil {
		return nil, err
	}
	assertion, err := session.client.signAssertion(ctx, inspection, identity, signer, aep.AssertionAuthenticate, options.Resource)
	if err != nil {
		return nil, err
	}
	headerName, err := aep.ProtectedResourceAuthorizationHeader(options.Carrier)
	if err != nil {
		return nil, err
	}
	headers := make(http.Header)
	headers.Set(headerName, aep.AuthorizationScheme+" "+assertion)
	return headers, nil
}

func validateProtectedResource(resource *url.URL, serviceURL *url.URL, allowInsecureLoopback bool) error {
	if resource.Opaque != "" || resource.Host == "" || resource.User != nil || resource.Fragment != "" {
		return errors.New("AEP protected resource URL is invalid")
	}
	if resource.Scheme != "https" && !(allowInsecureLoopback && resource.Scheme == "http" && isLoopback(resource.Hostname())) {
		return errors.New("AEP protected resource requires HTTPS")
	}
	if !sameOrigin(resource, serviceURL) {
		return errors.New("AEP protected resource must use the Service origin")
	}
	return nil
}

func (session *Session) ForgetCredential(ctx context.Context, credentialID string) error {
	if credentialID == "" {
		return errors.New("AEP credential ID is required")
	}
	inspection, err := session.Inspect(ctx)
	if err != nil {
		return err
	}
	return session.client.credentialStore.DeleteCredential(ctx, inspection.Document.Service.DID, credentialID)
}

func (session *Session) findCredential(ctx context.Context, serviceDID string, methods []aep.AuthenticationMethod, options AuthenticationOptions) (*CredentialRecord, error) {
	if options.CredentialID != "" {
		record, err := session.client.credentialStore.FindCredential(ctx, serviceDID, options.CredentialID)
		if err != nil || record == nil {
			return record, err
		}
		copy := cloneCredential(*record)
		if err := validateStoredCredential(copy, serviceDID, session.client.clock()); err != nil {
			return nil, err
		}
		if options.GrantType != "" && copy.GrantType != options.GrantType {
			return nil, errors.New("stored AEP credential does not match the requested grant type")
		}
		if !containsAuthenticationMethod(methods, aep.AuthenticationMethod(copy.GrantType)) {
			return nil, ErrNoAuthenticationMethod
		}
		return &copy, nil
	}
	records, err := session.client.credentialStore.ListCredentials(ctx, serviceDID)
	if err != nil {
		return nil, err
	}
	for _, method := range methods {
		for index := range records {
			copy := cloneCredential(records[index])
			if aep.AuthenticationMethod(copy.GrantType) == method && (options.GrantType == "" || copy.GrantType == options.GrantType) {
				if err := validateStoredCredential(copy, serviceDID, session.client.clock()); err != nil {
					return nil, err
				}
				return &copy, nil
			}
		}
	}
	return nil, nil
}

func credentialHeaders(record CredentialRecord, carrier aep.ProtectedResourceCarrier) (http.Header, error) {
	credential, err := aep.ParseBuiltInGrantResponse(record.GrantType, record.Payload)
	if err != nil {
		return nil, err
	}
	if credentialID(credential) != record.CredentialID {
		return nil, errors.New("stored AEP credential metadata does not match its payload")
	}
	switch value := credential.(type) {
	case aep.OAuthBearerGrantResponse:
		return authorizationHeaders(aep.CredentialSchemeBearer, value.AccessToken, carrier)
	case aep.APIKeyGrantResponse:
		if !aep.IsHTTPFieldName(value.Header) {
			return nil, errors.New("AEP API-key credential has an invalid header name")
		}
		headers := make(http.Header)
		headers.Set(value.Header, value.APIKey)
		return headers, nil
	case aep.BasicGrantResponse:
		encoded := base64.StdEncoding.EncodeToString([]byte(value.Username + ":" + value.Password))
		return authorizationHeaders(aep.CredentialSchemeBasic, encoded, carrier)
	default:
		return nil, errors.New("unsupported AEP built-in credential")
	}
}

func validateStoredCredential(record CredentialRecord, serviceDID string, now time.Time) error {
	if record.CredentialID == "" || record.ServiceDID != serviceDID || record.GrantType == "" || credentialExpired(record, now) {
		return errors.New("stored AEP credential metadata is invalid")
	}
	credential, err := aep.ParseBuiltInGrantResponse(record.GrantType, record.Payload)
	if err != nil || credentialID(credential) != record.CredentialID {
		return errors.New("stored AEP credential metadata does not match its payload")
	}
	expiresAt, err := time.Parse(time.RFC3339, credentialExpiresAt(credential))
	if err != nil || !expiresAt.Equal(record.ExpiresAt) {
		return errors.New("stored AEP credential expiration does not match its payload")
	}
	return nil
}

func credentialID(credential aep.BuiltInGrantResponse) string {
	switch value := credential.(type) {
	case aep.OAuthBearerGrantResponse:
		return value.CredentialID
	case aep.APIKeyGrantResponse:
		return value.CredentialID
	case aep.BasicGrantResponse:
		return value.CredentialID
	default:
		return ""
	}
}

func credentialExpiresAt(credential aep.BuiltInGrantResponse) string {
	switch value := credential.(type) {
	case aep.OAuthBearerGrantResponse:
		return value.ExpiresAt
	case aep.APIKeyGrantResponse:
		return value.ExpiresAt
	case aep.BasicGrantResponse:
		return value.ExpiresAt
	default:
		return ""
	}
}

func authorizationHeaders(scheme aep.CredentialScheme, credentials string, carrier aep.ProtectedResourceCarrier) (http.Header, error) {
	name, value, err := aep.RenderProtectedResourceAuthorization(aep.ProtectedResourceAuthorization{Carrier: carrier, Scheme: scheme, Credentials: credentials})
	if err != nil {
		return nil, err
	}
	headers := make(http.Header)
	headers.Set(name, value)
	return headers, nil
}

func authenticationMethods(document aep.InspectDocument) []aep.AuthenticationMethod {
	if document.Authentication == nil {
		return nil
	}
	return document.Authentication.Methods
}

func containsAuthenticationMethod(values []aep.AuthenticationMethod, expected aep.AuthenticationMethod) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func authenticationMethodIndex(values []aep.AuthenticationMethod, expected aep.AuthenticationMethod) int {
	for index, value := range values {
		if value == expected {
			return index
		}
	}
	return -1
}
