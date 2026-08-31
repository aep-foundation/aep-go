package service

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"

	aep "github.com/aep-foundation/aep-go"
)

func (service *Service) AuthenticateProtectedResource(ctx context.Context, request ProtectedResourceRequest) (ProtectedResourceResult, error) {
	resource, err := service.protectedResourceURL(request.URL)
	if err != nil {
		return ProtectedResourceResult{}, err
	}
	headers := normalizedHeader(request.Headers)
	presentation, valid := selectAuthorizationPresentation(request.Headers)
	if !valid {
		return service.protectedResourceProblem(aep.ErrorNotRecognized, resource), nil
	}
	if presentation != "" {
		headers.Set("Authorization", presentation)
		headers.Del(aep.AuthorizationHeader)
	}

	authorization := presentation
	if authorization == "" {
		authorization = headers.Get("Authorization")
	}
	if parsed, parseErr := aep.ParseProtectedResourceAuthorization(authorization, aep.ProtectedResourceStandard); parseErr == nil && parsed.Scheme == aep.CredentialSchemeAEP {
		if !slices.Contains(service.authenticationMethods, aep.AuthenticationMethodJWT) {
			return service.protectedResourceProblem(aep.ErrorUnsupportedAuthenticationMethod, resource), nil
		}
		claims, recognized, assertionErr := service.authenticateAssertion(ctx, CommandOptions{ClientAssertion: parsed.Credentials}, aep.AssertionAuthenticate, resource)
		if assertionErr != nil {
			return ProtectedResourceResult{}, assertionErr
		}
		if !recognized {
			return service.protectedResourceProblem(aep.ErrorNotRecognized, resource), nil
		}
		enrollment, findErr := service.enrollmentStore.FindEnrollment(ctx, claims.Subject)
		if findErr != nil {
			return ProtectedResourceResult{}, findErr
		}
		if enrollment == nil || enrollment.Status != aep.AgentActive {
			return service.protectedResourceProblem(aep.ErrorNotRecognized, resource), nil
		}
		principal := AuthenticatedPrincipal{
			AgentDID: claims.Subject, AuthenticationKind: AuthenticationKindJWT, AuthenticationMethod: aep.AuthenticationMethodJWT,
		}
		return ProtectedResourceResult{Authenticated: true, Principal: &principal}, nil
	}

	now := service.clock()
	presented := authorization != ""
	credentialInput := func() CredentialAuthenticationInput {
		resourceURL := *request.URL
		return CredentialAuthenticationInput{Headers: headers.Clone(), Method: request.Method, Now: now, URL: &resourceURL}
	}
	for _, method := range service.authenticationMethods {
		if method == aep.AuthenticationMethodJWT {
			continue
		}
		handler := service.grantHandlers[aep.GrantType(method)]
		if detector, ok := handler.(CredentialPresentationDetector); ok {
			detected, detectErr := detector.HasCredentialPresentation(ctx, credentialInput())
			if detectErr != nil {
				return ProtectedResourceResult{}, detectErr
			}
			presented = presented || detected
		}
		principal, authenticateErr := handler.(CredentialAuthenticator).AuthenticateCredential(ctx, credentialInput())
		if authenticateErr != nil {
			return ProtectedResourceResult{}, authenticateErr
		}
		if principal == nil {
			continue
		}
		if principal.AgentDID == "" || principal.AuthenticationMethod != method || principal.AuthenticationKind != AuthenticationKindSessionCredential || principal.GrantType != aep.GrantType(method) {
			return ProtectedResourceResult{}, errors.New("AEP credential authenticator returned an invalid principal")
		}
		enrollment, findErr := service.enrollmentStore.FindEnrollment(ctx, principal.AgentDID)
		if findErr != nil {
			return ProtectedResourceResult{}, findErr
		}
		if enrollment == nil || enrollment.Status != aep.AgentActive {
			return service.protectedResourceProblem(aep.ErrorNotRecognized, resource), nil
		}
		principal.Scopes = append([]string(nil), principal.Scopes...)
		return ProtectedResourceResult{Authenticated: true, Principal: principal}, nil
	}
	if presented {
		return service.protectedResourceProblem(aep.ErrorNotRecognized, resource), nil
	}
	return service.protectedResourceProblem(aep.ErrorAuthenticationRequired, resource), nil
}

func (service *Service) protectedResourceProblem(code aep.ErrorCode, resource string) ProtectedResourceResult {
	result := problemResult[struct{}](code, strings.ReplaceAll(string(code), "_", " "), http.StatusUnauthorized)
	inspectURL := service.inspectURL
	if inspectURL == nil {
		parsed, _ := url.Parse(resource)
		inspectURL = parsed.ResolveReference(&url.URL{Path: aep.WellKnownPath})
	}
	result.Headers.Set("WWW-Authenticate", fmt.Sprintf(`AEP service_did=%q,inspect=%q,reason=%q`, service.document.Service.DID, inspectURL.String(), code))
	return ProtectedResourceResult{Response: &ProblemResponse{
		Body: *result.Problem, ContentType: result.ContentType, Headers: result.Headers, Status: result.Status,
	}}
}

func (service *Service) protectedResourceURL(value *url.URL) (string, error) {
	if value == nil || value.Host == "" || value.User != nil || value.Opaque != "" || value.Fragment != "" {
		return "", errors.New("AEP protected resource URL must be absolute and must not contain credentials or a fragment")
	}
	if value.Scheme != "https" && !(service.clientAssertion.AllowInsecureLoopback && value.Scheme == "http" && isLoopbackHostname(value.Hostname())) {
		return "", errors.New("AEP protected resource URL must use HTTPS")
	}
	copy := *value
	return copy.String(), nil
}

func selectAuthorizationPresentation(source http.Header) (string, bool) {
	dedicated := headerValues(source, aep.AuthorizationHeader)
	if len(dedicated) == 0 {
		standard := headerValues(source, "Authorization")
		var recognized []string
		for _, value := range standard {
			if _, err := aep.ParseProtectedResourceAuthorization(value, aep.ProtectedResourceStandard); err == nil {
				recognized = append(recognized, value)
			}
		}
		if len(recognized) > 1 || (len(recognized) == 1 && len(standard) > 1) {
			return "", false
		}
		if len(recognized) == 1 {
			return recognized[0], true
		}
		return "", true
	}
	if len(dedicated) != 1 {
		return "", false
	}
	if _, err := aep.ParseProtectedResourceAuthorization(dedicated[0], aep.ProtectedResourceDedicated); err != nil {
		return "", false
	}
	for _, value := range headerValues(source, "Authorization") {
		if _, err := aep.ParseProtectedResourceAuthorization(value, aep.ProtectedResourceStandard); err == nil {
			return "", false
		}
	}
	return dedicated[0], true
}

func normalizedHeader(source http.Header) http.Header {
	result := make(http.Header, len(source))
	for name, values := range source {
		for _, value := range values {
			result.Add(name, value)
		}
	}
	return result
}

func headerValues(header http.Header, name string) []string {
	var values []string
	for candidate, candidateValues := range header {
		if strings.EqualFold(candidate, name) {
			values = append(values, candidateValues...)
		}
	}
	return values
}

func isLoopbackHostname(hostname string) bool {
	return strings.EqualFold(hostname, "localhost") || hostname == "127.0.0.1" || hostname == "::1"
}
