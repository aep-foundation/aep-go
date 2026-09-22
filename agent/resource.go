package agent

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	aep "github.com/aep-foundation/aep-go"
)

type ProtectedResourceOptions struct {
	Authentication                  AuthenticationOptions
	AdditionalAuthenticationHeaders http.Header
	MaximumRedirects                int
}

// FetchProtectedResource requires GetBody for a body and rejects request trailers.
// It leaves request untouched. Close the response body to release the operation's timeout.
func (client *Client) FetchProtectedResource(ctx context.Context, request *http.Request, options ProtectedResourceOptions) (*http.Response, error) {
	if request == nil || request.URL == nil {
		return nil, errors.New("AEP protected-resource request is required")
	}
	if len(request.Trailer) != 0 {
		return nil, errors.New("AEP request trailers cannot be replayed")
	}
	if request.Body != nil && request.Body != http.NoBody {
		if request.GetBody == nil {
			return nil, errors.New("AEP authentication requires a replayable request body")
		}
		body, err := request.GetBody()
		if err != nil {
			return nil, err
		}
		if body == nil {
			return nil, errors.New("AEP request GetBody returned no body")
		}
		if err := body.Close(); err != nil {
			return nil, err
		}
	}
	if _, err := aep.ProtectedResourceAuthorizationHeader(options.Authentication.Carrier); err != nil {
		return nil, err
	}
	if options.Authentication.ClientAssertionOnly && (options.Authentication.CredentialID != "" || options.Authentication.GrantType != "") {
		return nil, errors.New("AEP credential selection cannot be combined with client-assertion-only authentication")
	}
	maximum := options.MaximumRedirects
	if maximum == 0 {
		maximum = 5
	}
	if maximum < 0 {
		return nil, errors.New("AEP redirect limit must be nonnegative")
	}
	target := cloneURL(request.URL)
	if err := validateProtectedResource(target, target, client.allowInsecureLoopback); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, client.requestTimeout)
	response, err := client.fetchResource(ctx, request, target, options, maximum)
	if err != nil {
		cancel()
		return nil, err
	}
	response.Body = &resourceResponseBody{ReadCloser: response.Body, cancel: cancel}
	return response, nil
}

type resourceResponseBody struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (body *resourceResponseBody) Close() error { defer body.cancel(); return body.ReadCloser.Close() }

func (client *Client) fetchResource(ctx context.Context, original *http.Request, target *url.URL, options ProtectedResourceOptions, maximum int) (*http.Response, error) {
	requireChallenge := false
	for redirects := 0; ; {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		session, err := client.Service(target.String())
		if err != nil {
			return nil, err
		}
		policy, policyErr := session.OpenAPIPolicy(ctx, original.Method, target)
		if policyErr != nil {
			policy = OpenAPIOperationPolicy{State: "fallback"}
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		var anonymous *http.Response
		var challenge *resourceChallenge
		if policy.State != "required" || requireChallenge {
			headers := make(http.Header)
			if !requireChallenge {
				headers = original.Header.Clone()
				removeResourceHeaders(headers, "Authorization", aep.AuthorizationHeader, "PAYMENT-SIGNATURE", "Cookie", "Proxy-Authorization")
			}
			anonymous, err = client.sendResource(ctx, original, target, headers)
			if err != nil {
				return nil, err
			}
			if isRedirect(anonymous.StatusCode) {
				anonymous.Body.Close()
				next, err := client.resourceRedirect(anonymous, target, redirects, maximum)
				if err != nil {
					return nil, err
				}
				requireChallenge = requireChallenge || !sameOrigin(target, next)
				target = next
				redirects++
				continue
			}
			challenge = parseResourceChallenge(anonymous.Header.Get("WWW-Authenticate"))
			if anonymous.StatusCode != http.StatusUnauthorized || challenge == nil {
				return anonymous, nil
			}
			if !sameOrigin(challenge.inspect, target) {
				anonymous.Body.Close()
				return nil, errors.New("AEP challenge Inspect URI changed origin")
			}
		}
		inspection, err := session.Inspect(ctx)
		if err != nil {
			if anonymous != nil {
				anonymous.Body.Close()
			}
			return nil, err
		}
		if challenge != nil && challenge.serviceDID != inspection.Document.Service.DID {
			anonymous.Body.Close()
			return nil, errors.New("AEP challenge Service DID does not match Inspect")
		}
		if policy.State == "public" && challenge != nil {
			// Document refresh failure does not override the validated live challenge.
			_, _ = session.openAPIPolicy(ctx, original.Method, target, true)
			if err := ctx.Err(); err != nil {
				anonymous.Body.Close()
				return nil, err
			}
		}
		methods := authenticationMethods(inspection.Document)
		if policy.State == "required" {
			methods = policy.Methods
		}
		if len(methods) == 0 && anonymous != nil {
			return anonymous, nil
		}
		if anonymous != nil {
			anonymous.Body.Close()
		}
		authentication := options.Authentication
		authentication.Resource = target
		authentication.AllowedMethods = []aep.AuthenticationMethod{}
		for _, method := range methods {
			if containsAuthenticationMethod(authenticationMethods(inspection.Document), method) && (options.Authentication.AllowedMethods == nil || containsAuthenticationMethod(options.Authentication.AllowedMethods, method)) {
				authentication.AllowedMethods = append(authentication.AllowedMethods, method)
			}
		}
		headers, err := session.resourceAuthenticationHeaders(ctx, authentication)
		if err != nil {
			return nil, err
		}
		merged, err := mergeResourceHeaders(original, target, options.AdditionalAuthenticationHeaders, headers)
		if err != nil {
			return nil, err
		}
		response, err := client.sendResource(ctx, original, target, merged)
		if err != nil {
			return nil, err
		}
		if !isRedirect(response.StatusCode) {
			return response, nil
		}
		response.Body.Close()
		next, err := client.resourceRedirect(response, target, redirects, maximum)
		if err != nil {
			return nil, err
		}
		requireChallenge = requireChallenge || !sameOrigin(target, next)
		target = next
		redirects++
	}
}

func (session *Session) resourceAuthenticationHeaders(ctx context.Context, options AuthenticationOptions) (http.Header, error) {
	headers, err := session.AuthenticationHeaders(ctx, options)
	// Only a missing compatible credential permits Grant. Store and signing failures must surface.
	if err == nil || options.CredentialID != "" || options.ClientAssertionOnly || (!errors.Is(err, errCredentialNotFound) && !errors.Is(err, ErrNoAuthenticationMethod)) {
		return headers, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	grantType := options.GrantType
	if grantType == "" {
		for _, method := range options.AllowedMethods {
			if method != aep.AuthenticationMethodJWT {
				grantType = aep.GrantType(method)
				break
			}
		}
	}
	if grantType == "" || !containsAuthenticationMethod(options.AllowedMethods, aep.AuthenticationMethod(grantType)) {
		return nil, err
	}
	if _, err := session.Grant(ctx, GrantOptions{GrantType: grantType}); err != nil {
		return nil, err
	}
	options.GrantType = grantType
	return session.AuthenticationHeaders(ctx, options)
}

func mergeResourceHeaders(original *http.Request, target *url.URL, additional, controlled http.Header) (http.Header, error) {
	merged := make(http.Header)
	if sameOrigin(target, original.URL) {
		for name, values := range original.Header {
			for _, value := range values {
				merged.Add(name, value)
			}
		}
		for name, values := range additional {
			if strings.EqualFold(name, aep.AuthorizationHeader) || resourceHasHeader(controlled, name) {
				return nil, errors.New("additional authentication conflicts with selected AEP headers")
			}
			merged.Del(name)
			for _, value := range values {
				merged.Add(name, value)
			}
		}
	}
	removeResourceHeaders(merged, aep.AuthorizationHeader)
	if !resourceHasHeader(controlled, "Authorization") {
		if _, err := aep.ParseProtectedResourceAuthorization(merged.Get("Authorization"), aep.ProtectedResourceStandard); err == nil {
			if sameOrigin(target, original.URL) && resourceHasHeader(additional, "Authorization") {
				return nil, errors.New("additional Authorization conflicts with selected AEP authentication")
			}
			removeResourceHeaders(merged, "Authorization")
		}
	}
	for name, values := range controlled {
		removeResourceHeaders(merged, name)
		merged[name] = append([]string(nil), values...)
	}
	return merged, nil
}

func (client *Client) sendResource(ctx context.Context, original *http.Request, target *url.URL, headers http.Header) (*http.Response, error) {
	request := original.Clone(ctx)
	request.URL = cloneURL(target)
	request.Host = ""
	request.RequestURI = ""
	request.Header = headers
	request.Body = nil
	if original.Body != nil && original.Body != http.NoBody {
		var err error
		request.Body, err = original.GetBody()
		if err != nil {
			return nil, err
		}
		if request.Body == nil {
			return nil, errors.New("AEP request GetBody returned no body")
		}
	}
	return doWithoutRedirects(client.commandHTTPClient, request)
}

func (client *Client) resourceRedirect(response *http.Response, current *url.URL, count, maximum int) (*url.URL, error) {
	if count >= maximum {
		return nil, errors.New("AEP resource redirect limit exceeded")
	}
	location := response.Header.Get("Location")
	if location == "" {
		return nil, errors.New("AEP redirect omitted Location")
	}
	next, err := current.Parse(location)
	if err != nil {
		return nil, err
	}
	if err := validateProtectedResource(next, next, client.allowInsecureLoopback); err != nil {
		return nil, err
	}
	if current.Scheme == "https" && next.Scheme != "https" {
		return nil, errors.New("AEP redirect downgraded transport")
	}
	return next, nil
}

func removeResourceHeaders(header http.Header, names ...string) {
	for candidate := range header {
		for _, name := range names {
			if strings.EqualFold(candidate, name) {
				delete(header, candidate)
			}
		}
	}
}

func resourceHasHeader(header http.Header, name string) bool {
	for candidate := range header {
		if strings.EqualFold(candidate, name) {
			return true
		}
	}
	return false
}

type resourceChallenge struct {
	serviceDID string
	inspect    *url.URL
}

var challengeParameter = regexp.MustCompile(`(?i)([a-z_]+)[\t ]*=[\t ]*"([^"]*)"`)

func parseResourceChallenge(value string) *resourceChallenge {
	parts := strings.SplitN(strings.ReplaceAll(value, "\t", " "), " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "AEP") {
		return nil
	}
	parameters := make(map[string]string)
	for _, match := range challengeParameter.FindAllStringSubmatch(value, -1) {
		name := strings.ToLower(match[1])
		if _, exists := parameters[name]; exists {
			return nil
		}
		parameters[name] = match[2]
	}
	inspect, err := url.Parse(parameters["inspect"])
	if err != nil || parameters["service_did"] == "" || inspect.Host == "" || inspect.User != nil || inspect.Fragment != "" || (inspect.Scheme != "https" && !(inspect.Scheme == "http" && isLoopback(inspect.Hostname()))) {
		return nil
	}
	return &resourceChallenge{serviceDID: parameters["service_did"], inspect: inspect}
}
