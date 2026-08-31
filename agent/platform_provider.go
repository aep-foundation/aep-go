package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	aep "github.com/aep-foundation/aep-go"
	"github.com/aep-foundation/aep-go/platform"
)

type PlatformAuthenticationHeaders func(context.Context) (http.Header, error)

type PlatformContextProvider func(context.Context, ServiceIdentity, aep.ClientAssertionClaims) (map[string]json.RawMessage, error)

type PlatformPendingSign struct {
	Identity          ServiceIdentity
	PlatformContext   map[string]json.RawMessage
	RetryAfterSeconds int
}

type PlatformPendingSignResolver func(context.Context, PlatformPendingSign) (map[string]json.RawMessage, error)

type PlatformIdentityProviderOptions struct {
	AllowInsecureLoopback bool
	AuthenticationHeaders PlatformAuthenticationHeaders
	Authorization         string
	Clock                 func() time.Time
	HTTPClient            *http.Client
	IdempotencyKey        func() (string, error)
	MaximumResponseBytes  int64
	PendingSignResolver   PlatformPendingSignResolver
	PlatformContext       PlatformContextProvider
	PlatformURL           string
	RequestTimeout        time.Duration
}

type PlatformIdentityProvider struct {
	allowInsecureLoopback bool
	authenticationHeaders PlatformAuthenticationHeaders
	authorization         string
	clock                 func() time.Time
	discovery             *platformDiscoveryEntry
	discoveryMu           sync.Mutex
	httpClient            *http.Client
	idempotencyKey        func() (string, error)
	maximumResponseBytes  int64
	pendingSignResolver   PlatformPendingSignResolver
	platformContext       PlatformContextProvider
	platformURL           *url.URL
	requestTimeout        time.Duration
}

type PlatformSignPendingError struct {
	Pending PlatformPendingSign
}

func (err *PlatformSignPendingError) Error() string {
	return "AEP Platform signing is pending"
}

type PlatformCommandError struct {
	Problem *aep.ProblemDetails
	Status  int
}

func (err *PlatformCommandError) Error() string {
	if err.Problem != nil && err.Problem.Title != "" {
		return "AEP Platform command failed: " + err.Problem.Title
	}
	return fmt.Sprintf("AEP Platform command failed with HTTP %d", err.Status)
}

type platformDiscoveryEntry struct {
	cacheControl string
	cachedAt     time.Time
	document     platform.DiscoveryDocument
	etag         string
	finalURL     *url.URL
	lastModified string
}

func NewPlatformIdentityProvider(options PlatformIdentityProviderOptions) (*PlatformIdentityProvider, error) {
	platformURL, err := resolveServiceReference(options.PlatformURL, options.AllowInsecureLoopback)
	if err != nil {
		return nil, errors.New("invalid AEP Platform URL")
	}
	maximumResponseBytes := options.MaximumResponseBytes
	if maximumResponseBytes == 0 {
		maximumResponseBytes = defaultMaximumResponseBytes
	}
	if maximumResponseBytes < 1 || maximumResponseBytes == math.MaxInt64 {
		return nil, errors.New("AEP Platform maximum response bytes are outside the supported range")
	}
	requestTimeout := options.RequestTimeout
	if requestTimeout == 0 {
		requestTimeout = defaultRequestTimeout
	}
	if requestTimeout <= 0 {
		return nil, errors.New("AEP Platform request timeout must be positive")
	}
	clock := options.Clock
	if clock == nil {
		clock = time.Now
	}
	httpClient := options.HTTPClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	idempotencyKey := options.IdempotencyKey
	if idempotencyKey == nil {
		idempotencyKey = randomIdentifier
	}
	return &PlatformIdentityProvider{
		allowInsecureLoopback: options.AllowInsecureLoopback,
		authenticationHeaders: options.AuthenticationHeaders,
		authorization:         options.Authorization,
		clock:                 clock,
		httpClient:            httpClient,
		idempotencyKey:        idempotencyKey,
		maximumResponseBytes:  maximumResponseBytes,
		pendingSignResolver:   options.PendingSignResolver,
		platformContext:       options.PlatformContext,
		platformURL:           platformURL,
		requestTimeout:        requestTimeout,
	}, nil
}

func (provider *PlatformIdentityProvider) FindIdentityByServiceDID(ctx context.Context, serviceDID string) (*ServiceIdentity, error) {
	if !strings.HasPrefix(serviceDID, "did:") {
		return nil, errors.New("invalid AEP Service DID")
	}
	discovery, err := provider.discover(ctx)
	if err != nil {
		return nil, err
	}
	endpoint, err := provider.endpoint(discovery.document.Endpoints.List, "")
	if err != nil {
		return nil, err
	}
	query := endpoint.Query()
	query.Set("descending", "true")
	query.Set("limit", "100")
	query.Set("service_did", serviceDID)
	endpoint.RawQuery = query.Encode()
	var listed platform.AgentIdentityListResponse
	if _, _, err := provider.command(ctx, http.MethodGet, endpoint, "", nil, &listed); err != nil {
		return nil, err
	}
	if err := validatePlatformIdentityList(listed, provider.allowInsecureLoopback); err != nil {
		return nil, err
	}
	for _, candidate := range listed.Data {
		if candidate.ServiceDID == serviceDID && candidate.Status == platform.ManagedAgentActive {
			identity, identityErr := provider.serviceIdentity(candidate)
			if identityErr != nil {
				return nil, identityErr
			}
			return &identity, nil
		}
	}
	return nil, nil
}

func (provider *PlatformIdentityProvider) GetOrCreateIdentity(ctx context.Context, request IdentityRequest) (ServiceIdentity, error) {
	existing, err := provider.FindIdentityByServiceDID(ctx, request.ServiceDID)
	if err != nil {
		return ServiceIdentity{}, err
	}
	if existing != nil {
		return *existing, nil
	}
	discovery, err := provider.discover(ctx)
	if err != nil {
		return ServiceIdentity{}, err
	}
	endpoint, err := provider.endpoint(discovery.document.Endpoints.Provision, "")
	if err != nil {
		return ServiceIdentity{}, err
	}
	key, err := provider.newIdempotencyKey()
	if err != nil {
		return ServiceIdentity{}, err
	}
	var provisioned platform.AgentIdentity
	if _, _, err := provider.command(ctx, http.MethodPost, endpoint, key, platform.ProvisionRequest{ServiceDID: request.ServiceDID}, &provisioned); err != nil {
		return ServiceIdentity{}, err
	}
	if provisioned.ServiceDID != request.ServiceDID || provisioned.Status != platform.ManagedAgentActive {
		return ServiceIdentity{}, errors.New("AEP Platform provisioned an identity outside the requested Service scope")
	}
	return provider.serviceIdentity(provisioned)
}

func (provider *PlatformIdentityProvider) SignerFor(_ context.Context, identity ServiceIdentity) (AssertionSigner, error) {
	identity = cloneIdentity(identity)
	if err := provider.validatePlatformIdentity(identity); err != nil {
		return nil, err
	}
	return func(ctx context.Context, claims aep.ClientAssertionClaims, algorithms []aep.SigningAlgorithm) (string, error) {
		if claims.Issuer != identity.AgentDID || claims.Subject != identity.AgentDID || claims.Audience != identity.ServiceDID {
			return "", errors.New("AEP Platform signer received claims for another identity")
		}
		if len(intersectAlgorithms(identity.SigningAlgorithms, algorithms)) == 0 {
			return "", errors.New("AEP Platform and Service have no compatible signing algorithm")
		}
		var platformContext map[string]json.RawMessage
		var err error
		if provider.platformContext != nil {
			platformContext, err = provider.platformContext(ctx, cloneIdentity(identity), claims)
			if err != nil {
				return "", err
			}
		}
		previousIdempotencyKey := ""
		for {
			idempotencyKey, keyErr := provider.newIdempotencyKey()
			if keyErr != nil {
				return "", keyErr
			}
			if idempotencyKey == previousIdempotencyKey {
				return "", errors.New("AEP Platform pending Sign stages require distinct idempotency keys")
			}
			result, signErr := provider.sign(ctx, identity, claims, platformContext, idempotencyKey)
			if signErr != nil {
				return "", signErr
			}
			if result.Status == platform.SignCompleted {
				return result.ClientAssertion, nil
			}
			seconds, parseErr := strconv.Atoi(result.RetryAfterSeconds)
			if parseErr != nil || seconds < 1 || seconds > 300 {
				return "", errors.New("AEP Platform returned an invalid pending Sign response")
			}
			pending := PlatformPendingSign{Identity: cloneIdentity(identity), PlatformContext: cloneRawMessages(result.PlatformContext), RetryAfterSeconds: seconds}
			if provider.pendingSignResolver == nil {
				return "", &PlatformSignPendingError{Pending: pending}
			}
			previousIdempotencyKey = idempotencyKey
			platformContext, err = provider.pendingSignResolver(ctx, pending)
			if err != nil {
				return "", err
			}
		}
	}, nil
}

func (provider *PlatformIdentityProvider) sign(ctx context.Context, identity ServiceIdentity, claims aep.ClientAssertionClaims, platformContext map[string]json.RawMessage, idempotencyKey string) (platform.SignResponse, error) {
	discovery, err := provider.discover(ctx)
	if err != nil {
		return platform.SignResponse{}, err
	}
	endpoint, err := provider.endpoint(discovery.document.Endpoints.Sign, identity.Metadata["agent_identity_id"])
	if err != nil {
		return platform.SignResponse{}, err
	}
	request := platform.SignRequest{
		JWTID:           claims.JWTID,
		LifetimeSeconds: strconv.FormatInt(claims.ExpiresAt-claims.IssuedAt, 10),
		Operation:       claims.Operation,
		PlatformContext: cloneRawMessages(platformContext),
		Resource:        claims.Resource,
		ServiceDID:      claims.Audience,
	}
	var response platform.SignResponse
	status, headers, err := provider.command(ctx, http.MethodPost, endpoint, idempotencyKey, request, &response)
	if err != nil {
		return platform.SignResponse{}, err
	}
	if response.Status == platform.SignCompleted {
		issuedAt, issuedErr := time.Parse(time.RFC3339, response.IssuedAt)
		expiresAt, expiresErr := time.Parse(time.RFC3339, response.ExpiresAt)
		if status != http.StatusOK || response.ClientAssertion == "" || response.AgentDID != identity.AgentDID || response.ServiceDID != identity.ServiceDID || response.JWTID != claims.JWTID || issuedErr != nil || expiresErr != nil || issuedAt.Unix() != claims.IssuedAt || expiresAt.Unix() != claims.ExpiresAt {
			return platform.SignResponse{}, errors.New("AEP Platform returned an invalid completed Sign response")
		}
		return response, nil
	}
	if response.Status != platform.SignPending || status != http.StatusAccepted || headers.Get("Retry-After") != "" {
		return platform.SignResponse{}, errors.New("AEP Platform returned an invalid Sign status")
	}
	return response, nil
}

func (provider *PlatformIdentityProvider) newIdempotencyKey() (string, error) {
	key, err := provider.idempotencyKey()
	if err != nil || strings.TrimSpace(key) == "" {
		return "", errors.New("AEP Platform idempotency key generation failed")
	}
	return key, nil
}

func (provider *PlatformIdentityProvider) command(ctx context.Context, method string, endpoint *url.URL, idempotencyKey string, body any, target any) (int, http.Header, error) {
	var encoded []byte
	var err error
	if body != nil {
		encoded, err = json.Marshal(body)
		if err != nil {
			return 0, nil, err
		}
	}
	requestContext, cancel := context.WithTimeout(ctx, provider.requestTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(requestContext, method, endpoint.String(), bytes.NewReader(encoded))
	if err != nil {
		return 0, nil, err
	}
	headers, err := provider.headers(requestContext)
	if err != nil {
		return 0, nil, err
	}
	request.Header = headers
	request.Header.Set("Accept", aep.MediaType)
	if body != nil {
		request.Header.Set("Content-Type", aep.MediaType)
	}
	if idempotencyKey != "" {
		request.Header.Set("Idempotency-Key", idempotencyKey)
	}
	response, err := doWithoutRedirects(provider.httpClient, request)
	if err != nil {
		return 0, nil, err
	}
	defer response.Body.Close()
	data, err := readBounded(response.Body, provider.maximumResponseBytes)
	if err != nil {
		return 0, nil, err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		commandErr := &PlatformCommandError{Status: response.StatusCode}
		if mediaTypeMatches(response.Header.Get("Content-Type"), aep.ProblemMediaType) {
			if problem, problemErr := aep.ParseProblemDetails(data); problemErr == nil && problem.Status == response.StatusCode {
				commandErr.Problem = &problem
			}
		}
		return response.StatusCode, response.Header.Clone(), commandErr
	}
	if !mediaTypeMatches(response.Header.Get("Content-Type"), aep.MediaType) {
		return response.StatusCode, response.Header.Clone(), errors.New("AEP Platform response media type is invalid")
	}
	if err := decodePlatformJSON(data, target); err != nil {
		return response.StatusCode, response.Header.Clone(), errors.New("AEP Platform response is invalid JSON")
	}
	return response.StatusCode, response.Header.Clone(), nil
}

func (provider *PlatformIdentityProvider) headers(ctx context.Context) (http.Header, error) {
	headers := make(http.Header)
	if provider.authorization != "" {
		headers.Set("Authorization", provider.authorization)
	}
	if provider.authenticationHeaders != nil {
		supplied, err := provider.authenticationHeaders(ctx)
		if err != nil {
			return nil, err
		}
		for name, values := range supplied {
			switch strings.ToLower(name) {
			case "accept", "content-type", "idempotency-key":
				continue
			}
			headers[http.CanonicalHeaderKey(name)] = slices.Clone(values)
		}
	}
	return headers, nil
}

func (provider *PlatformIdentityProvider) discover(ctx context.Context) (platformDiscoveryEntry, error) {
	provider.discoveryMu.Lock()
	defer provider.discoveryMu.Unlock()
	if provider.discovery != nil && platformDiscoveryFresh(*provider.discovery, provider.clock()) {
		return *provider.discovery, nil
	}
	discoveryURL := provider.platformURL.ResolveReference(&url.URL{Path: platform.WellKnownPath})
	current := discoveryURL
	if provider.discovery != nil && provider.discovery.finalURL != nil {
		current = provider.discovery.finalURL
	}
	requestContext, cancel := context.WithTimeout(ctx, provider.requestTimeout)
	defer cancel()
	for redirects := 0; ; redirects++ {
		request, err := http.NewRequestWithContext(requestContext, http.MethodGet, current.String(), nil)
		if err != nil {
			return platformDiscoveryEntry{}, err
		}
		request.Header.Set("Accept", aep.MediaType)
		if provider.discovery != nil {
			if provider.discovery.etag != "" {
				request.Header.Set("If-None-Match", provider.discovery.etag)
			}
			if provider.discovery.lastModified != "" {
				request.Header.Set("If-Modified-Since", provider.discovery.lastModified)
			}
		}
		response, err := doWithoutRedirects(provider.httpClient, request)
		if err != nil {
			return platformDiscoveryEntry{}, err
		}
		if isRedirect(response.StatusCode) {
			_ = response.Body.Close()
			if redirects >= maximumInspectRedirects {
				return platformDiscoveryEntry{}, errors.New("AEP Platform discovery exceeded five redirects")
			}
			location := response.Header.Get("Location")
			next, resolveErr := current.Parse(location)
			if location == "" || resolveErr != nil || !validInspectTarget(next) || next.Scheme != current.Scheme || !sameOrigin(next, current) {
				return platformDiscoveryEntry{}, errors.New("AEP Platform discovery redirect changed origin or scheme")
			}
			current = next
			continue
		}
		entry, err := provider.discoveryResponse(response, current)
		if err != nil {
			return platformDiscoveryEntry{}, err
		}
		if cacheDirective(entry.cacheControl, "no-store") {
			provider.discovery = nil
		} else {
			provider.discovery = &entry
		}
		return entry, nil
	}
}

func (provider *PlatformIdentityProvider) discoveryResponse(response *http.Response, finalURL *url.URL) (platformDiscoveryEntry, error) {
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotModified {
		if provider.discovery == nil {
			return platformDiscoveryEntry{}, errors.New("AEP Platform discovery returned 304 without a cached document")
		}
		entry := *provider.discovery
		entry.cachedAt = provider.clock()
		entry.finalURL = cloneURL(finalURL)
		if value := response.Header.Get("Cache-Control"); value != "" {
			entry.cacheControl = value
		}
		if value := response.Header.Get("ETag"); value != "" {
			entry.etag = value
		}
		if value := response.Header.Get("Last-Modified"); value != "" {
			entry.lastModified = value
		}
		return entry, nil
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return platformDiscoveryEntry{}, fmt.Errorf("AEP Platform discovery failed with HTTP %d", response.StatusCode)
	}
	if !mediaTypeMatches(response.Header.Get("Content-Type"), aep.MediaType) {
		return platformDiscoveryEntry{}, errors.New("AEP Platform discovery response media type is invalid")
	}
	data, err := readBounded(response.Body, provider.maximumResponseBytes)
	if err != nil {
		return platformDiscoveryEntry{}, err
	}
	var document platform.DiscoveryDocument
	if err := decodePlatformJSON(data, &document); err != nil || validatePlatformDiscovery(document) != nil {
		return platformDiscoveryEntry{}, errors.New("AEP Platform discovery document is invalid")
	}
	return platformDiscoveryEntry{cacheControl: response.Header.Get("Cache-Control"), cachedAt: provider.clock(), document: document, etag: response.Header.Get("ETag"), finalURL: cloneURL(finalURL), lastModified: response.Header.Get("Last-Modified")}, nil
}

func (provider *PlatformIdentityProvider) endpoint(path string, identityID string) (*url.URL, error) {
	if identityID != "" {
		path = strings.ReplaceAll(path, "{agent_identity_id}", url.PathEscape(identityID))
	}
	if !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") || strings.Contains(path, "{") {
		return nil, errors.New("AEP Platform advertised an invalid endpoint")
	}
	reference, err := url.Parse(path)
	if err != nil || reference.RawQuery != "" || reference.Fragment != "" || reference.User != nil {
		return nil, errors.New("AEP Platform advertised an invalid endpoint")
	}
	endpoint := provider.platformURL.ResolveReference(reference)
	if !sameOrigin(endpoint, provider.platformURL) {
		return nil, errors.New("AEP Platform endpoint changed origin")
	}
	return endpoint, nil
}

func (provider *PlatformIdentityProvider) serviceIdentity(identity platform.AgentIdentity) (ServiceIdentity, error) {
	if err := validatePlatformAgentIdentity(identity, provider.allowInsecureLoopback); err != nil {
		return ServiceIdentity{}, err
	}
	return ServiceIdentity{
		AgentDID:          identity.AgentDID,
		IdentityMethod:    aep.IdentityMethodDIDWeb,
		ServiceDID:        identity.ServiceDID,
		SigningAlgorithms: append([]aep.SigningAlgorithm(nil), identity.SigningAlgorithms...),
		Metadata: map[string]string{
			"agent_identity_id": identity.AgentIdentityID,
			"created_at":        identity.CreatedAt,
			"did_document_url":  identity.DIDDocumentURL,
			"key_id":            identity.KeyID,
			"platform_url":      provider.platformURL.String(),
			"status":            string(identity.Status),
			"updated_at":        identity.UpdatedAt,
		},
	}, nil
}

func (provider *PlatformIdentityProvider) validatePlatformIdentity(identity ServiceIdentity) error {
	if identity.Metadata["platform_url"] != provider.platformURL.String() || identity.Metadata["agent_identity_id"] == "" || identity.Metadata["status"] != string(platform.ManagedAgentActive) {
		return errors.New("AEP identity is not an active identity from this Platform")
	}
	return validateServiceIdentityRecord(identity, identity.ServiceDID)
}

func validatePlatformDiscovery(document platform.DiscoveryDocument) error {
	lifetime, lifetimeErr := strconv.Atoi(document.Signing.DefaultLifetimeSeconds)
	if !aep.IsVersionCompatible(document.AEPVersion, aep.Version) || document.Platform.Name == "" || document.HTTP.EndpointBase == "" || len(document.Signing.Algorithms) == 0 || document.Endpoints.Lifecycle == "" || document.Endpoints.List == "" || document.Endpoints.Provision == "" || document.Endpoints.Sign == "" || document.Identity.DIDURLTemplate == "" || lifetimeErr != nil || lifetime < 1 || lifetime > 300 {
		return errors.New("invalid AEP Platform discovery document")
	}
	if document.Platform.DID != "" && !strings.HasPrefix(document.Platform.DID, "did:") {
		return errors.New("AEP Platform discovery contains an invalid Platform DID")
	}
	if document.Platform.HostedVerification != (document.Endpoints.HostedVerification != "") {
		return errors.New("AEP Platform hosted verification advertisement is inconsistent")
	}
	for name, path := range map[string]string{
		"endpoint base":       document.HTTP.EndpointBase,
		"lifecycle":           document.Endpoints.Lifecycle,
		"list":                document.Endpoints.List,
		"provision":           document.Endpoints.Provision,
		"sign":                document.Endpoints.Sign,
		"hosted verification": document.Endpoints.HostedVerification,
	} {
		if path != "" {
			if err := validatePlatformEndpointPath(name, path); err != nil {
				return err
			}
		}
	}
	if strings.Count(document.Endpoints.Lifecycle, "{agent_identity_id}") != 1 || strings.Count(document.Endpoints.Sign, "{agent_identity_id}") != 1 || strings.Contains(document.Endpoints.List, "{") || strings.Contains(document.Endpoints.Provision, "{") || strings.Contains(document.HTTP.EndpointBase, "{") || strings.Contains(document.Endpoints.HostedVerification, "{") {
		return errors.New("AEP Platform discovery endpoint templates are invalid")
	}
	if strings.Count(document.Identity.DIDURLTemplate, "{agent_did_id}") != 1 {
		return errors.New("AEP Platform DID URL template is invalid")
	}
	didURL, err := url.Parse(strings.Replace(document.Identity.DIDURLTemplate, "{agent_did_id}", "validation", 1))
	if err != nil || didURL.Scheme != "https" || didURL.Hostname() == "" || didURL.User != nil || didURL.Fragment != "" {
		return errors.New("AEP Platform DID URL template is invalid")
	}
	if len(document.Identity.DIDMethods) == 0 || !slices.Contains(document.Identity.DIDMethods, "did:web") {
		return errors.New("AEP Platform does not advertise did:web")
	}
	for _, algorithm := range document.Signing.Algorithms {
		if algorithm != aep.SigningAlgorithmEdDSA && algorithm != aep.SigningAlgorithmES256 {
			return errors.New("AEP Platform advertises an unsupported signing algorithm")
		}
	}
	return nil
}

func validatePlatformEndpointPath(name string, path string) error {
	parsed, err := url.Parse(path)
	if err != nil || !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") || parsed.IsAbs() || parsed.Host != "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return fmt.Errorf("AEP Platform %s must be an absolute path", name)
	}
	return nil
}

func validatePlatformAgentIdentity(identity platform.AgentIdentity, allowInsecureLoopback bool) error {
	if identity.AgentIdentityID == "" || !strings.HasPrefix(identity.AgentDID, "did:web:") || identity.KeyID != identity.AgentDID || !strings.HasPrefix(identity.ServiceDID, "did:") || len(identity.SigningAlgorithms) == 0 || !managedAgentStatus(identity.Status) {
		return errors.New("AEP Platform returned an invalid identity")
	}
	for _, algorithm := range identity.SigningAlgorithms {
		if algorithm != aep.SigningAlgorithmEdDSA && algorithm != aep.SigningAlgorithmES256 {
			return errors.New("AEP Platform returned an unsupported signing algorithm")
		}
	}
	if _, err := time.Parse(time.RFC3339, identity.CreatedAt); err != nil {
		return errors.New("AEP Platform returned an invalid identity creation time")
	}
	if _, err := time.Parse(time.RFC3339, identity.UpdatedAt); err != nil {
		return errors.New("AEP Platform returned an invalid identity update time")
	}
	documentURL, err := url.Parse(identity.DIDDocumentURL)
	if err != nil || documentURL.Host == "" || (documentURL.Scheme != "https" && !(allowInsecureLoopback && documentURL.Scheme == "http" && isLoopback(documentURL.Hostname()))) {
		return errors.New("AEP Platform returned an invalid DID document URL")
	}
	expected, err := aep.DIDWebDocumentURLWithOptions(identity.AgentDID, aep.DIDWebDocumentURLOptions{AllowInsecureLoopback: allowInsecureLoopback})
	if err != nil || expected.String() != documentURL.String() {
		return errors.New("AEP Platform DID document URL does not match the Agent DID")
	}
	return nil
}

func validatePlatformIdentityList(list platform.AgentIdentityListResponse, allowInsecureLoopback bool) error {
	count, countErr := strconv.Atoi(list.Count)
	total, totalErr := strconv.Atoi(list.Total)
	if countErr != nil || totalErr != nil || count != len(list.Data) || count < 0 || total < count {
		return errors.New("AEP Platform returned an invalid identity list")
	}
	for _, identity := range list.Data {
		if err := validatePlatformAgentIdentity(identity, allowInsecureLoopback); err != nil {
			return err
		}
	}
	return nil
}

func managedAgentStatus(status platform.ManagedAgentStatus) bool {
	return status == platform.ManagedAgentActive || status == platform.ManagedAgentRevoked || status == platform.ManagedAgentSuspended || status == platform.ManagedAgentTerminated
}

func platformDiscoveryFresh(entry platformDiscoveryEntry, now time.Time) bool {
	if cacheDirective(entry.cacheControl, "no-cache") || cacheDirective(entry.cacheControl, "no-store") {
		return false
	}
	maxAge := 300 * time.Second
	if value, found := cacheDirectiveValue(entry.cacheControl, "max-age"); found {
		seconds, err := strconv.ParseInt(value, 10, 64)
		if err != nil || seconds < 0 || seconds > math.MaxInt64/int64(time.Second) {
			return false
		}
		maxAge = time.Duration(seconds) * time.Second
	}
	return entry.cachedAt.Add(maxAge).After(now)
}

func cloneRawMessages(value map[string]json.RawMessage) map[string]json.RawMessage {
	if value == nil {
		return nil
	}
	copy := make(map[string]json.RawMessage, len(value))
	for name, raw := range value {
		copy[name] = append(json.RawMessage(nil), raw...)
	}
	return copy
}

func decodePlatformJSON(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("AEP Platform response contains trailing JSON")
	}
	return nil
}
