package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"net/url"
	"strings"

	aep "github.com/aep-foundation/aep-go"
)

type OpenAPIOperationPolicy struct {
	State            string
	Methods          []aep.AuthenticationMethod
	MatchedOperation *aep.OpenAPIPathMatch
}

// InterpretOpenAPIOperation returns fallback when no complete authentication alternative is understood.
func InterpretOpenAPIOperation(data []byte, options aep.OpenAPIPathMatchOptions) (OpenAPIOperationPolicy, error) {
	fallback := OpenAPIOperationPolicy{State: "fallback", Methods: []aep.AuthenticationMethod{}}
	var document struct {
		Version    string                                `json:"openapi"`
		Paths      map[string]map[string]json.RawMessage `json:"paths"`
		Security   json.RawMessage                       `json:"security"`
		Components struct {
			SecuritySchemes map[string]json.RawMessage `json:"securitySchemes"`
		} `json:"components"`
	}
	if err := json.Unmarshal(data, &document); err != nil || !strings.HasPrefix(document.Version, "3.1.") {
		return fallback, errors.New("AEP OpenAPI document must be OpenAPI 3.1 JSON")
	}
	if options.Method == "" {
		options.Method = http.MethodGet
	}
	method := strings.ToLower(options.Method)
	var templates []string
	for path, item := range document.Paths {
		var operation map[string]json.RawMessage
		if json.Unmarshal(item[method], &operation) == nil && operation != nil {
			templates = append(templates, path)
		}
	}
	match, err := aep.MatchOpenAPIPath(templates, options)
	if err != nil {
		return fallback, nil
	}
	var operation map[string]json.RawMessage
	if err := json.Unmarshal(document.Paths[match.Template][method], &operation); err != nil {
		return fallback, err
	}
	security, present := operation["security"]
	if !present {
		security = document.Security
	}
	var alternatives []map[string]json.RawMessage
	if json.Unmarshal(security, &alternatives) != nil || alternatives == nil {
		return fallback, nil
	}
	policy := OpenAPIOperationPolicy{State: "public", Methods: []aep.AuthenticationMethod{}, MatchedOperation: &match}
	if len(alternatives) == 0 {
		return policy, nil
	}
	for _, alternative := range alternatives {
		if alternative == nil {
			continue
		}
		if len(alternative) == 0 {
			policy.State = "public"
			policy.Methods = []aep.AuthenticationMethod{}
			return policy, nil
		}
		// Header generation selects one method; it cannot satisfy a compound requirement.
		if len(alternative) != 1 {
			continue
		}
		for name, scopes := range alternative {
			var requiredScopes []string
			if json.Unmarshal(scopes, &requiredScopes) != nil || requiredScopes == nil {
				continue
			}
			var scheme struct {
				Method aep.AuthenticationMethod `json:"x-aep-authentication-method"`
			}
			if json.Unmarshal(document.Components.SecuritySchemes[name], &scheme) != nil || scheme.Method == "" {
				continue
			}
			if !containsAuthenticationMethod(policy.Methods, scheme.Method) {
				policy.Methods = append(policy.Methods, scheme.Method)
			}
		}
	}
	if len(policy.Methods) == 0 {
		policy.State = "fallback"
	} else {
		policy.State = "required"
	}
	return policy, nil
}

type openAPIEntry struct {
	metadata InspectCacheEntry
	data     []byte
}

func (session *Session) OpenAPIPolicy(ctx context.Context, method string, resource *url.URL) (OpenAPIOperationPolicy, error) {
	return session.openAPIPolicy(ctx, method, resource, false)
}

func (session *Session) openAPIPolicy(ctx context.Context, method string, resource *url.URL, revalidate bool) (OpenAPIOperationPolicy, error) {
	fallback := OpenAPIOperationPolicy{State: "fallback", Methods: []aep.AuthenticationMethod{}}
	if resource == nil {
		return fallback, errors.New("AEP OpenAPI policy requires a resource URL")
	}
	if err := validateProtectedResource(resource, session.serviceURL, session.client.allowInsecureLoopback); err != nil {
		return fallback, err
	}
	inspection, err := session.Inspect(ctx)
	if err != nil {
		return fallback, err
	}
	advertisement := inspection.Document.HTTP.OpenAPI
	if advertisement == nil {
		return fallback, nil
	}
	target, err := aep.ResolveOpenAPIURL(inspection.FinalURL.String(), advertisement.URL, session.client.allowInsecureLoopback)
	if err != nil {
		return fallback, err
	}
	if inspection.FinalURL.Scheme == "https" && target.Scheme != "https" {
		return fallback, errors.New("AEP OpenAPI URL downgrades transport")
	}
	data, err := session.client.openAPI(ctx, target, revalidate)
	if err != nil {
		return fallback, err
	}
	return InterpretOpenAPIOperation(data, aep.OpenAPIPathMatchOptions{Method: method, Path: resource.EscapedPath(), TrailingSlash: advertisement.PathMatching.TrailingSlash})
}

func (client *Client) openAPI(ctx context.Context, target *url.URL, revalidate bool) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, client.requestTimeout)
	defer cancel()
	key := target.String()
	client.openAPIMu.Lock()
	cached, found := client.openAPICache[key]
	client.openAPIMu.Unlock()
	if !revalidate && found && inspectCacheFresh(cached.metadata, client.clock()) {
		return append([]byte(nil), cached.data...), nil
	}
	current := target
	if found {
		var err error
		current, err = url.Parse(cached.metadata.FinalURL)
		if err != nil {
			return nil, err
		}
	}
	for redirects := 0; ; redirects++ {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, current.String(), nil)
		if err != nil {
			return nil, err
		}
		request.Header.Set("Accept", "application/vnd.oai.openapi+json;version=3.1, application/json")
		if found {
			if cached.metadata.ETag != "" {
				request.Header.Set("If-None-Match", cached.metadata.ETag)
			}
			if cached.metadata.LastModified != "" {
				request.Header.Set("If-Modified-Since", cached.metadata.LastModified)
			}
		}
		response, err := doWithoutRedirects(client.inspectHTTPClient, request)
		if err != nil {
			return nil, err
		}
		if isRedirect(response.StatusCode) {
			response.Body.Close()
			if redirects >= 5 {
				return nil, errors.New("OpenAPI exceeded five redirects")
			}
			location := response.Header.Get("Location")
			if location == "" {
				return nil, errors.New("OpenAPI redirect omitted Location")
			}
			next, resolveErr := aep.ResolveOpenAPIURL(current.String(), location, client.allowInsecureLoopback)
			if resolveErr != nil {
				return nil, resolveErr
			}
			if current.Scheme == "https" && next.Scheme != "https" {
				return nil, errors.New("OpenAPI redirect downgraded transport")
			}
			current = next
			continue
		}
		entry, err := client.readOpenAPI(response, current, cached, found)
		if err != nil {
			return nil, err
		}
		client.openAPIMu.Lock()
		if client.openAPICache == nil {
			client.openAPICache = make(map[string]openAPIEntry)
		}
		if cacheDirective(entry.metadata.CacheControl, "no-store") {
			delete(client.openAPICache, key)
		} else {
			client.openAPICache[key] = entry
		}
		client.openAPIMu.Unlock()
		return append([]byte(nil), entry.data...), nil
	}
}

func (client *Client) readOpenAPI(response *http.Response, current *url.URL, cached openAPIEntry, found bool) (openAPIEntry, error) {
	defer response.Body.Close()
	entry := openAPIEntry{}
	if response.StatusCode == http.StatusNotModified {
		if !found {
			return entry, errors.New("OpenAPI returned 304 without a cached document")
		}
		entry = cached
	} else {
		if response.StatusCode < 200 || response.StatusCode >= 300 {
			return entry, fmt.Errorf("OpenAPI returned HTTP %d", response.StatusCode)
		}
		mediaType, params, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
		if err != nil || !(strings.EqualFold(mediaType, "application/json") || strings.EqualFold(mediaType, "application/vnd.oai.openapi+json") && params["version"] == "3.1") {
			return entry, errors.New("OpenAPI response media type is invalid")
		}
		entry.data, err = readBounded(response.Body, client.maximumResponseBytes)
		if err != nil {
			return entry, err
		}
		if _, err := InterpretOpenAPIOperation(entry.data, aep.OpenAPIPathMatchOptions{Method: "GET", Path: "/", TrailingSlash: "strict"}); err != nil {
			return entry, err
		}
	}
	mergeCacheHeaders(&entry.metadata, response.Header)
	entry.metadata.FinalURL = current.String()
	entry.metadata.CachedAt = client.clock()
	return entry, nil
}
