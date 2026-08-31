package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	aep "github.com/aep-foundation/aep-go"
)

const maximumInspectRedirects = 5

func (session *Session) Inspect(ctx context.Context) (Inspection, error) {
	session.inspectionMu.Lock()
	defer session.inspectionMu.Unlock()
	return session.client.inspect(ctx, session.serviceURL)
}

func (client *Client) inspect(ctx context.Context, serviceURL *url.URL) (Inspection, error) {
	inspectURL := serviceURL.ResolveReference(&url.URL{Path: aep.WellKnownPath})
	cacheKey := inspectURL.String()
	cached, err := client.inspectCache.FindInspect(ctx, cacheKey)
	if err != nil {
		return Inspection{}, err
	}
	if cached != nil {
		copy, cloneErr := cloneInspectCacheEntry(*cached)
		if cloneErr != nil {
			if err := client.inspectCache.DeleteInspect(ctx, cacheKey); err != nil {
				return Inspection{}, err
			}
			cached = nil
		} else {
			cached = &copy
		}
	}
	if cached != nil && inspectCacheFresh(*cached, client.clock()) {
		inspection, buildErr := inspectionFromCache(serviceURL, inspectURL, *cached)
		if buildErr == nil {
			return inspection, nil
		}
		if err := client.inspectCache.DeleteInspect(ctx, cacheKey); err != nil {
			return Inspection{}, err
		}
		cached = nil
	}
	requestContext, cancel := context.WithTimeout(ctx, client.requestTimeout)
	defer cancel()
	current := inspectURL
	if cached != nil {
		cachedURL, parseErr := url.Parse(cached.FinalURL)
		if parseErr != nil || !validInspectTarget(cachedURL) || cachedURL.Scheme != inspectURL.Scheme || !sameOrigin(cachedURL, inspectURL) {
			if err := client.inspectCache.DeleteInspect(ctx, cacheKey); err != nil {
				return Inspection{}, err
			}
			cached = nil
		} else {
			current = cachedURL
		}
	}
	for redirects := 0; ; redirects++ {
		request, requestErr := http.NewRequestWithContext(requestContext, http.MethodGet, current.String(), nil)
		if requestErr != nil {
			return Inspection{}, inspectError(InspectHTTPError, 0, "create AEP Inspect request", requestErr)
		}
		request.Header.Set("Accept", aep.MediaType)
		if cached != nil {
			if cached.ETag != "" {
				request.Header.Set("If-None-Match", cached.ETag)
			}
			if cached.LastModified != "" {
				request.Header.Set("If-Modified-Since", cached.LastModified)
			}
		}
		response, responseErr := doWithoutRedirects(client.inspectHTTPClient, request)
		if responseErr != nil {
			code := InspectHTTPError
			if errors.Is(responseErr, context.Canceled) || errors.Is(responseErr, context.DeadlineExceeded) {
				code = InspectAborted
			}
			return Inspection{}, inspectError(code, 0, "fetch AEP Inspect document", responseErr)
		}
		if isRedirect(response.StatusCode) {
			_ = response.Body.Close()
			if redirects >= maximumInspectRedirects {
				return Inspection{}, &InspectError{Code: InspectInvalidRedirect, Text: "AEP Inspect exceeded five redirects"}
			}
			location := response.Header.Get("Location")
			if location == "" {
				return Inspection{}, &InspectError{Code: InspectInvalidRedirect, Text: "AEP Inspect redirect omitted Location"}
			}
			next, resolveErr := current.Parse(location)
			if resolveErr != nil || !validInspectTarget(next) || next.Scheme != current.Scheme || !sameOrigin(next, current) {
				return Inspection{}, &InspectError{Code: InspectInvalidRedirect, Text: "AEP Inspect redirect changed origin or scheme"}
			}
			current = next
			continue
		}
		inspection, responseErr := client.inspectResponse(response, serviceURL, inspectURL, current, cached)
		if responseErr != nil {
			_ = client.inspectCache.DeleteInspect(ctx, cacheKey)
			return Inspection{}, responseErr
		}
		entry := InspectCacheEntry{
			CacheControl: inspection.CacheControl,
			CachedAt:     client.clock(),
			Document:     inspection.Document,
			ETag:         inspection.ETag,
			FinalURL:     inspection.FinalURL.String(),
			LastModified: inspection.LastModified,
		}
		if cacheDirective(inspection.CacheControl, "no-store") {
			if err := client.inspectCache.DeleteInspect(ctx, cacheKey); err != nil {
				return Inspection{}, err
			}
		} else {
			stored, cloneErr := cloneInspectCacheEntry(entry)
			if cloneErr != nil {
				return Inspection{}, cloneErr
			}
			if err := client.inspectCache.SaveInspect(ctx, cacheKey, stored); err != nil {
				return Inspection{}, err
			}
		}
		return inspection, nil
	}
}

func (client *Client) inspectResponse(response *http.Response, serviceURL *url.URL, inspectURL *url.URL, finalURL *url.URL, cached *InspectCacheEntry) (Inspection, error) {
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotModified {
		if cached == nil {
			return Inspection{}, &InspectError{Code: InspectHTTPError, Status: response.StatusCode, Text: "AEP Inspect returned 304 without a cached document"}
		}
		entry := *cached
		entry.CachedAt = client.clock()
		entry.FinalURL = finalURL.String()
		mergeCacheHeaders(&entry, response.Header)
		return inspectionFromCache(serviceURL, inspectURL, entry)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return Inspection{}, &InspectError{Code: InspectHTTPError, Status: response.StatusCode, Text: fmt.Sprintf("AEP Inspect failed with HTTP %d", response.StatusCode)}
	}
	if !mediaTypeMatches(response.Header.Get("Content-Type"), aep.MediaType) {
		return Inspection{}, &InspectError{Code: InspectInvalidMediaType, Status: response.StatusCode, Text: "AEP Inspect response media type is invalid"}
	}
	data, err := readBounded(response.Body, client.maximumResponseBytes)
	if err != nil {
		if errors.Is(err, errResponseTooLarge) {
			return Inspection{}, &InspectError{Code: InspectResponseTooLarge, Status: response.StatusCode, Text: "AEP Inspect response exceeds the configured limit"}
		}
		return Inspection{}, inspectError(InspectInvalidJSON, response.StatusCode, "read AEP Inspect response", err)
	}
	document, err := aep.ParseInspectDocument(data)
	if err != nil {
		code := InspectValidationFailed
		if !json.Valid(data) {
			code = InspectInvalidJSON
		}
		return Inspection{}, inspectError(code, response.StatusCode, "validate AEP Inspect document", err)
	}
	inspection := Inspection{
		CacheControl: response.Header.Get("Cache-Control"),
		Document:     document,
		ETag:         response.Header.Get("ETag"),
		FinalURL:     cloneURL(finalURL),
		InspectURL:   cloneURL(inspectURL),
		LastModified: response.Header.Get("Last-Modified"),
		ServiceURL:   cloneURL(serviceURL),
	}
	if err := validateServiceIdentity(inspection, client.allowInsecureLoopback); err != nil {
		return Inspection{}, err
	}
	return inspection, nil
}

func doWithoutRedirects(client *http.Client, request *http.Request) (*http.Response, error) {
	copy := *client
	copy.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	copy.Jar = nil
	return copy.Do(request)
}

func inspectionFromCache(serviceURL *url.URL, inspectURL *url.URL, entry InspectCacheEntry) (Inspection, error) {
	finalURL, err := url.Parse(entry.FinalURL)
	if err != nil {
		return Inspection{}, err
	}
	document, err := cloneInspectDocument(entry.Document)
	if err != nil {
		return Inspection{}, err
	}
	inspection := Inspection{
		CacheControl: entry.CacheControl,
		Document:     document,
		ETag:         entry.ETag,
		FinalURL:     finalURL,
		InspectURL:   cloneURL(inspectURL),
		LastModified: entry.LastModified,
		ServiceURL:   cloneURL(serviceURL),
	}
	return inspection, validateServiceIdentity(inspection, serviceURL.Scheme == "http")
}

func validateServiceIdentity(inspection Inspection, allowInsecureLoopback bool) error {
	serviceDID := inspection.Document.Service.DID
	if !strings.HasPrefix(serviceDID, "did:web:") {
		return &InspectError{Code: InspectServiceIdentityMismatch, Text: "AEP Inspect Service DID has no supported origin binding"}
	}
	documentURL, err := aep.DIDWebDocumentURLWithOptions(serviceDID, aep.DIDWebDocumentURLOptions{AllowInsecureLoopback: allowInsecureLoopback})
	if err != nil || documentURL.Scheme != inspection.FinalURL.Scheme || !sameOrigin(documentURL, inspection.FinalURL) {
		return &InspectError{Code: InspectServiceIdentityMismatch, Text: "AEP Inspect Service DID does not match the Inspect origin"}
	}
	return nil
}

func inspectCacheFresh(entry InspectCacheEntry, now time.Time) bool {
	if cacheDirective(entry.CacheControl, "no-cache") || cacheDirective(entry.CacheControl, "no-store") {
		return false
	}
	maxAge := aep.DefaultInspectFreshness
	if value, found := cacheDirectiveValue(entry.CacheControl, "max-age"); found {
		seconds, err := strconv.ParseInt(value, 10, 64)
		if err != nil || seconds < 0 {
			return false
		}
		if seconds > math.MaxInt64/int64(time.Second) {
			return false
		}
		maxAge = time.Duration(seconds) * time.Second
	}
	return entry.CachedAt.Add(maxAge).After(now)
}

func mergeCacheHeaders(entry *InspectCacheEntry, headers http.Header) {
	if value := headers.Get("Cache-Control"); value != "" {
		entry.CacheControl = value
	}
	if value := headers.Get("ETag"); value != "" {
		entry.ETag = value
	}
	if value := headers.Get("Last-Modified"); value != "" {
		entry.LastModified = value
	}
}

func cacheDirective(value string, name string) bool {
	_, found := cacheDirectiveValue(value, name)
	return found
}

func cacheDirectiveValue(value string, name string) (string, bool) {
	for _, part := range strings.Split(value, ",") {
		fields := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if strings.EqualFold(fields[0], name) {
			if len(fields) == 1 {
				return "", true
			}
			return strings.Trim(fields[1], "\""), true
		}
	}
	return "", false
}

func mediaTypeMatches(value string, expected string) bool {
	parsed, _, err := mime.ParseMediaType(value)
	return err == nil && strings.EqualFold(parsed, expected)
}

var errResponseTooLarge = errors.New("response exceeds configured limit")

func readBounded(reader io.Reader, maximum int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(reader, maximum+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maximum {
		return nil, errResponseTooLarge
	}
	return data, nil
}

func sameOrigin(first *url.URL, second *url.URL) bool {
	return strings.EqualFold(first.Scheme, second.Scheme) && strings.EqualFold(first.Hostname(), second.Hostname()) && effectivePort(first) == effectivePort(second)
}

func validInspectTarget(target *url.URL) bool {
	return target.Opaque == "" && target.Host != "" && target.User == nil && target.Fragment == ""
}

func effectivePort(value *url.URL) string {
	if value.Port() != "" {
		return value.Port()
	}
	if value.Scheme == "https" {
		return "443"
	}
	if value.Scheme == "http" {
		return "80"
	}
	return ""
}

func cloneURL(value *url.URL) *url.URL {
	copy := *value
	return &copy
}

func isRedirect(status int) bool {
	return status == http.StatusMovedPermanently || status == http.StatusFound || status == http.StatusSeeOther || status == http.StatusTemporaryRedirect || status == http.StatusPermanentRedirect
}

func inspectError(code InspectErrorCode, status int, operation string, err error) error {
	return &InspectError{Cause: err, Code: code, Status: status, Text: operation + ": " + err.Error()}
}
