package aep

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-jose/go-jose/v4"
)

const maxDIDDocumentBytes = 1 << 20

type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

type ResolveDIDWebPublicKeyOptions struct {
	AllowInsecureLoopback bool
	Client                HTTPDoer
	DID                   string
	KeyID                 string
}

type DIDWebDocumentURLOptions struct {
	AllowInsecureLoopback bool
}

func DIDWebDocumentURL(did string) (*url.URL, error) {
	return didWebDocumentURL(did, false)
}

func DIDWebDocumentURLWithOptions(did string, options DIDWebDocumentURLOptions) (*url.URL, error) {
	return didWebDocumentURL(did, options.AllowInsecureLoopback)
}

func didWebDocumentURL(did string, allowInsecureLoopback bool) (*url.URL, error) {
	const prefix = "did:web:"
	if !strings.HasPrefix(did, prefix) {
		return nil, fmt.Errorf("unsupported DID method: %s", did)
	}
	parts := strings.Split(strings.TrimPrefix(did, prefix), ":")
	if len(parts) == 0 || parts[0] == "" {
		return nil, fmt.Errorf("invalid did:web identifier: %s", did)
	}
	host, err := url.PathUnescape(parts[0])
	if err != nil {
		return nil, fmt.Errorf("decode did:web host: %w", err)
	}
	parsedHost, err := url.Parse("https://" + host)
	if err != nil || parsedHost.Host != host || parsedHost.Hostname() == "" || parsedHost.User != nil || parsedHost.Path != "" {
		return nil, fmt.Errorf("invalid did:web host: %s", host)
	}
	scheme := "https"
	if allowInsecureLoopback && isLoopbackHost(parsedHost.Hostname()) {
		scheme = "http"
	}
	path := "/.well-known/did.json"
	if len(parts) > 1 {
		decoded := make([]string, 0, len(parts)-1)
		for _, part := range parts[1:] {
			component, decodeErr := url.PathUnescape(part)
			if decodeErr != nil {
				return nil, fmt.Errorf("decode did:web path: %w", decodeErr)
			}
			decoded = append(decoded, component)
		}
		path = "/" + strings.Join(decoded, "/") + "/did.json"
	}
	return &url.URL{Scheme: scheme, Host: host, Path: path}, nil
}

func ResolveDIDWebPublicKey(ctx context.Context, options ResolveDIDWebPublicKeyOptions) (jose.JSONWebKey, error) {
	if options.KeyID == "" {
		return jose.JSONWebKey{}, errors.New("AEP did:web key ID is required")
	}
	keyDID, _, _ := strings.Cut(options.KeyID, "#")
	if keyDID != options.DID {
		return jose.JSONWebKey{}, errors.New("AEP did:web key ID does not identify the assertion issuer")
	}
	documentURL, err := didWebDocumentURL(options.DID, options.AllowInsecureLoopback)
	if err != nil {
		return jose.JSONWebKey{}, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, documentURL.String(), nil)
	if err != nil {
		return jose.JSONWebKey{}, fmt.Errorf("create did:web request: %w", err)
	}
	request.Header.Set("Accept", "application/did+json, application/json")
	client := options.Client
	if client == nil {
		client = http.DefaultClient
	}
	if httpClient, ok := client.(*http.Client); ok {
		redirectSafeClient := *httpClient
		redirectSafeClient.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		}
		client = &redirectSafeClient
	}
	response, err := client.Do(request)
	if err != nil {
		return jose.JSONWebKey{}, fmt.Errorf("fetch did:web document: %w", err)
	}
	defer response.Body.Close()
	if response.Request == nil || response.Request.URL == nil || response.Request.URL.String() != documentURL.String() {
		return jose.JSONWebKey{}, errors.New("did:web document redirects are not allowed")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return jose.JSONWebKey{}, fmt.Errorf("fetch did:web document: HTTP %d", response.StatusCode)
	}
	var document struct {
		VerificationMethods []struct {
			ID           string          `json:"id"`
			PublicKeyJWK json.RawMessage `json:"publicKeyJwk"`
		} `json:"verificationMethod"`
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, maxDIDDocumentBytes+1))
	if err != nil {
		return jose.JSONWebKey{}, fmt.Errorf("read did:web document: %w", err)
	}
	if len(data) > maxDIDDocumentBytes {
		return jose.JSONWebKey{}, errors.New("did:web document exceeds the 1 MiB limit")
	}
	if err := decodeOne(data, &document); err != nil {
		return jose.JSONWebKey{}, fmt.Errorf("decode did:web document: %w", err)
	}
	for _, method := range document.VerificationMethods {
		if method.ID != options.KeyID {
			continue
		}
		if len(method.PublicKeyJWK) == 0 {
			continue
		}
		var key jose.JSONWebKey
		if err := json.Unmarshal(method.PublicKeyJWK, &key); err != nil {
			return jose.JSONWebKey{}, fmt.Errorf("decode did:web public JWK: %w", err)
		}
		if !key.Valid() {
			return jose.JSONWebKey{}, errors.New("did:web public JWK is invalid")
		}
		return key, nil
	}
	return jose.JSONWebKey{}, fmt.Errorf("no public JWK found for %s", options.KeyID)
}

func isLoopbackHost(hostname string) bool {
	return hostname == "localhost" || hostname == "127.0.0.1" || hostname == "::1"
}
