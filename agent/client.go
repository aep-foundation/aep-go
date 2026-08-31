package agent

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"math"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	aep "github.com/aep-foundation/aep-go"
)

const (
	defaultMaximumResponseBytes = int64(1 << 20)
	defaultRequestTimeout       = 30 * time.Second
)

func New(options Options) (*Client, error) {
	if options.IdentityProvider == nil {
		return nil, errors.New("AEP Agent identity provider is required")
	}
	assertionLifetime := options.AssertionLifetime
	if assertionLifetime == 0 {
		assertionLifetime = aep.MaxAssertionLifetime
	}
	if assertionLifetime < time.Second || assertionLifetime > aep.MaxAssertionLifetime || assertionLifetime%time.Second != 0 {
		return nil, errors.New("AEP Agent assertion lifetime must be whole seconds from 1 through 300")
	}
	maximumResponseBytes := options.MaximumResponseBytes
	if maximumResponseBytes == 0 {
		maximumResponseBytes = defaultMaximumResponseBytes
	}
	if maximumResponseBytes < 1 || maximumResponseBytes == math.MaxInt64 {
		return nil, errors.New("AEP Agent maximum response bytes are outside the supported range")
	}
	requestTimeout := options.RequestTimeout
	if requestTimeout == 0 {
		requestTimeout = defaultRequestTimeout
	}
	if requestTimeout <= 0 {
		return nil, errors.New("AEP Agent request timeout must be positive")
	}
	clock := options.Clock
	if clock == nil {
		clock = time.Now
	}
	jti := options.JTI
	if jti == nil {
		jti = randomIdentifier
	}
	identityStore := options.IdentityStore
	if identityStore == nil {
		identityStore = NewMemoryIdentityStore()
	}
	credentialStore := options.CredentialStore
	if credentialStore == nil {
		credentialStore = newMemoryCredentialStore(clock)
	}
	idempotencyKeys := options.IdempotencyKeys
	if idempotencyKeys == nil {
		idempotencyKeys = RandomIdempotencyKeyProvider{}
	}
	inspectCache := options.InspectCache
	if inspectCache == nil {
		inspectCache = NewMemoryInspectCache()
	}
	httpClient := options.HTTPClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	inspectHTTPClient := options.InspectHTTPClient
	if inspectHTTPClient == nil {
		inspectHTTPClient = httpClient
	}
	commandHTTPClient := options.CommandHTTPClient
	if commandHTTPClient == nil {
		commandHTTPClient = httpClient
	}
	return &Client{
		allowInsecureLoopback: options.AllowInsecureLoopback,
		assertionLifetime:     assertionLifetime,
		clock:                 clock,
		commandHTTPClient:     commandHTTPClient,
		credentialStore:       credentialStore,
		identityProvider:      options.IdentityProvider,
		identityStore:         identityStore,
		idempotencyKeys:       idempotencyKeys,
		inspectCache:          inspectCache,
		inspectHTTPClient:     inspectHTTPClient,
		jti:                   jti,
		maximumResponseBytes:  maximumResponseBytes,
		requestTimeout:        requestTimeout,
	}, nil
}

func (client *Client) Service(reference string) (*Session, error) {
	serviceURL, err := resolveServiceReference(reference, client.allowInsecureLoopback)
	if err != nil {
		return nil, err
	}
	return &Session{client: client, serviceURL: serviceURL}, nil
}

func resolveServiceReference(reference string, allowInsecureLoopback bool) (*url.URL, error) {
	value := strings.TrimSpace(reference)
	if value == "" {
		return nil, errors.New("invalid AEP Service reference")
	}
	if strings.HasPrefix(value, "did:web:") {
		documentURL, err := aep.DIDWebDocumentURLWithOptions(value, aep.DIDWebDocumentURLOptions{AllowInsecureLoopback: allowInsecureLoopback})
		if err != nil {
			return nil, errors.New("invalid AEP Service reference")
		}
		value = documentURL.Scheme + "://" + documentURL.Host
	} else if parsed, err := url.Parse(value); err != nil || parsed.Scheme == "" {
		value = "https://" + value
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed == nil {
		return nil, errors.New("invalid AEP Service reference")
	}
	hostname := parsed.Hostname()
	if parsed.Host == "" || hostname == "" || parsed.User != nil || parsed.Opaque != "" || (strings.Contains(hostname, ":") && net.ParseIP(hostname) == nil) {
		return nil, errors.New("invalid AEP Service reference")
	}
	if parsed.Scheme != "https" && !(allowInsecureLoopback && parsed.Scheme == "http" && isLoopback(parsed.Hostname())) {
		return nil, errors.New("AEP Service references require HTTPS")
	}
	return &url.URL{Scheme: parsed.Scheme, Host: parsed.Host, Path: "/"}, nil
}

func isLoopback(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

func randomIdentifier() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return hex.EncodeToString(value), nil
}

type RandomIdempotencyKeyProvider struct{}

func (RandomIdempotencyKeyProvider) CreateKey(context.Context, OperationKey) (string, error) {
	return randomIdentifier()
}

type memoryIdentityStore struct {
	mu      sync.RWMutex
	records map[string]ServiceIdentity
}

func NewMemoryIdentityStore() IdentityStore {
	return &memoryIdentityStore{records: make(map[string]ServiceIdentity)}
}

func (store *memoryIdentityStore) FindIdentity(_ context.Context, serviceDID string) (*ServiceIdentity, error) {
	store.mu.RLock()
	defer store.mu.RUnlock()
	identity, found := store.records[serviceDID]
	if !found {
		return nil, nil
	}
	copy := cloneIdentity(identity)
	return &copy, nil
}

func (store *memoryIdentityStore) SaveIdentity(_ context.Context, identity ServiceIdentity) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.records[identity.ServiceDID] = cloneIdentity(identity)
	return nil
}

func cloneIdentity(identity ServiceIdentity) ServiceIdentity {
	copy := identity
	copy.SigningAlgorithms = append([]aep.SigningAlgorithm(nil), identity.SigningAlgorithms...)
	if identity.Metadata != nil {
		copy.Metadata = make(map[string]string, len(identity.Metadata))
		for name, value := range identity.Metadata {
			copy.Metadata[name] = value
		}
	}
	return copy
}
