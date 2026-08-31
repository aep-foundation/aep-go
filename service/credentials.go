package service

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	aep "github.com/aep-foundation/aep-go"
)

func StoredOAuthBearerGrantType(options StoredCredentialGrantTypeOptions[aep.OAuthBearerGrantResponse]) (GrantTypeDefinition, error) {
	return storedCredentialGrantType(aep.GrantTypeOAuthBearer, options.Config, options.Issue, options.Store)
}

func StoredAPIKeyGrantType(options StoredCredentialGrantTypeOptions[aep.APIKeyGrantResponse]) (GrantTypeDefinition, error) {
	return storedCredentialGrantType(aep.GrantTypeAPIKey, options.Config, options.Issue, options.Store)
}

func StoredBasicGrantType(options StoredCredentialGrantTypeOptions[aep.BasicGrantResponse]) (GrantTypeDefinition, error) {
	return storedCredentialGrantType(aep.GrantTypeBasic, options.Config, options.Issue, options.Store)
}

func storedCredentialGrantType[Credential aep.BuiltInGrantResponse](grantType aep.GrantType, config aep.GrantTypeConfig, issue BuiltInCredentialIssuer[Credential], store ServiceCredentialStore) (GrantTypeDefinition, error) {
	if issue == nil || store == nil {
		return GrantTypeDefinition{}, errors.New("AEP stored credential Grant Type requires an issuer and store")
	}
	config = cloneGrantTypeConfig(config)
	config.SupportsPerCredentialRevoke = "true"
	if grantType == aep.GrantTypeAPIKey {
		if _, err := configuredAPIKeyHeaders(config); err != nil {
			return GrantTypeDefinition{}, err
		}
	}
	return GrantTypeDefinition{
		Config: config, GrantType: grantType,
		Handler: &storedCredentialHandler[Credential]{config: config, grantType: grantType, issue: issue, store: store},
	}, nil
}

type storedCredentialHandler[Credential aep.BuiltInGrantResponse] struct {
	config    aep.GrantTypeConfig
	grantType aep.GrantType
	issue     BuiltInCredentialIssuer[Credential]
	store     ServiceCredentialStore
}

func (handler *storedCredentialHandler[Credential]) Grant(ctx context.Context, request aep.GrantRequest, grantContext GrantContext) (json.RawMessage, error) {
	credential, err := handler.issue(ctx, request, grantContext)
	if err != nil {
		return nil, err
	}
	if err := aep.ValidateBuiltInGrantResponse(handler.grantType, credential); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(credential)
	if err != nil {
		return nil, err
	}
	parsed, err := aep.ParseBuiltInGrantResponse(handler.grantType, encoded)
	if err != nil {
		return nil, err
	}
	if err := validateIssuedCredentialConfig(parsed, handler.config); err != nil {
		return nil, err
	}
	record, err := serviceCredentialRecord(grantContext.AgentDID, parsed, grantContext.Now)
	if err != nil {
		return nil, err
	}
	if err := handler.store.SaveCredential(ctx, record); err != nil {
		return nil, err
	}
	return encoded, nil
}

func validateIssuedCredentialConfig(credential aep.BuiltInGrantResponse, config aep.GrantTypeConfig) error {
	apiKey, ok := credential.(aep.APIKeyGrantResponse)
	if !ok {
		return nil
	}
	headerNames, err := configuredAPIKeyHeaders(config)
	if err != nil || headerNames == nil {
		return err
	}
	for _, header := range headerNames {
		if strings.EqualFold(header, apiKey.Header) {
			return nil
		}
	}
	return errors.New("AEP issued API-key header is not advertised by the Service")
}

func configuredAPIKeyHeaders(config aep.GrantTypeConfig) ([]string, error) {
	raw, found := config.Additional["header_names"]
	if !found {
		return nil, nil
	}
	var headerNames []string
	if err := json.Unmarshal(raw, &headerNames); err != nil || headerNames == nil {
		return nil, errors.New("AEP API-key header_names configuration is invalid")
	}
	seen := make(map[string]struct{}, len(headerNames))
	for _, header := range headerNames {
		canonical := strings.ToLower(header)
		if !aep.IsHTTPFieldName(header) {
			return nil, errors.New("AEP API-key header_names configuration contains an invalid HTTP field name")
		}
		if _, found := seen[canonical]; found {
			return nil, errors.New("AEP API-key header_names configuration contains a duplicate field name")
		}
		seen[canonical] = struct{}{}
	}
	return headerNames, nil
}

func (handler *storedCredentialHandler[Credential]) Revoke(ctx context.Context, request aep.RevokeRequest, revokeContext RevokeContext) error {
	if request.CredentialID != "" {
		return handler.store.RevokeCredential(ctx, revokeContext.AgentDID, handler.grantType, request.CredentialID, revokeContext.Now)
	}
	return handler.store.RevokeGrantType(ctx, revokeContext.AgentDID, handler.grantType, revokeContext.Now)
}

func (handler *storedCredentialHandler[Credential]) AuthenticateCredential(ctx context.Context, input CredentialAuthenticationInput) (*AuthenticatedPrincipal, error) {
	match, err := handler.store.AuthenticateCredential(ctx, handler.grantType, input)
	if err != nil || match == nil {
		return nil, err
	}
	if match.AgentDID == "" || match.CredentialID == "" || !match.ExpiresAt.After(input.Now) || match.GrantType != handler.grantType {
		return nil, errors.New("AEP credential store returned an invalid match")
	}
	return &AuthenticatedPrincipal{
		AgentDID: match.AgentDID, AuthenticationKind: AuthenticationKindSessionCredential,
		AuthenticationMethod: aep.AuthenticationMethod(handler.grantType), CredentialID: match.CredentialID,
		GrantType: handler.grantType, Scopes: append([]string(nil), match.Scopes...),
	}, nil
}

func (handler *storedCredentialHandler[Credential]) HasCredentialPresentation(ctx context.Context, input CredentialAuthenticationInput) (bool, error) {
	return handler.store.HasCredentialPresentation(ctx, handler.grantType, input)
}

func serviceCredentialRecord(agentDID string, credential aep.BuiltInGrantResponse, createdAt time.Time) (ServiceCredentialRecord, error) {
	if agentDID == "" || createdAt.IsZero() {
		return ServiceCredentialRecord{}, errors.New("AEP issued credential requires an Agent DID and issuance time")
	}
	credentialID, expiresAt, err := builtInCredentialMetadata(credential)
	if err != nil {
		return ServiceCredentialRecord{}, err
	}
	expiry, err := time.Parse(time.RFC3339, expiresAt)
	if err != nil || !expiry.After(createdAt) {
		return ServiceCredentialRecord{}, errors.New("AEP issued credential must expire after issuance")
	}
	return ServiceCredentialRecord{
		AgentDID: agentDID, CreatedAt: createdAt, Credential: credential, CredentialID: credentialID,
		ExpiresAt: expiry, GrantType: credential.GrantType(),
	}, nil
}

func builtInCredentialMetadata(credential aep.BuiltInGrantResponse) (string, string, error) {
	switch value := credential.(type) {
	case aep.OAuthBearerGrantResponse:
		return value.CredentialID, value.ExpiresAt, nil
	case aep.APIKeyGrantResponse:
		return value.CredentialID, value.ExpiresAt, nil
	case aep.BasicGrantResponse:
		return value.CredentialID, value.ExpiresAt, nil
	default:
		return "", "", errors.New("AEP credential store requires a built-in credential")
	}
}

type memoryServiceCredentialRecord struct {
	agentDID     string
	credentialID string
	expiresAt    time.Time
	grantType    aep.GrantType
	header       string
	revokedAt    time.Time
	scopes       []string
	verifier     [sha256.Size]byte
}

type memoryServiceCredentialStore struct {
	mu      sync.RWMutex
	records map[string]memoryServiceCredentialRecord
}

func NewMemoryServiceCredentialStore() ServiceCredentialStore {
	return &memoryServiceCredentialStore{records: make(map[string]memoryServiceCredentialRecord)}
}

func (store *memoryServiceCredentialStore) SaveCredential(ctx context.Context, record ServiceCredentialRecord) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	stored, err := memoryCredentialRecord(record)
	if err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if _, found := store.records[record.CredentialID]; found {
		return errors.New("AEP credential identifier has already been issued")
	}
	for _, existing := range store.records {
		if existing.grantType == stored.grantType && existing.header == stored.header && subtle.ConstantTimeCompare(existing.verifier[:], stored.verifier[:]) == 1 {
			return errors.New("AEP credential secret has already been issued")
		}
	}
	store.records[record.CredentialID] = stored
	return nil
}

func (store *memoryServiceCredentialStore) AuthenticateCredential(ctx context.Context, grantType aep.GrantType, input CredentialAuthenticationInput) (*CredentialMatch, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	presentations := credentialPresentations(grantType, input.Headers)
	if grantType == aep.GrantTypeAPIKey {
		headers := make(map[string]struct{})
		for _, record := range store.records {
			if record.grantType == grantType {
				headers[record.header] = struct{}{}
			}
		}
		for header := range headers {
			presentations = append(presentations, apiKeyPresentations(input.Headers, header)...)
		}
	}
	if len(presentations) != 1 {
		return nil, nil
	}
	for _, record := range store.records {
		if record.grantType != grantType || record.header != presentations[0].header || !record.revokedAt.IsZero() || !record.expiresAt.After(input.Now) {
			continue
		}
		candidate := sha256.Sum256([]byte(presentations[0].value))
		if subtle.ConstantTimeCompare(candidate[:], record.verifier[:]) == 1 {
			return &CredentialMatch{
				AgentDID: record.agentDID, CredentialID: record.credentialID, ExpiresAt: record.expiresAt, GrantType: record.grantType,
				Scopes: append([]string(nil), record.scopes...),
			}, nil
		}
	}
	return nil, nil
}

func (store *memoryServiceCredentialStore) HasCredentialPresentation(ctx context.Context, grantType aep.GrantType, input CredentialAuthenticationInput) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if grantType != aep.GrantTypeAPIKey {
		return len(credentialPresentations(grantType, input.Headers)) != 0, nil
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	for _, record := range store.records {
		if record.grantType == grantType && len(headerValues(input.Headers, record.header)) != 0 {
			return true, nil
		}
	}
	for _, values := range input.Headers {
		for _, value := range values {
			candidate := sha256.Sum256([]byte(value))
			for _, record := range store.records {
				if record.grantType == grantType && subtle.ConstantTimeCompare(candidate[:], record.verifier[:]) == 1 {
					return true, nil
				}
			}
		}
	}
	return false, nil
}

func (store *memoryServiceCredentialStore) RevokeCredential(ctx context.Context, agentDID string, grantType aep.GrantType, credentialID string, revokedAt time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if revokedAt.IsZero() {
		return errors.New("AEP credential revocation requires a time")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	record, found := store.records[credentialID]
	if found && record.agentDID == agentDID && record.grantType == grantType {
		record.revokedAt = revokedAt
		store.records[credentialID] = record
	}
	return nil
}

func (store *memoryServiceCredentialStore) RevokeGrantType(ctx context.Context, agentDID string, grantType aep.GrantType, revokedAt time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if revokedAt.IsZero() {
		return errors.New("AEP credential revocation requires a time")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	for credentialID, record := range store.records {
		if record.agentDID == agentDID && record.grantType == grantType {
			record.revokedAt = revokedAt
			store.records[credentialID] = record
		}
	}
	return nil
}

func memoryCredentialRecord(record ServiceCredentialRecord) (memoryServiceCredentialRecord, error) {
	if record.AgentDID == "" || record.CredentialID == "" || record.CreatedAt.IsZero() || !record.ExpiresAt.After(record.CreatedAt) || record.GrantType == "" || record.Credential == nil {
		return memoryServiceCredentialRecord{}, errors.New("AEP credential store received an invalid record")
	}
	if err := aep.ValidateBuiltInGrantResponse(record.GrantType, record.Credential); err != nil {
		return memoryServiceCredentialRecord{}, err
	}
	encoded, err := json.Marshal(record.Credential)
	if err != nil {
		return memoryServiceCredentialRecord{}, err
	}
	credential, err := aep.ParseBuiltInGrantResponse(record.GrantType, encoded)
	if err != nil {
		return memoryServiceCredentialRecord{}, err
	}
	credentialID, expiresAt, err := builtInCredentialMetadata(credential)
	credentialExpiry, expiryErr := time.Parse(time.RFC3339, expiresAt)
	if err != nil || expiryErr != nil || credentialID != record.CredentialID || !credentialExpiry.Equal(record.ExpiresAt) {
		return memoryServiceCredentialRecord{}, errors.New("AEP credential record metadata does not match its credential")
	}
	stored := memoryServiceCredentialRecord{
		agentDID: record.AgentDID, credentialID: record.CredentialID, expiresAt: record.ExpiresAt,
		grantType: record.GrantType,
	}
	var secret string
	switch credential := credential.(type) {
	case aep.OAuthBearerGrantResponse:
		secret, stored.header, stored.scopes = credential.AccessToken, "Authorization", append([]string(nil), credential.Scopes...)
	case aep.APIKeyGrantResponse:
		secret, stored.header, stored.scopes = credential.APIKey, http.CanonicalHeaderKey(credential.Header), append([]string(nil), credential.Scopes...)
	case aep.BasicGrantResponse:
		secret = base64.StdEncoding.EncodeToString([]byte(credential.Username + ":" + credential.Password))
		stored.header = "Authorization"
		stored.scopes = append([]string(nil), credential.Scopes...)
	default:
		return memoryServiceCredentialRecord{}, errors.New("AEP credential store requires a built-in credential")
	}
	stored.verifier = sha256.Sum256([]byte(secret))
	return stored, nil
}

type credentialPresentation struct {
	header string
	value  string
}

func credentialPresentations(grantType aep.GrantType, headers http.Header) []credentialPresentation {
	if grantType == aep.GrantTypeAPIKey {
		return nil
	}
	values := headerValues(headers, "Authorization")
	result := make([]credentialPresentation, 0, len(values))
	for _, value := range values {
		parsed, err := aep.ParseProtectedResourceAuthorization(value, aep.ProtectedResourceStandard)
		if err != nil {
			continue
		}
		expected := aep.CredentialSchemeBearer
		if grantType == aep.GrantTypeBasic {
			expected = aep.CredentialSchemeBasic
		}
		if parsed.Scheme == expected {
			result = append(result, credentialPresentation{header: "Authorization", value: parsed.Credentials})
		}
	}
	return result
}

func apiKeyPresentations(headers http.Header, header string) []credentialPresentation {
	values := headerValues(headers, header)
	result := make([]credentialPresentation, len(values))
	for index, value := range values {
		result[index] = credentialPresentation{header: http.CanonicalHeaderKey(header), value: value}
	}
	return result
}
