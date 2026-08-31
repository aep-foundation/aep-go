package platform

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	aep "github.com/aep-foundation/aep-go"
)

const maximumListLimit = 100

func New(options Options) (*Platform, error) {
	if options.Authorizer == nil {
		return nil, errors.New("AEP Platform authorizer is required")
	}
	if options.KeyStore == nil {
		return nil, errors.New("AEP Platform key store is required")
	}
	if options.ServiceDIDResolver == nil {
		return nil, errors.New("AEP Platform Service DID resolver is required")
	}
	if options.DIDHost == "" || options.DIDURLTemplate == "" {
		return nil, errors.New("AEP Platform DID host and URL template are required")
	}
	if _, err := CreateServiceScopedAgentDID(options.DIDHost, options.DIDPathPrefix, "validation"); err != nil {
		return nil, err
	}
	signingAlgorithms := slices.Clone(options.SigningAlgorithms)
	if len(signingAlgorithms) == 0 || hasDuplicateAlgorithms(signingAlgorithms) {
		return nil, errors.New("AEP Platform requires unique signing algorithms")
	}
	for _, algorithm := range signingAlgorithms {
		if algorithm != aep.SigningAlgorithmEdDSA && algorithm != aep.SigningAlgorithmES256 {
			return nil, fmt.Errorf("unsupported AEP Platform signing algorithm %q", algorithm)
		}
	}
	maximumLifetime := options.MaximumLifetime
	if maximumLifetime == 0 {
		maximumLifetime = aep.MaxAssertionLifetime
	}
	if maximumLifetime <= 0 || maximumLifetime > aep.MaxAssertionLifetime || maximumLifetime%time.Second != 0 {
		return nil, errors.New("AEP Platform maximum assertion lifetime must be a whole number of seconds from 1 through 300")
	}
	defaultLifetime := options.DefaultLifetime
	if defaultLifetime == 0 {
		defaultLifetime = aep.MaxAssertionLifetime
	}
	if defaultLifetime <= 0 || defaultLifetime > maximumLifetime || defaultLifetime%time.Second != 0 {
		return nil, errors.New("AEP Platform default assertion lifetime must be a whole number of seconds within the configured maximum")
	}
	if options.HostedVerification && options.ReplayStore == nil {
		return nil, errors.New("AEP Platform hosted verification requires a replay store")
	}
	discovery, err := createDiscoveryDocument(options, defaultLifetime)
	if err != nil {
		return nil, err
	}
	clock := options.Clock
	if clock == nil {
		clock = time.Now
	}
	identityStore := options.IdentityStore
	if identityStore == nil {
		identityStore = NewMemoryIdentityStore()
	}
	idempotencyStore := options.IdempotencyStore
	if idempotencyStore == nil {
		idempotencyStore = newMemoryIdempotencyStore(clock)
	}
	identifier := options.Identifier
	if identifier == nil {
		identifier = randomIdentifier
	}
	agentDIDIDGenerator := options.AgentDIDIDGenerator
	if agentDIDIDGenerator == nil {
		agentDIDIDGenerator = randomIdentifier
	}
	lifecyclePolicy := options.LifecyclePolicy
	if lifecyclePolicy == nil {
		lifecyclePolicy = defaultLifecyclePolicy{}
	}
	return &Platform{
		agentDIDIDGenerator: agentDIDIDGenerator,
		authorizer:          options.Authorizer,
		clock:               clock,
		defaultLifetime:     defaultLifetime,
		didHost:             options.DIDHost,
		didPathPrefix:       options.DIDPathPrefix,
		didURLTemplate:      options.DIDURLTemplate,
		discovery:           discovery,
		hostedVerification:  options.HostedVerification,
		identifier:          identifier,
		idempotencyStore:    idempotencyStore,
		identityStore:       identityStore,
		keyStore:            options.KeyStore,
		lifecyclePolicy:     lifecyclePolicy,
		maximumLifetime:     maximumLifetime,
		replayStore:         options.ReplayStore,
		serviceDIDResolver:  options.ServiceDIDResolver,
		signHandler:         options.SignHandler,
		signingAlgorithms:   signingAlgorithms,
	}, nil
}

func (platform *Platform) Discovery() Result[DiscoveryDocument] {
	return successResult(http.StatusOK, cloneDiscoveryDocument(platform.discovery), http.Header{"Cache-Control": []string{"max-age=300"}})
}

func (platform *Platform) GetDIDDocument(ctx context.Context, agentDIDID string) (Result[DIDDocument], error) {
	identity, err := platform.identityStore.FindIdentityByAgentDIDID(ctx, agentDIDID)
	if err != nil {
		return Result[DIDDocument]{}, err
	}
	if identity == nil {
		return problemResult[DIDDocument](http.StatusNotFound, aep.ErrorNotRecognized, "Identity not recognized."), nil
	}
	method, err := platform.keyStore.DIDVerificationMethod(ctx, cloneIdentityRecord(*identity))
	if err != nil {
		return Result[DIDDocument]{}, err
	}
	document, err := CreateDIDDocument(*identity, method)
	if err != nil {
		return Result[DIDDocument]{}, err
	}
	result := successResult(http.StatusOK, document, http.Header{"Cache-Control": []string{"max-age=300"}})
	result.ContentType = DIDMediaType
	return result, nil
}

func (platform *Platform) GetIdentity(ctx context.Context, agentIdentityID string, requestContext RequestContext) (Result[AgentIdentity], error) {
	identity, err := platform.authorizedIdentity(ctx, agentIdentityID, AuthorizationRequest{Operation: AuthorizeGetIdentity}, requestContext)
	if err != nil {
		return Result[AgentIdentity]{}, err
	}
	if identity == nil {
		return problemResult[AgentIdentity](http.StatusNotFound, aep.ErrorNotRecognized, "Identity not recognized."), nil
	}
	return successResult(http.StatusOK, agentIdentityFromRecord(*identity), nil), nil
}

func (platform *Platform) List(ctx context.Context, query IdentityListQuery, requestContext RequestContext) (Result[AgentIdentityListResponse], error) {
	if query.Limit < 0 || query.Limit > maximumListLimit || query.Offset < 0 || query.ServiceDID != "" && !isDID(query.ServiceDID) || query.Status != "" && !isManagedAgentStatus(query.Status) {
		return problemResult[AgentIdentityListResponse](http.StatusBadRequest, aep.ErrorInvalidRequest, "Identity list query is invalid."), nil
	}
	if query.Limit == 0 {
		query.Limit = maximumListLimit
	}
	request := AuthorizationRequest{ListQuery: cloneListQuery(&query), Operation: AuthorizeListIdentities}
	authorized, err := platform.authorizer.Authorize(ctx, request, requestContext)
	if err != nil {
		return Result[AgentIdentityListResponse]{}, err
	}
	if !authorized || requestContext.Principal == "" {
		return problemResult[AgentIdentityListResponse](http.StatusNotFound, aep.ErrorNotRecognized, "Identity not recognized."), nil
	}
	listed, err := platform.identityStore.ListIdentities(ctx, requestContext.Principal, query)
	if err != nil {
		return Result[AgentIdentityListResponse]{}, err
	}
	data := make([]AgentIdentity, 0, len(listed.Identities))
	for _, identity := range listed.Identities {
		data = append(data, agentIdentityFromRecord(identity))
	}
	body := AgentIdentityListResponse{
		Count: strconv.Itoa(len(data)),
		Data:  data,
		Total: strconv.Itoa(listed.Total),
	}
	return successResult(http.StatusOK, body, nil), nil
}

func (platform *Platform) Provision(ctx context.Context, request ProvisionRequest, requestContext RequestContext) (Result[AgentIdentity], error) {
	if !isDID(request.ServiceDID) {
		return problemResult[AgentIdentity](http.StatusBadRequest, aep.ErrorInvalidRequest, "service_did must be a DID."), nil
	}
	return executeIdempotent(ctx, IdempotentProvision, request, requestContext, platform.idempotencyStore, func() (Result[AgentIdentity], error) {
		authorized, err := platform.authorizer.Authorize(ctx, AuthorizationRequest{Operation: AuthorizeProvision, ProvisionRequest: cloneProvisionRequest(&request)}, requestContext)
		if err != nil {
			return Result[AgentIdentity]{}, err
		}
		if !authorized {
			return problemResult[AgentIdentity](http.StatusNotFound, aep.ErrorNotRecognized, "Identity not recognized."), nil
		}
		resolved, err := platform.serviceDIDResolver.ResolveServiceDID(ctx, request.ServiceDID)
		if err != nil {
			return Result[AgentIdentity]{}, err
		}
		if !resolved {
			return problemResult[AgentIdentity](http.StatusBadRequest, aep.ErrorInvalidRequest, "Service DID could not be resolved."), nil
		}
		identity, _, err := platform.identityStore.FindOrCreateIdentity(ctx, requestContext.Principal, request.ServiceDID, func() (IdentityRecord, error) {
			return platform.createIdentity(ctx, requestContext.Principal, request.ServiceDID)
		})
		if err != nil {
			return Result[AgentIdentity]{}, err
		}
		return successResult(http.StatusOK, agentIdentityFromRecord(identity), nil), nil
	})
}

func (platform *Platform) Sign(ctx context.Context, agentIdentityID string, request SignRequest, requestContext RequestContext) (Result[SignResponse], error) {
	lifetime, err := platform.validateSignRequest(request)
	if err != nil {
		return problemResult[SignResponse](http.StatusBadRequest, aep.ErrorInvalidRequest, err.Error()), nil
	}
	material := struct {
		AgentIdentityID string      `json:"agent_identity_id"`
		Request         SignRequest `json:"request"`
	}{AgentIdentityID: agentIdentityID, Request: request}
	return executeIdempotent(ctx, IdempotentSign, material, requestContext, platform.idempotencyStore, func() (Result[SignResponse], error) {
		identity, err := platform.authorizedIdentity(ctx, agentIdentityID, AuthorizationRequest{Operation: AuthorizeSign, SignRequest: cloneSignRequest(&request)}, requestContext)
		if err != nil {
			return Result[SignResponse]{}, err
		}
		if identity == nil || identity.ServiceDID != request.ServiceDID {
			return problemResult[SignResponse](http.StatusNotFound, aep.ErrorNotRecognized, "Identity not recognized."), nil
		}
		allowed, err := platform.lifecyclePolicy.CanSign(ctx, cloneIdentityRecord(*identity), requestContext)
		if err != nil {
			return Result[SignResponse]{}, err
		}
		if !allowed {
			return problemResult[SignResponse](http.StatusForbidden, lifecycleErrorCode(identity.Status), "Identity cannot sign."), nil
		}
		if platform.signHandler != nil {
			handled, err := platform.signHandler(ctx, SignHandlerInput{Identity: cloneIdentityRecord(*identity), Request: cloneSignRequestValue(request)}, requestContext)
			if err != nil {
				return Result[SignResponse]{}, err
			}
			if handled != nil {
				if err := validateSignResult(*handled, *identity, request); err != nil {
					return Result[SignResponse]{}, err
				}
				return cloneSignResult(*handled), nil
			}
		}
		now := requestContext.Now
		if now.IsZero() {
			now = platform.clock()
		}
		claims := aep.ClientAssertionClaims{
			Audience:  request.ServiceDID,
			ExpiresAt: now.Add(lifetime).Unix(),
			IssuedAt:  now.Unix(),
			Issuer:    identity.AgentDID,
			JWTID:     request.JWTID,
			Operation: request.Operation,
			Resource:  request.Resource,
			Subject:   identity.AgentDID,
		}
		assertion, err := platform.keyStore.Sign(ctx, cloneIdentityRecord(*identity), claims)
		if err != nil {
			return Result[SignResponse]{}, err
		}
		body := SignResponse{
			AgentDID:        identity.AgentDID,
			ClientAssertion: assertion,
			ExpiresAt:       now.Add(lifetime).UTC().Format(time.RFC3339),
			IssuedAt:        now.UTC().Format(time.RFC3339),
			JWTID:           request.JWTID,
			PlatformContext: cloneRawMap(request.PlatformContext),
			ServiceDID:      request.ServiceDID,
			Status:          SignCompleted,
		}
		return successResult(http.StatusOK, body, nil), nil
	})
}

func (platform *Platform) UpdateIdentity(ctx context.Context, agentIdentityID string, request LifecycleRequest, requestContext RequestContext) (Result[AgentIdentity], error) {
	if !isManagedAgentStatus(request.Status) {
		return problemResult[AgentIdentity](http.StatusBadRequest, aep.ErrorInvalidRequest, "Lifecycle status is invalid."), nil
	}
	identity, err := platform.authorizedIdentity(ctx, agentIdentityID, AuthorizationRequest{LifecycleRequest: cloneLifecycleRequest(&request), Operation: AuthorizeUpdateIdentity}, requestContext)
	if err != nil {
		return Result[AgentIdentity]{}, err
	}
	if identity == nil {
		return problemResult[AgentIdentity](http.StatusNotFound, aep.ErrorNotRecognized, "Identity not recognized."), nil
	}
	allowed, err := platform.lifecyclePolicy.CanTransition(ctx, cloneIdentityRecord(*identity), request.Status, requestContext)
	if err != nil {
		return Result[AgentIdentity]{}, err
	}
	if !allowed {
		return problemResult[AgentIdentity](http.StatusForbidden, lifecycleErrorCode(identity.Status), "Lifecycle transition rejected."), nil
	}
	updated, err := platform.identityStore.UpdateIdentity(ctx, agentIdentityID, request.Status, platform.clock())
	if err != nil {
		return Result[AgentIdentity]{}, err
	}
	if updated == nil {
		return problemResult[AgentIdentity](http.StatusNotFound, aep.ErrorNotRecognized, "Identity not recognized."), nil
	}
	return successResult(http.StatusOK, agentIdentityFromRecord(*updated), nil), nil
}

func (platform *Platform) createIdentity(ctx context.Context, principal string, serviceDID string) (IdentityRecord, error) {
	agentIdentityID, err := platform.identifier()
	if err != nil {
		return IdentityRecord{}, err
	}
	if agentIdentityID == "" {
		return IdentityRecord{}, errors.New("AEP Platform identity generator returned an empty identifier")
	}
	if !strings.HasPrefix(agentIdentityID, "pai_") {
		agentIdentityID = "pai_" + agentIdentityID
	}
	agentDIDID, err := platform.agentDIDIDGenerator()
	if err != nil {
		return IdentityRecord{}, err
	}
	agentDID, err := CreateServiceScopedAgentDID(platform.didHost, platform.didPathPrefix, agentDIDID)
	if err != nil {
		return IdentityRecord{}, err
	}
	didDocumentURL, err := renderDIDURL(platform.didURLTemplate, agentDIDID)
	if err != nil {
		return IdentityRecord{}, err
	}
	now := platform.clock()
	identity := IdentityRecord{
		AgentDID:          agentDID,
		AgentDIDID:        agentDIDID,
		AgentIdentityID:   agentIdentityID,
		CreatedAt:         now,
		DIDDocumentURL:    didDocumentURL,
		KeyID:             agentDID,
		Principal:         principal,
		ServiceDID:        serviceDID,
		SigningAlgorithms: slices.Clone(platform.signingAlgorithms),
		Status:            ManagedAgentActive,
		UpdatedAt:         now,
	}
	if err := validateIdentityRecord(identity); err != nil {
		return IdentityRecord{}, err
	}
	if err := platform.keyStore.CreateKey(ctx, cloneIdentityRecord(identity)); err != nil {
		return IdentityRecord{}, err
	}
	return identity, nil
}

func (platform *Platform) authorizedIdentity(ctx context.Context, agentIdentityID string, request AuthorizationRequest, requestContext RequestContext) (*IdentityRecord, error) {
	identity, err := platform.identityStore.GetIdentity(ctx, agentIdentityID)
	if err != nil || identity == nil {
		return identity, err
	}
	copy := cloneIdentityRecord(*identity)
	request.Identity = &copy
	authorized, err := platform.authorizer.Authorize(ctx, request, requestContext)
	if err != nil {
		return nil, err
	}
	if !authorized || requestContext.Principal == "" || identity.Principal != requestContext.Principal {
		return nil, nil
	}
	return identity, nil
}

func (platform *Platform) validateSignRequest(request SignRequest) (time.Duration, error) {
	if request.JWTID == "" || !isAssertionOperation(request.Operation) || !isDID(request.ServiceDID) {
		return 0, errors.New("AEP Platform signing request is invalid")
	}
	if request.Operation == aep.AssertionAuthenticate {
		if !isAbsoluteHTTPSURL(request.Resource) {
			return 0, errors.New("resource must be an absolute HTTPS URL for authenticate")
		}
	} else if request.Resource != "" {
		return 0, errors.New("resource is only permitted for authenticate")
	}
	if request.LifetimeSeconds == "" {
		return platform.defaultLifetime, nil
	}
	seconds, err := strconv.ParseInt(request.LifetimeSeconds, 10, 64)
	if err != nil || seconds <= 0 {
		return 0, errors.New("lifetime_seconds must be a positive integer string")
	}
	if seconds > int64(platform.maximumLifetime/time.Second) || seconds > int64(aep.MaxAssertionLifetime/time.Second) {
		return 0, errors.New("lifetime_seconds exceeds the configured maximum")
	}
	return time.Duration(seconds) * time.Second, nil
}

func executeIdempotent[Body any](ctx context.Context, operation IdempotentOperation, material any, requestContext RequestContext, store IdempotencyStore, execute func() (Result[Body], error)) (Result[Body], error) {
	if requestContext.IdempotencyKey == "" || requestContext.Principal == "" {
		return problemResult[Body](http.StatusBadRequest, aep.ErrorInvalidRequest, "Idempotency-Key and authenticated principal are required."), nil
	}
	encoded, err := json.Marshal(material)
	if err != nil {
		return Result[Body]{}, err
	}
	hash := sha256.Sum256(encoded)
	result, err := store.ExecuteIdempotent(ctx, IdempotencyInput{
		IdempotencyKey: requestContext.IdempotencyKey,
		Operation:      operation,
		Principal:      requestContext.Principal,
		RequestHash:    hex.EncodeToString(hash[:]),
	}, func() (StoredResponse, error) {
		response, err := execute()
		if err != nil {
			return StoredResponse{}, err
		}
		return storeResult(response)
	})
	if err != nil {
		return Result[Body]{}, err
	}
	if result.State == IdempotencyConflict {
		return problemResult[Body](http.StatusConflict, aep.ErrorIdempotencyConflict, "Idempotency key conflicts with an earlier request."), nil
	}
	return restoreResult[Body](result.Response)
}

func storeResult[Body any](result Result[Body]) (StoredResponse, error) {
	value := any(result.Body)
	if result.Problem != nil {
		value = result.Problem
	}
	body, err := json.Marshal(value)
	if err != nil {
		return StoredResponse{}, err
	}
	return StoredResponse{Body: body, ContentType: result.ContentType, Headers: cloneHeader(result.Headers), Status: result.Status}, nil
}

func restoreResult[Body any](stored StoredResponse) (Result[Body], error) {
	result := Result[Body]{ContentType: stored.ContentType, Headers: cloneHeader(stored.Headers), Status: stored.Status}
	if stored.ContentType == aep.ProblemMediaType {
		var problem aep.ProblemDetails
		if err := json.Unmarshal(stored.Body, &problem); err != nil {
			return Result[Body]{}, err
		}
		result.Problem = &problem
		return result, nil
	}
	if err := json.Unmarshal(stored.Body, &result.Body); err != nil {
		return Result[Body]{}, err
	}
	return result, nil
}

func successResult[Body any](status int, body Body, headers http.Header) Result[Body] {
	return Result[Body]{Body: body, ContentType: aep.MediaType, Headers: cloneHeader(headers), Status: status}
}

func problemResult[Body any](status int, code aep.ErrorCode, title string) Result[Body] {
	problem := aep.NewProblemDetails(code, title, status)
	return Result[Body]{ContentType: aep.ProblemMediaType, Problem: &problem, Status: status}
}

func agentIdentityFromRecord(record IdentityRecord) AgentIdentity {
	return AgentIdentity{
		AgentDID:          record.AgentDID,
		AgentIdentityID:   record.AgentIdentityID,
		CreatedAt:         record.CreatedAt.UTC().Format(time.RFC3339),
		DIDDocumentURL:    record.DIDDocumentURL,
		KeyID:             record.KeyID,
		ServiceDID:        record.ServiceDID,
		SigningAlgorithms: slices.Clone(record.SigningAlgorithms),
		Status:            record.Status,
		UpdatedAt:         record.UpdatedAt.UTC().Format(time.RFC3339),
	}
}

func isManagedAgentStatus(status ManagedAgentStatus) bool {
	return status == ManagedAgentActive || status == ManagedAgentRevoked || status == ManagedAgentSuspended || status == ManagedAgentTerminated
}

func isAssertionOperation(operation aep.AssertionOperation) bool {
	return operation == aep.AssertionEnroll || operation == aep.AssertionGrant || operation == aep.AssertionRevoke || operation == aep.AssertionStatus || operation == aep.AssertionAuthenticate
}

func isDID(value string) bool {
	if !strings.HasPrefix(value, "did:") {
		return false
	}
	method, identifier, found := strings.Cut(strings.TrimPrefix(value, "did:"), ":")
	if !found || method == "" || identifier == "" {
		return false
	}
	for _, character := range method {
		if character < 'a' || character > 'z' {
			if character < '0' || character > '9' {
				return false
			}
		}
	}
	for index := 0; index < len(identifier); index++ {
		character := identifier[index]
		if isDIDIdentifierCharacter(character) {
			continue
		}
		if character != '%' || index+2 >= len(identifier) || !isHex(identifier[index+1]) || !isHex(identifier[index+2]) {
			return false
		}
		index += 2
	}
	return true
}

func isDIDIdentifierCharacter(character byte) bool {
	return character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || strings.ContainsRune("._:-!$&'()*+,;=", rune(character))
}

func isHex(character byte) bool {
	return character >= '0' && character <= '9' || character >= 'a' && character <= 'f' || character >= 'A' && character <= 'F'
}

func isAbsoluteHTTPSURL(value string) bool {
	parsed, err := url.Parse(value)
	return err == nil && parsed.Scheme == "https" && parsed.Hostname() != "" && parsed.User == nil && parsed.Fragment == ""
}

func hasDuplicateAlgorithms(algorithms []aep.SigningAlgorithm) bool {
	seen := make(map[aep.SigningAlgorithm]struct{}, len(algorithms))
	for _, algorithm := range algorithms {
		if _, found := seen[algorithm]; found {
			return true
		}
		seen[algorithm] = struct{}{}
	}
	return false
}

func lifecycleErrorCode(status ManagedAgentStatus) aep.ErrorCode {
	if status == ManagedAgentTerminated {
		return aep.ErrorIdentityTerminated
	}
	if status == ManagedAgentSuspended || status == ManagedAgentRevoked {
		return aep.ErrorIdentitySuspended
	}
	return aep.ErrorIdentityUnavailable
}

func cloneHeader(header http.Header) http.Header {
	if header == nil {
		return nil
	}
	return header.Clone()
}

func cloneProvisionRequest(request *ProvisionRequest) *ProvisionRequest {
	copy := *request
	return &copy
}

func cloneListQuery(query *IdentityListQuery) *IdentityListQuery {
	copy := *query
	return &copy
}

func cloneSignRequest(request *SignRequest) *SignRequest {
	copy := cloneSignRequestValue(*request)
	return &copy
}

func cloneLifecycleRequest(request *LifecycleRequest) *LifecycleRequest {
	copy := *request
	return &copy
}

func cloneSignRequestValue(request SignRequest) SignRequest {
	copy := request
	copy.PlatformContext = cloneRawMap(request.PlatformContext)
	return copy
}

func cloneRawMap(value map[string]json.RawMessage) map[string]json.RawMessage {
	if value == nil {
		return nil
	}
	copy := make(map[string]json.RawMessage, len(value))
	for name, raw := range value {
		copy[name] = slices.Clone(raw)
	}
	return copy
}

func cloneSignResult(result Result[SignResponse]) Result[SignResponse] {
	copy := result
	copy.Body.PlatformContext = cloneRawMap(result.Body.PlatformContext)
	copy.Headers = cloneHeader(result.Headers)
	if result.Problem != nil {
		problem := *result.Problem
		copy.Problem = &problem
	}
	return copy
}

func validateSignResult(result Result[SignResponse], identity IdentityRecord, request SignRequest) error {
	if result.Problem != nil {
		if result.ContentType != aep.ProblemMediaType || result.Status != result.Problem.Status {
			return errors.New("AEP Platform sign handler returned an invalid Problem Details response")
		}
		return aep.ValidateProblemDetails(*result.Problem)
	}
	if result.Body.Status == SignPending {
		seconds, err := strconv.Atoi(result.Body.RetryAfterSeconds)
		if result.ContentType != aep.MediaType || result.Status != http.StatusAccepted || result.Headers.Get("Retry-After") != "" || err != nil || seconds < 1 || seconds > 300 {
			return errors.New("AEP Platform sign handler returned an invalid pending response")
		}
		return nil
	}
	issuedAt, issuedAtError := time.Parse(time.RFC3339, result.Body.IssuedAt)
	expiresAt, expiresAtError := time.Parse(time.RFC3339, result.Body.ExpiresAt)
	if result.Body.Status != SignCompleted || result.ContentType != aep.MediaType || result.Status != http.StatusOK || result.Body.AgentDID != identity.AgentDID || result.Body.ClientAssertion == "" || issuedAtError != nil || expiresAtError != nil || !expiresAt.After(issuedAt) || expiresAt.Sub(issuedAt) > aep.MaxAssertionLifetime || result.Body.JWTID != request.JWTID || result.Body.ServiceDID != request.ServiceDID {
		return errors.New("AEP Platform sign handler returned an invalid completed response")
	}
	return nil
}

func randomIdentifier() (string, error) {
	data := make([]byte, 16)
	if _, err := rand.Read(data); err != nil {
		return "", err
	}
	return hex.EncodeToString(data), nil
}

type defaultLifecyclePolicy struct{}

func (defaultLifecyclePolicy) CanSign(_ context.Context, identity IdentityRecord, _ RequestContext) (bool, error) {
	return identity.Status == ManagedAgentActive, nil
}

func (defaultLifecyclePolicy) CanTransition(context.Context, IdentityRecord, ManagedAgentStatus, RequestContext) (bool, error) {
	return true, nil
}

func (defaultLifecyclePolicy) CanVerify(_ context.Context, identity IdentityRecord, _ RequestContext) (bool, error) {
	return identity.Status == ManagedAgentActive, nil
}
