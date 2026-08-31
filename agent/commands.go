package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"strings"
	"time"

	aep "github.com/aep-foundation/aep-go"
)

func (session *Session) Enroll(ctx context.Context, options EnrollOptions) (CommandResult[aep.EnrollResponse], error) {
	inspection, identity, signer, err := session.commandContext(ctx, aep.CommandEnroll)
	if err != nil {
		return CommandResult[aep.EnrollResponse]{}, err
	}
	var required []aep.ClaimName
	if inspection.Document.Claims != nil {
		required = inspection.Document.Claims.Required
	}
	missing := aep.MissingRequiredClaimNames(required, options.Claims)
	if len(missing) != 0 {
		return CommandResult[aep.EnrollResponse]{}, &ClaimRequirementsError{MissingRequiredClaimNames: append([]aep.ClaimName(nil), missing...)}
	}
	key, err := session.idempotencyKey(ctx, inspection, OperationKey{Command: aep.CommandEnroll}, options.IdempotencyKey)
	if err != nil {
		return CommandResult[aep.EnrollResponse]{}, err
	}
	requestBody := aep.EnrollRequest{AgentDID: identity.AgentDID, Claims: options.Claims, IdempotencyKey: key}
	if err := aep.ValidateEnrollRequest(requestBody); err != nil {
		return CommandResult[aep.EnrollResponse]{}, err
	}
	return executeCommand(session, ctx, inspection, identity, signer, aep.CommandEnroll, http.MethodPost, requestBody, key, aep.ParseEnrollResponse)
}

func (session *Session) Status(ctx context.Context) (CommandResult[aep.StatusResponse], error) {
	inspection, identity, signer, err := session.commandContext(ctx, aep.CommandStatus)
	if err != nil {
		return CommandResult[aep.StatusResponse]{}, err
	}
	return executeCommand(session, ctx, inspection, identity, signer, aep.CommandStatus, http.MethodGet, nil, "", aep.ParseStatusResponse)
}

func (session *Session) WaitForActive(ctx context.Context, options WaitOptions) (CommandResult[aep.StatusResponse], error) {
	interval := options.Interval
	if interval == 0 {
		interval = time.Second
	}
	if interval <= 0 {
		return CommandResult[aep.StatusResponse]{}, errors.New("AEP Status polling interval must be positive")
	}
	timeout := options.Timeout
	if timeout == 0 {
		timeout = session.client.requestTimeout
	}
	if timeout <= 0 {
		return CommandResult[aep.StatusResponse]{}, errors.New("AEP Status polling timeout must be positive")
	}
	waitContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	for {
		result, err := session.Status(waitContext)
		if err != nil {
			return CommandResult[aep.StatusResponse]{}, err
		}
		switch result.Body.Status {
		case aep.AgentActive:
			return result, nil
		case aep.AgentRejected, aep.AgentSuspended, aep.AgentTerminated:
			return result, &EnrollmentStateError{Status: result.Body.Status}
		}
		timer := time.NewTimer(interval)
		select {
		case <-waitContext.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return CommandResult[aep.StatusResponse]{}, waitContext.Err()
		case <-timer.C:
		}
	}
}

func (session *Session) Grant(ctx context.Context, options GrantOptions) (CommandResult[GrantResult], error) {
	inspection, identity, signer, err := session.existingCommandContext(ctx, aep.CommandGrant)
	if err != nil {
		return CommandResult[GrantResult]{}, err
	}
	grantType, err := selectGrantType(inspection.Document, options.GrantType, options.PreferredGrantTypes)
	if err != nil {
		return CommandResult[GrantResult]{}, err
	}
	if !containsCommand(inspection.Document.Commands.Supported, aep.CommandStatus) {
		return CommandResult[GrantResult]{}, errors.New("AEP Grant requires the Service to advertise Status")
	}
	status, err := executeCommand(session, ctx, inspection, identity, signer, aep.CommandStatus, http.MethodGet, nil, "", aep.ParseStatusResponse)
	if err != nil {
		return CommandResult[GrantResult]{}, err
	}
	if status.Body.Status != aep.AgentActive {
		return CommandResult[GrantResult]{}, &CommandError{Status: http.StatusUnauthorized, Text: "AEP Grant requires active enrollment"}
	}
	key, err := session.idempotencyKey(ctx, inspection, OperationKey{Command: aep.CommandGrant, GrantType: grantType}, options.IdempotencyKey)
	if err != nil {
		return CommandResult[GrantResult]{}, err
	}
	requestBody := aep.GrantRequest{GrantType: grantType, RequestedScopes: append([]string(nil), options.RequestedScopes...)}
	if err := aep.ValidateGrantRequest(requestBody); err != nil {
		return CommandResult[GrantResult]{}, err
	}
	result, err := executeCommand(session, ctx, inspection, identity, signer, aep.CommandGrant, http.MethodPost, requestBody, key, func(data []byte) (GrantResult, error) {
		raw := append(json.RawMessage(nil), data...)
		credential, parseErr := aep.ParseBuiltInGrantResponse(grantType, data)
		if parseErr != nil {
			if isBuiltInGrantType(grantType) {
				return GrantResult{}, parseErr
			}
			var object map[string]json.RawMessage
			if err := json.Unmarshal(data, &object); err != nil || object == nil {
				return GrantResult{}, errors.New("AEP Grant response must be a JSON object")
			}
			return GrantResult{GrantType: grantType, Raw: raw}, nil
		}
		return GrantResult{Credential: credential, GrantType: grantType, Raw: raw}, nil
	})
	if err != nil {
		return CommandResult[GrantResult]{}, err
	}
	if result.Body.Credential != nil {
		record, recordErr := credentialRecord(result.Body.Credential, result.Body.Raw, inspection, session.client.clock())
		if recordErr != nil {
			return CommandResult[GrantResult]{}, recordErr
		}
		if err := validateStoredCredential(record, inspection.Document.Service.DID, session.client.clock()); err != nil {
			return CommandResult[GrantResult]{}, err
		}
		if err := session.client.credentialStore.SaveCredential(ctx, record); err != nil {
			return CommandResult[GrantResult]{}, err
		}
	}
	return result, nil
}

func (session *Session) Revoke(ctx context.Context, options RevokeOptions) (CommandResult[aep.RevokeResponse], error) {
	if options.AllGrantTypes && (options.GrantType != "" || options.CredentialID != "") {
		return CommandResult[aep.RevokeResponse]{}, errors.New("AEP all-grant-types Revoke cannot include a grant type or credential ID")
	}
	inspection, identity, signer, err := session.commandContext(ctx, aep.CommandRevoke)
	if err != nil {
		return CommandResult[aep.RevokeResponse]{}, err
	}
	requestBody := aep.RevokeRequest{GrantType: options.GrantType, CredentialID: options.CredentialID}
	if options.AllGrantTypes {
		requestBody = aep.RevokeRequest{AllGrantTypes: "true"}
	}
	if err := aep.ValidateRevokeRequest(requestBody); err != nil {
		return CommandResult[aep.RevokeResponse]{}, err
	}
	if requestBody.CredentialID != "" {
		config, found := inspection.Document.Commands.GrantTypesConfig[string(requestBody.GrantType)]
		if !found || config.SupportsPerCredentialRevoke != "true" {
			return CommandResult[aep.RevokeResponse]{}, errors.New("AEP Service does not advertise per-credential Revoke")
		}
	}
	key, err := session.idempotencyKey(ctx, inspection, OperationKey{Command: aep.CommandRevoke, CredentialID: requestBody.CredentialID, GrantType: requestBody.GrantType}, options.IdempotencyKey)
	if err != nil {
		return CommandResult[aep.RevokeResponse]{}, err
	}
	result, err := executeCommand(session, ctx, inspection, identity, signer, aep.CommandRevoke, http.MethodPost, requestBody, key, aep.ParseRevokeResponse)
	if err != nil {
		return CommandResult[aep.RevokeResponse]{}, err
	}
	if err := session.deleteRevokedCredentials(ctx, inspection.Document.Service.DID, requestBody); err != nil {
		return CommandResult[aep.RevokeResponse]{}, err
	}
	return result, nil
}

func executeCommand[T any](session *Session, ctx context.Context, inspection Inspection, identity ServiceIdentity, signer AssertionSigner, command aep.Command, method string, body any, idempotencyKey string, parse func([]byte) (T, error)) (CommandResult[T], error) {
	commandURL, err := inspection.CommandURL(command)
	if err != nil {
		return CommandResult[T]{}, err
	}
	assertion, err := session.client.signAssertion(ctx, inspection, identity, signer, assertionOperation(command), nil)
	if err != nil {
		return CommandResult[T]{}, err
	}
	var encoded []byte
	if body != nil {
		encoded, err = json.Marshal(body)
		if err != nil {
			return CommandResult[T]{}, err
		}
	}
	requestContext, cancel := context.WithTimeout(ctx, session.client.requestTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(requestContext, method, commandURL.String(), bytes.NewReader(encoded))
	if err != nil {
		return CommandResult[T]{}, err
	}
	request.Header.Set("Accept", aep.MediaType)
	request.Header.Set("Authorization", aep.AuthorizationScheme+" "+assertion)
	if body != nil {
		request.Header.Set("Content-Type", aep.MediaType)
	}
	if idempotencyKey != "" {
		request.Header.Set("Idempotency-Key", idempotencyKey)
	}
	response, err := doWithoutRedirects(session.client.commandHTTPClient, request)
	if err != nil {
		return CommandResult[T]{}, err
	}
	defer response.Body.Close()
	data, err := readBounded(response.Body, session.client.maximumResponseBytes)
	if err != nil {
		return CommandResult[T]{}, err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return CommandResult[T]{}, commandError(response.StatusCode, data)
	}
	if !mediaTypeMatches(response.Header.Get("Content-Type"), aep.MediaType) {
		return CommandResult[T]{}, errors.New("AEP command response media type is invalid")
	}
	parsed, err := parse(data)
	if err != nil {
		return CommandResult[T]{}, err
	}
	return CommandResult[T]{Body: parsed, Status: response.StatusCode, URL: commandURL}, nil
}

func (session *Session) commandContext(ctx context.Context, command aep.Command) (Inspection, ServiceIdentity, AssertionSigner, error) {
	inspection, err := session.Inspect(ctx)
	if err != nil {
		return Inspection{}, ServiceIdentity{}, nil, err
	}
	if !containsCommand(inspection.Document.Commands.Supported, command) {
		return Inspection{}, ServiceIdentity{}, nil, fmt.Errorf("AEP Service does not advertise %s", command)
	}
	identity, err := session.resolveIdentity(ctx, inspection)
	if err != nil {
		return Inspection{}, ServiceIdentity{}, nil, err
	}
	signer, err := session.client.signerFor(ctx, identity)
	return inspection, identity, signer, err
}

func (session *Session) existingCommandContext(ctx context.Context, command aep.Command) (Inspection, ServiceIdentity, AssertionSigner, error) {
	inspection, err := session.Inspect(ctx)
	if err != nil {
		return Inspection{}, ServiceIdentity{}, nil, err
	}
	if !containsCommand(inspection.Document.Commands.Supported, command) {
		return Inspection{}, ServiceIdentity{}, nil, fmt.Errorf("AEP Service does not advertise %s", command)
	}
	identity, err := session.client.identityStore.FindIdentity(ctx, inspection.Document.Service.DID)
	if err != nil {
		return Inspection{}, ServiceIdentity{}, nil, err
	}
	if identity == nil {
		return Inspection{}, ServiceIdentity{}, nil, &CommandError{Status: http.StatusUnauthorized, Text: "AEP Grant requires an existing enrolled identity"}
	}
	if err := validateIdentityForInspection(*identity, inspection); err != nil {
		return Inspection{}, ServiceIdentity{}, nil, err
	}
	signer, err := session.client.signerFor(ctx, *identity)
	return inspection, *identity, signer, err
}

func (session *Session) Identity(ctx context.Context) (ServiceIdentity, error) {
	inspection, err := session.Inspect(ctx)
	if err != nil {
		return ServiceIdentity{}, err
	}
	return session.resolveIdentity(ctx, inspection)
}

func (session *Session) resolveIdentity(ctx context.Context, inspection Inspection) (ServiceIdentity, error) {
	session.identityMu.Lock()
	defer session.identityMu.Unlock()
	serviceDID := inspection.Document.Service.DID
	if session.identity != nil && session.identity.ServiceDID == serviceDID {
		if err := validateIdentityForInspection(*session.identity, inspection); err != nil {
			return ServiceIdentity{}, err
		}
		return cloneIdentity(*session.identity), nil
	}
	session.identity = nil
	session.client.identityMu.Lock()
	defer session.client.identityMu.Unlock()
	existing, err := session.client.identityStore.FindIdentity(ctx, serviceDID)
	if err != nil {
		return ServiceIdentity{}, err
	}
	if existing != nil {
		if err := validateIdentityForInspection(*existing, inspection); err != nil {
			return ServiceIdentity{}, err
		}
		stored := cloneIdentity(*existing)
		session.identity = &stored
		return cloneIdentity(stored), nil
	}
	document, err := cloneInspectDocument(inspection.Document)
	if err != nil {
		return ServiceIdentity{}, err
	}
	identity, err := session.client.identityProvider.GetOrCreateIdentity(ctx, IdentityRequest{
		Inspect: document, ServiceDID: serviceDID, ServiceURL: cloneURL(session.serviceURL),
	})
	if err != nil {
		return ServiceIdentity{}, err
	}
	if err := validateIdentityForInspection(identity, inspection); err != nil {
		return ServiceIdentity{}, err
	}
	if err := session.client.identityStore.SaveIdentity(ctx, identity); err != nil {
		return ServiceIdentity{}, err
	}
	stored := cloneIdentity(identity)
	session.identity = &stored
	return cloneIdentity(stored), nil
}

func (client *Client) signAssertion(ctx context.Context, inspection Inspection, identity ServiceIdentity, signer AssertionSigner, operation aep.AssertionOperation, resource *url.URL) (string, error) {
	if err := validateIdentityForInspection(identity, inspection); err != nil {
		return "", err
	}
	now := client.clock().Unix()
	lifetime := int64(client.assertionLifetime / time.Second)
	if now > math.MaxInt64-lifetime {
		return "", errors.New("AEP assertion expiration exceeds the supported time range")
	}
	jti, err := client.jti()
	if err != nil {
		return "", err
	}
	claims := aep.ClientAssertionClaims{
		Audience:  inspection.Document.Service.DID,
		ExpiresAt: now + lifetime,
		IssuedAt:  now,
		Issuer:    identity.AgentDID,
		JWTID:     jti,
		Operation: operation,
		Subject:   identity.AgentDID,
	}
	if resource != nil {
		claims.Resource = resource.String()
	}
	if err := aep.ValidateClientAssertionClaimsWithOptions(claims, aep.ClientAssertionValidationOptions{AllowInsecureLoopback: client.allowInsecureLoopback}); err != nil {
		return "", err
	}
	algorithms := intersectAlgorithms(identity.SigningAlgorithms, inspection.Document.Core.SigningAlgorithms)
	if len(algorithms) == 0 {
		return "", errors.New("AEP identity and Service have no compatible signing algorithm")
	}
	if signer == nil {
		return "", errors.New("AEP identity provider returned no assertion signer")
	}
	assertion, err := signer(ctx, claims, algorithms)
	if err != nil {
		return "", err
	}
	if assertion == "" {
		return "", errors.New("AEP assertion signer returned an empty assertion")
	}
	return assertion, nil
}

func (client *Client) signerFor(ctx context.Context, identity ServiceIdentity) (AssertionSigner, error) {
	return client.identityProvider.SignerFor(ctx, cloneIdentity(identity))
}

func validateServiceIdentityRecord(identity ServiceIdentity, serviceDID string) error {
	if !strings.HasPrefix(identity.AgentDID, "did:") || identity.IdentityMethod == "" || identity.ServiceDID != serviceDID || len(identity.SigningAlgorithms) == 0 {
		return errors.New("AEP identity provider returned an invalid Service-scoped identity")
	}
	if identity.IdentityMethod != aep.IdentityMethodDIDWeb {
		return errors.New("AEP Agent identity method has no supported origin binding")
	}
	if !strings.HasPrefix(identity.AgentDID, "did:web:") {
		return errors.New("AEP Agent DID does not match its identity method")
	}
	return nil
}

func validateIdentityForInspection(identity ServiceIdentity, inspection Inspection) error {
	if err := validateServiceIdentityRecord(identity, inspection.Document.Service.DID); err != nil {
		return err
	}
	if !containsIdentityMethod(inspection.Document.Identity.Methods, identity.IdentityMethod) {
		return errors.New("AEP Service does not advertise the Agent identity method")
	}
	if len(intersectAlgorithms(identity.SigningAlgorithms, inspection.Document.Core.SigningAlgorithms)) == 0 {
		return errors.New("AEP identity and Service have no compatible signing algorithm")
	}
	return nil
}

func (session *Session) idempotencyKey(ctx context.Context, inspection Inspection, operation OperationKey, provided string) (string, error) {
	if provided != "" {
		return provided, nil
	}
	operation.ServiceDID = inspection.Document.Service.DID
	operation.ServiceURL = session.serviceURL.String()
	key, err := session.client.idempotencyKeys.CreateKey(ctx, operation)
	if err != nil {
		return "", err
	}
	if key == "" {
		return "", errors.New("AEP idempotency key provider returned an empty key")
	}
	return key, nil
}

func commandError(status int, data []byte) error {
	problem, err := aep.ParseProblemDetails(data)
	if err != nil {
		return &CommandError{Status: status, Text: fmt.Sprintf("AEP command failed with HTTP %d", status)}
	}
	return &CommandError{Problem: &problem, Status: status, Text: fmt.Sprintf("AEP command failed with HTTP %d: %s", status, problem.Code)}
}

func assertionOperation(command aep.Command) aep.AssertionOperation {
	switch command {
	case aep.CommandEnroll:
		return aep.AssertionEnroll
	case aep.CommandGrant:
		return aep.AssertionGrant
	case aep.CommandRevoke:
		return aep.AssertionRevoke
	case aep.CommandStatus:
		return aep.AssertionStatus
	default:
		return ""
	}
}

func containsCommand(values []aep.Command, expected aep.Command) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func selectGrantType(document aep.InspectDocument, selected aep.GrantType, preferred []aep.GrantType) (aep.GrantType, error) {
	if selected != "" {
		if containsGrantType(document.Commands.GrantTypes, selected) {
			return selected, nil
		}
		return "", ErrNoCompatibleGrantType
	}
	if len(preferred) == 0 {
		preferred = document.Commands.GrantTypes
	}
	for _, value := range preferred {
		if containsGrantType(document.Commands.GrantTypes, value) {
			return value, nil
		}
	}
	return "", ErrNoCompatibleGrantType
}

func containsGrantType(values []aep.GrantType, expected aep.GrantType) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func containsIdentityMethod(values []aep.IdentityMethod, expected aep.IdentityMethod) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func intersectAlgorithms(first []aep.SigningAlgorithm, second []aep.SigningAlgorithm) []aep.SigningAlgorithm {
	result := make([]aep.SigningAlgorithm, 0)
	for _, candidate := range second {
		for _, available := range first {
			if candidate == available {
				result = append(result, candidate)
				break
			}
		}
	}
	return result
}

func isBuiltInGrantType(value aep.GrantType) bool {
	return value == aep.GrantTypeOAuthBearer || value == aep.GrantTypeAPIKey || value == aep.GrantTypeBasic
}

func credentialRecord(credential aep.BuiltInGrantResponse, raw json.RawMessage, inspection Inspection, issuedAt time.Time) (CredentialRecord, error) {
	var credentialID string
	var expiresAt string
	switch value := credential.(type) {
	case aep.OAuthBearerGrantResponse:
		credentialID, expiresAt = value.CredentialID, value.ExpiresAt
	case aep.APIKeyGrantResponse:
		credentialID, expiresAt = value.CredentialID, value.ExpiresAt
	case aep.BasicGrantResponse:
		credentialID, expiresAt = value.CredentialID, value.ExpiresAt
	default:
		return CredentialRecord{}, errors.New("unsupported AEP built-in credential")
	}
	expiry, err := time.Parse(time.RFC3339, expiresAt)
	if err != nil {
		return CredentialRecord{}, err
	}
	return CredentialRecord{
		CredentialID: credentialID, ExpiresAt: expiry, GrantType: credential.GrantType(), IssuedAt: issuedAt,
		Payload: append(json.RawMessage(nil), raw...), ServiceDID: inspection.Document.Service.DID,
		ServiceURL: inspection.ServiceURL.String(),
	}, nil
}

func (session *Session) deleteRevokedCredentials(ctx context.Context, serviceDID string, selector aep.RevokeRequest) error {
	records, err := session.client.credentialStore.ListCredentials(ctx, serviceDID)
	if err != nil {
		return err
	}
	for _, record := range records {
		matches := selector.AllGrantTypes == "true" || selector.CredentialID == record.CredentialID || (selector.CredentialID == "" && selector.GrantType == record.GrantType)
		if matches {
			if err := session.client.credentialStore.DeleteCredential(ctx, serviceDID, record.CredentialID); err != nil {
				return err
			}
		}
	}
	return nil
}
