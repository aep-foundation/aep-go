package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"slices"
	"strings"
	"time"

	aep "github.com/aep-foundation/aep-go"
)

func (service *Service) Enroll(ctx context.Context, body []byte, options CommandOptions) (Result[aep.EnrollResponse], error) {
	claims, recognized, err := service.authenticateAssertion(ctx, options, aep.AssertionEnroll, "")
	if err != nil {
		return Result[aep.EnrollResponse]{}, err
	}
	if !recognized {
		return problemResult[aep.EnrollResponse](aep.ErrorNotRecognized, "Not recognized", http.StatusUnauthorized), nil
	}
	request, err := aep.ParseEnrollRequest(body)
	if err != nil || request.AgentDID != claims.Subject || !claimValuesWithinLimits(request.Claims, service.claimValueLimits) || !validIdempotencyKey(options.IdempotencyKey) || (request.IdempotencyKey != "" && request.IdempotencyKey != options.IdempotencyKey) {
		return problemResult[aep.EnrollResponse](aep.ErrorInvalidRequest, "Invalid request", http.StatusBadRequest), nil
	}
	return executeIdempotent(service, ctx, claims.Subject, IdempotentEnroll, options.IdempotencyKey, request, aep.ParseEnrollResponse, func() (Result[aep.EnrollResponse], error) {
		record, _, createErr := service.enrollmentStore.FindOrCreateEnrollment(ctx, claims.Subject, func() (EnrollmentRecord, error) {
			var required []aep.ClaimName
			if service.document.Claims != nil {
				required = service.document.Claims.Required
			}
			missing := aep.MissingRequiredClaimNames(required, request.Claims)
			if len(missing) != 0 {
				return EnrollmentRecord{}, requirementsUnmetError{requirements: missing}
			}
			now := service.clock()
			decision, policyErr := service.enrollmentPolicy.DecideEnrollment(ctx, request, EnrollmentPolicyContext{Now: now})
			if policyErr != nil {
				return EnrollmentRecord{}, policyErr
			}
			if decision.Status == "" {
				decision.Status = aep.EnrollmentActive
			}
			candidate := enrollmentResponse(decision.Status, decision.OwnerActionRequired, decision.VerificationPending, decision.RequirementsPending)
			if err := aep.ValidateEnrollResponse(candidate); err != nil {
				return EnrollmentRecord{}, err
			}
			identifier, identifierErr := service.identifier()
			if identifierErr != nil || identifier == "" {
				if identifierErr != nil {
					return EnrollmentRecord{}, identifierErr
				}
				return EnrollmentRecord{}, errors.New("AEP enrollment identifier provider returned an empty identifier")
			}
			claimValues, cloneErr := cloneClaimValues(request.Claims)
			if cloneErr != nil {
				return EnrollmentRecord{}, cloneErr
			}
			return EnrollmentRecord{
				AgentDID: claims.Subject, Claims: claimValues, CreatedAt: now, EnrollmentID: identifier,
				OwnerActionRequired: decision.OwnerActionRequired, RequirementsPending: append([]string(nil), decision.RequirementsPending...),
				Since: now, Status: aep.AgentStatus(decision.Status), UpdatedAt: now, VerificationPending: append([]string(nil), decision.VerificationPending...),
			}, nil
		})
		if createErr != nil {
			var unmet requirementsUnmetError
			if errors.As(createErr, &unmet) {
				result := problemResult[aep.EnrollResponse](aep.ErrorRequirementsUnmet, "Requirements unmet", http.StatusUnprocessableEntity)
				result.Problem.RequirementsPending = make([]string, len(unmet.requirements))
				for index, requirement := range unmet.requirements {
					result.Problem.RequirementsPending[index] = string(requirement)
				}
				return result, nil
			}
			return Result[aep.EnrollResponse]{}, createErr
		}
		response, lifecycle := enrollmentResult(record)
		if lifecycle != nil {
			return *lifecycle, nil
		}
		if err := aep.ValidateEnrollResponse(response); err != nil {
			return Result[aep.EnrollResponse]{}, err
		}
		return successResult(http.StatusOK, response), nil
	})
}

type requirementsUnmetError struct {
	requirements []aep.ClaimName
}

func (requirementsUnmetError) Error() string {
	return "AEP enrollment requirements are unmet"
}

func (service *Service) Status(ctx context.Context, options CommandOptions) (Result[aep.StatusResponse], error) {
	claims, recognized, err := service.authenticateAssertion(ctx, options, aep.AssertionStatus, "")
	if err != nil {
		return Result[aep.StatusResponse]{}, err
	}
	if !recognized {
		return problemResult[aep.StatusResponse](aep.ErrorNotRecognized, "Not recognized", http.StatusUnauthorized), nil
	}
	record, err := service.enrollmentStore.FindEnrollment(ctx, claims.Subject)
	if err != nil {
		return Result[aep.StatusResponse]{}, err
	}
	if record == nil {
		return problemResult[aep.StatusResponse](aep.ErrorNotRecognized, "Not recognized", http.StatusUnauthorized), nil
	}
	response := statusResponse(*record)
	if err := aep.ValidateStatusResponse(response); err != nil {
		return Result[aep.StatusResponse]{}, err
	}
	return successResult(http.StatusOK, response), nil
}

func (service *Service) Grant(ctx context.Context, body []byte, options CommandOptions) (Result[json.RawMessage], error) {
	claims, recognized, err := service.authenticateAssertion(ctx, options, aep.AssertionGrant, "")
	if err != nil {
		return Result[json.RawMessage]{}, err
	}
	if !recognized {
		return problemResult[json.RawMessage](aep.ErrorNotRecognized, "Not recognized", http.StatusUnauthorized), nil
	}
	request, err := aep.ParseGrantRequest(body)
	if err != nil || !validIdempotencyKey(options.IdempotencyKey) {
		return problemResult[json.RawMessage](aep.ErrorInvalidRequest, "Invalid request", http.StatusBadRequest), nil
	}
	return executeIdempotent(service, ctx, claims.Subject, IdempotentGrant, options.IdempotencyKey, request, parseJSONObject, func() (Result[json.RawMessage], error) {
		record, findErr := service.enrollmentStore.FindEnrollment(ctx, claims.Subject)
		if findErr != nil {
			return Result[json.RawMessage]{}, findErr
		}
		if record == nil {
			return problemResult[json.RawMessage](aep.ErrorNotRecognized, "Not recognized", http.StatusUnauthorized), nil
		}
		handler := service.grantHandlers[request.GrantType]
		if handler == nil {
			return problemResult[json.RawMessage](aep.ErrorUnsupportedGrantType, "Unsupported grant type", http.StatusBadRequest), nil
		}
		if record.Status != aep.AgentActive {
			return grantLifecycleProblem[json.RawMessage](*record), nil
		}
		enrollment, cloneErr := cloneEnrollment(*record)
		if cloneErr != nil {
			return Result[json.RawMessage]{}, cloneErr
		}
		credential, grantErr := handler.Grant(ctx, request, GrantContext{AgentDID: claims.Subject, Enrollment: enrollment, GrantType: request.GrantType, Now: service.clock()})
		if grantErr != nil {
			return Result[json.RawMessage]{}, grantErr
		}
		credential, grantErr = validatedCredentialObject(credential)
		if grantErr != nil {
			return Result[json.RawMessage]{}, grantErr
		}
		return successResult(http.StatusOK, credential), nil
	})
}

func (service *Service) Revoke(ctx context.Context, body []byte, options CommandOptions) (Result[aep.RevokeResponse], error) {
	claims, recognized, err := service.authenticateAssertion(ctx, options, aep.AssertionRevoke, "")
	if err != nil {
		return Result[aep.RevokeResponse]{}, err
	}
	if !recognized {
		return problemResult[aep.RevokeResponse](aep.ErrorNotRecognized, "Not recognized", http.StatusUnauthorized), nil
	}
	request, err := aep.ParseRevokeRequest(body)
	if err != nil || !validIdempotencyKey(options.IdempotencyKey) {
		return problemResult[aep.RevokeResponse](aep.ErrorInvalidRequest, "Invalid request", http.StatusBadRequest), nil
	}
	return executeIdempotent(service, ctx, claims.Subject, IdempotentRevoke, options.IdempotencyKey, request, aep.ParseRevokeResponse, func() (Result[aep.RevokeResponse], error) {
		record, findErr := service.enrollmentStore.FindEnrollment(ctx, claims.Subject)
		if findErr != nil {
			return Result[aep.RevokeResponse]{}, findErr
		}
		if record == nil {
			return problemResult[aep.RevokeResponse](aep.ErrorNotRecognized, "Not recognized", http.StatusUnauthorized), nil
		}
		if request.GrantType != "" {
			if service.grantHandlers[request.GrantType] == nil {
				return problemResult[aep.RevokeResponse](aep.ErrorUnsupportedGrantType, "Unsupported grant type", http.StatusBadRequest), nil
			}
			if request.CredentialID != "" {
				config := service.document.Commands.GrantTypesConfig[string(request.GrantType)]
				if config.SupportsPerCredentialRevoke != "true" {
					return problemResult[aep.RevokeResponse](aep.ErrorInvalidRequest, "Invalid request", http.StatusBadRequest), nil
				}
			}
		}
		enrollment, cloneErr := cloneEnrollment(*record)
		if cloneErr != nil {
			return Result[aep.RevokeResponse]{}, cloneErr
		}
		if request.AllGrantTypes == "true" {
			now := service.clock()
			grantTypes := make([]aep.GrantType, 0, len(service.grantHandlers))
			for grantType := range service.grantHandlers {
				grantTypes = append(grantTypes, grantType)
			}
			slices.Sort(grantTypes)
			for _, grantType := range grantTypes {
				if err := service.grantHandlers[grantType].Revoke(ctx, request, RevokeContext{AgentDID: claims.Subject, Enrollment: enrollment, GrantType: grantType, Now: now}); err != nil {
					return Result[aep.RevokeResponse]{}, err
				}
			}
		} else {
			handler := service.grantHandlers[request.GrantType]
			if err := handler.Revoke(ctx, request, RevokeContext{AgentDID: claims.Subject, Enrollment: enrollment, GrantType: request.GrantType, Now: service.clock()}); err != nil {
				return Result[aep.RevokeResponse]{}, err
			}
		}
		return successResult(http.StatusOK, aep.RevokeResponse{}), nil
	})
}

func (service *Service) authenticateAssertion(ctx context.Context, options CommandOptions, operation aep.AssertionOperation, resource string) (aep.ClientAssertionClaims, bool, error) {
	if options.ClientAssertion == "" {
		return aep.ClientAssertionClaims{}, false, nil
	}
	now := service.clock()
	claims, err := service.verifier(ctx, options.ClientAssertion, AssertionVerificationContext{
		AllowInsecureLoopback: service.clientAssertion.AllowInsecureLoopback,
		ClockTolerance:        service.clientAssertion.ClockSkew, CurrentTime: now, IdempotencyKey: options.IdempotencyKey,
		Operation: operation, Resource: resource, ServiceDID: service.document.Service.DID,
		SigningAlgorithms: append([]aep.SigningAlgorithm(nil), service.document.Core.SigningAlgorithms...),
	})
	if err != nil || !service.validAssertion(options.ClientAssertion, claims, operation, resource, now) {
		return aep.ClientAssertionClaims{}, false, nil
	}
	skewSeconds := int64(service.clientAssertion.ClockSkew / time.Second)
	if claims.ExpiresAt > math.MaxInt64-skewSeconds {
		return aep.ClientAssertionClaims{}, false, nil
	}
	consumed, err := service.replayStore.ConsumeReplay(ctx, ReplayRecord{ExpiresAt: claims.ExpiresAt + skewSeconds, JWTID: claims.JWTID, Subject: claims.Subject}, now.Unix())
	if err != nil {
		return aep.ClientAssertionClaims{}, false, err
	}
	if !consumed {
		return aep.ClientAssertionClaims{}, false, nil
	}
	return claims, true, nil
}

func (service *Service) validAssertion(assertion string, claims aep.ClientAssertionClaims, operation aep.AssertionOperation, resource string, now time.Time) bool {
	if aep.ValidateClientAssertionClaimsWithOptions(claims, aep.ClientAssertionValidationOptions{AllowInsecureLoopback: service.clientAssertion.AllowInsecureLoopback}) != nil {
		return false
	}
	if claims.Issuer != claims.Subject || claims.Audience != service.document.Service.DID || claims.Operation != operation || claims.Resource != resource {
		return false
	}
	method := identityMethod(claims.Subject)
	if !slices.Contains(service.document.Identity.Methods, method) {
		return false
	}
	decoded, err := aep.DecodeJWTUnverified(assertion)
	if err != nil {
		return false
	}
	algorithm, algorithmOK := decoded.Header["alg"].(string)
	typeValue, typeOK := decoded.Header["typ"].(string)
	keyID, keyOK := decoded.Header["kid"].(string)
	keyDID, _, _ := strings.Cut(keyID, "#")
	if !algorithmOK || !slices.Contains(service.document.Core.SigningAlgorithms, aep.SigningAlgorithm(algorithm)) || !typeOK || typeValue != "JWT" || !keyOK || keyDID != claims.Subject {
		return false
	}
	nowSeconds := now.Unix()
	skewSeconds := int64(service.clientAssertion.ClockSkew / time.Second)
	maximumLifetime := int64(service.clientAssertion.MaximumLifetime / time.Second)
	if claims.ExpiresAt <= claims.IssuedAt || claims.IssuedAt > math.MaxInt64-maximumLifetime || claims.ExpiresAt > claims.IssuedAt+maximumLifetime {
		return false
	}
	issuedDeadline := nowSeconds
	if nowSeconds <= math.MaxInt64-skewSeconds {
		issuedDeadline += skewSeconds
	} else {
		issuedDeadline = math.MaxInt64
	}
	expiryDeadline := nowSeconds
	if nowSeconds >= math.MinInt64+skewSeconds {
		expiryDeadline -= skewSeconds
	} else {
		expiryDeadline = math.MinInt64
	}
	return claims.IssuedAt <= issuedDeadline && claims.ExpiresAt > expiryDeadline
}

func identityMethod(did string) aep.IdentityMethod {
	parts := strings.SplitN(did, ":", 3)
	if len(parts) < 3 || parts[0] != "did" || parts[1] == "" {
		return ""
	}
	return aep.IdentityMethod("did:" + parts[1])
}

func executeIdempotent[Body any](service *Service, ctx context.Context, agentDID string, command IdempotentCommand, key string, request any, parse func([]byte) (Body, error), execute func() (Result[Body], error)) (Result[Body], error) {
	canonical, err := json.Marshal(request)
	if err != nil {
		return Result[Body]{}, err
	}
	digest := sha256.Sum256(canonical)
	result, err := service.idempotencyStore.ExecuteIdempotent(ctx, IdempotencyInput{
		AgentDID: agentDID, Command: command, IdempotencyKey: key, RequestHash: "sha256:" + hex.EncodeToString(digest[:]),
	}, func() (StoredResponse, error) {
		created, executeErr := execute()
		if executeErr != nil {
			return StoredResponse{}, executeErr
		}
		return storeResult(created, service.clock())
	})
	if err != nil {
		return Result[Body]{}, err
	}
	if result.State == IdempotencyConflict {
		return problemResult[Body](aep.ErrorIdempotencyConflict, "Idempotency conflict", http.StatusConflict), nil
	}
	return parseStoredResult(result.Response, parse)
}

func storeResult[Body any](result Result[Body], createdAt time.Time) (StoredResponse, error) {
	value := any(result.Body)
	if result.Problem != nil {
		value = *result.Problem
	}
	body, err := json.Marshal(value)
	if err != nil {
		return StoredResponse{}, err
	}
	return StoredResponse{Body: body, ContentType: result.ContentType, CreatedAt: createdAt, Headers: cloneHeader(result.Headers), Status: result.Status}, nil
}

func parseStoredResult[Body any](response StoredResponse, parse func([]byte) (Body, error)) (Result[Body], error) {
	if response.ContentType == aep.ProblemMediaType {
		problem, err := aep.ParseProblemDetails(response.Body)
		if err != nil {
			return Result[Body]{}, err
		}
		return Result[Body]{ContentType: response.ContentType, Headers: cloneHeader(response.Headers), Problem: &problem, Status: response.Status}, nil
	}
	body, err := parse(response.Body)
	if err != nil {
		return Result[Body]{}, err
	}
	return Result[Body]{Body: body, ContentType: response.ContentType, Headers: cloneHeader(response.Headers), Status: response.Status}, nil
}

func successResult[Body any](status int, body Body) Result[Body] {
	return Result[Body]{Body: body, ContentType: aep.MediaType, Status: status}
}

func problemResult[Body any](code aep.ErrorCode, title string, status int) Result[Body] {
	problem := aep.NewProblemDetails(code, title, status)
	result := Result[Body]{ContentType: aep.ProblemMediaType, Problem: &problem, Status: status}
	if status == http.StatusUnauthorized {
		result.Headers = make(http.Header)
		result.Headers.Set("WWW-Authenticate", fmt.Sprintf(`AEP reason=%q`, code))
	}
	return result
}

func lifecycleProblem[Body any](code aep.ErrorCode, title string, status int, record EnrollmentRecord) Result[Body] {
	result := problemResult[Body](code, title, status)
	result.Problem.RequirementsPending = append([]string(nil), record.RequirementsPending...)
	result.Problem.VerificationPending = append([]string(nil), record.VerificationPending...)
	if record.OwnerActionRequired {
		value := "true"
		result.Problem.OwnerActionRequired = &value
	}
	return result
}

func enrollmentResponse(status aep.EnrollmentStatus, ownerAction bool, verification []string, requirements []string) aep.EnrollResponse {
	response := aep.EnrollResponse{Status: status, VerificationPending: append([]string(nil), verification...), RequirementsPending: append([]string(nil), requirements...)}
	if ownerAction {
		value := "true"
		response.OwnerActionRequired = &value
	}
	return response
}

func enrollmentResult(record EnrollmentRecord) (aep.EnrollResponse, *Result[aep.EnrollResponse]) {
	switch record.Status {
	case aep.AgentActive, aep.AgentPending, aep.AgentRejected:
		return enrollmentResponse(aep.EnrollmentStatus(record.Status), record.OwnerActionRequired, record.VerificationPending, record.RequirementsPending), nil
	case aep.AgentSuspended:
		result := lifecycleProblem[aep.EnrollResponse](aep.ErrorIdentitySuspended, "Identity suspended", http.StatusForbidden, record)
		return aep.EnrollResponse{}, &result
	case aep.AgentTerminated:
		result := lifecycleProblem[aep.EnrollResponse](aep.ErrorIdentityTerminated, "Identity terminated", http.StatusForbidden, record)
		return aep.EnrollResponse{}, &result
	case aep.AgentUnavailable:
		result := lifecycleProblem[aep.EnrollResponse](aep.ErrorIdentityUnavailable, "Identity unavailable", http.StatusForbidden, record)
		return aep.EnrollResponse{}, &result
	default:
		result := problemResult[aep.EnrollResponse](aep.ErrorEnrollmentFailed, "Enrollment failed", http.StatusBadRequest)
		return aep.EnrollResponse{}, &result
	}
}

func grantLifecycleProblem[Body any](record EnrollmentRecord) Result[Body] {
	switch record.Status {
	case aep.AgentPending:
		return lifecycleProblem[Body](aep.ErrorVerificationPending, "Verification pending", http.StatusForbidden, record)
	case aep.AgentSuspended:
		return lifecycleProblem[Body](aep.ErrorIdentitySuspended, "Identity suspended", http.StatusForbidden, record)
	case aep.AgentTerminated:
		return lifecycleProblem[Body](aep.ErrorIdentityTerminated, "Identity terminated", http.StatusForbidden, record)
	case aep.AgentUnavailable:
		return lifecycleProblem[Body](aep.ErrorIdentityUnavailable, "Identity unavailable", http.StatusForbidden, record)
	default:
		return problemResult[Body](aep.ErrorEnrollmentFailed, "Enrollment failed", http.StatusBadRequest)
	}
}

func statusResponse(record EnrollmentRecord) aep.StatusResponse {
	response := aep.StatusResponse{
		Status: record.Status, VerificationPending: append([]string(nil), record.VerificationPending...),
		RequirementsPending: append([]string(nil), record.RequirementsPending...), Since: record.Since.UTC().Format(time.RFC3339),
	}
	if record.OwnerActionRequired {
		value := "true"
		response.OwnerActionRequired = &value
	}
	return response
}

func validIdempotencyKey(value string) bool {
	return strings.TrimSpace(value) != ""
}

func validatedCredentialObject(value json.RawMessage) (json.RawMessage, error) {
	object, err := parseJSONObject(value)
	if err != nil {
		return nil, err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(object, &fields); err != nil {
		return nil, err
	}
	var credentialID string
	if err := json.Unmarshal(fields["credential_id"], &credentialID); err != nil || credentialID == "" {
		return nil, errors.New("AEP Grant response requires a stable credential_id")
	}
	return object, nil
}

func parseJSONObject(value []byte) (json.RawMessage, error) {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(value, &object); err != nil || object == nil {
		return nil, errors.New("AEP Grant response must be a JSON object")
	}
	return append(json.RawMessage(nil), value...), nil
}

func cloneClaimValues(value *aep.ClaimValues) (*aep.ClaimValues, error) {
	if value == nil {
		return nil, nil
	}
	data, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	copy, err := aep.ParseClaimValues(data)
	if err != nil {
		return nil, err
	}
	return &copy, nil
}
