package platform

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	aep "github.com/aep-foundation/aep-go"
)

func (platform *Platform) Verify(ctx context.Context, request VerificationRequest, requestContext RequestContext) (Result[VerificationResponse], error) {
	if !platform.hostedVerification {
		return problemResult[VerificationResponse](http.StatusNotFound, aep.ErrorNotRecognized, "Hosted verification is not available."), nil
	}
	if err := validateVerificationRequest(request); err != nil {
		return problemResult[VerificationResponse](http.StatusBadRequest, aep.ErrorInvalidRequest, err.Error()), nil
	}
	return executeIdempotent(ctx, IdempotentHostedVerification, request, requestContext, platform.idempotencyStore, func() (Result[VerificationResponse], error) {
		return platform.verifyAssertion(ctx, request, requestContext)
	})
}

func (platform *Platform) verifyAssertion(ctx context.Context, request VerificationRequest, requestContext RequestContext) (Result[VerificationResponse], error) {
	unrecognized := successResult(http.StatusOK, VerificationResponse{
		Reason:     "not_recognized",
		ServiceDID: request.ServiceDID,
		Verified:   false,
	}, nil)
	decoded, err := aep.DecodeJWTUnverified(request.ClientAssertion)
	if err != nil {
		return unrecognized, nil
	}
	agentDID, valid := decoded.Payload["iss"].(string)
	subject, subjectValid := decoded.Payload["sub"].(string)
	keyID, keyIDValid := decoded.Header["kid"].(string)
	if !valid || !subjectValid || !keyIDValid || agentDID == "" || agentDID != subject || keyID != agentDID {
		return unrecognized, nil
	}
	identity, err := platform.identityStore.FindIdentityByAgentDID(ctx, agentDID)
	if err != nil {
		return Result[VerificationResponse]{}, err
	}
	if identity == nil || identity.ServiceDID != request.ServiceDID || identity.Principal != requestContext.Principal {
		return unrecognized, nil
	}
	authorizationRequest := AuthorizationRequest{
		Identity:            cloneIdentityPointer(identity),
		Operation:           AuthorizeVerify,
		VerificationRequest: cloneVerificationRequest(&request),
	}
	authorized, err := platform.authorizer.Authorize(ctx, authorizationRequest, requestContext)
	if err != nil {
		return Result[VerificationResponse]{}, err
	}
	if !authorized {
		return unrecognized, nil
	}
	allowed, err := platform.lifecyclePolicy.CanVerify(ctx, cloneIdentityRecord(*identity), requestContext)
	if err != nil {
		return Result[VerificationResponse]{}, err
	}
	if !allowed {
		return unrecognized, nil
	}
	key, err := platform.keyStore.VerificationKey(ctx, cloneIdentityRecord(*identity))
	if err != nil {
		return Result[VerificationResponse]{}, err
	}
	now := requestContext.Now
	if now.IsZero() {
		now = platform.clock()
	}
	claims, err := aep.VerifyClientAssertion(ctx, request.ClientAssertion, aep.VerifyClientAssertionOptions{
		Algorithms:  identity.SigningAlgorithms,
		Audience:    request.ServiceDID,
		CurrentTime: now,
		Issuer:      agentDID,
		Key:         key,
		Operation:   request.Operation,
		Resource:    request.Resource,
		Subject:     agentDID,
	})
	if err != nil || request.Operation != aep.AssertionAuthenticate && claims.Resource != "" {
		return unrecognized, nil
	}
	replayKey := fmt.Sprintf("%s\x00%s\x00%s\x00%s", request.ServiceDID, request.Operation, agentDID, claims.JWTID)
	consumed, err := platform.replayStore.ConsumeReplay(ctx, replayKey, time.Unix(claims.ExpiresAt, 0))
	if err != nil {
		return Result[VerificationResponse]{}, err
	}
	if !consumed {
		return unrecognized, nil
	}
	return successResult(http.StatusOK, VerificationResponse{
		AgentDID:        identity.AgentDID,
		AgentIdentityID: identity.AgentIdentityID,
		Operation:       request.Operation,
		Reason:          "verified",
		ServiceDID:      request.ServiceDID,
		Status:          identity.Status,
		Verified:        true,
	}, nil), nil
}

func validateVerificationRequest(request VerificationRequest) error {
	if request.ClientAssertion == "" || !isAssertionOperation(request.Operation) || !isDID(request.ServiceDID) {
		return errors.New("AEP Platform verification request is invalid")
	}
	if request.Operation == aep.AssertionAuthenticate {
		if !isAbsoluteHTTPSURL(request.Resource) {
			return errors.New("resource must be an absolute HTTPS URL for authenticate")
		}
	} else if request.Resource != "" {
		return errors.New("resource is only permitted for authenticate")
	}
	return nil
}

func cloneVerificationRequest(request *VerificationRequest) *VerificationRequest {
	copy := *request
	return &copy
}

func cloneIdentityPointer(identity *IdentityRecord) *IdentityRecord {
	copy := cloneIdentityRecord(*identity)
	return &copy
}
