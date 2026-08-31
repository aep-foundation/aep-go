package service

import (
	"context"
	"errors"

	aep "github.com/aep-foundation/aep-go"
)

type DIDWebVerifierOptions struct {
	HTTPClient aep.HTTPDoer
}

func NewDIDWebAssertionVerifier(options DIDWebVerifierOptions) AssertionVerifier {
	return func(ctx context.Context, assertion string, verification AssertionVerificationContext) (aep.ClientAssertionClaims, error) {
		decoded, err := aep.DecodeJWTUnverified(assertion)
		if err != nil {
			return aep.ClientAssertionClaims{}, err
		}
		issuer, ok := decoded.Payload["iss"].(string)
		if !ok || issuer == "" {
			return aep.ClientAssertionClaims{}, errors.New("AEP client assertion issuer is invalid")
		}
		keyID, ok := decoded.Header["kid"].(string)
		if !ok || keyID == "" {
			return aep.ClientAssertionClaims{}, errors.New("AEP client assertion key ID is invalid")
		}
		key, err := aep.ResolveDIDWebPublicKey(ctx, aep.ResolveDIDWebPublicKeyOptions{
			AllowInsecureLoopback: verification.AllowInsecureLoopback,
			DID:                   issuer,
			Client:                options.HTTPClient,
			KeyID:                 keyID,
		})
		if err != nil {
			return aep.ClientAssertionClaims{}, err
		}
		return aep.VerifyClientAssertion(ctx, assertion, aep.VerifyClientAssertionOptions{
			Algorithms:            verification.SigningAlgorithms,
			AllowInsecureLoopback: verification.AllowInsecureLoopback,
			Audience:              verification.ServiceDID,
			ClockTolerance:        verification.ClockTolerance,
			CurrentTime:           verification.CurrentTime,
			Key:                   key,
			Operation:             verification.Operation,
			Resource:              verification.Resource,
		})
	}
}
