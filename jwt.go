package aep

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
)

type SignClientAssertionOptions struct {
	Algorithm SigningAlgorithm
	Key       any
	KeyID     string
}

type ClientAssertionKeyResolver func(context.Context, jose.Header) (any, error)

type VerifyClientAssertionOptions struct {
	Algorithms     []SigningAlgorithm
	Audience       string
	ClockTolerance time.Duration
	CurrentTime    time.Time
	Issuer         string
	Key            any
	KeyResolver    ClientAssertionKeyResolver
	Operation      AssertionOperation
	Resource       string
	Subject        string
}

type DecodedJWT struct {
	Header  map[string]any
	Payload map[string]any
}

func SignClientAssertion(claims ClientAssertionClaims, options SignClientAssertionOptions) (string, error) {
	if err := ValidateClientAssertionClaims(claims); err != nil {
		return "", err
	}
	algorithm, err := joseAlgorithm(options.Algorithm)
	if err != nil {
		return "", err
	}
	if options.Key == nil {
		return "", errors.New("AEP client assertion signing key is required")
	}
	if err := validateAssertionKeyID(options.KeyID, claims); err != nil {
		return "", err
	}
	signerOptions := (&jose.SignerOptions{}).WithType("JWT")
	signerOptions.WithHeader(jose.HeaderKey("kid"), options.KeyID)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: algorithm, Key: options.Key}, signerOptions)
	if err != nil {
		return "", fmt.Errorf("create AEP client assertion signer: %w", err)
	}
	serialized, err := josejwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		return "", fmt.Errorf("sign AEP client assertion: %w", err)
	}
	return serialized, nil
}

func VerifyClientAssertion(ctx context.Context, assertion string, options VerifyClientAssertionOptions) (ClientAssertionClaims, error) {
	algorithms := options.Algorithms
	if len(algorithms) == 0 {
		algorithms = []SigningAlgorithm{SigningAlgorithmEdDSA, SigningAlgorithmES256}
	}
	allowed := make([]jose.SignatureAlgorithm, 0, len(algorithms))
	for _, algorithm := range algorithms {
		mapped, err := joseAlgorithm(algorithm)
		if err != nil {
			return ClientAssertionClaims{}, err
		}
		allowed = append(allowed, mapped)
	}
	token, err := josejwt.ParseSigned(assertion, allowed)
	if err != nil {
		return ClientAssertionClaims{}, fmt.Errorf("parse AEP client assertion: %w", err)
	}
	if len(token.Headers) != 1 {
		return ClientAssertionClaims{}, errors.New("AEP client assertion must contain exactly one signature")
	}
	header := token.Headers[0]
	if header.KeyID == "" {
		return ClientAssertionClaims{}, errors.New("AEP client assertion kid is required")
	}
	if headerType, ok := header.ExtraHeaders[jose.HeaderKey("typ")].(string); !ok || headerType != "JWT" {
		return ClientAssertionClaims{}, errors.New("AEP client assertion typ must be JWT")
	}
	key := options.Key
	if options.KeyResolver != nil {
		key, err = options.KeyResolver(ctx, header)
		if err != nil {
			return ClientAssertionClaims{}, fmt.Errorf("resolve AEP client assertion key: %w", err)
		}
	}
	if key == nil {
		return ClientAssertionClaims{}, errors.New("AEP client assertion verification key is required")
	}
	var claims ClientAssertionClaims
	if err := token.Claims(key, &claims); err != nil {
		return ClientAssertionClaims{}, fmt.Errorf("verify AEP client assertion: %w", err)
	}
	if err := ValidateClientAssertionClaims(claims); err != nil {
		return ClientAssertionClaims{}, err
	}
	if err := validateAssertionKeyID(header.KeyID, claims); err != nil {
		return ClientAssertionClaims{}, err
	}
	if options.Audience != "" && claims.Audience != options.Audience {
		return ClientAssertionClaims{}, errors.New("AEP client assertion audience does not match")
	}
	if options.Issuer != "" && claims.Issuer != options.Issuer {
		return ClientAssertionClaims{}, errors.New("AEP client assertion issuer does not match")
	}
	if options.Subject != "" && claims.Subject != options.Subject {
		return ClientAssertionClaims{}, errors.New("AEP client assertion subject does not match")
	}
	if options.Operation != "" && claims.Operation != options.Operation {
		return ClientAssertionClaims{}, errors.New("AEP client assertion operation does not match")
	}
	if options.Resource != "" && claims.Resource != options.Resource {
		return ClientAssertionClaims{}, errors.New("AEP client assertion resource does not match")
	}
	now := options.CurrentTime
	if now.IsZero() {
		now = time.Now()
	}
	if options.ClockTolerance < 0 {
		return ClientAssertionClaims{}, errors.New("AEP client assertion clock tolerance must not be negative")
	}
	nowSeconds := now.Unix()
	toleranceSeconds := int64(options.ClockTolerance / time.Second)
	if claims.IssuedAt > nowSeconds+toleranceSeconds || claims.ExpiresAt < nowSeconds-toleranceSeconds {
		return ClientAssertionClaims{}, errors.New("AEP client assertion is outside its validity window")
	}
	return claims, nil
}

func validateAssertionKeyID(keyID string, claims ClientAssertionClaims) error {
	if keyID == "" {
		return errors.New("AEP client assertion kid is required")
	}
	keyDID, _, _ := strings.Cut(keyID, "#")
	if keyDID != claims.Issuer || keyDID != claims.Subject {
		return errors.New("AEP client assertion kid must identify the Agent DID")
	}
	return nil
}

func DecodeJWTUnverified(assertion string) (DecodedJWT, error) {
	parts := strings.Split(assertion, ".")
	if len(parts) != 3 {
		return DecodedJWT{}, errors.New("invalid JWT")
	}
	header, err := decodeJWTPart(parts[0])
	if err != nil {
		return DecodedJWT{}, fmt.Errorf("decode JWT header: %w", err)
	}
	payload, err := decodeJWTPart(parts[1])
	if err != nil {
		return DecodedJWT{}, fmt.Errorf("decode JWT payload: %w", err)
	}
	return DecodedJWT{Header: header, Payload: payload}, nil
}

func joseAlgorithm(algorithm SigningAlgorithm) (jose.SignatureAlgorithm, error) {
	switch algorithm {
	case SigningAlgorithmEdDSA:
		return jose.EdDSA, nil
	case SigningAlgorithmES256:
		return jose.ES256, nil
	default:
		return "", fmt.Errorf("unsupported AEP signing algorithm %q", algorithm)
	}
}

func decodeJWTPart(value string) (map[string]any, error) {
	data, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return nil, err
	}
	var object map[string]any
	if err := json.Unmarshal(data, &object); err != nil {
		return nil, err
	}
	if object == nil {
		return nil, errors.New("expected a JSON object")
	}
	return object, nil
}
