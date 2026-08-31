package service

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"time"

	aep "github.com/aep-foundation/aep-go"
)

func New(options Options) (*Service, error) {
	if options.ServiceDID == "" {
		return nil, errors.New("AEP Service DID is required")
	}
	if options.Verifier == nil {
		return nil, errors.New("AEP Service client assertion verifier is required")
	}
	identityMethods, err := uniqueIdentityMethods(options.IdentityMethods)
	if err != nil || len(identityMethods) == 0 {
		return nil, errors.New("AEP Service requires at least one unique identity method")
	}
	signingAlgorithms := append([]aep.SigningAlgorithm(nil), options.SigningAlgorithms...)
	if len(signingAlgorithms) == 0 {
		signingAlgorithms = []aep.SigningAlgorithm{aep.SigningAlgorithmEdDSA, aep.SigningAlgorithmES256}
	}
	if !slices.Contains(signingAlgorithms, aep.SigningAlgorithmEdDSA) || !slices.Contains(signingAlgorithms, aep.SigningAlgorithmES256) || hasDuplicates(signingAlgorithms) {
		return nil, errors.New("AEP Service signing algorithms must uniquely include EdDSA and ES256")
	}
	grantHandlers, grantTypes, grantConfigs, err := configureGrantTypes(options.GrantTypes)
	if err != nil {
		return nil, err
	}
	authenticationMethods := append([]aep.AuthenticationMethod(nil), options.AuthenticationMethods...)
	if len(authenticationMethods) > aep.MaxAuthenticationMethods || hasDuplicates(authenticationMethods) {
		return nil, errors.New("AEP Service authentication methods must be unique and within the protocol limit")
	}
	for _, method := range authenticationMethods {
		if method == aep.AuthenticationMethodJWT {
			continue
		}
		handler := grantHandlers[aep.GrantType(method)]
		if handler == nil {
			return nil, fmt.Errorf("AEP authentication method %q has no advertised Grant Type handler", method)
		}
		if _, ok := handler.(CredentialAuthenticator); !ok {
			return nil, fmt.Errorf("AEP authentication method %q has no credential authenticator", method)
		}
	}
	endpointBase, err := aep.NormalizeEndpointBase(options.EndpointBase)
	if err != nil {
		return nil, err
	}
	commands := []aep.Command{aep.CommandEnroll, aep.CommandInspect, aep.CommandStatus}
	if len(grantTypes) != 0 {
		commands = []aep.Command{aep.CommandEnroll, aep.CommandGrant, aep.CommandInspect, aep.CommandRevoke, aep.CommandStatus}
	}
	document := aep.InspectDocument{
		AEPVersion: aep.Version,
		Bindings:   aep.Bindings{Supported: []aep.Binding{aep.BindingHTTP}},
		Claims:     cloneInspectClaims(options.Claims),
		Commands: aep.Commands{
			Supported: commands, GrantTypes: grantTypes, GrantTypesConfig: grantConfigs,
		},
		Core:       aep.Core{SigningAlgorithms: signingAlgorithms},
		Extensions: inspectExtensions(options.Extensions),
		HTTP:       aep.HTTPConfiguration{EndpointBase: endpointBase, OpenAPI: cloneOpenAPI(options.OpenAPI)},
		Identity:   aep.Identity{Methods: identityMethods},
		Service:    aep.ServiceIdentity{DID: options.ServiceDID},
	}
	if len(authenticationMethods) != 0 {
		document.Authentication = &aep.Authentication{Methods: authenticationMethods}
	}
	if err := aep.ValidateInspectDocument(document); err != nil {
		return nil, err
	}
	inspectURL, err := validateInspectURL(options.InspectURL, options.ClientAssertion.AllowInsecureLoopback)
	if err != nil {
		return nil, err
	}
	clientAssertion, err := resolveClientAssertionOptions(options.ClientAssertion)
	if err != nil {
		return nil, err
	}
	claimValueLimits, err := resolveClaimValueLimits(options.ClaimValueLimits)
	if err != nil {
		return nil, err
	}
	clock := options.Clock
	if clock == nil {
		clock = time.Now
	}
	enrollmentStore := options.EnrollmentStore
	if enrollmentStore == nil {
		enrollmentStore = NewMemoryEnrollmentStore()
	}
	enrollmentPolicy := options.EnrollmentPolicy
	if enrollmentPolicy == nil {
		enrollmentPolicy = NewStaticEnrollmentPolicy(EnrollmentDecision{})
	}
	replayStore := options.ReplayStore
	if replayStore == nil {
		replayStore = NewMemoryReplayStore()
	}
	idempotencyStore := options.IdempotencyStore
	if idempotencyStore == nil {
		idempotencyStore = newMemoryIdempotencyStore(clock)
	}
	identifier := options.Identifier
	if identifier == nil {
		identifier = randomIdentifier
	}
	return &Service{
		authenticationMethods: authenticationMethods,
		clientAssertion:       clientAssertion,
		claimValueLimits:      claimValueLimits,
		clock:                 clock,
		document:              document,
		enrollmentPolicy:      enrollmentPolicy,
		enrollmentStore:       enrollmentStore,
		grantHandlers:         grantHandlers,
		identifier:            identifier,
		idempotencyStore:      idempotencyStore,
		inspectURL:            inspectURL,
		replayStore:           replayStore,
		verifier:              options.Verifier,
	}, nil
}

func (service *Service) InspectDocument() (aep.InspectDocument, error) {
	return cloneInspectDocument(service.document)
}

func configureGrantTypes(definitions []GrantTypeDefinition) (map[aep.GrantType]GrantTypeHandler, []aep.GrantType, map[string]aep.GrantTypeConfig, error) {
	handlers := make(map[aep.GrantType]GrantTypeHandler, len(definitions))
	grantTypes := make([]aep.GrantType, 0, len(definitions))
	configs := make(map[string]aep.GrantTypeConfig)
	for _, definition := range definitions {
		if definition.GrantType == "" || definition.Handler == nil {
			return nil, nil, nil, errors.New("AEP Grant Type definitions require an identifier and handler")
		}
		if _, found := handlers[definition.GrantType]; found {
			return nil, nil, nil, fmt.Errorf("duplicate AEP Grant Type %q", definition.GrantType)
		}
		handlers[definition.GrantType] = definition.Handler
		grantTypes = append(grantTypes, definition.GrantType)
		if definition.Config.SupportsPerCredentialRevoke != "" || len(definition.Config.Additional) != 0 {
			configs[string(definition.GrantType)] = cloneGrantTypeConfig(definition.Config)
		}
	}
	if len(configs) == 0 {
		configs = nil
	}
	return handlers, grantTypes, configs, nil
}

func resolveClientAssertionOptions(options ClientAssertionOptions) (clientAssertionOptions, error) {
	clockSkew := aep.RecommendedClockSkew
	if options.ClockSkew != nil {
		clockSkew = *options.ClockSkew
	}
	if options.MaximumLifetime == 0 {
		options.MaximumLifetime = aep.MaxAssertionLifetime
	}
	if clockSkew < 0 || clockSkew > aep.RecommendedClockSkew || clockSkew%time.Second != 0 {
		return clientAssertionOptions{}, errors.New("AEP Service clock skew must be whole seconds from 0 through 30")
	}
	if options.MaximumLifetime < time.Second || options.MaximumLifetime > aep.MaxAssertionLifetime || options.MaximumLifetime%time.Second != 0 {
		return clientAssertionOptions{}, errors.New("AEP Service assertion lifetime must be whole seconds from 1 through 300")
	}
	return clientAssertionOptions{
		AllowInsecureLoopback: options.AllowInsecureLoopback, ClockSkew: clockSkew, MaximumLifetime: options.MaximumLifetime,
	}, nil
}

func validateInspectURL(value *url.URL, allowInsecureLoopback bool) (*url.URL, error) {
	if value == nil {
		return nil, nil
	}
	secure := value.Scheme == "https"
	insecureLoopback := allowInsecureLoopback && value.Scheme == "http" && isLoopbackHostname(value.Hostname())
	if (!secure && !insecureLoopback) || value.Host == "" || value.User != nil || value.Opaque != "" || value.Fragment != "" {
		return nil, errors.New("AEP Inspect URL must be an absolute HTTPS URL without credentials or a fragment")
	}
	copy := *value
	return &copy, nil
}

func uniqueIdentityMethods(values []aep.IdentityMethod) ([]aep.IdentityMethod, error) {
	copy := append([]aep.IdentityMethod(nil), values...)
	if hasDuplicates(copy) {
		return nil, errors.New("duplicate AEP identity method")
	}
	return copy, nil
}

func hasDuplicates[Value comparable](values []Value) bool {
	seen := make(map[Value]struct{}, len(values))
	for _, value := range values {
		if _, found := seen[value]; found {
			return true
		}
		seen[value] = struct{}{}
	}
	return false
}

func randomIdentifier() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return hex.EncodeToString(value), nil
}

func cloneInspectDocument(document aep.InspectDocument) (aep.InspectDocument, error) {
	data, err := json.Marshal(document)
	if err != nil {
		return aep.InspectDocument{}, err
	}
	return aep.ParseInspectDocument(data)
}

func cloneInspectClaims(value *aep.InspectClaims) *aep.InspectClaims {
	if value == nil {
		return nil
	}
	return &aep.InspectClaims{
		Required: append([]aep.ClaimName(nil), value.Required...), Preferred: append([]aep.ClaimName(nil), value.Preferred...), Optional: append([]aep.ClaimName(nil), value.Optional...),
	}
}

func inspectExtensions(values []string) *aep.Extensions {
	if len(values) == 0 {
		return nil
	}
	return &aep.Extensions{Supported: append([]string(nil), values...)}
}

func cloneOpenAPI(value *aep.OpenAPIReference) *aep.OpenAPIReference {
	if value == nil {
		return nil
	}
	copy := *value
	copy.Additional = cloneAdditional(value.Additional)
	copy.PathMatching.Additional = cloneAdditional(value.PathMatching.Additional)
	return &copy
}

func cloneGrantTypeConfig(value aep.GrantTypeConfig) aep.GrantTypeConfig {
	value.Additional = cloneAdditional(value.Additional)
	return value
}

func cloneAdditional(value aep.AdditionalMembers) aep.AdditionalMembers {
	if value == nil {
		return nil
	}
	copy := make(aep.AdditionalMembers, len(value))
	for name, raw := range value {
		copy[name] = append([]byte(nil), raw...)
	}
	return copy
}
