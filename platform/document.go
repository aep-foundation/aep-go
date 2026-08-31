package platform

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	aep "github.com/aep-foundation/aep-go"
)

const (
	defaultDIDPathPrefix   = "agents"
	didContext             = "https://www.w3.org/ns/did/v1"
	platformDIDPlaceholder = "{agent_did_id}"
)

func createDiscoveryDocument(options Options, defaultLifetime time.Duration) (DiscoveryDocument, error) {
	endpointBase := options.Discovery.EndpointBase
	if err := validateEndpointPath("endpoint base", endpointBase); err != nil {
		return DiscoveryDocument{}, err
	}
	endpoints := DiscoveryEndpoints{
		Lifecycle: options.Discovery.LifecycleEndpoint,
		List:      options.Discovery.ListEndpoint,
		Provision: options.Discovery.ProvisionEndpoint,
		Sign:      options.Discovery.SignEndpoint,
	}
	for name, path := range map[string]string{
		"lifecycle": endpoints.Lifecycle,
		"list":      endpoints.List,
		"provision": endpoints.Provision,
		"sign":      endpoints.Sign,
	} {
		if err := validateEndpointPath(name, path); err != nil {
			return DiscoveryDocument{}, err
		}
	}
	if options.HostedVerification {
		if err := validateEndpointPath("hosted verification", options.Discovery.HostedVerificationEndpoint); err != nil {
			return DiscoveryDocument{}, err
		}
		endpoints.HostedVerification = options.Discovery.HostedVerificationEndpoint
	} else if options.Discovery.HostedVerificationEndpoint != "" {
		return DiscoveryDocument{}, errors.New("AEP Platform hosted verification endpoint requires hosted verification")
	}
	if options.Discovery.PlatformName == "" {
		return DiscoveryDocument{}, errors.New("AEP Platform name is required")
	}
	if options.Discovery.PlatformDID != "" && !strings.HasPrefix(options.Discovery.PlatformDID, "did:") {
		return DiscoveryDocument{}, errors.New("AEP Platform DID must be a DID")
	}
	if _, err := renderDIDURL(options.DIDURLTemplate, "validation"); err != nil {
		return DiscoveryDocument{}, err
	}
	return DiscoveryDocument{
		AEPVersion: aep.Version,
		Endpoints:  endpoints,
		HTTP:       DiscoveryHTTP{EndpointBase: endpointBase},
		Identity: DiscoveryIdentity{
			DIDMethods:     []string{string(aep.IdentityMethodDIDWeb)},
			DIDURLTemplate: options.DIDURLTemplate,
		},
		Platform: DiscoveryPlatform{
			DID:                options.Discovery.PlatformDID,
			HostedVerification: options.HostedVerification,
			Name:               options.Discovery.PlatformName,
		},
		Signing: DiscoverySigning{
			Algorithms:             slices.Clone(options.SigningAlgorithms),
			DefaultLifetimeSeconds: strconv.FormatInt(int64(defaultLifetime/time.Second), 10),
		},
	}, nil
}

func CreateServiceScopedAgentDID(host string, pathPrefix string, agentDIDID string) (string, error) {
	if host == "" || agentDIDID == "" {
		return "", errors.New("AEP Platform DID host and Agent DID identifier are required")
	}
	parsed, err := url.Parse("https://" + host)
	if err != nil || parsed.Host != host || parsed.Hostname() == "" || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", errors.New("AEP Platform DID host is invalid")
	}
	if pathPrefix == "" {
		pathPrefix = defaultDIDPathPrefix
	}
	parts := []string{"did", "web", escapeDIDComponent(host)}
	for _, part := range strings.Split(strings.Trim(pathPrefix, "/"), "/") {
		if part != "" {
			parts = append(parts, escapeDIDComponent(part))
		}
	}
	parts = append(parts, escapeDIDComponent(agentDIDID))
	return strings.Join(parts, ":"), nil
}

func CreateDIDDocument(identity IdentityRecord, method DIDVerificationMethod) (DIDDocument, error) {
	if err := validateIdentityRecord(identity); err != nil {
		return DIDDocument{}, err
	}
	if method.ID != identity.KeyID || method.Controller != identity.AgentDID || method.Type == "" || len(method.PublicKeyJWK) == 0 {
		return DIDDocument{}, errors.New("AEP Platform DID verification method does not match the managed identity")
	}
	var key map[string]json.RawMessage
	if err := json.Unmarshal(method.PublicKeyJWK, &key); err != nil || key == nil {
		return DIDDocument{}, errors.New("AEP Platform DID verification method requires a public JWK object")
	}
	return DIDDocument{
		Context:              []string{didContext},
		AssertionMethod:      []string{method.ID},
		Authentication:       []string{method.ID},
		CapabilityInvocation: []string{method.ID},
		ID:                   identity.AgentDID,
		VerificationMethod:   []DIDVerificationMethod{cloneVerificationMethod(method)},
	}, nil
}

func renderDIDURL(template string, agentDIDID string) (string, error) {
	if strings.Count(template, platformDIDPlaceholder) != 1 {
		return "", errors.New("AEP Platform DID URL template must contain one {agent_did_id} placeholder")
	}
	rendered := strings.Replace(template, platformDIDPlaceholder, escapeDIDComponent(agentDIDID), 1)
	parsed, err := url.Parse(rendered)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil || parsed.Fragment != "" {
		return "", errors.New("AEP Platform DID URL template must render an absolute HTTPS URL")
	}
	return parsed.String(), nil
}

func escapeDIDComponent(value string) string {
	return strings.ReplaceAll(url.QueryEscape(value), "+", "%20")
}

func validateEndpointPath(name string, path string) error {
	parsed, err := url.Parse(path)
	if err != nil || path == "" || !strings.HasPrefix(path, "/") || parsed.IsAbs() || parsed.Host != "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return fmt.Errorf("AEP Platform %s endpoint must be an absolute path", name)
	}
	return nil
}

func cloneDiscoveryDocument(document DiscoveryDocument) DiscoveryDocument {
	copy := document
	copy.Identity.DIDMethods = slices.Clone(document.Identity.DIDMethods)
	copy.Signing.Algorithms = slices.Clone(document.Signing.Algorithms)
	return copy
}

func cloneVerificationMethod(method DIDVerificationMethod) DIDVerificationMethod {
	copy := method
	copy.PublicKeyJWK = slices.Clone(method.PublicKeyJWK)
	return copy
}
