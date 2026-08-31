package aep

import (
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

var (
	versionPattern       = regexp.MustCompile(`^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$`)
	advertisementPattern = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)
	identityPattern      = regexp.MustCompile(`^[a-z0-9]+(?::[a-z0-9]+)*(?:-[a-z0-9]+)*$`)
	claimNamePattern     = regexp.MustCompile(`^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)*$`)
)

func ParseInspectDocument(data []byte) (InspectDocument, error) {
	var document InspectDocument
	if err := decodeOne(data, &document); err != nil {
		return InspectDocument{}, wrapDecodeError("Inspect document", err)
	}
	if err := rejectNullPaths(data, "Inspect document", "/authentication", "/claims", "/commands/grant_types_config", "/extensions", "/http/openapi"); err != nil {
		return InspectDocument{}, err
	}
	if err := ValidateInspectDocument(document); err != nil {
		return InspectDocument{}, err
	}
	return document, nil
}

func ValidateInspectDocument(document InspectDocument) error {
	issues := make([]ValidationIssue, 0)
	if !versionPattern.MatchString(document.AEPVersion) {
		issues = append(issues, ValidationIssue{Path: "$.aep_version", Message: "Expected major.minor version syntax."})
	} else if !IsVersionCompatible(document.AEPVersion, Version) {
		issues = append(issues, ValidationIssue{Path: "$.aep_version", Message: fmt.Sprintf("Unsupported AEP major version: %s.", document.AEPVersion)})
	}
	validateAuthentication(document.Authentication, &issues)
	validateAdvertisements(document.Bindings.Supported, "$.bindings.supported", true, &issues)
	if !contains(document.Bindings.Supported, BindingHTTP) {
		issues = append(issues, ValidationIssue{Path: "$.bindings.supported", Message: "Expected http to be advertised."})
	}
	validateClaims(document.Claims, &issues)
	validateAdvertisements(document.Commands.Supported, "$.commands.supported", true, &issues)
	if !contains(document.Commands.Supported, CommandInspect) {
		issues = append(issues, ValidationIssue{Path: "$.commands.supported", Message: "Expected inspect to be advertised."})
	}
	validateAdvertisements(document.Commands.GrantTypes, "$.commands.grant_types", false, &issues)
	validateGrantTypeConfigs(document.Commands.GrantTypesConfig, document.Commands.GrantTypes, &issues)
	if (contains(document.Commands.Supported, CommandGrant) || contains(document.Commands.Supported, CommandRevoke)) && len(document.Commands.GrantTypes) == 0 {
		issues = append(issues, ValidationIssue{Path: "$.commands.grant_types", Message: "Expected at least one grant type when Grant or Revoke is advertised."})
	}
	if len(document.Core.SigningAlgorithms) == 0 {
		issues = append(issues, ValidationIssue{Path: "$.core.signing_algorithms", Message: "Expected at least one signing algorithm."})
	}
	if !contains(document.Core.SigningAlgorithms, SigningAlgorithmEdDSA) {
		issues = append(issues, ValidationIssue{Path: "$.core.signing_algorithms", Message: "Expected EdDSA to be advertised."})
	}
	if !contains(document.Core.SigningAlgorithms, SigningAlgorithmES256) {
		issues = append(issues, ValidationIssue{Path: "$.core.signing_algorithms", Message: "Expected ES256 to be advertised."})
	}
	validateExtensions(document.Extensions, &issues)
	validateHTTP(document.HTTP, &issues)
	validateIdentity(document.Identity, document.Commands.Supported, &issues)
	if !strings.HasPrefix(document.Service.DID, "did:") {
		issues = append(issues, ValidationIssue{Path: "$.service.did", Message: "Expected a DID."})
	}
	return validationResult("Inspect document", issues)
}

func validateGrantTypeConfigs(configs map[string]GrantTypeConfig, grantTypes []GrantType, issues *[]ValidationIssue) {
	for name, config := range configs {
		path := "$.commands.grant_types_config." + name
		if !advertisementPattern.MatchString(name) {
			*issues = append(*issues, ValidationIssue{Path: path, Message: "Expected a lowercase grant-type identifier."})
		}
		if !contains(grantTypes, GrantType(name)) {
			*issues = append(*issues, ValidationIssue{Path: path, Message: "Expected configuration for an advertised grant type."})
		}
		if value := config.SupportsPerCredentialRevoke; value != "" && value != "false" && value != "true" {
			*issues = append(*issues, ValidationIssue{Path: path + ".supports_per_credential_revoke", Message: "Expected false or true."})
		}
	}
}

func IsVersionCompatible(received string, supported string) bool {
	if !versionPattern.MatchString(received) || !versionPattern.MatchString(supported) {
		return false
	}
	receivedMajor, _ := strconv.Atoi(strings.SplitN(received, ".", 2)[0])
	supportedMajor, _ := strconv.Atoi(strings.SplitN(supported, ".", 2)[0])
	return receivedMajor == supportedMajor
}

func validateAuthentication(authentication *Authentication, issues *[]ValidationIssue) {
	if authentication == nil {
		return
	}
	if len(authentication.Additional) != 0 {
		for name := range authentication.Additional {
			*issues = append(*issues, ValidationIssue{Path: "$.authentication." + name, Message: "Expected no additional property."})
		}
	}
	if len(authentication.Methods) == 0 {
		*issues = append(*issues, ValidationIssue{Path: "$.authentication.methods", Message: "Expected at least one item."})
	}
	if len(authentication.Methods) > MaxAuthenticationMethods {
		*issues = append(*issues, ValidationIssue{Path: "$.authentication.methods", Message: "Expected at most 16 items."})
	}
	validateAdvertisements(authentication.Methods, "$.authentication.methods", false, issues)
	requireUniqueStrings(authentication.Methods, "$.authentication.methods", issues)
}

func validateClaims(claims *InspectClaims, issues *[]ValidationIssue) {
	if claims == nil {
		return
	}
	for _, group := range []struct {
		name   string
		values []ClaimName
	}{{"required", claims.Required}, {"preferred", claims.Preferred}, {"optional", claims.Optional}} {
		for index, value := range group.values {
			if !claimNamePattern.MatchString(string(value)) {
				*issues = append(*issues, ValidationIssue{Path: fmt.Sprintf("$.claims.%s[%d]", group.name, index), Message: "Expected a registered claim-name shape."})
			}
		}
	}
}

func validateAdvertisements[Value ~string](values []Value, path string, requireItem bool, issues *[]ValidationIssue) {
	if requireItem && len(values) == 0 {
		*issues = append(*issues, ValidationIssue{Path: path, Message: "Expected at least one item."})
	}
	for index, value := range values {
		if !advertisementPattern.MatchString(string(value)) {
			*issues = append(*issues, ValidationIssue{Path: fmt.Sprintf("%s[%d]", path, index), Message: "Expected a lowercase advertisement identifier."})
		}
	}
}

func validateExtensions(extensions *Extensions, issues *[]ValidationIssue) {
	if extensions == nil {
		return
	}
	for index, value := range extensions.Supported {
		parsed, err := url.Parse(value)
		if err != nil || !parsed.IsAbs() {
			*issues = append(*issues, ValidationIssue{Path: fmt.Sprintf("$.extensions.supported[%d]", index), Message: "Expected an absolute URI."})
		}
	}
}

func validateHTTP(http HTTPConfiguration, issues *[]ValidationIssue) {
	if http.EndpointBase != "" && (!strings.HasPrefix(http.EndpointBase, "/") || strings.HasPrefix(http.EndpointBase, "//")) {
		*issues = append(*issues, ValidationIssue{Path: "$.http.endpoint_base", Message: "Expected an origin-relative absolute path."})
	}
	if http.OpenAPI == nil {
		return
	}
	if len(http.OpenAPI.Additional) != 0 {
		for name := range http.OpenAPI.Additional {
			*issues = append(*issues, ValidationIssue{Path: "$.http.openapi." + name, Message: "Expected no additional property."})
		}
	}
	if http.OpenAPI.URL == "" {
		*issues = append(*issues, ValidationIssue{Path: "$.http.openapi.url", Message: "Expected a non-empty URI reference."})
	} else if _, err := url.Parse(http.OpenAPI.URL); err != nil || strings.ContainsAny(http.OpenAPI.URL, " \t\r\n") {
		*issues = append(*issues, ValidationIssue{Path: "$.http.openapi.url", Message: "Expected a URI reference."})
	}
	if len(http.OpenAPI.PathMatching.Additional) != 0 {
		for name := range http.OpenAPI.PathMatching.Additional {
			*issues = append(*issues, ValidationIssue{Path: "$.http.openapi.path_matching." + name, Message: "Expected no additional property."})
		}
	}
	if mode := http.OpenAPI.PathMatching.TrailingSlash; mode != "strict" && mode != "equivalent" {
		*issues = append(*issues, ValidationIssue{Path: "$.http.openapi.path_matching.trailing_slash", Message: "Expected strict or equivalent."})
	}
}

func validateIdentity(identity Identity, commands []Command, issues *[]ValidationIssue) {
	for index, method := range identity.Methods {
		if !identityPattern.MatchString(string(method)) {
			*issues = append(*issues, ValidationIssue{Path: fmt.Sprintf("$.identity.methods[%d]", index), Message: "Expected an identity-method identifier."})
		}
	}
	authenticated := contains(commands, CommandEnroll) || contains(commands, CommandGrant) || contains(commands, CommandRevoke) || contains(commands, CommandStatus)
	if authenticated && len(identity.Methods) == 0 {
		*issues = append(*issues, ValidationIssue{Path: "$.identity.methods", Message: "Expected at least one identity method for authenticated commands."})
	}
}
