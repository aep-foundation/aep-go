package aep

import (
	"net/url"
	"regexp"
	"strconv"
	"time"
)

var bodyHashPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

func ParseEnrollRequest(data []byte) (EnrollRequest, error) {
	var value EnrollRequest
	err := parseAndValidate(data, "Enroll request", &value, func() error {
		return ValidateEnrollRequest(value)
	}, "/claims")
	return value, err
}

func ValidateEnrollRequest(value EnrollRequest) error {
	issues := make([]ValidationIssue, 0)
	requireNonEmpty(value.AgentDID, "$.agent_did", &issues)
	requireNonEmpty(value.IdempotencyKey, "$.idempotency_key", &issues)
	if value.Claims != nil {
		appendValidationIssues(ValidateClaimValues(*value.Claims), &issues)
	}
	return validationResult("Enroll request", issues)
}

func ParseEnrollResponse(data []byte) (EnrollResponse, error) {
	var value EnrollResponse
	err := parseAndValidate(data, "Enroll response", &value, func() error {
		return ValidateEnrollResponse(value)
	}, "/owner_action_required", "/verification_pending", "/requirements_pending")
	return value, err
}

func ValidateEnrollResponse(value EnrollResponse) error {
	issues := make([]ValidationIssue, 0)
	if value.Status != EnrollmentActive && value.Status != EnrollmentPending && value.Status != EnrollmentRejected {
		issues = append(issues, ValidationIssue{Path: "$.status", Message: "Expected active, pending, or rejected."})
	}
	validateOwnerActionRequired(value.OwnerActionRequired, &issues)
	validateNonEmptyStrings(value.VerificationPending, "$.verification_pending", &issues)
	validateNonEmptyStrings(value.RequirementsPending, "$.requirements_pending", &issues)
	return validationResult("Enroll response", issues)
}

func ParseStatusResponse(data []byte) (StatusResponse, error) {
	var value StatusResponse
	err := parseAndValidate(data, "Status response", &value, func() error {
		return ValidateStatusResponse(value)
	}, "/owner_action_required", "/verification_pending", "/requirements_pending", "/since")
	return value, err
}

func ValidateStatusResponse(value StatusResponse) error {
	issues := make([]ValidationIssue, 0)
	switch value.Status {
	case AgentActive, AgentPending, AgentRejected, AgentSuspended, AgentTerminated, AgentUnavailable:
	default:
		issues = append(issues, ValidationIssue{Path: "$.status", Message: "Expected a registered Agent status."})
	}
	validateOwnerActionRequired(value.OwnerActionRequired, &issues)
	validateNonEmptyStrings(value.VerificationPending, "$.verification_pending", &issues)
	validateNonEmptyStrings(value.RequirementsPending, "$.requirements_pending", &issues)
	if value.Since != "" {
		if _, err := time.Parse(time.RFC3339, value.Since); err != nil {
			issues = append(issues, ValidationIssue{Path: "$.since", Message: "Expected an RFC 3339 date-time."})
		}
	}
	return validationResult("Status response", issues)
}

func ParseGrantRequest(data []byte) (GrantRequest, error) {
	var value GrantRequest
	err := parseAndValidate(data, "Grant request", &value, func() error {
		return ValidateGrantRequest(value)
	}, "/requested_scopes")
	return value, err
}

func ValidateGrantRequest(value GrantRequest) error {
	issues := make([]ValidationIssue, 0)
	requireNonEmpty(string(value.GrantType), "$.grant_type", &issues)
	validateStrings(value.RequestedScopes, "$.requested_scopes", &issues)
	return validationResult("Grant request", issues)
}

func ParseRevokeRequest(data []byte) (RevokeRequest, error) {
	var value RevokeRequest
	err := parseAndValidate(data, "Revoke request", &value, func() error {
		return ValidateRevokeRequest(value)
	}, "/grant_type", "/credential_id", "/all_grant_types")
	return value, err
}

func ValidateRevokeRequest(value RevokeRequest) error {
	issues := make([]ValidationIssue, 0)
	selectors := 0
	if value.GrantType != "" {
		selectors++
	}
	if value.CredentialID != "" {
		selectors++
	}
	if value.AllGrantTypes != "" {
		selectors++
		if value.AllGrantTypes != "true" {
			issues = append(issues, ValidationIssue{Path: "$.all_grant_types", Message: "Expected true."})
		}
	}
	if selectors != 1 {
		issues = append(issues, ValidationIssue{Path: "$", Message: "Expected exactly one of grant_type, credential_id, or all_grant_types."})
	}
	return validationResult("Revoke request", issues)
}

func ParseRevokeResponse(data []byte) (RevokeResponse, error) {
	var value map[string]any
	if err := decodeOne(data, &value); err != nil {
		return RevokeResponse{}, wrapDecodeError("Revoke response", err)
	}
	if value == nil || len(value) != 0 {
		return RevokeResponse{}, invalid("Revoke response", "$", "Expected an empty object.")
	}
	return RevokeResponse{}, nil
}

func ValidateRevokeResponse(RevokeResponse) error {
	return nil
}

func ParseIdempotencyMetadata(data []byte) (IdempotencyMetadata, error) {
	var value IdempotencyMetadata
	err := parseAndValidate(data, "Idempotency metadata", &value, func() error {
		return ValidateIdempotencyMetadata(value)
	}, "/agent_did", "/first_body_hash", "/second_body_hash")
	return value, err
}

func ValidateIdempotencyMetadata(value IdempotencyMetadata) error {
	issues := make([]ValidationIssue, 0)
	requireNonEmpty(value.IdempotencyKey, "$.idempotency_key", &issues)
	if value.AgentDID != nil && *value.AgentDID == "" {
		issues = append(issues, ValidationIssue{Path: "$.agent_did", Message: "Expected a non-empty string."})
	}
	validateBodyHash(value.FirstBodyHash, "$.first_body_hash", &issues)
	validateBodyHash(value.SecondBodyHash, "$.second_body_hash", &issues)
	return validationResult("Idempotency metadata", issues)
}

func ParseOpenAPIAEPSecurityScheme(data []byte) (OpenAPIAEPSecurityScheme, error) {
	var value OpenAPIAEPSecurityScheme
	err := parseAndValidate(data, "OpenAPI AEP security scheme", &value, func() error {
		return ValidateOpenAPIAEPSecurityScheme(value)
	})
	return value, err
}

func ValidateOpenAPIAEPSecurityScheme(value OpenAPIAEPSecurityScheme) error {
	issues := make([]ValidationIssue, 0)
	if !advertisementPattern.MatchString(string(value.AuthenticationMethod)) {
		issues = append(issues, ValidationIssue{Path: "$.x-aep-authentication-method", Message: "Expected a lowercase authentication-method identifier."})
	}
	return validationResult("OpenAPI AEP security scheme", issues)
}

func ValidateClientAssertionClaims(value ClientAssertionClaims) error {
	issues := make([]ValidationIssue, 0)
	requireNonEmpty(value.Issuer, "$.iss", &issues)
	requireNonEmpty(value.Subject, "$.sub", &issues)
	if value.Issuer != "" && value.Subject != "" && value.Issuer != value.Subject {
		issues = append(issues, ValidationIssue{Path: "$.sub", Message: "Expected sub to equal iss."})
	}
	requireNonEmpty(value.Audience, "$.aud", &issues)
	requireNonEmpty(value.JWTID, "$.jti", &issues)
	switch value.Operation {
	case AssertionEnroll, AssertionGrant, AssertionRevoke, AssertionStatus, AssertionAuthenticate:
	default:
		issues = append(issues, ValidationIssue{Path: "$.op", Message: "Expected a registered assertion operation."})
	}
	if value.Operation == AssertionAuthenticate {
		if !isProtectedResourceURI(value.Resource) {
			issues = append(issues, ValidationIssue{Path: "$.resource", Message: "Expected an HTTPS protected-resource URI without a fragment."})
		}
	} else if value.Resource != "" {
		issues = append(issues, ValidationIssue{Path: "$.resource", Message: "resource is only valid for authenticate."})
	}
	if value.ExpiresAt <= value.IssuedAt {
		issues = append(issues, ValidationIssue{Path: "$.exp", Message: "Expected exp after iat."})
	} else if time.Duration(value.ExpiresAt-value.IssuedAt)*time.Second > MaxAssertionLifetime {
		issues = append(issues, ValidationIssue{Path: "$.exp", Message: "Expected an assertion lifetime no greater than 300 seconds."})
	}
	return validationResult("client assertion claims", issues)
}

func ParseClientAssertionClaims(data []byte) (ClientAssertionClaims, error) {
	var value ClientAssertionClaims
	err := parseAndValidate(data, "client assertion claims", &value, func() error {
		return ValidateClientAssertionClaims(value)
	})
	return value, err
}

func NewProblemDetails(code ErrorCode, title string, status int) ProblemDetails {
	return ProblemDetails{
		Type:   "urn:aep:error:" + string(code),
		Title:  title,
		Status: status,
		Code:   code,
	}
}

func ParseProblemDetails(data []byte) (ProblemDetails, error) {
	var value ProblemDetails
	err := parseAndValidate(data, "Problem Details", &value, func() error {
		return ValidateProblemDetails(value)
	}, "/detail", "/instance", "/owner_action_required", "/verification_pending", "/requirements_pending")
	return value, err
}

func ValidateProblemDetails(value ProblemDetails) error {
	issues := make([]ValidationIssue, 0)
	if len(value.Type) < len("urn:aep:error:") || value.Type[:len("urn:aep:error:")] != "urn:aep:error:" {
		issues = append(issues, ValidationIssue{Path: "$.type", Message: "Expected an AEP error URN."})
	}
	requireNonEmpty(value.Title, "$.title", &issues)
	if value.Status == 0 {
		issues = append(issues, ValidationIssue{Path: "$.status", Message: "Expected an integer HTTP status."})
	}
	requireNonEmpty(string(value.Code), "$.code", &issues)
	if value.OwnerActionRequired != nil && *value.OwnerActionRequired != "true" {
		issues = append(issues, ValidationIssue{Path: "$.owner_action_required", Message: "Expected true."})
	}
	validateNonEmptyStrings(value.VerificationPending, "$.verification_pending", &issues)
	validateNonEmptyStrings(value.RequirementsPending, "$.requirements_pending", &issues)
	if value.Code == ErrorNotRecognized && (len(value.VerificationPending) != 0 || len(value.RequirementsPending) != 0) {
		issues = append(issues, ValidationIssue{Path: "$", Message: "not_recognized must not expose pending-name metadata."})
	}
	return validationResult("Problem Details", issues)
}

func ParseBuiltInGrantResponse(grantType GrantType, data []byte) (BuiltInGrantResponse, error) {
	switch grantType {
	case GrantTypeOAuthBearer:
		var value OAuthBearerGrantResponse
		err := parseAndValidate(data, "OAuth Bearer Grant response", &value, func() error {
			return ValidateOAuthBearerGrantResponse(value)
		})
		return value, err
	case GrantTypeAPIKey:
		var value APIKeyGrantResponse
		err := parseAndValidate(data, "API-key Grant response", &value, func() error {
			return ValidateAPIKeyGrantResponse(value)
		})
		return value, err
	case GrantTypeBasic:
		var value BasicGrantResponse
		err := parseAndValidate(data, "Basic Grant response", &value, func() error {
			return ValidateBasicGrantResponse(value)
		}, "/realm")
		return value, err
	default:
		return nil, invalid("Grant response", "$.grant_type", "Expected a built-in AEP grant type.")
	}
}

func ValidateBuiltInGrantResponse(grantType GrantType, value BuiltInGrantResponse) error {
	if value == nil {
		return invalid("Grant response", "$.grant_type", "Expected the selected built-in AEP grant type.")
	}
	switch response := value.(type) {
	case OAuthBearerGrantResponse:
		if grantType != GrantTypeOAuthBearer {
			break
		}
		return ValidateOAuthBearerGrantResponse(response)
	case *OAuthBearerGrantResponse:
		if response == nil || grantType != GrantTypeOAuthBearer {
			break
		}
		return ValidateOAuthBearerGrantResponse(*response)
	case APIKeyGrantResponse:
		if grantType != GrantTypeAPIKey {
			break
		}
		return ValidateAPIKeyGrantResponse(response)
	case *APIKeyGrantResponse:
		if response == nil || grantType != GrantTypeAPIKey {
			break
		}
		return ValidateAPIKeyGrantResponse(*response)
	case BasicGrantResponse:
		if grantType != GrantTypeBasic {
			break
		}
		return ValidateBasicGrantResponse(response)
	case *BasicGrantResponse:
		if response == nil || grantType != GrantTypeBasic {
			break
		}
		return ValidateBasicGrantResponse(*response)
	}
	return invalid("Grant response", "$.grant_type", "Expected the selected built-in AEP grant type.")
}

func ParseOAuthBearerGrantResponse(data []byte) (OAuthBearerGrantResponse, error) {
	var value OAuthBearerGrantResponse
	err := parseAndValidate(data, "OAuth Bearer Grant response", &value, func() error {
		return ValidateOAuthBearerGrantResponse(value)
	})
	return value, err
}

func ParseAPIKeyGrantResponse(data []byte) (APIKeyGrantResponse, error) {
	var value APIKeyGrantResponse
	err := parseAndValidate(data, "API-key Grant response", &value, func() error {
		return ValidateAPIKeyGrantResponse(value)
	})
	return value, err
}

func ParseBasicGrantResponse(data []byte) (BasicGrantResponse, error) {
	var value BasicGrantResponse
	err := parseAndValidate(data, "Basic Grant response", &value, func() error {
		return ValidateBasicGrantResponse(value)
	}, "/realm")
	return value, err
}

func ValidateOAuthBearerGrantResponse(value OAuthBearerGrantResponse) error {
	issues := make([]ValidationIssue, 0)
	requireNonEmpty(value.AccessToken, "$.access_token", &issues)
	requireCredentialFields(value.CredentialID, value.ExpiresAt, value.Scopes, &issues)
	if value.TokenType != "Bearer" {
		issues = append(issues, ValidationIssue{Path: "$.token_type", Message: "Expected Bearer."})
	}
	return validationResult("OAuth Bearer Grant response", issues)
}

func ValidateAPIKeyGrantResponse(value APIKeyGrantResponse) error {
	issues := make([]ValidationIssue, 0)
	requireNonEmpty(value.APIKey, "$.api_key", &issues)
	requireNonEmpty(value.Header, "$.header", &issues)
	requireCredentialFields(value.CredentialID, value.ExpiresAt, value.Scopes, &issues)
	return validationResult("API-key Grant response", issues)
}

func ValidateBasicGrantResponse(value BasicGrantResponse) error {
	issues := make([]ValidationIssue, 0)
	requireNonEmpty(value.Password, "$.password", &issues)
	requireNonEmpty(value.Username, "$.username", &issues)
	if value.Realm != nil && *value.Realm == "" {
		issues = append(issues, ValidationIssue{Path: "$.realm", Message: "Expected a non-empty string."})
	}
	requireCredentialFields(value.CredentialID, value.ExpiresAt, value.Scopes, &issues)
	return validationResult("Basic Grant response", issues)
}

func requireCredentialFields(credentialID, expiresAt string, scopes []string, issues *[]ValidationIssue) {
	requireNonEmpty(credentialID, "$.credential_id", issues)
	requireNonEmpty(expiresAt, "$.expires_at", issues)
	if expiresAt != "" {
		if _, err := time.Parse(time.RFC3339, expiresAt); err != nil {
			*issues = append(*issues, ValidationIssue{Path: "$.expires_at", Message: "Expected an RFC 3339 date-time."})
		}
	}
	validateStrings(scopes, "$.scopes", issues)
}

func parseAndValidate(data []byte, documentType string, target any, validate func() error, nonNullPaths ...string) error {
	if err := decodeOne(data, target); err != nil {
		return wrapDecodeError(documentType, err)
	}
	if err := rejectNullPaths(data, documentType, nonNullPaths...); err != nil {
		return err
	}
	return validate()
}

func appendValidationIssues(err error, issues *[]ValidationIssue) {
	if validation, ok := err.(*ValidationError); ok {
		*issues = append(*issues, validation.Issues...)
	}
}

func validateOwnerActionRequired(value *string, issues *[]ValidationIssue) {
	if value != nil && *value != "true" && *value != "false" {
		*issues = append(*issues, ValidationIssue{Path: "$.owner_action_required", Message: "Expected true or false."})
	}
}

func validateNonEmptyStrings(values []string, path string, issues *[]ValidationIssue) {
	if values != nil && len(values) == 0 {
		*issues = append(*issues, ValidationIssue{Path: path, Message: "Expected at least one item."})
	}
	for index, value := range values {
		if value == "" {
			*issues = append(*issues, ValidationIssue{Path: path + "[" + strconv.Itoa(index) + "]", Message: "Expected a non-empty string."})
		}
	}
	requireUniqueStrings(values, path, issues)
}

func validateStrings(values []string, path string, issues *[]ValidationIssue) {
	for index, value := range values {
		if value == "" {
			*issues = append(*issues, ValidationIssue{Path: path + "[" + strconv.Itoa(index) + "]", Message: "Expected a string."})
		}
	}
}

func isProtectedResourceURI(value string) bool {
	parsed, err := url.Parse(value)
	return err == nil && parsed.Scheme == "https" && parsed.Host != "" && parsed.Fragment == ""
}

func validateBodyHash(value *string, path string, issues *[]ValidationIssue) {
	if value != nil && !bodyHashPattern.MatchString(*value) {
		*issues = append(*issues, ValidationIssue{Path: path, Message: "Expected a lowercase SHA-256 body hash."})
	}
}
