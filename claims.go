package aep

import (
	"net"
	"regexp"
	"strings"
	"time"
)

var (
	e164Pattern        = regexp.MustCompile(`^\+[1-9][0-9]{1,14}$`)
	countryPattern     = regexp.MustCompile(`^[A-Z]{2}$`)
	atomPattern        = regexp.MustCompile(`^[A-Za-z0-9!#$%&'*+\-/=?^_` + "`" + `{|}~]+$`)
	domainLabelPattern = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$`)
)

func ParseClaimValues(data []byte) (ClaimValues, error) {
	var value ClaimValues
	if err := decodeOne(data, &value); err != nil {
		return ClaimValues{}, wrapDecodeError("Claim Values", err)
	}
	if err := rejectNullPaths(data, "Claim Values",
		"/contact.address.primary", "/contact.address.primary/city", "/contact.address.primary/country",
		"/contact.address.primary/first_name", "/contact.address.primary/last_name",
		"/contact.address.primary/line1", "/contact.address.primary/line2",
		"/contact.address.primary/line3", "/contact.address.primary/postcode",
		"/contact.address.primary/region", "/contact.email", "/contact.mobile",
		"/person.birthdate", "/person.first_name", "/person.last_name", "/person.username"); err != nil {
		return ClaimValues{}, err
	}
	if err := ValidateClaimValues(value); err != nil {
		return ClaimValues{}, err
	}
	return value, nil
}

func ValidateClaimValues(value ClaimValues) error {
	issues := make([]ValidationIssue, 0)
	if address := value.ContactAddressPrimary; address != nil {
		path := "$.contact.address.primary"
		requireNonEmpty(address.Country, path+".country", &issues)
		if address.Country != "" && !countryPattern.MatchString(address.Country) {
			issues = append(issues, ValidationIssue{Path: path + ".country", Message: "Expected a two-letter uppercase country code."})
		}
		requireNonEmpty(address.FirstName, path+".first_name", &issues)
		requireNonEmpty(address.LastName, path+".last_name", &issues)
		requireNonEmpty(address.Line1, path+".line1", &issues)
		if address.City != nil && *address.City == "" {
			issues = append(issues, ValidationIssue{Path: path + ".city", Message: "Expected a non-empty string."})
		}
		if _, legacy := address.Additional["postal_code"]; legacy {
			issues = append(issues, ValidationIssue{Path: path + ".postal_code", Message: "Expected the postcode member."})
		}
	}
	validateOptionalString(value.ContactEmail, "$.contact.email", &issues, func(input string) bool {
		return len(input) >= 3 && isEmailMailbox(input)
	}, "Expected an RFC 5321 Mailbox.")
	validateOptionalString(value.ContactMobile, "$.contact.mobile", &issues, e164Pattern.MatchString, "Expected an E.164 telephone number.")
	validateOptionalString(value.PersonBirthdate, "$.person.birthdate", &issues, isFullDate, "Expected an RFC 3339 full-date.")
	validateOptionalNonEmpty(value.PersonFirstName, "$.person.first_name", &issues)
	validateOptionalNonEmpty(value.PersonLastName, "$.person.last_name", &issues)
	validateOptionalNonEmpty(value.PersonUsername, "$.person.username", &issues)
	return validationResult("Claim Values", issues)
}

type ClaimSupportEvaluation struct {
	CanSatisfyRequired  bool
	SupportedOptional   []ClaimName
	SupportedPreferred  []ClaimName
	UnsupportedRequired []ClaimName
}

func EvaluateClaimSupport(requested *InspectClaims, supportedClaimNames []ClaimName) ClaimSupportEvaluation {
	supported := make(map[ClaimName]struct{}, len(supportedClaimNames))
	for _, name := range supportedClaimNames {
		supported[name] = struct{}{}
	}
	evaluation := ClaimSupportEvaluation{}
	if requested == nil {
		evaluation.CanSatisfyRequired = true
		return evaluation
	}
	for _, name := range requested.Required {
		if _, ok := supported[name]; !ok {
			evaluation.UnsupportedRequired = append(evaluation.UnsupportedRequired, name)
		}
	}
	for _, name := range requested.Preferred {
		if _, ok := supported[name]; ok {
			evaluation.SupportedPreferred = append(evaluation.SupportedPreferred, name)
		}
	}
	for _, name := range requested.Optional {
		if _, ok := supported[name]; ok {
			evaluation.SupportedOptional = append(evaluation.SupportedOptional, name)
		}
	}
	evaluation.CanSatisfyRequired = len(evaluation.UnsupportedRequired) == 0
	return evaluation
}

func MissingRequiredClaimNames(required []ClaimName, values *ClaimValues) []ClaimName {
	missing := make([]ClaimName, 0)
	for _, name := range required {
		if values == nil || !values.has(name) {
			missing = append(missing, name)
		}
	}
	return missing
}

func (value ClaimValues) has(name ClaimName) bool {
	switch name {
	case ClaimContactAddressPrimary:
		return value.ContactAddressPrimary != nil
	case ClaimContactEmail:
		return value.ContactEmail != nil
	case ClaimContactMobile:
		return value.ContactMobile != nil
	case ClaimPersonBirthdate:
		return value.PersonBirthdate != nil
	case ClaimPersonFirstName:
		return value.PersonFirstName != nil
	case ClaimPersonLastName:
		return value.PersonLastName != nil
	case ClaimPersonUsername:
		return value.PersonUsername != nil
	default:
		_, ok := value.Additional[string(name)]
		return ok
	}
}

func validateOptionalNonEmpty(value *string, path string, issues *[]ValidationIssue) {
	validateOptionalString(value, path, issues, func(input string) bool { return input != "" }, "Expected a non-empty string.")
}

func validateOptionalString(value *string, path string, issues *[]ValidationIssue, valid func(string) bool, message string) {
	if value != nil && !valid(*value) {
		*issues = append(*issues, ValidationIssue{Path: path, Message: message})
	}
}

func isEmailMailbox(value string) bool {
	separator := mailboxSeparator(value)
	if separator < 1 || separator == len(value)-1 {
		return false
	}
	local, domain := value[:separator], value[separator+1:]
	return len([]byte(local)) <= 64 && len([]byte(domain)) <= 255 && isLocalPart(local) && isMailboxDomain(domain)
}

func mailboxSeparator(value string) int {
	if !strings.HasPrefix(value, `"`) {
		separator := strings.IndexByte(value, '@')
		if separator != strings.LastIndexByte(value, '@') {
			return -1
		}
		return separator
	}
	escaped := false
	for index := 1; index < len(value); index++ {
		switch {
		case escaped:
			escaped = false
		case value[index] == '\\':
			escaped = true
		case value[index] == '"':
			if index+1 < len(value) && value[index+1] == '@' {
				return index + 1
			}
			return -1
		}
	}
	return -1
}

func isLocalPart(value string) bool {
	if strings.HasPrefix(value, `"`) {
		return isQuotedLocalPart(value)
	}
	parts := strings.Split(value, ".")
	for _, atom := range parts {
		if !atomPattern.MatchString(atom) {
			return false
		}
	}
	return true
}

func isQuotedLocalPart(value string) bool {
	if len(value) < 2 || !strings.HasSuffix(value, `"`) {
		return false
	}
	for index := 1; index < len(value)-1; index++ {
		code := value[index]
		if code == '\\' {
			index++
			if index >= len(value)-1 || value[index] < 32 || value[index] > 126 {
				return false
			}
			continue
		}
		if !((code >= 32 && code <= 33) || (code >= 35 && code <= 91) || (code >= 93 && code <= 126)) {
			return false
		}
	}
	return true
}

func isMailboxDomain(value string) bool {
	if strings.HasPrefix(value, "[") || strings.HasSuffix(value, "]") {
		return isAddressLiteral(value)
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) > 63 || !domainLabelPattern.MatchString(label) {
			return false
		}
	}
	return true
}

func isAddressLiteral(value string) bool {
	if len(value) < 2 || value[0] != '[' || value[len(value)-1] != ']' {
		return false
	}
	content := value[1 : len(value)-1]
	if strings.Contains(content, ".") && net.ParseIP(content) != nil {
		return true
	}
	if strings.HasPrefix(content, "IPv6:") {
		return net.ParseIP(content[5:]) != nil
	}
	separator := strings.IndexByte(content, ':')
	if separator < 1 || separator == len(content)-1 {
		return false
	}
	tag, literal := content[:separator], content[separator+1:]
	if !regexp.MustCompile(`^[A-Za-z0-9-]*[A-Za-z0-9]$`).MatchString(tag) {
		return false
	}
	for _, character := range []byte(literal) {
		if !((character >= 33 && character <= 90) || (character >= 94 && character <= 126)) {
			return false
		}
	}
	return true
}

func isFullDate(value string) bool {
	if len(value) != 10 || value[4] != '-' || value[7] != '-' {
		return false
	}
	_, err := time.Parse("2006-01-02", value)
	return err == nil
}
