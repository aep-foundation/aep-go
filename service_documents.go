package aep

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"unicode/utf8"
)

const ServiceDocumentsExtension = "urn:aep:ext:aep-foundation:service-documents#v=1.0.0"
const MaxServiceDocumentBytes = 1 << 20

var ErrUnsupportedServiceDocument = errors.New("unsupported portable Service document")

// PreferredServiceDocumentTypes returns registry recommendations; custom types remain valid.
func PreferredServiceDocumentTypes() []string {
	return []string{"acceptable_use_policy", "age_or_parental_consent", "ai_data_use_policy", "community_guidelines", "cookie_policy", "data_processing_agreement", "data_retention_notice", "electronic_signature_consent", "privacy_policy", "security_policy", "subscription_terms", "supplemental_terms", "terms_of_service"}
}

type ServiceDocument struct {
	ID              string                   `json:"id"`
	Type            string                   `json:"type"`
	Title           string                   `json:"title"`
	Enrollment      string                   `json:"enrollment"`
	Representations []DocumentRepresentation `json:"representations"`
}

type DocumentRepresentation struct {
	MediaType string `json:"media_type"`
	URL       string `json:"url"`
}

type PortableServiceDocument struct {
	Format  string          `json:"format"`
	Version string          `json:"version"`
	ID      string          `json:"id"`
	Summary []DocumentBlock `json:"summary,omitzero"`
	Content []DocumentBlock `json:"content"`
}

type DocumentBlock struct {
	Type   string          `json:"type"`
	Text   string          `json:"text,omitempty"`
	Title  string          `json:"title,omitempty"`
	Blocks []DocumentBlock `json:"blocks,omitzero"`
	Items  []string        `json:"items,omitzero"`
}

var documentIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$`)
var documentTypePattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
var documentMediaPattern = regexp.MustCompile("^[a-z0-9!#$&^_.+-]+/[a-z0-9!#$&^_.+-]+$")

func ValidateDocumentIDs(ids []string) error {
	issues := []ValidationIssue{}
	if len(ids) > 7 {
		issues = append(issues, ValidationIssue{Path: "$", Message: "At most seven document identifiers are allowed."})
	}
	requireUniqueStrings(ids, "$", &issues)
	for index, id := range ids {
		if !documentIDPattern.MatchString(id) {
			issues = append(issues, ValidationIssue{Path: fmt.Sprintf("$[%d]", index), Message: "Invalid document identifier."})
		}
	}
	return validationResult("Document identifiers", issues)
}

func ValidateServiceDocuments(documents []ServiceDocument) error {
	if len(documents) == 0 || len(documents) > 7 {
		return invalid("Service documents", "$", "Expected one through seven documents.")
	}
	ids := make([]string, 0, len(documents))
	for index, document := range documents {
		ids = append(ids, document.ID)
		if err := ValidateServiceDocument(document); err != nil {
			return fmt.Errorf("Service document %d: %w", index, err)
		}
	}
	return ValidateDocumentIDs(ids)
}

func ValidateServiceDocument(document ServiceDocument) error {
	if err := ValidateDocumentIDs([]string{document.ID}); err != nil {
		return err
	}
	if !documentTypePattern.MatchString(document.Type) || !documentText(document.Title, 256) {
		return invalid("Service document", "$", "Invalid document type or title.")
	}
	if document.Enrollment != "required" && document.Enrollment != "not-required" {
		return invalid("Service document", "$.enrollment", "Expected required or not-required.")
	}
	if len(document.Representations) < 1 || len(document.Representations) > 8 {
		return invalid("Service document", "$.representations", "Expected one through eight representations.")
	}
	seen := map[string]bool{}
	for _, representation := range document.Representations {
		if seen[representation.MediaType] || !documentMediaPattern.MatchString(representation.MediaType) {
			return invalid("Service document", "$.representations", "Expected unique lowercase media types without parameters.")
		}
		seen[representation.MediaType] = true
		if err := ValidateDocumentURL(representation.URL); err != nil {
			return err
		}
	}
	if !seen["text/html"] {
		return invalid("Service document", "$.representations", "An HTML representation is required.")
	}
	return nil
}

func ValidateDocumentURL(value string) error {
	parsed, err := url.Parse(value)
	if err != nil || (parsed.Scheme != "https" && !(parsed.Scheme == "http" && isLoopbackHost(parsed.Hostname()))) || parsed.Hostname() == "" || parsed.User != nil || parsed.Opaque != "" || len(value) > 2048 {
		return invalid("Service document", "$.url", "Expected HTTPS or loopback HTTP without user information.")
	}
	for _, character := range value {
		if character > 127 || character <= 32 {
			return invalid("Service document", "$.url", "Expected an ASCII URI serialization.")
		}
	}
	return nil
}

func ParsePortableServiceDocument(data []byte, expectedID string) (PortableServiceDocument, error) {
	var document PortableServiceDocument
	if len(data) > MaxServiceDocumentBytes {
		return document, invalid("Portable document", "$", "Document exceeds one MiB.")
	}
	if err := decodeOne(data, &document); err != nil {
		return document, wrapDecodeError("Portable document", err)
	}
	if err := rejectNullPaths(data, "Portable document", "/summary"); err != nil {
		return document, err
	}
	if document.Format != "aep-service-document" || document.Version != "1.0" {
		return document, ErrUnsupportedServiceDocument
	}
	if err := ValidateDocumentIDs([]string{document.ID}); err != nil {
		return document, err
	}
	if document.ID != expectedID {
		return document, invalid("Portable document", "$.id", "Document ID does not match its descriptor.")
	}
	if len(document.Content) == 0 || (document.Summary != nil && len(document.Summary) == 0) {
		return document, invalid("Portable document", "$", "Content and any supplied summary must be nonempty.")
	}
	count := 0
	for _, blocks := range [][]DocumentBlock{document.Summary, document.Content} {
		if err := validateDocumentBlocks(blocks, 0, &count); err != nil {
			return document, err
		}
	}
	return document, nil
}

func validateDocumentBlocks(blocks []DocumentBlock, depth int, count *int) error {
	for _, block := range blocks {
		*count++
		if *count > 1024 {
			return invalid("Portable document", "$", "Document exceeds 1024 blocks.")
		}
		switch block.Type {
		case "paragraph":
			if !documentText(block.Text, 16384) {
				return invalid("Portable document", "$.text", "Invalid paragraph text.")
			}
		case "section":
			if depth >= 8 || !documentText(block.Title, 256) || len(block.Blocks) == 0 {
				return invalid("Portable document", "$.blocks", "Invalid section or section depth.")
			}
			if err := validateDocumentBlocks(block.Blocks, depth+1, count); err != nil {
				return err
			}
		case "bulleted_list", "numbered_list":
			if len(block.Items) == 0 || len(block.Items) > 128 {
				return invalid("Portable document", "$.items", "Expected one through 128 items.")
			}
			for _, item := range block.Items {
				if !documentText(item, 16384) {
					return invalid("Portable document", "$.items", "Invalid list text.")
				}
			}
		default:
			return ErrUnsupportedServiceDocument
		}
	}
	return nil
}

func documentText(value string, maximum int) bool {
	return value != "" && utf8.ValidString(value) && utf8.RuneCountInString(value) <= maximum
}

func (value *ServiceDocument) UnmarshalJSON(data []byte) error {
	type plain ServiceDocument
	var decoded plain
	if err := decodeOne(data, &decoded); err != nil {
		return err
	}
	*value = ServiceDocument(decoded)
	return ValidateServiceDocument(*value)
}
