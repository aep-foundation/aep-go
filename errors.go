package aep

import "fmt"

type ValidationIssue struct {
	Message string `json:"message"`
	Path    string `json:"path"`
}

type ValidationError struct {
	DocumentType string            `json:"document_type"`
	Issues       []ValidationIssue `json:"issues"`
}

func (err *ValidationError) Error() string {
	return "invalid AEP " + err.DocumentType
}

type AuthorizationCarrierError struct {
	Code ErrorCode
	Text string
}

func (err *AuthorizationCarrierError) Error() string {
	return err.Text
}

func invalid(documentType, path, message string) error {
	return &ValidationError{
		DocumentType: documentType,
		Issues:       []ValidationIssue{{Path: path, Message: message}},
	}
}

func wrapDecodeError(documentType string, err error) error {
	return invalid(documentType, "$", fmt.Sprintf("Invalid JSON: %v", err))
}
