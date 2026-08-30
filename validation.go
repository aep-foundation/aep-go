package aep

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
)

func decodeOne(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}

func rejectNullPaths(data []byte, documentType string, paths ...string) error {
	var root any
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(&root); err != nil {
		return nil
	}
	issues := make([]ValidationIssue, 0)
	for _, path := range paths {
		parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
		current := root
		present := true
		for _, part := range parts {
			object, ok := current.(map[string]any)
			if !ok {
				present = false
				break
			}
			current, present = object[part]
			if !present {
				break
			}
		}
		if present && current == nil {
			issues = append(issues, ValidationIssue{Path: "$" + strings.ReplaceAll(path, "/", "."), Message: "Expected a non-null value."})
		}
	}
	return validationResult(documentType, issues)
}

func validationResult(documentType string, issues []ValidationIssue) error {
	if len(issues) == 0 {
		return nil
	}
	return &ValidationError{DocumentType: documentType, Issues: issues}
}

func requireNonEmpty(value, path string, issues *[]ValidationIssue) {
	if value == "" {
		*issues = append(*issues, ValidationIssue{Path: path, Message: "Expected a non-empty string."})
	}
}

func requireUniqueStrings[Value ~string](values []Value, path string, issues *[]ValidationIssue) {
	seen := make(map[Value]struct{}, len(values))
	for _, value := range values {
		if _, exists := seen[value]; exists {
			*issues = append(*issues, ValidationIssue{
				Path:    path,
				Message: "Expected unique items.",
			})
			return
		}
		seen[value] = struct{}{}
	}
}

func contains[Value comparable](values []Value, expected Value) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}
