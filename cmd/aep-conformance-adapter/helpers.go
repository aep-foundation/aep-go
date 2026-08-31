package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
)

func requiredField[T any](object map[string]json.RawMessage, name string) (T, error) {
	var value T
	raw, found := object[name]
	if !found {
		return value, fmt.Errorf("required field %q is missing", name)
	}
	if err := json.Unmarshal(raw, &value); err != nil {
		return value, fmt.Errorf("decode field %q: %w", name, err)
	}
	return value, nil
}

func optionalField[T any](object map[string]json.RawMessage, name string) (T, bool, error) {
	var value T
	raw, found := object[name]
	if !found {
		return value, false, nil
	}
	if err := json.Unmarshal(raw, &value); err != nil {
		return value, true, fmt.Errorf("decode field %q: %w", name, err)
	}
	return value, true, nil
}

func rawField(object map[string]json.RawMessage, name string) (json.RawMessage, error) {
	raw, found := object[name]
	if !found {
		return nil, fmt.Errorf("required field %q is missing", name)
	}
	return append(json.RawMessage(nil), raw...), nil
}

func validExpectation(request adapterRequest) (bool, error) {
	return requiredField[bool](request.Case.Expected, "valid")
}

func parseValidity(request adapterRequest, name string, parse func([]byte) error) (bool, error) {
	raw, err := rawField(request.Case.Input, name)
	if err != nil {
		return false, err
	}
	expected, err := validExpectation(request)
	if err != nil {
		return false, err
	}
	return (parse(raw) == nil) == expected, nil
}

func jsonEqual(left any, right any) bool {
	leftJSON, leftErr := json.Marshal(left)
	rightJSON, rightErr := json.Marshal(right)
	if leftErr != nil || rightErr != nil {
		return false
	}
	var leftValue any
	var rightValue any
	return json.Unmarshal(leftJSON, &leftValue) == nil && json.Unmarshal(rightJSON, &rightValue) == nil && reflect.DeepEqual(leftValue, rightValue)
}

func joined(errorsToJoin ...error) error {
	return errors.Join(errorsToJoin...)
}
