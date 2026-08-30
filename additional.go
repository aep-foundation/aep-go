package aep

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
)

func decodeAdditional(data []byte, known any) (AdditionalMembers, error) {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(data, &object); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, known); err != nil {
		return nil, err
	}
	valueType := reflect.TypeOf(known)
	if valueType.Kind() != reflect.Pointer || valueType.Elem().Kind() != reflect.Struct {
		return nil, fmt.Errorf("AEP additional-member target must be a struct pointer")
	}
	for name := range jsonFieldNames(valueType.Elem()) {
		delete(object, name)
	}
	if len(object) == 0 {
		return nil, nil
	}
	return object, nil
}

func encodeAdditional(known any, additional AdditionalMembers) ([]byte, error) {
	data, err := json.Marshal(known)
	if err != nil || len(additional) == 0 {
		return data, err
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(data, &object); err != nil {
		return nil, err
	}
	knownType := reflect.TypeOf(known)
	if knownType.Kind() == reflect.Pointer {
		knownType = knownType.Elem()
	}
	fields := jsonFieldNames(knownType)
	for name, value := range additional {
		if _, knownName := fields[name]; !knownName {
			object[name] = value
		}
	}
	return json.Marshal(object)
}

func jsonFieldNames(valueType reflect.Type) map[string]struct{} {
	names := make(map[string]struct{}, valueType.NumField())
	for index := 0; index < valueType.NumField(); index++ {
		name := strings.Split(valueType.Field(index).Tag.Get("json"), ",")[0]
		if name != "" && name != "-" {
			names[name] = struct{}{}
		}
	}
	return names
}

func (value *Authentication) UnmarshalJSON(data []byte) error {
	type plain Authentication
	var decoded plain
	additional, err := decodeAdditional(data, &decoded)
	if err != nil {
		return err
	}
	*value = Authentication(decoded)
	value.Additional = additional
	return nil
}

func (value Authentication) MarshalJSON() ([]byte, error) {
	type plain Authentication
	return encodeAdditional(plain(value), value.Additional)
}

func (value *OpenAPIPathMatching) UnmarshalJSON(data []byte) error {
	type plain OpenAPIPathMatching
	var decoded plain
	additional, err := decodeAdditional(data, &decoded)
	if err != nil {
		return err
	}
	*value = OpenAPIPathMatching(decoded)
	value.Additional = additional
	return nil
}

func (value OpenAPIPathMatching) MarshalJSON() ([]byte, error) {
	type plain OpenAPIPathMatching
	return encodeAdditional(plain(value), value.Additional)
}

func (value *OpenAPIReference) UnmarshalJSON(data []byte) error {
	type plain OpenAPIReference
	var decoded plain
	additional, err := decodeAdditional(data, &decoded)
	if err != nil {
		return err
	}
	*value = OpenAPIReference(decoded)
	value.Additional = additional
	return nil
}

func (value OpenAPIReference) MarshalJSON() ([]byte, error) {
	type plain OpenAPIReference
	return encodeAdditional(plain(value), value.Additional)
}

func (value *InspectDocument) UnmarshalJSON(data []byte) error {
	type plain InspectDocument
	var decoded plain
	additional, err := decodeAdditional(data, &decoded)
	if err != nil {
		return err
	}
	*value = InspectDocument(decoded)
	value.Additional = additional
	return nil
}

func (value InspectDocument) MarshalJSON() ([]byte, error) {
	type plain InspectDocument
	return encodeAdditional(plain(value), value.Additional)
}

func (value *ContactAddressPrimary) UnmarshalJSON(data []byte) error {
	type plain ContactAddressPrimary
	var decoded plain
	additional, err := decodeAdditional(data, &decoded)
	if err != nil {
		return err
	}
	*value = ContactAddressPrimary(decoded)
	value.Additional = additional
	return nil
}

func (value ContactAddressPrimary) MarshalJSON() ([]byte, error) {
	type plain ContactAddressPrimary
	return encodeAdditional(plain(value), value.Additional)
}

func (value *ClaimValues) UnmarshalJSON(data []byte) error {
	var claims map[string]json.RawMessage
	if err := json.Unmarshal(data, &claims); err != nil {
		return err
	}
	if claims == nil {
		return errors.New("AEP Claim Values must be an object")
	}
	value.Additional = make(AdditionalMembers)
	for name, raw := range claims {
		switch ClaimName(name) {
		case ClaimContactAddressPrimary:
			var address ContactAddressPrimary
			if err := json.Unmarshal(raw, &address); err != nil {
				return err
			}
			value.ContactAddressPrimary = &address
		case ClaimContactEmail:
			if err := json.Unmarshal(raw, &value.ContactEmail); err != nil {
				return err
			}
		case ClaimContactMobile:
			if err := json.Unmarshal(raw, &value.ContactMobile); err != nil {
				return err
			}
		case ClaimPersonBirthdate:
			if err := json.Unmarshal(raw, &value.PersonBirthdate); err != nil {
				return err
			}
		case ClaimPersonFirstName:
			if err := json.Unmarshal(raw, &value.PersonFirstName); err != nil {
				return err
			}
		case ClaimPersonLastName:
			if err := json.Unmarshal(raw, &value.PersonLastName); err != nil {
				return err
			}
		case ClaimPersonUsername:
			if err := json.Unmarshal(raw, &value.PersonUsername); err != nil {
				return err
			}
		default:
			value.Additional[name] = raw
		}
	}
	if len(value.Additional) == 0 {
		value.Additional = nil
	}
	return nil
}

func (value ClaimValues) MarshalJSON() ([]byte, error) {
	object := make(map[string]any, len(value.Additional)+7)
	for name, raw := range value.Additional {
		object[name] = raw
	}
	if value.ContactAddressPrimary != nil {
		object[string(ClaimContactAddressPrimary)] = value.ContactAddressPrimary
	}
	if value.ContactEmail != nil {
		object[string(ClaimContactEmail)] = *value.ContactEmail
	}
	if value.ContactMobile != nil {
		object[string(ClaimContactMobile)] = *value.ContactMobile
	}
	if value.PersonBirthdate != nil {
		object[string(ClaimPersonBirthdate)] = *value.PersonBirthdate
	}
	if value.PersonFirstName != nil {
		object[string(ClaimPersonFirstName)] = *value.PersonFirstName
	}
	if value.PersonLastName != nil {
		object[string(ClaimPersonLastName)] = *value.PersonLastName
	}
	if value.PersonUsername != nil {
		object[string(ClaimPersonUsername)] = *value.PersonUsername
	}
	return json.Marshal(object)
}

func (value *EnrollRequest) UnmarshalJSON(data []byte) error {
	type plain EnrollRequest
	var decoded plain
	additional, err := decodeAdditional(data, &decoded)
	if err != nil {
		return err
	}
	*value = EnrollRequest(decoded)
	value.Additional = additional
	return nil
}

func (value EnrollRequest) MarshalJSON() ([]byte, error) {
	type plain EnrollRequest
	return encodeAdditional(plain(value), value.Additional)
}

func (value *ProblemDetails) UnmarshalJSON(data []byte) error {
	type plain ProblemDetails
	var decoded plain
	additional, err := decodeAdditional(data, &decoded)
	if err != nil {
		return err
	}
	*value = ProblemDetails(decoded)
	value.Additional = additional
	return nil
}

func (value ProblemDetails) MarshalJSON() ([]byte, error) {
	type plain ProblemDetails
	return encodeCanonicalOwnerAction(plain(value), value.Additional, value.OwnerActionRequired)
}

func (value *EnrollResponse) UnmarshalJSON(data []byte) error {
	type plain EnrollResponse
	var decoded plain
	additional, err := decodeAdditional(data, &decoded)
	if err != nil {
		return err
	}
	*value = EnrollResponse(decoded)
	value.Additional = additional
	return nil
}

func (value EnrollResponse) MarshalJSON() ([]byte, error) {
	type plain EnrollResponse
	return encodeCanonicalOwnerAction(plain(value), value.Additional, value.OwnerActionRequired)
}

func (value *StatusResponse) UnmarshalJSON(data []byte) error {
	type plain StatusResponse
	var decoded plain
	additional, err := decodeAdditional(data, &decoded)
	if err != nil {
		return err
	}
	*value = StatusResponse(decoded)
	value.Additional = additional
	return nil
}

func (value StatusResponse) MarshalJSON() ([]byte, error) {
	type plain StatusResponse
	return encodeCanonicalOwnerAction(plain(value), value.Additional, value.OwnerActionRequired)
}

func encodeCanonicalOwnerAction(known any, additional AdditionalMembers, ownerAction *string) ([]byte, error) {
	data, err := encodeAdditional(known, additional)
	if err != nil || ownerAction == nil || *ownerAction == "true" {
		return data, err
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(data, &object); err != nil {
		return nil, err
	}
	delete(object, "owner_action_required")
	return json.Marshal(object)
}

func (value *GrantRequest) UnmarshalJSON(data []byte) error {
	type plain GrantRequest
	var decoded plain
	additional, err := decodeAdditional(data, &decoded)
	if err != nil {
		return err
	}
	*value = GrantRequest(decoded)
	value.Additional = additional
	return nil
}

func (value GrantRequest) MarshalJSON() ([]byte, error) {
	type plain GrantRequest
	return encodeAdditional(plain(value), value.Additional)
}

func (value *RevokeRequest) UnmarshalJSON(data []byte) error {
	type plain RevokeRequest
	var decoded plain
	additional, err := decodeAdditional(data, &decoded)
	if err != nil {
		return err
	}
	*value = RevokeRequest(decoded)
	value.Additional = additional
	return nil
}

func (value RevokeRequest) MarshalJSON() ([]byte, error) {
	type plain RevokeRequest
	return encodeAdditional(plain(value), value.Additional)
}

func (value *IdempotencyMetadata) UnmarshalJSON(data []byte) error {
	type plain IdempotencyMetadata
	var decoded plain
	additional, err := decodeAdditional(data, &decoded)
	if err != nil {
		return err
	}
	*value = IdempotencyMetadata(decoded)
	value.Additional = additional
	return nil
}

func (value IdempotencyMetadata) MarshalJSON() ([]byte, error) {
	type plain IdempotencyMetadata
	return encodeAdditional(plain(value), value.Additional)
}

func (value *OpenAPIAEPSecurityScheme) UnmarshalJSON(data []byte) error {
	type plain OpenAPIAEPSecurityScheme
	var decoded plain
	additional, err := decodeAdditional(data, &decoded)
	if err != nil {
		return err
	}
	*value = OpenAPIAEPSecurityScheme(decoded)
	value.Additional = additional
	return nil
}

func (value OpenAPIAEPSecurityScheme) MarshalJSON() ([]byte, error) {
	type plain OpenAPIAEPSecurityScheme
	return encodeAdditional(plain(value), value.Additional)
}

func (value *ClientAssertionClaims) UnmarshalJSON(data []byte) error {
	type plain ClientAssertionClaims
	var decoded plain
	additional, err := decodeAdditional(data, &decoded)
	if err != nil {
		return err
	}
	*value = ClientAssertionClaims(decoded)
	value.Additional = additional
	return nil
}

func (value ClientAssertionClaims) MarshalJSON() ([]byte, error) {
	type plain ClientAssertionClaims
	return encodeAdditional(plain(value), value.Additional)
}
