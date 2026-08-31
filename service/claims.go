package service

import (
	"bytes"
	"encoding/json"
	"errors"
	"unicode/utf8"

	aep "github.com/aep-foundation/aep-go"
)

var defaultClaimValueLimits = ClaimValueLimits{
	MaxEncodedBytes: 65_536,
	MaxMemberCount:  128,
	MaxObjectDepth:  8,
	MaxStringLength: 4_096,
}

func DefaultClaimValueLimits() ClaimValueLimits {
	return defaultClaimValueLimits
}

func resolveClaimValueLimits(configured *ClaimValueLimits) (ClaimValueLimits, error) {
	limits := defaultClaimValueLimits
	if configured != nil {
		if configured.MaxEncodedBytes < 0 || configured.MaxMemberCount < 0 || configured.MaxObjectDepth < 0 || configured.MaxStringLength < 0 {
			return ClaimValueLimits{}, errors.New("AEP Service Claim Value limits must not be negative")
		}
		if configured.MaxEncodedBytes != 0 {
			limits.MaxEncodedBytes = configured.MaxEncodedBytes
		}
		if configured.MaxMemberCount != 0 {
			limits.MaxMemberCount = configured.MaxMemberCount
		}
		if configured.MaxObjectDepth != 0 {
			limits.MaxObjectDepth = configured.MaxObjectDepth
		}
		if configured.MaxStringLength != 0 {
			limits.MaxStringLength = configured.MaxStringLength
		}
	}
	return limits, nil
}

func claimValuesWithinLimits(value *aep.ClaimValues, limits ClaimValueLimits) bool {
	if value == nil {
		return true
	}
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded) > limits.MaxEncodedBytes {
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	var document any
	if err := decoder.Decode(&document); err != nil {
		return false
	}
	members := 0
	return claimValueWithinLimits(document, 1, limits, &members)
}

func claimValueWithinLimits(value any, depth int, limits ClaimValueLimits, members *int) bool {
	switch typed := value.(type) {
	case string:
		return utf8.RuneCountInString(typed) <= limits.MaxStringLength
	case nil, bool, json.Number:
		return true
	case []any:
		if depth > limits.MaxObjectDepth {
			return false
		}
		for _, member := range typed {
			if !claimValueWithinLimits(member, depth+1, limits, members) {
				return false
			}
		}
		return true
	case map[string]any:
		if depth > limits.MaxObjectDepth {
			return false
		}
		for name, member := range typed {
			*members = *members + 1
			if *members > limits.MaxMemberCount || utf8.RuneCountInString(name) > limits.MaxStringLength || !claimValueWithinLimits(member, depth+1, limits, members) {
				return false
			}
		}
		return true
	default:
		return false
	}
}
