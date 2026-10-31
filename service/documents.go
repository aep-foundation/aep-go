package service

import (
	"context"
	"encoding/json"
	"errors"
	"slices"

	aep "github.com/aep-foundation/aep-go"
)

func (service *Service) updateEnrollment(ctx context.Context, request aep.EnrollRequest, existing EnrollmentRecord) (Result[aep.EnrollResponse], error) {
	if err := validateEnrollmentRecord(existing); err != nil {
		return Result[aep.EnrollResponse]{}, err
	}
	decision, err := service.enrollmentPolicy.DecideEnrollment(ctx, request, EnrollmentPolicyContext{Now: service.clock()})
	if err != nil {
		return Result[aep.EnrollResponse]{}, err
	}
	if decision.Status != "" && !validEnrollmentDecisionStatus(decision.Status) {
		return Result[aep.EnrollResponse]{}, errors.New("AEP enrollment policy returned an invalid status")
	}
	if decision.Status == aep.EnrollmentRejected {
		return problemResult[aep.EnrollResponse](aep.ErrorEnrollmentFailed, "Enrollment failed", 403), nil
	}
	if decision.UpdateExisting == nil || *decision.UpdateExisting {
		merged, mergeErr := mergeDocumentClaims(existing.Claims, request.Claims)
		if mergeErr != nil {
			return Result[aep.EnrollResponse]{}, mergeErr
		}
		missingClaims := service.missingClaims(merged)
		missingIDs := service.missingDocumentIDs(existing)
		if request.AcknowledgedDocumentIDs != nil {
			missingIDs = nil
		}
		if len(missingClaims) != 0 || len(missingIDs) != 0 {
			return documentRequirements[aep.EnrollResponse](missingClaims, missingIDs), nil
		}
		existing.Claims = merged
		if decision.OwnerActionRequired != nil {
			existing.OwnerActionRequired = *decision.OwnerActionRequired
		}
		if decision.RequirementsPending != nil {
			existing.RequirementsPending = slices.Clone(decision.RequirementsPending)
		}
		if decision.VerificationPending != nil {
			existing.VerificationPending = slices.Clone(decision.VerificationPending)
		}
		existing.AcknowledgedDocumentIDs = service.acceptedDocumentIDs(existing.AcknowledgedDocumentIDs, request.AcknowledgedDocumentIDs)
		existing.RequiredDocumentIDs = slices.DeleteFunc(slices.Clone(existing.RequiredDocumentIDs), func(id string) bool { return slices.Contains(request.AcknowledgedDocumentIDs, id) })
		existing.UpdatedAt = service.clock()
		existing, err = service.enrollmentStore.SaveEnrollment(ctx, existing)
		if err != nil {
			return Result[aep.EnrollResponse]{}, err
		}
	}
	response, failure := enrollmentResult(existing)
	if failure != nil {
		return *failure, nil
	}
	response.AcknowledgedDocumentIDs = slices.Clone(request.AcknowledgedDocumentIDs)
	return successResult(200, response), nil
}

func mergeDocumentClaims(existing, supplied *aep.ClaimValues) (*aep.ClaimValues, error) {
	if existing == nil {
		return cloneClaimValues(supplied)
	}
	merged := map[string]json.RawMessage{}
	for _, claims := range []*aep.ClaimValues{existing, supplied} {
		if claims == nil {
			continue
		}
		data, err := json.Marshal(claims)
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(data, &merged); err != nil {
			return nil, err
		}
	}
	data, err := json.Marshal(merged)
	if err != nil {
		return nil, err
	}
	claims, err := aep.ParseClaimValues(data)
	return &claims, err
}

func (service *Service) missingClaims(claims *aep.ClaimValues) []aep.ClaimName {
	if service.document.Claims == nil {
		return nil
	}
	return aep.MissingRequiredClaimNames(service.document.Claims.Required, claims)
}

func (service *Service) missingDocumentIDs(record EnrollmentRecord) []string {
	var missing []string
	for _, document := range service.document.ServiceDocuments {
		if document.Enrollment == "required" && (!slices.Contains(record.AcknowledgedDocumentIDs, document.ID) || slices.Contains(record.RequiredDocumentIDs, document.ID)) {
			missing = append(missing, document.ID)
		}
	}
	return missing
}

func (service *Service) acceptedDocumentIDs(existing, declared []string) []string {
	ids := slices.Clone(existing)
	for _, id := range declared {
		if !slices.Contains(ids, id) && slices.ContainsFunc(service.document.ServiceDocuments, func(document aep.ServiceDocument) bool { return document.ID == id }) {
			ids = append(ids, id)
		}
	}
	return ids
}

func documentRequirements[T any](claims []aep.ClaimName, ids []string) Result[T] {
	result := problemResult[T](aep.ErrorRequirementsUnmet, "Requirements unmet", 422)
	for _, claim := range claims {
		result.Problem.RequirementsPending = append(result.Problem.RequirementsPending, string(claim))
	}
	if len(ids) != 0 {
		ownerAction := "true"
		result.Problem.OwnerActionRequired = &ownerAction
		result.Problem.RequiredDocumentIDs = slices.Clone(ids)
		result.Problem.RequirementsPending = append(result.Problem.RequirementsPending, "service_documents")
	}
	return result
}
