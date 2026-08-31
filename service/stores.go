package service

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"time"

	aep "github.com/aep-foundation/aep-go"
)

type memoryEnrollmentStore struct {
	mu      sync.Mutex
	pending map[string]chan struct{}
	records map[string]EnrollmentRecord
}

func NewMemoryEnrollmentStore() EnrollmentStore {
	return &memoryEnrollmentStore{pending: make(map[string]chan struct{}), records: make(map[string]EnrollmentRecord)}
}

func (store *memoryEnrollmentStore) FindEnrollment(ctx context.Context, agentDID string) (*EnrollmentRecord, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	store.mu.Lock()
	record, found := store.records[agentDID]
	store.mu.Unlock()
	if !found {
		return nil, nil
	}
	copy, err := cloneEnrollment(record)
	if err != nil {
		return nil, err
	}
	return &copy, nil
}

func (store *memoryEnrollmentStore) FindOrCreateEnrollment(ctx context.Context, agentDID string, create func() (EnrollmentRecord, error)) (EnrollmentRecord, bool, error) {
	if agentDID == "" || create == nil {
		return EnrollmentRecord{}, false, errors.New("AEP enrollment store requires a create function")
	}
	for {
		if err := ctx.Err(); err != nil {
			return EnrollmentRecord{}, false, err
		}
		store.mu.Lock()
		if existing, found := store.records[agentDID]; found {
			store.mu.Unlock()
			copy, err := cloneEnrollment(existing)
			return copy, false, err
		}
		if pending := store.pending[agentDID]; pending != nil {
			store.mu.Unlock()
			select {
			case <-ctx.Done():
				return EnrollmentRecord{}, false, ctx.Err()
			case <-pending:
				continue
			}
		}
		pending := make(chan struct{})
		store.pending[agentDID] = pending
		store.mu.Unlock()

		record, err := create()
		if err == nil {
			err = validateEnrollmentRecord(record)
		}
		if err == nil && record.AgentDID != agentDID {
			err = errors.New("AEP enrollment store record does not match the requested Agent DID")
		}
		var stored EnrollmentRecord
		if err == nil {
			stored, err = cloneEnrollment(record)
		}
		store.mu.Lock()
		delete(store.pending, agentDID)
		if err == nil {
			store.records[agentDID] = stored
		}
		close(pending)
		store.mu.Unlock()
		if err != nil {
			return EnrollmentRecord{}, false, err
		}
		copy, cloneErr := cloneEnrollment(stored)
		return copy, true, cloneErr
	}
}

func (store *memoryEnrollmentStore) SaveEnrollment(ctx context.Context, record EnrollmentRecord) (EnrollmentRecord, error) {
	if err := validateEnrollmentRecord(record); err != nil {
		return EnrollmentRecord{}, err
	}
	for {
		if err := ctx.Err(); err != nil {
			return EnrollmentRecord{}, err
		}
		store.mu.Lock()
		if pending := store.pending[record.AgentDID]; pending != nil {
			store.mu.Unlock()
			select {
			case <-ctx.Done():
				return EnrollmentRecord{}, ctx.Err()
			case <-pending:
				continue
			}
		}
		stored, err := cloneEnrollment(record)
		if err != nil {
			store.mu.Unlock()
			return EnrollmentRecord{}, err
		}
		store.records[record.AgentDID] = stored
		store.mu.Unlock()
		return cloneEnrollment(stored)
	}
}

func validateEnrollmentRecord(record EnrollmentRecord) error {
	if record.AgentDID == "" || record.EnrollmentID == "" || record.CreatedAt.IsZero() || record.Since.IsZero() || record.UpdatedAt.IsZero() {
		return errors.New("AEP enrollment store received an invalid record")
	}
	if record.Status != aep.AgentActive && record.Status != aep.AgentPending && record.Status != aep.AgentRejected && record.Status != aep.AgentSuspended && record.Status != aep.AgentTerminated && record.Status != aep.AgentUnavailable {
		return errors.New("AEP enrollment store received an invalid enrollment status")
	}
	return nil
}

type memoryReplayStore struct {
	mu      sync.Mutex
	records map[string]ReplayRecord
}

func NewMemoryReplayStore() ReplayStore {
	return &memoryReplayStore{records: make(map[string]ReplayRecord)}
}

func (store *memoryReplayStore) ConsumeReplay(ctx context.Context, record ReplayRecord, now int64) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if record.Subject == "" || record.JWTID == "" || record.ExpiresAt <= now {
		return false, errors.New("AEP replay store received an invalid record")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	for key, existing := range store.records {
		if existing.ExpiresAt <= now {
			delete(store.records, key)
		}
	}
	key := record.Subject + "\x00" + record.JWTID
	if _, found := store.records[key]; found {
		return false, nil
	}
	store.records[key] = record
	return true, nil
}

type idempotencyRecord struct {
	input    IdempotencyInput
	response StoredResponse
}

type memoryIdempotencyStore struct {
	clock   func() time.Time
	mu      sync.Mutex
	pending map[string]chan struct{}
	records map[string]idempotencyRecord
}

func NewMemoryIdempotencyStore() IdempotencyStore {
	return newMemoryIdempotencyStore(time.Now)
}

func newMemoryIdempotencyStore(clock func() time.Time) IdempotencyStore {
	return &memoryIdempotencyStore{clock: clock, pending: make(map[string]chan struct{}), records: make(map[string]idempotencyRecord)}
}

func (store *memoryIdempotencyStore) ExecuteIdempotent(ctx context.Context, input IdempotencyInput, execute func() (StoredResponse, error)) (IdempotencyResult, error) {
	if input.AgentDID == "" || input.Command == "" || input.IdempotencyKey == "" || input.RequestHash == "" || execute == nil {
		return IdempotencyResult{}, errors.New("AEP idempotency store received invalid input")
	}
	key := input.AgentDID + "\x00" + input.IdempotencyKey
	for {
		store.mu.Lock()
		store.expire(store.clock())
		if existing, found := store.records[key]; found {
			store.mu.Unlock()
			if existing.input.Command != input.Command || existing.input.RequestHash != input.RequestHash {
				return IdempotencyResult{State: IdempotencyConflict}, nil
			}
			return IdempotencyResult{Response: cloneStoredResponse(existing.response), State: IdempotencyReplayed}, nil
		}
		if pending := store.pending[key]; pending != nil {
			store.mu.Unlock()
			select {
			case <-ctx.Done():
				return IdempotencyResult{}, ctx.Err()
			case <-pending:
				continue
			}
		}
		pending := make(chan struct{})
		store.pending[key] = pending
		store.mu.Unlock()

		response, err := execute()
		store.mu.Lock()
		delete(store.pending, key)
		if err == nil {
			if response.CreatedAt.IsZero() {
				response.CreatedAt = store.clock()
			}
			store.records[key] = idempotencyRecord{input: input, response: cloneStoredResponse(response)}
		}
		close(pending)
		store.mu.Unlock()
		if err != nil {
			return IdempotencyResult{}, err
		}
		return IdempotencyResult{Response: cloneStoredResponse(response), State: IdempotencyCreated}, nil
	}
}

func (store *memoryIdempotencyStore) expire(now time.Time) {
	for key, record := range store.records {
		if !record.response.CreatedAt.Add(time.Hour).After(now) {
			delete(store.records, key)
		}
	}
}

type staticEnrollmentPolicy struct {
	decision EnrollmentDecision
}

func NewStaticEnrollmentPolicy(decision EnrollmentDecision) EnrollmentPolicy {
	return staticEnrollmentPolicy{decision: decision}
}

func (policy staticEnrollmentPolicy) DecideEnrollment(context.Context, aep.EnrollRequest, EnrollmentPolicyContext) (EnrollmentDecision, error) {
	decision := policy.decision
	if decision.Status == "" {
		decision.Status = aep.EnrollmentActive
	}
	decision.RequirementsPending = append([]string(nil), decision.RequirementsPending...)
	decision.VerificationPending = append([]string(nil), decision.VerificationPending...)
	return decision, nil
}

func cloneEnrollment(record EnrollmentRecord) (EnrollmentRecord, error) {
	copy := record
	copy.RequirementsPending = append([]string(nil), record.RequirementsPending...)
	copy.VerificationPending = append([]string(nil), record.VerificationPending...)
	if record.Claims != nil {
		data, err := json.Marshal(record.Claims)
		if err != nil {
			return EnrollmentRecord{}, err
		}
		claims, err := aep.ParseClaimValues(data)
		if err != nil {
			return EnrollmentRecord{}, err
		}
		copy.Claims = &claims
	}
	return copy, nil
}

func cloneStoredResponse(response StoredResponse) StoredResponse {
	copy := response
	copy.Body = append(json.RawMessage(nil), response.Body...)
	copy.Headers = cloneHeader(response.Headers)
	return copy
}

func cloneHeader(header http.Header) http.Header {
	if header == nil {
		return nil
	}
	return header.Clone()
}
