package platform

import (
	"context"
	"errors"
	"slices"
	"sort"
	"sync"
	"time"
)

type memoryIdentityStore struct {
	byAgentDID   map[string]string
	byAgentDIDID map[string]string
	byScope      map[string]string
	mu           sync.Mutex
	pending      map[string]chan struct{}
	records      map[string]IdentityRecord
}

func NewMemoryIdentityStore() IdentityStore {
	return &memoryIdentityStore{
		byAgentDID:   make(map[string]string),
		byAgentDIDID: make(map[string]string),
		byScope:      make(map[string]string),
		pending:      make(map[string]chan struct{}),
		records:      make(map[string]IdentityRecord),
	}
}

func (store *memoryIdentityStore) FindOrCreateIdentity(ctx context.Context, principal string, serviceDID string, create func() (IdentityRecord, error)) (IdentityRecord, bool, error) {
	if principal == "" || serviceDID == "" || create == nil {
		return IdentityRecord{}, false, errors.New("AEP Platform identity store requires a principal, Service DID, and create function")
	}
	key := identityScopeKey(principal, serviceDID)
	for {
		if err := ctx.Err(); err != nil {
			return IdentityRecord{}, false, err
		}
		store.mu.Lock()
		if identityID := store.byScope[key]; identityID != "" {
			record := cloneIdentityRecord(store.records[identityID])
			store.mu.Unlock()
			return record, false, nil
		}
		if pending := store.pending[key]; pending != nil {
			store.mu.Unlock()
			select {
			case <-ctx.Done():
				return IdentityRecord{}, false, ctx.Err()
			case <-pending:
				continue
			}
		}
		pending := make(chan struct{})
		store.pending[key] = pending
		store.mu.Unlock()

		record, err := create()
		if err == nil {
			err = validateIdentityRecord(record)
		}
		if err == nil && (record.Principal != principal || record.ServiceDID != serviceDID) {
			err = errors.New("AEP Platform identity store record does not match its requested scope")
		}

		store.mu.Lock()
		delete(store.pending, key)
		if err == nil {
			if _, found := store.records[record.AgentIdentityID]; found || store.byAgentDID[record.AgentDID] != "" || store.byAgentDIDID[record.AgentDIDID] != "" {
				err = errors.New("AEP Platform identity store received duplicate identity material")
			} else {
				stored := cloneIdentityRecord(record)
				store.records[stored.AgentIdentityID] = stored
				store.byScope[key] = stored.AgentIdentityID
				store.byAgentDID[stored.AgentDID] = stored.AgentIdentityID
				store.byAgentDIDID[stored.AgentDIDID] = stored.AgentIdentityID
			}
		}
		close(pending)
		store.mu.Unlock()
		if err != nil {
			return IdentityRecord{}, false, err
		}
		return cloneIdentityRecord(record), true, nil
	}
}

func (store *memoryIdentityStore) FindIdentityByAgentDID(ctx context.Context, agentDID string) (*IdentityRecord, error) {
	return store.find(ctx, store.byAgentDID, agentDID)
}

func (store *memoryIdentityStore) FindIdentityByAgentDIDID(ctx context.Context, agentDIDID string) (*IdentityRecord, error) {
	return store.find(ctx, store.byAgentDIDID, agentDIDID)
}

func (store *memoryIdentityStore) find(ctx context.Context, index map[string]string, key string) (*IdentityRecord, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	store.mu.Lock()
	identityID := index[key]
	record, found := store.records[identityID]
	store.mu.Unlock()
	if !found {
		return nil, nil
	}
	copy := cloneIdentityRecord(record)
	return &copy, nil
}

func (store *memoryIdentityStore) GetIdentity(ctx context.Context, agentIdentityID string) (*IdentityRecord, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	store.mu.Lock()
	record, found := store.records[agentIdentityID]
	store.mu.Unlock()
	if !found {
		return nil, nil
	}
	copy := cloneIdentityRecord(record)
	return &copy, nil
}

func (store *memoryIdentityStore) ListIdentities(ctx context.Context, principal string, query IdentityListQuery) (IdentityListResult, error) {
	if err := ctx.Err(); err != nil {
		return IdentityListResult{}, err
	}
	if principal == "" || query.Limit < 0 || query.Offset < 0 {
		return IdentityListResult{}, errors.New("AEP Platform identity list query is invalid")
	}
	store.mu.Lock()
	records := make([]IdentityRecord, 0, len(store.records))
	for _, record := range store.records {
		if record.Principal != principal || query.ServiceDID != "" && record.ServiceDID != query.ServiceDID || query.Status != "" && record.Status != query.Status {
			continue
		}
		records = append(records, cloneIdentityRecord(record))
	}
	store.mu.Unlock()
	sort.Slice(records, func(first int, second int) bool {
		if records[first].CreatedAt.Equal(records[second].CreatedAt) {
			if query.Descending {
				return records[first].AgentIdentityID > records[second].AgentIdentityID
			}
			return records[first].AgentIdentityID < records[second].AgentIdentityID
		}
		if query.Descending {
			return records[first].CreatedAt.After(records[second].CreatedAt)
		}
		return records[first].CreatedAt.Before(records[second].CreatedAt)
	})
	total := len(records)
	if query.Offset >= total {
		records = []IdentityRecord{}
	} else if query.Offset != 0 {
		records = records[query.Offset:]
	}
	if query.Limit != 0 && len(records) > query.Limit {
		records = records[:query.Limit]
	}
	return IdentityListResult{Identities: records, Total: total}, nil
}

func (store *memoryIdentityStore) UpdateIdentity(ctx context.Context, agentIdentityID string, status ManagedAgentStatus, updatedAt time.Time) (*IdentityRecord, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !isManagedAgentStatus(status) || updatedAt.IsZero() {
		return nil, errors.New("AEP Platform identity update is invalid")
	}
	store.mu.Lock()
	record, found := store.records[agentIdentityID]
	if found {
		record.Status = status
		record.UpdatedAt = updatedAt
		store.records[agentIdentityID] = record
	}
	store.mu.Unlock()
	if !found {
		return nil, nil
	}
	copy := cloneIdentityRecord(record)
	return &copy, nil
}

type memoryIdempotencyStore struct {
	clock   func() time.Time
	mu      sync.Mutex
	pending map[string]chan struct{}
	records map[string]idempotencyRecord
}

type idempotencyRecord struct {
	input    IdempotencyInput
	response StoredResponse
}

func NewMemoryIdempotencyStore() IdempotencyStore {
	return newMemoryIdempotencyStore(time.Now)
}

func newMemoryIdempotencyStore(clock func() time.Time) IdempotencyStore {
	return &memoryIdempotencyStore{clock: clock, pending: make(map[string]chan struct{}), records: make(map[string]idempotencyRecord)}
}

func (store *memoryIdempotencyStore) ExecuteIdempotent(ctx context.Context, input IdempotencyInput, execute func() (StoredResponse, error)) (IdempotencyResult, error) {
	if input.Principal == "" || input.IdempotencyKey == "" || input.Operation == "" || input.RequestHash == "" || execute == nil {
		return IdempotencyResult{}, errors.New("AEP Platform idempotency store received invalid input")
	}
	key := input.Principal + "\x00" + input.IdempotencyKey
	for {
		if err := ctx.Err(); err != nil {
			return IdempotencyResult{}, err
		}
		store.mu.Lock()
		store.expire(store.clock())
		if record, found := store.records[key]; found {
			store.mu.Unlock()
			if record.input.Operation != input.Operation || record.input.RequestHash != input.RequestHash {
				return IdempotencyResult{State: IdempotencyConflict}, nil
			}
			return IdempotencyResult{Response: cloneStoredResponse(record.response), State: IdempotencyReplayed}, nil
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

type memoryReplayStore struct {
	mu      sync.Mutex
	records map[string]time.Time
}

func NewMemoryReplayStore() ReplayStore {
	return &memoryReplayStore{records: make(map[string]time.Time)}
}

func (store *memoryReplayStore) ConsumeReplay(ctx context.Context, key string, expiresAt time.Time) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if key == "" || expiresAt.IsZero() {
		return false, errors.New("AEP Platform replay store received invalid input")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	now := time.Now()
	if !expiresAt.After(now) {
		return false, nil
	}
	for existingKey, existingExpiry := range store.records {
		if !existingExpiry.After(now) {
			delete(store.records, existingKey)
		}
	}
	if _, found := store.records[key]; found {
		return false, nil
	}
	store.records[key] = expiresAt
	return true, nil
}

func validateIdentityRecord(record IdentityRecord) error {
	if record.AgentDID == "" || record.AgentDIDID == "" || record.AgentIdentityID == "" || record.CreatedAt.IsZero() || record.DIDDocumentURL == "" || record.KeyID == "" || record.Principal == "" || record.ServiceDID == "" || len(record.SigningAlgorithms) == 0 || !isManagedAgentStatus(record.Status) || record.UpdatedAt.IsZero() {
		return errors.New("AEP Platform identity store received an invalid record")
	}
	return nil
}

func cloneIdentityRecord(record IdentityRecord) IdentityRecord {
	copy := record
	copy.SigningAlgorithms = slices.Clone(record.SigningAlgorithms)
	return copy
}

func cloneStoredResponse(response StoredResponse) StoredResponse {
	copy := response
	copy.Body = slices.Clone(response.Body)
	if response.Headers != nil {
		copy.Headers = response.Headers.Clone()
	}
	return copy
}

func identityScopeKey(principal string, serviceDID string) string {
	return principal + "\x00" + serviceDID
}
