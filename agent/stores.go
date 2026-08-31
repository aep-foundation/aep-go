package agent

import (
	"context"
	"encoding/json"
	"sort"
	"sync"
	"time"

	aep "github.com/aep-foundation/aep-go"
)

type memoryCredentialStore struct {
	clock   func() time.Time
	mu      sync.RWMutex
	records map[string]CredentialRecord
}

func NewMemoryCredentialStore() CredentialStore {
	return newMemoryCredentialStore(time.Now)
}

func newMemoryCredentialStore(clock func() time.Time) CredentialStore {
	if clock == nil {
		clock = time.Now
	}
	return &memoryCredentialStore{clock: clock, records: make(map[string]CredentialRecord)}
}

func (store *memoryCredentialStore) DeleteCredential(_ context.Context, serviceDID string, credentialID string) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	delete(store.records, credentialKey(serviceDID, credentialID))
	return nil
}

func (store *memoryCredentialStore) FindCredential(_ context.Context, serviceDID string, credentialID string) (*CredentialRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	key := credentialKey(serviceDID, credentialID)
	record, found := store.records[key]
	if !found {
		return nil, nil
	}
	if credentialExpired(record, store.clock()) {
		delete(store.records, key)
		return nil, nil
	}
	copy := cloneCredential(record)
	return &copy, nil
}

func (store *memoryCredentialStore) ListCredentials(_ context.Context, serviceDID string) ([]CredentialRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	now := store.clock()
	result := make([]CredentialRecord, 0)
	for key, record := range store.records {
		if credentialExpired(record, now) {
			delete(store.records, key)
			continue
		}
		if record.ServiceDID == serviceDID {
			result = append(result, cloneCredential(record))
		}
	}
	sort.Slice(result, func(first, second int) bool {
		if result[first].IssuedAt.Equal(result[second].IssuedAt) {
			return result[first].CredentialID < result[second].CredentialID
		}
		return result[first].IssuedAt.After(result[second].IssuedAt)
	})
	return result, nil
}

func (store *memoryCredentialStore) SaveCredential(_ context.Context, record CredentialRecord) error {
	if err := validateStoredCredential(record, record.ServiceDID, store.clock()); err != nil {
		return err
	}
	if _, err := credentialHeaders(record, aep.ProtectedResourceStandard); err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	store.records[credentialKey(record.ServiceDID, record.CredentialID)] = cloneCredential(record)
	return nil
}

func credentialKey(serviceDID string, credentialID string) string {
	return serviceDID + "\x00" + credentialID
}

func credentialExpired(record CredentialRecord, now time.Time) bool {
	return record.ExpiresAt.IsZero() || !record.ExpiresAt.After(now)
}

func cloneCredential(record CredentialRecord) CredentialRecord {
	copy := record
	copy.Payload = append([]byte(nil), record.Payload...)
	return copy
}

type memoryInspectCache struct {
	mu      sync.RWMutex
	records map[string]InspectCacheEntry
}

func NewMemoryInspectCache() InspectCache {
	return &memoryInspectCache{records: make(map[string]InspectCacheEntry)}
}

func (cache *memoryInspectCache) DeleteInspect(_ context.Context, key string) error {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	delete(cache.records, key)
	return nil
}

func (cache *memoryInspectCache) FindInspect(_ context.Context, key string) (*InspectCacheEntry, error) {
	cache.mu.RLock()
	defer cache.mu.RUnlock()
	entry, found := cache.records[key]
	if !found {
		return nil, nil
	}
	copy, err := cloneInspectCacheEntry(entry)
	if err != nil {
		return nil, err
	}
	return &copy, nil
}

func (cache *memoryInspectCache) SaveInspect(_ context.Context, key string, entry InspectCacheEntry) error {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	copy, err := cloneInspectCacheEntry(entry)
	if err != nil {
		return err
	}
	cache.records[key] = copy
	return nil
}

func cloneInspectCacheEntry(entry InspectCacheEntry) (InspectCacheEntry, error) {
	copy := entry
	var err error
	copy.Document, err = cloneInspectDocument(entry.Document)
	if err != nil {
		return InspectCacheEntry{}, err
	}
	return copy, nil
}

func cloneInspectDocument(document aep.InspectDocument) (aep.InspectDocument, error) {
	data, err := json.Marshal(document)
	if err != nil {
		return aep.InspectDocument{}, err
	}
	return aep.ParseInspectDocument(data)
}
