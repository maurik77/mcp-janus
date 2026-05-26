package auth

import (
	"sync"
	"time"
)

// jtiStore prevents JWT assertion replay by tracking seen jti values until
// the assertion's expiry time.
type jtiStore struct {
	mu      sync.Mutex
	entries map[string]time.Time // jti → expiry
}

func newJTIStore() *jtiStore {
	return &jtiStore{entries: make(map[string]time.Time)}
}

// Seen returns true if this jti was already seen (replay attempt), and registers
// it otherwise. Expired entries are pruned on every call.
func (s *jtiStore) Seen(jti string, exp time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	// Prune expired entries.
	for k, v := range s.entries {
		if now.After(v) {
			delete(s.entries, k)
		}
	}

	if _, exists := s.entries[jti]; exists {
		return true
	}
	s.entries[jti] = exp
	return false
}
