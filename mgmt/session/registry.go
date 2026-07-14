package session

import (
	"sync"
	"time"
)

type lockState struct {
	endpoint   string
	lastActive time.Time
}

type Registry struct {
	mu    sync.RWMutex
	locks map[string]lockState
}

func NewRegistry() *Registry {
	return &Registry{locks: make(map[string]lockState)}
}

func (r *Registry) Set(userID, endpoint string, activeAt time.Time) {
	if activeAt.IsZero() {
		activeAt = time.Now().UTC()
	} else {
		activeAt = activeAt.UTC()
	}
	r.mu.Lock()
	r.locks[userID] = lockState{endpoint: endpoint, lastActive: activeAt}
	r.mu.Unlock()
}

func (r *Registry) Get(userID string) (endpoint string, lastActive time.Time, ok bool) {
	r.mu.RLock()
	state, ok := r.locks[userID]
	r.mu.RUnlock()
	if !ok {
		return "", time.Time{}, false
	}
	return state.endpoint, state.lastActive, true
}

func (r *Registry) Clear(userID string) {
	r.mu.Lock()
	delete(r.locks, userID)
	r.mu.Unlock()
}
