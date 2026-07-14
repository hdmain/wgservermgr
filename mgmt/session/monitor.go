package session

import (
	"time"

	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/mgmt/peers"
	"golang.zx2c4.com/wireguard/mgmt/store"
)

const pollInterval = 3 * time.Second

var defaultRegistry = NewRegistry()

type Monitor struct {
	pm          *peers.Manager
	st          *store.Store
	registry    *Registry
	logger      *device.Logger
	idleTimeout time.Duration
}

func Start(pm *peers.Manager, st *store.Store, logger *device.Logger, idleSeconds int) {
	if idleSeconds <= 0 {
		idleSeconds = 180
	}
	m := &Monitor{
		pm:          pm,
		st:          st,
		registry:    defaultRegistry,
		logger:      logger,
		idleTimeout: time.Duration(idleSeconds) * time.Second,
	}
	go m.run()
}

func ClearUser(userID string) {
	defaultRegistry.Clear(userID)
}

func (m *Monitor) run() {
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for range ticker.C {
		m.tick()
	}
}

func (m *Monitor) tick() {
	users, err := m.st.List()
	if err != nil {
		m.logger.Errorf("Session monitor: list users: %v", err)
		return
	}

	peerMap, err := m.pm.ListPeers()
	if err != nil {
		m.logger.Errorf("Session monitor: list peers: %v", err)
		return
	}

	for i := range users {
		user := &users[i]
		if !user.Enabled {
			continue
		}

		info, ok := peerMap[user.PublicKey]
		if !ok {
			continue
		}

		m.handleUser(user, info)
	}
}

func (m *Monitor) handleUser(user *store.User, info peers.PeerInfo) {
	currentEndpoint := info.Endpoint
	hasRecentHS := info.HasRecentHandshake(m.idleTimeout)

	lockedEndpoint, lockedLastActive, hasLock := m.registry.Get(user.ID)

	if !hasLock || lockedEndpoint == "" {
		if hasRecentHS && currentEndpoint != "" {
			m.registry.Set(user.ID, currentEndpoint, info.LastHandshake())
			m.logger.Verbosef("Session locked for %s", user.Name)
		}
		return
	}

	if endpointsEqual(currentEndpoint, lockedEndpoint) {
		if hasRecentHS {
			hs := info.LastHandshake()
			if lockedLastActive.IsZero() || hs.After(lockedLastActive) {
				m.registry.Set(user.ID, lockedEndpoint, hs)
			}
			return
		}
		lockActive := !lockedLastActive.IsZero() && time.Since(lockedLastActive) <= m.idleTimeout
		if !lockActive {
			m.registry.Clear(user.ID)
		}
		return
	}

	lockActive := !lockedLastActive.IsZero() && time.Since(lockedLastActive) <= m.idleTimeout
	if lockActive && currentEndpoint != "" {
		if err := m.pm.SetPeerEndpoint(user.PublicKey, lockedEndpoint); err != nil {
			m.logger.Errorf("Session monitor: revert endpoint for %s: %v", user.Name, err)
			return
		}
		m.logger.Verbosef("Blocked second device for %s", user.Name)
		return
	}

	if hasRecentHS && currentEndpoint != "" {
		m.registry.Set(user.ID, currentEndpoint, info.LastHandshake())
		m.logger.Verbosef("Session moved for %s", user.Name)
		return
	}

	if !lockActive {
		m.registry.Clear(user.ID)
	}
}

func endpointsEqual(a, b string) bool {
	return a == b
}
