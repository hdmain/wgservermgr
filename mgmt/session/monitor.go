package session

import (
	"time"

	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/mgmt/peers"
	"golang.zx2c4.com/wireguard/mgmt/store"
)

const pollInterval = 3 * time.Second

type Monitor struct {
	pm          *peers.Manager
	st          *store.Store
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
		logger:      logger,
		idleTimeout: time.Duration(idleSeconds) * time.Second,
	}
	go m.run()
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

	if user.LockedEndpoint == "" {
		if hasRecentHS && currentEndpoint != "" {
			if err := m.st.SetSessionLock(user.ID, currentEndpoint, info.LastHandshake()); err != nil {
				m.logger.Errorf("Session monitor: lock %s: %v", user.Name, err)
			} else {
				m.logger.Verbosef("Session locked for %s at %s", user.Name, currentEndpoint)
			}
		}
		return
	}

	if endpointsEqual(currentEndpoint, user.LockedEndpoint) {
		if hasRecentHS {
			hs := info.LastHandshake()
			if user.LockedLastActiveAt.IsZero() || hs.After(user.LockedLastActiveAt) {
				_ = m.st.SetSessionLock(user.ID, user.LockedEndpoint, hs)
			}
			return
		}
		lockActive := !user.LockedLastActiveAt.IsZero() && time.Since(user.LockedLastActiveAt) <= m.idleTimeout
		if !lockActive {
			_ = m.st.ClearSessionLock(user.ID)
		}
		return
	}

	lockActive := !user.LockedLastActiveAt.IsZero() && time.Since(user.LockedLastActiveAt) <= m.idleTimeout
	if lockActive && currentEndpoint != "" {
		if err := m.pm.SetPeerEndpoint(user.PublicKey, user.LockedEndpoint); err != nil {
			m.logger.Errorf("Session monitor: revert endpoint for %s: %v", user.Name, err)
			return
		}
		m.logger.Verbosef("Blocked second device for %s (locked: %s, tried: %s)", user.Name, user.LockedEndpoint, currentEndpoint)
		return
	}

	if hasRecentHS && currentEndpoint != "" {
		if err := m.st.SetSessionLock(user.ID, currentEndpoint, info.LastHandshake()); err != nil {
			m.logger.Errorf("Session monitor: relock %s: %v", user.Name, err)
		} else {
			m.logger.Verbosef("Session moved for %s to %s", user.Name, currentEndpoint)
		}
		return
	}

	if !lockActive && user.LockedEndpoint != "" {
		_ = m.st.ClearSessionLock(user.ID)
	}
}

func endpointsEqual(a, b string) bool {
	return a == b
}
