//go:build !linux

package ratelimit

import (
	"fmt"
	"runtime"

	"golang.zx2c4.com/wireguard/mgmt/store"
)

type noopLimiter struct{}

func New() Limiter {
	return noopLimiter{}
}

func (noopLimiter) Init(iface string) error {
	return nil
}

func (noopLimiter) Apply(user *store.User) error {
	if user.BandwidthMbps > 0 {
		return fmt.Errorf("per-user bandwidth limiting requires Linux (current OS: %s)", runtime.GOOS)
	}
	return nil
}

func (noopLimiter) Remove(*store.User) error {
	return nil
}

func (noopLimiter) Update(user *store.User) error {
	return noopLimiter{}.Apply(user)
}
