package ratelimit

import "golang.zx2c4.com/wireguard/mgmt/store"

type Limiter interface {
	Init(iface string) error
	Apply(user *store.User) error
	Remove(user *store.User) error
	Update(user *store.User) error
}
