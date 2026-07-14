//go:build !linux

package setup

import (
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/mgmt/config"
	"golang.zx2c4.com/wireguard/mgmt/store"
)

func PrepareInterface(string) {}

func ConfigureServer(*device.Device, string, *config.Config, *store.Store, *device.Logger) error {
	return nil
}
