package mgmt

import (
	"fmt"
	"os"

	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/mgmt/api"
	"golang.zx2c4.com/wireguard/mgmt/config"
	"golang.zx2c4.com/wireguard/mgmt/peers"
	"golang.zx2c4.com/wireguard/mgmt/ratelimit"
	"golang.zx2c4.com/wireguard/mgmt/setup"
	"golang.zx2c4.com/wireguard/mgmt/store"
)

func Start(dev *device.Device, iface string, logger *device.Logger) error {
	cfg, err := config.Load(iface)
	if err != nil {
		return err
	}
	if cfg == nil {
		return nil
	}

	st, err := store.Open(cfg.DBPath, cfg.Subnet)
	if err != nil {
		return fmt.Errorf("open user store: %w", err)
	}

	if err := setup.ConfigureServer(dev, iface, cfg, st, logger); err != nil {
		return fmt.Errorf("auto-setup server: %w", err)
	}

	pm := peers.NewManager(dev)
	limiter := ratelimit.New()
	if err := limiter.Init(iface); err != nil {
		logger.Errorf("Bandwidth limiter init failed: %v", err)
	}

	users, err := st.List()
	if err != nil {
		return fmt.Errorf("restore users: %w", err)
	}
	for i := range users {
		user := &users[i]
		if !user.Enabled {
			continue
		}
		if err := pm.AddPeer(user.PublicKey, user.AssignedIP); err != nil {
			logger.Errorf("Failed to restore peer %s: %v", user.Name, err)
			continue
		}
		if err := limiter.Apply(user); err != nil {
			logger.Errorf("Failed to restore bandwidth limit for %s: %v", user.Name, err)
		}
	}

	logger.Errorf("Management API listening on http://0.0.0.0:%d", cfg.APIPort)
	fmt.Fprintf(os.Stderr, "wireguard-go: management API listening on :%d\n", cfg.APIPort)
	server := api.New(cfg, st, pm, limiter)
	return server.Run()
}
