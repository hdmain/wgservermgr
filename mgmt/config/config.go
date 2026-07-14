package config

import (
	"fmt"
	"net/netip"
	"os"
	"strconv"
)

type Config struct {
	Interface         string
	ServerEndpoint    string
	ServerPublicKey   string
	ServerIP          string
	Subnet            string
	DNS               string
	ListenPort        int
	APIPort           int
	APIKey            string
	DBPath            string
	KeepaliveInterval int
}

func Enabled() bool {
	return os.Getenv("WG_API") != "0"
}

func Load(iface string) (*Config, error) {
	if !Enabled() {
		return nil, nil
	}

	port, err := strconv.Atoi(getEnv("API_PORT", "8080"))
	if err != nil {
		return nil, fmt.Errorf("invalid API_PORT: %w", err)
	}

	listenPort, err := strconv.Atoi(getEnv("WG_LISTEN_PORT", "51820"))
	if err != nil {
		return nil, fmt.Errorf("invalid WG_LISTEN_PORT: %w", err)
	}

	keepalive, err := strconv.Atoi(getEnv("WG_KEEPALIVE_INTERVAL", "25"))
	if err != nil {
		return nil, fmt.Errorf("invalid WG_KEEPALIVE_INTERVAL: %w", err)
	}

	subnet := getEnv("WG_SUBNET", "10.8.0.0/24")
	serverIP, err := resolveServerIP(subnet)
	if err != nil {
		return nil, err
	}

	cfg := &Config{
		Interface:         iface,
		ServerEndpoint:    os.Getenv("WG_SERVER_ENDPOINT"),
		ServerPublicKey:   os.Getenv("WG_SERVER_PUBLIC_KEY"),
		ServerIP:          serverIP,
		Subnet:            subnet,
		DNS:               getEnv("WG_DNS", "1.1.1.1"),
		ListenPort:        listenPort,
		APIPort:           port,
		APIKey:            os.Getenv("API_KEY"),
		DBPath:            getEnv("DB_PATH", fmt.Sprintf("wireguard-%s.db", iface)),
		KeepaliveInterval: keepalive,
	}

	return cfg, nil
}

func resolveServerIP(subnet string) (string, error) {
	if ip := os.Getenv("WG_SERVER_IP"); ip != "" {
		return ip, nil
	}
	prefix, err := netip.ParsePrefix(subnet)
	if err != nil {
		return "", fmt.Errorf("invalid WG_SUBNET: %w", err)
	}
	base := prefix.Addr().As4()
	addr := netip.AddrFrom4([4]byte{base[0], base[1], base[2], 1})
	return addr.String(), nil
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
