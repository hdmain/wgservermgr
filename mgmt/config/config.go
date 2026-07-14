package config

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
)

const DefaultPath = "config.json"

// FileConfig is the on-disk JSON shape for managed settings.
type FileConfig struct {
	APIEnabled        *bool  `json:"api_enabled"`
	APIPort           int    `json:"api_port"`
	SecretKey         string `json:"secret_key"`
	ListenPort        int    `json:"listen_port"`
	Subnet            string `json:"subnet"`
	ServerIP          string `json:"server_ip"`
	ServerEndpoint    string `json:"server_endpoint"`
	ServerPublicKey   string `json:"server_public_key,omitempty"`
	DNS               string `json:"dns"`
	OutInterface      string `json:"out_interface"`
	KeepaliveInterval int    `json:"keepalive_interval"`
	DBPath            string `json:"db_path"`
	LogLevel          string `json:"log_level"`
}

type Config struct {
	Interface         string
	ServerEndpoint    string
	ServerPublicKey   string
	ServerIP          string
	Subnet            string
	DNS               string
	OutInterface      string
	ListenPort        int
	APIPort           int
	APIKey            string
	DBPath            string
	KeepaliveInterval int
	LogLevel          string
	ConfigPath        string
}

func Enabled() bool {
	if v := os.Getenv("WG_API"); v != "" {
		return v != "0"
	}
	return true
}

func Load(iface string) (*Config, error) {
	path := getEnv("WG_CONFIG", DefaultPath)

	file, created, err := loadOrCreateFile(path, iface)
	if err != nil {
		return nil, err
	}
	if created {
		fmt.Fprintf(os.Stderr, "wireguard-go: created %s\n", path)
	}
	if file.SecretKey != "" {
		fmt.Fprintf(os.Stderr, "wireguard-go: API secret_key loaded from %s\n", path)
	}

	if !enabledFrom(file) {
		return nil, nil
	}

	subnet := firstNonEmpty(os.Getenv("WG_SUBNET"), file.Subnet, "10.8.0.0/24")
	serverIP := firstNonEmpty(os.Getenv("WG_SERVER_IP"), file.ServerIP)
	if serverIP == "" {
		serverIP, err = defaultServerIP(subnet)
		if err != nil {
			return nil, err
		}
	}

	apiPort := file.APIPort
	if apiPort == 0 {
		apiPort = 8080
	}
	if v := os.Getenv("API_PORT"); v != "" {
		apiPort, err = strconv.Atoi(v)
		if err != nil {
			return nil, fmt.Errorf("invalid API_PORT: %w", err)
		}
	}

	listenPort := file.ListenPort
	if listenPort == 0 {
		listenPort = 51820
	}
	if v := os.Getenv("WG_LISTEN_PORT"); v != "" {
		listenPort, err = strconv.Atoi(v)
		if err != nil {
			return nil, fmt.Errorf("invalid WG_LISTEN_PORT: %w", err)
		}
	}

	keepalive := file.KeepaliveInterval
	if keepalive == 0 {
		keepalive = 25
	}
	if v := os.Getenv("WG_KEEPALIVE_INTERVAL"); v != "" {
		keepalive, err = strconv.Atoi(v)
		if err != nil {
			return nil, fmt.Errorf("invalid WG_KEEPALIVE_INTERVAL: %w", err)
		}
	}

	dbPath := firstNonEmpty(os.Getenv("DB_PATH"), file.DBPath, fmt.Sprintf("wireguard-%s.db", iface))
	secret := firstNonEmpty(os.Getenv("API_KEY"), file.SecretKey)

	cfg := &Config{
		Interface:         iface,
		ServerEndpoint:    firstNonEmpty(os.Getenv("WG_SERVER_ENDPOINT"), file.ServerEndpoint),
		ServerPublicKey:   firstNonEmpty(os.Getenv("WG_SERVER_PUBLIC_KEY"), file.ServerPublicKey),
		ServerIP:          serverIP,
		Subnet:            subnet,
		DNS:               firstNonEmpty(os.Getenv("WG_DNS"), file.DNS, "1.1.1.1"),
		OutInterface:      firstNonEmpty(os.Getenv("WG_OUT_INTERFACE"), file.OutInterface),
		ListenPort:        listenPort,
		APIPort:           apiPort,
		APIKey:            secret,
		DBPath:            dbPath,
		KeepaliveInterval: keepalive,
		LogLevel:          firstNonEmpty(os.Getenv("LOG_LEVEL"), file.LogLevel),
		ConfigPath:        path,
	}

	return cfg, nil
}

func loadOrCreateFile(path, iface string) (*FileConfig, bool, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		var file FileConfig
		if err := json.Unmarshal(data, &file); err != nil {
			return nil, false, fmt.Errorf("parse %s: %w", path, err)
		}
		changed := false
		if file.SecretKey == "" {
			file.SecretKey, err = generateSecretKey()
			if err != nil {
				return nil, false, err
			}
			changed = true
			fmt.Fprintf(os.Stderr, "wireguard-go: generated secret_key in %s\n", path)
		}
		applyFileDefaults(&file, iface)
		if changed {
			if err := saveFile(path, &file); err != nil {
				return nil, false, err
			}
		}
		return &file, false, nil
	}
	if !os.IsNotExist(err) {
		return nil, false, fmt.Errorf("read %s: %w", path, err)
	}

	secret, err := generateSecretKey()
	if err != nil {
		return nil, false, err
	}
	serverIP, err := defaultServerIP("10.8.0.0/24")
	if err != nil {
		return nil, false, err
	}
	enabled := true
	file := &FileConfig{
		APIEnabled:        &enabled,
		APIPort:           8080,
		SecretKey:         secret,
		ListenPort:        51820,
		Subnet:            "10.8.0.0/24",
		ServerIP:          serverIP,
		ServerEndpoint:    "",
		DNS:               "1.1.1.1",
		OutInterface:      "",
		KeepaliveInterval: 25,
		DBPath:            fmt.Sprintf("wireguard-%s.db", iface),
		LogLevel:          "verbose",
	}
	if err := saveFile(path, file); err != nil {
		return nil, false, err
	}
	fmt.Fprintf(os.Stderr, "wireguard-go: generated secret_key=%s\n", secret)
	return file, true, nil
}

func applyFileDefaults(file *FileConfig, iface string) {
	if file.APIPort == 0 {
		file.APIPort = 8080
	}
	if file.ListenPort == 0 {
		file.ListenPort = 51820
	}
	if file.Subnet == "" {
		file.Subnet = "10.8.0.0/24"
	}
	if file.ServerIP == "" {
		if ip, err := defaultServerIP(file.Subnet); err == nil {
			file.ServerIP = ip
		}
	}
	if file.DNS == "" {
		file.DNS = "1.1.1.1"
	}
	if file.KeepaliveInterval == 0 {
		file.KeepaliveInterval = 25
	}
	if file.DBPath == "" {
		file.DBPath = fmt.Sprintf("wireguard-%s.db", iface)
	}
}

func saveFile(path string, file *FileConfig) error {
	if err := os.MkdirAll(filepath.Dir(absOrDot(path)), 0o755); err != nil && path != DefaultPath {
		// ignore mkdir for simple filenames in cwd
		_ = err
	}
	data, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0o600)
}

func absOrDot(path string) string {
	if filepath.Dir(path) == "." {
		return "."
	}
	return path
}

func generateSecretKey() (string, error) {
	var buf [32]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", fmt.Errorf("generate secret_key: %w", err)
	}
	return hex.EncodeToString(buf[:]), nil
}

func enabledFrom(file *FileConfig) bool {
	if v := os.Getenv("WG_API"); v != "" {
		return v != "0"
	}
	if file.APIEnabled != nil {
		return *file.APIEnabled
	}
	return true
}

func defaultServerIP(subnet string) (string, error) {
	prefix, err := netip.ParsePrefix(subnet)
	if err != nil {
		return "", fmt.Errorf("invalid subnet %q: %w", subnet, err)
	}
	base := prefix.Addr().As4()
	addr := netip.AddrFrom4([4]byte{base[0], base[1], base[2], 1})
	return addr.String(), nil
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
