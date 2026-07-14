package peers

import (
	"bufio"
	"fmt"
	"strconv"
	"strings"

	"golang.zx2c4.com/wireguard/device"
)

type Manager struct {
	dev *device.Device
}

func NewManager(dev *device.Device) *Manager {
	return &Manager{dev: dev}
}

func (m *Manager) AddPeer(publicKey, allowedIP string) error {
	config := fmt.Sprintf(`public_key=%s
replace_allowed_ips=true
allowed_ip=%s/32
`, publicKey, allowedIP)
	return m.dev.IpcSet(config)
}

func (m *Manager) RemovePeer(publicKey string) error {
	config := fmt.Sprintf(`public_key=%s
remove=true
`, publicKey)
	return m.dev.IpcSet(config)
}

type PeerStats struct {
	TxBytes           uint64
	RxBytes           uint64
	LastHandshakeSec  int64
	LastHandshakeNsec int64
}

func (m *Manager) PeerStats(publicKey string) (PeerStats, error) {
	body, err := m.dev.IpcGet()
	if err != nil {
		return PeerStats{}, err
	}

	var stats PeerStats
	var currentKey string
	found := false

	scanner := bufio.NewScanner(strings.NewReader(body))
	for scanner.Scan() {
		key, value, ok := strings.Cut(scanner.Text(), "=")
		if !ok {
			continue
		}
		switch key {
		case "public_key":
			currentKey = value
			found = currentKey == publicKey
		case "tx_bytes":
			if found {
				stats.TxBytes, _ = strconv.ParseUint(value, 10, 64)
			}
		case "rx_bytes":
			if found {
				stats.RxBytes, _ = strconv.ParseUint(value, 10, 64)
			}
		case "last_handshake_time_sec":
			if found {
				stats.LastHandshakeSec, _ = strconv.ParseInt(value, 10, 64)
			}
		case "last_handshake_time_nsec":
			if found {
				stats.LastHandshakeNsec, _ = strconv.ParseInt(value, 10, 64)
			}
		}
	}
	if !found {
		return PeerStats{}, fmt.Errorf("peer %s not found", publicKey)
	}
	return stats, scanner.Err()
}

func ServerPublicKey(dev *device.Device) (string, error) {
	body, err := dev.IpcGet()
	if err != nil {
		return "", err
	}

	scanner := bufio.NewScanner(strings.NewReader(body))
	for scanner.Scan() {
		key, value, ok := strings.Cut(scanner.Text(), "=")
		if ok && key == "private_key" && value != "" {
			return PublicKeyFromPrivate(value)
		}
	}
	return "", fmt.Errorf("device private key not configured")
}

func BuildClientConfig(privateKey, assignedIP, serverPublicKey, serverEndpoint, dns string, keepalive int) string {
	clientPrivateKey, err := KeyHexToBase64(privateKey)
	if err != nil {
		clientPrivateKey = privateKey
	}
	serverPubKey, err := KeyHexToBase64(serverPublicKey)
	if err != nil {
		serverPubKey = serverPublicKey
	}

	var b strings.Builder
	b.WriteString("[Interface]\n")
	b.WriteString("PrivateKey = ")
	b.WriteString(clientPrivateKey)
	b.WriteString("\nAddress = ")
	b.WriteString(assignedIP)
	b.WriteString("/32\n")
	if dns != "" {
		b.WriteString("DNS = ")
		b.WriteString(dns)
		b.WriteString("\n")
	}
	b.WriteString("\n[Peer]\n")
	b.WriteString("PublicKey = ")
	b.WriteString(serverPubKey)
	b.WriteString("\nEndpoint = ")
	b.WriteString(serverEndpoint)
	b.WriteString("\nAllowedIPs = 0.0.0.0/0\n")
	b.WriteString("PersistentKeepalive = ")
	b.WriteString(strconv.Itoa(keepalive))
	b.WriteString("\n")
	return b.String()
}
