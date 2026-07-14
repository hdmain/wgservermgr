package peers

import (
	"bufio"
	"fmt"
	"strconv"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/device"
)

type Manager struct {
	dev *device.Device
}

type PeerInfo struct {
	PublicKey         string
	Endpoint          string
	TxBytes           uint64
	RxBytes           uint64
	LastHandshakeSec  int64
	LastHandshakeNsec int64
}

type PeerStats struct {
	TxBytes           uint64
	RxBytes           uint64
	LastHandshakeSec  int64
	LastHandshakeNsec int64
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

func (m *Manager) SetPeerEndpoint(publicKey, endpoint string) error {
	config := fmt.Sprintf(`public_key=%s
update_only=true
endpoint=%s
`, publicKey, endpoint)
	return m.dev.IpcSet(config)
}

func (m *Manager) GetPeer(publicKey string) (PeerInfo, error) {
	peers, err := m.ListPeers()
	if err != nil {
		return PeerInfo{}, err
	}
	peer, ok := peers[publicKey]
	if !ok {
		return PeerInfo{}, fmt.Errorf("peer %s not found", publicKey)
	}
	return peer, nil
}

func (m *Manager) ListPeers() (map[string]PeerInfo, error) {
	body, err := m.dev.IpcGet()
	if err != nil {
		return nil, err
	}

	peers := make(map[string]PeerInfo)
	var current *PeerInfo

	scanner := bufio.NewScanner(strings.NewReader(body))
	for scanner.Scan() {
		key, value, ok := strings.Cut(scanner.Text(), "=")
		if !ok {
			continue
		}
		switch key {
		case "public_key":
			if current != nil && current.PublicKey != "" {
				peers[current.PublicKey] = *current
			}
			current = &PeerInfo{PublicKey: value}
		case "endpoint":
			if current != nil {
				current.Endpoint = value
			}
		case "tx_bytes":
			if current != nil {
				current.TxBytes, _ = strconv.ParseUint(value, 10, 64)
			}
		case "rx_bytes":
			if current != nil {
				current.RxBytes, _ = strconv.ParseUint(value, 10, 64)
			}
		case "last_handshake_time_sec":
			if current != nil {
				current.LastHandshakeSec, _ = strconv.ParseInt(value, 10, 64)
			}
		case "last_handshake_time_nsec":
			if current != nil {
				current.LastHandshakeNsec, _ = strconv.ParseInt(value, 10, 64)
			}
		}
	}
	if current != nil && current.PublicKey != "" {
		peers[current.PublicKey] = *current
	}
	return peers, scanner.Err()
}

func (m *Manager) PeerStats(publicKey string) (PeerStats, error) {
	info, err := m.GetPeer(publicKey)
	if err != nil {
		return PeerStats{}, err
	}
	return PeerStats{
		TxBytes:           info.TxBytes,
		RxBytes:           info.RxBytes,
		LastHandshakeSec:  info.LastHandshakeSec,
		LastHandshakeNsec: info.LastHandshakeNsec,
	}, nil
}

func (info PeerInfo) LastHandshake() time.Time {
	if info.LastHandshakeSec == 0 && info.LastHandshakeNsec == 0 {
		return time.Time{}
	}
	return time.Unix(info.LastHandshakeSec, info.LastHandshakeNsec)
}

func (info PeerInfo) HasRecentHandshake(idle time.Duration) bool {
	hs := info.LastHandshake()
	if hs.IsZero() {
		return false
	}
	return time.Since(hs) <= idle
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
