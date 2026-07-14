//go:build linux

package setup

import (
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"strings"

	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/mgmt/config"
	"golang.zx2c4.com/wireguard/mgmt/peers"
	"golang.zx2c4.com/wireguard/mgmt/store"
)

var srcIPRe = regexp.MustCompile(`\bsrc\s+(\S+)`)
var devRe = regexp.MustCompile(`\bdev\s+(\S+)`)

func PrepareInterface(name string) {
	_ = exec.Command("ip", "link", "set", "dev", name, "down").Run()
	_ = exec.Command("ip", "link", "del", name).Run()
}

func ConfigureServer(dev *device.Device, iface string, cfg *config.Config, st *store.Store, logger *device.Logger) error {
	sc, err := st.GetServerConfig()
	if err != nil {
		keys, err := peers.GenerateKeyPair()
		if err != nil {
			return fmt.Errorf("generate server keys: %w", err)
		}
		sc = &store.ServerConfig{
			PrivateKey: keys.PrivateKey,
			PublicKey:  keys.PublicKey,
			ListenPort: cfg.ListenPort,
			ServerIP:   cfg.ServerIP,
		}
		if err := st.SaveServerConfig(sc); err != nil {
			return fmt.Errorf("save server config: %w", err)
		}
		logger.Errorf("Generated new server keypair")
	} else if strings.HasSuffix(sc.ServerIP, ".0") {
		sc.ServerIP = cfg.ServerIP
		_ = st.SaveServerConfig(sc)
	}

	if err := dev.IpcSet(fmt.Sprintf("private_key=%s\nlisten_port=%d\n", sc.PrivateKey, sc.ListenPort)); err != nil {
		return fmt.Errorf("configure device: %w", err)
	}
	if err := dev.Up(); err != nil {
		return fmt.Errorf("bring device up: %w", err)
	}

	prefix, err := netip.ParsePrefix(cfg.Subnet)
	if err != nil {
		return fmt.Errorf("invalid subnet: %w", err)
	}
	if err := configureInterfaceNetwork(iface, prefix, sc.ServerIP); err != nil {
		return fmt.Errorf("configure interface network: %w", err)
	}

	if err := configureRouting(iface, cfg.Subnet); err != nil {
		logger.Errorf("Routing setup warning: %v", err)
	}

	cfg.ServerPublicKey = sc.PublicKey
	if cfg.ServerEndpoint == "" {
		host, err := detectOutboundIP()
		if err != nil {
			return fmt.Errorf("detect server endpoint (set WG_SERVER_ENDPOINT): %w", err)
		}
		cfg.ServerEndpoint = fmt.Sprintf("%s:%d", host, sc.ListenPort)
		logger.Errorf("Auto-detected server endpoint: %s", cfg.ServerEndpoint)
	}

	fmt.Fprintf(os.Stderr, "wireguard-go: server public key: %s\n", mustKeyBase64(sc.PublicKey))
	fmt.Fprintf(os.Stderr, "wireguard-go: server VPN IP: %s\n", sc.ServerIP)
	fmt.Fprintf(os.Stderr, "wireguard-go: listen port: %d\n", sc.ListenPort)
	fmt.Fprintf(os.Stderr, "wireguard-go: client endpoint: %s\n", cfg.ServerEndpoint)
	return nil
}

func configureInterfaceNetwork(iface string, prefix netip.Prefix, serverIP string) error {
	_ = exec.Command("ip", "link", "set", "dev", iface, "up").Run()
	_ = exec.Command("ip", "addr", "flush", "dev", iface).Run()
	err := run("ip", "addr", "add", fmt.Sprintf("%s/%d", serverIP, prefix.Bits()), "dev", iface)
	if err != nil && strings.Contains(err.Error(), "File exists") {
		return nil
	}
	return err
}

func configureRouting(wgIface, subnet string) error {
	_ = exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1").Run()
	_ = exec.Command("sysctl", "-w", "net.ipv6.conf.all.forwarding=1").Run()

	outIface := os.Getenv("WG_OUT_INTERFACE")
	if outIface == "" {
		var err error
		outIface, err = detectOutboundInterface()
		if err != nil {
			return err
		}
	}

	listenPort := os.Getenv("WG_LISTEN_PORT")
	if listenPort == "" {
		listenPort = "51820"
	}

	var lastErr error
	for _, setup := range []func(string, string, string) error{
		setupIptablesRouting,
		setupNftRouting,
	} {
		if err := setup(wgIface, subnet, outIface); err != nil {
			lastErr = err
			continue
		}
		_ = openListenPort(listenPort)
		fmt.Fprintf(os.Stderr, "wireguard-go: NAT enabled (%s -> %s)\n", subnet, outIface)
		return nil
	}
	return lastErr
}

func setupIptablesRouting(wgIface, subnet, outIface string) error {
	ipt := findCmd("iptables-legacy", "iptables-nft", "iptables")
	if ipt == "" {
		return fmt.Errorf("iptables not found")
	}

	checkNat := []string{"-t", "nat", "-C", "POSTROUTING", "-s", subnet, "-o", outIface, "-j", "MASQUERADE"}
	addNat := []string{"-t", "nat", "-A", "POSTROUTING", "-s", subnet, "-o", outIface, "-j", "MASQUERADE"}
	if run(ipt, checkNat...) != nil {
		if err := run(ipt, addNat...); err != nil {
			return err
		}
	}

	for _, args := range [][]string{
		{"-A", "FORWARD", "-i", wgIface, "-j", "ACCEPT"},
		{"-A", "FORWARD", "-o", wgIface, "-j", "ACCEPT"},
	} {
		check := append([]string{"-C"}, args[1:]...)
		if run(ipt, check...) != nil {
			if err := run(ipt, args...); err != nil {
				return err
			}
		}
	}
	return nil
}

func setupNftRouting(wgIface, subnet, outIface string) error {
	if findCmd("nft") == "" {
		return fmt.Errorf("nft not found")
	}

	lines := []string{
		"add table ip wg_nat",
		"add chain ip wg_nat postrouting { type nat hook postrouting priority 100; policy accept; }",
		fmt.Sprintf(`add rule ip wg_nat postrouting ip saddr %s oifname "%s" masquerade`, subnet, outIface),
		"add table ip wg_filter",
		"add chain ip wg_filter forward { type filter hook forward priority 0; policy accept; }",
		fmt.Sprintf(`add rule ip wg_filter forward iifname "%s" accept`, wgIface),
		fmt.Sprintf(`add rule ip wg_filter forward oifname "%s" accept`, wgIface),
	}

	for _, line := range lines {
		if err := nftLine(line); err != nil && !isBenignNftError(err) {
			return err
		}
	}
	return nil
}

func openListenPort(port string) error {
	ipt := findCmd("iptables-legacy", "iptables-nft", "iptables")
	if ipt != "" {
		check := []string{"-C", "INPUT", "-p", "udp", "--dport", port, "-j", "ACCEPT"}
		add := []string{"-A", "INPUT", "-p", "udp", "--dport", port, "-j", "ACCEPT"}
		if run(ipt, check...) != nil {
			if err := run(ipt, add...); err != nil {
				return err
			}
		}
		return nil
	}

	lines := []string{
		"add table ip wg_filter",
		"add chain ip wg_filter input { type filter hook input priority 0; policy accept; }",
		fmt.Sprintf("add rule ip wg_filter input udp dport %s accept", port),
	}
	for _, line := range lines {
		if err := nftLine(line); err != nil && !isBenignNftError(err) {
			return err
		}
	}
	return nil
}

func findCmd(names ...string) string {
	for _, name := range names {
		if path, err := exec.LookPath(name); err == nil {
			return path
		}
	}
	return ""
}

func nftLine(line string) error {
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(line + "\n")
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			msg = err.Error()
		}
		return fmt.Errorf("nft: %s (%s)", line, msg)
	}
	return nil
}

func isBenignNftError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "File exists") ||
		strings.Contains(msg, "already exists") ||
		strings.Contains(msg, "Chain already exists") ||
		strings.Contains(msg, "Table already exists") ||
		strings.Contains(msg, "rule exists")
}

func mustKeyBase64(hexKey string) string {
	b64, err := peers.KeyHexToBase64(hexKey)
	if err != nil {
		return hexKey
	}
	return b64
}

func detectOutboundInterface() (string, error) {
	out, err := exec.Command("ip", "-4", "route", "get", "1.1.1.1").Output()
	if err != nil {
		return "", err
	}
	m := devRe.FindStringSubmatch(string(out))
	if len(m) < 2 {
		return "", fmt.Errorf("could not detect outbound interface: %s", strings.TrimSpace(string(out)))
	}
	return m[1], nil
}

func detectOutboundIP() (string, error) {
	out, err := exec.Command("ip", "-4", "route", "get", "1.1.1.1").Output()
	if err != nil {
		return "", err
	}
	m := srcIPRe.FindStringSubmatch(string(out))
	if len(m) < 2 {
		return "", fmt.Errorf("could not parse route output: %s", strings.TrimSpace(string(out)))
	}
	return m[1], nil
}

func run(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %s", name, strings.Join(args, " "), strings.TrimSpace(string(out)))
	}
	return nil
}
