//go:build linux

package ratelimit

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"sync"

	"golang.zx2c4.com/wireguard/mgmt/store"
)

const ifbDevice = "ifb0"

type tcLimiter struct {
	mu     sync.Mutex
	iface  string
	inited bool
}

func New() Limiter {
	return &tcLimiter{}
}

func (l *tcLimiter) Init(iface string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.initLocked(iface)
}

func (l *tcLimiter) initLocked(iface string) error {
	l.iface = iface

	_ = exec.Command("modprobe", "ifb").Run()
	_ = exec.Command("ip", "link", "add", ifbDevice, "type", "ifb").Run()
	_ = exec.Command("ip", "link", "set", "dev", ifbDevice, "up").Run()

	wgCommands := [][]string{
		{"tc", "qdisc", "replace", "dev", iface, "root", "handle", "1:", "htb", "default", "10"},
		{"tc", "class", "replace", "dev", iface, "parent", "1:", "classid", "1:1", "htb", "rate", "10gbit"},
		{"tc", "class", "replace", "dev", iface, "parent", "1:1", "classid", "1:10", "htb", "rate", "10gbit", "ceil", "10gbit"},
		{"tc", "qdisc", "replace", "dev", iface, "handle", "ffff:", "ingress"},
	}

	for _, cmd := range wgCommands {
		if err := runTC(cmd); err != nil && !isBenignTCError(err) {
			return fmt.Errorf("init tc on %s: %w", iface, err)
		}
	}

	ifbCommands := [][]string{
		{"tc", "qdisc", "replace", "dev", ifbDevice, "root", "handle", "1:", "htb", "default", "10"},
		{"tc", "class", "replace", "dev", ifbDevice, "parent", "1:", "classid", "1:1", "htb", "rate", "10gbit"},
		{"tc", "class", "replace", "dev", ifbDevice, "parent", "1:1", "classid", "1:10", "htb", "rate", "10gbit", "ceil", "10gbit"},
	}

	for _, cmd := range ifbCommands {
		_ = runTC(cmd)
	}

	l.inited = true
	return nil
}

func (l *tcLimiter) Apply(user *store.User) error {
	if user.BandwidthMbps <= 0 {
		return nil
	}
	return l.applyRules(user)
}

func (l *tcLimiter) Update(user *store.User) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if err := l.removeRulesLocked(user); err != nil {
		return err
	}
	if user.BandwidthMbps <= 0 {
		return nil
	}
	return l.applyRulesLocked(user)
}

func (l *tcLimiter) Remove(user *store.User) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.removeRulesLocked(user)
}

func (l *tcLimiter) applyRules(user *store.User) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.inited {
		if err := l.initLocked(l.iface); err != nil {
			return err
		}
	}
	return l.applyRulesLocked(user)
}

func (l *tcLimiter) applyRulesLocked(user *store.User) error {
	if !l.inited {
		return fmt.Errorf("tc limiter not initialized")
	}

	classID := fmt.Sprintf("1:%d", user.TCClassID)
	prio := strconv.Itoa(user.TCClassID)
	rate := fmt.Sprintf("%dmbit", user.BandwidthMbps)

	commands := [][]string{
		{"tc", "class", "replace", "dev", l.iface, "parent", "1:1", "classid", classID, "htb", "rate", rate, "ceil", rate},
		{"tc", "filter", "replace", "dev", l.iface, "protocol", "ip", "parent", "1:0", "prio", prio, "u32",
			"match", "ip", "dst", user.AssignedIP + "/32", "flowid", classID},
		{"tc", "filter", "replace", "dev", l.iface, "parent", "ffff:", "protocol", "ip", "prio", prio, "u32",
			"match", "ip", "src", user.AssignedIP + "/32", "action", "mirred", "egress", "redirect", "dev", ifbDevice},
		{"tc", "class", "replace", "dev", ifbDevice, "parent", "1:1", "classid", classID, "htb", "rate", rate, "ceil", rate},
		{"tc", "filter", "replace", "dev", ifbDevice, "protocol", "ip", "parent", "1:0", "prio", prio, "u32",
			"match", "ip", "src", user.AssignedIP + "/32", "flowid", classID},
	}

	for _, cmd := range commands {
		if err := runTC(cmd); err != nil && !isBenignTCError(err) {
			return fmt.Errorf("apply bandwidth limit for %s: %w", user.Name, err)
		}
	}
	return nil
}

func (l *tcLimiter) removeRulesLocked(user *store.User) error {
	if !l.inited {
		return nil
	}

	classID := fmt.Sprintf("1:%d", user.TCClassID)
	prio := strconv.Itoa(user.TCClassID)
	commands := [][]string{
		{"tc", "filter", "del", "dev", l.iface, "protocol", "ip", "parent", "1:0", "prio", prio},
		{"tc", "filter", "del", "dev", l.iface, "parent", "ffff:", "protocol", "ip", "prio", prio},
		{"tc", "class", "del", "dev", l.iface, "classid", classID},
		{"tc", "filter", "del", "dev", ifbDevice, "protocol", "ip", "parent", "1:0", "prio", prio},
		{"tc", "class", "del", "dev", ifbDevice, "classid", classID},
	}

	for _, cmd := range commands {
		_ = runTC(cmd)
	}
	return nil
}

func runTC(args []string) error {
	cmd := exec.Command(args[0], args[1:]...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %s", strings.Join(args, " "), strings.TrimSpace(string(out)))
	}
	return nil
}

func isBenignTCError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "File exists") ||
		strings.Contains(msg, "RTNETLINK answers: File exists") ||
		strings.Contains(msg, "already exists") ||
		strings.Contains(msg, "Exclusivity flag on") ||
		strings.Contains(msg, "RTNETLINK answers: Invalid argument") ||
		strings.Contains(msg, "Cannot find device")
}
