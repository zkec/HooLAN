package netfilter

import (
	"bufio"
	"bytes"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

func (m *Manager) ConfigPath() string { return m.confFile }

// ValidateBackupConfig accepts only literal assignments to known settings.
// The restored file is sourced by bash: NEVER accept arbitrary shell syntax.
func ValidateBackupConfig(data []byte, port int) error {
	if len(data) > 64<<10 {
		return fmt.Errorf("tproxy.conf is too large")
	}
	values := map[string]string{}
	allowed := map[string]bool{"LAN_IF": true, "TPROXY_PORT": true, "TPROXY_FWMARK": true, "TPROXY_TABLE": true, "TPROXY_RULE_PRIORITY": true, "PI_LAN_IP": true, "SELF_ORIGIN_NETS": true, "WG_RP_FILTER": true}
	scan := bufio.NewScanner(bytes.NewReader(data))
	for scan.Scan() {
		line := strings.TrimSpace(scan.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if !ok || !allowed[key] {
			return fmt.Errorf("unsupported tproxy.conf assignment")
		}
		if _, duplicate := values[key]; duplicate {
			return fmt.Errorf("duplicate tproxy.conf key %s", key)
		}
		if len(value) >= 2 && ((value[0] == '"' && value[len(value)-1] == '"') || (value[0] == '\'' && value[len(value)-1] == '\'')) {
			value = value[1 : len(value)-1]
		}
		if strings.ContainsAny(value, "$`\\\"';&|<>(){}\x00\r\n") {
			return fmt.Errorf("tproxy.conf must contain only literal values")
		}
		values[key] = value
	}
	if err := scan.Err(); err != nil {
		return err
	}
	if !regexp.MustCompile(`^[a-zA-Z0-9_.:-]{1,15}$`).MatchString(values["LAN_IF"]) {
		return fmt.Errorf("invalid LAN_IF")
	}
	number := func(key string, min, max uint64) error {
		v, err := strconv.ParseUint(values[key], 10, 32)
		if err != nil || v < min || v > max || strconv.FormatUint(v, 10) != values[key] {
			return fmt.Errorf("invalid %s", key)
		}
		return nil
	}
	if err := number("TPROXY_PORT", 1, 65535); err != nil {
		return err
	}
	if values["TPROXY_PORT"] != strconv.Itoa(port) {
		return fmt.Errorf("restored TPROXY_PORT must match engine port %d", port)
	}
	if err := number("TPROXY_TABLE", 1, 999999999); err != nil {
		return err
	}
	table := values["TPROXY_TABLE"]
	if table == "253" || table == "254" || table == "255" {
		return fmt.Errorf("reserved routing table")
	}
	mark := values["TPROXY_FWMARK"]
	if !regexp.MustCompile(`^(0x[0-9a-fA-F]{1,8}|[1-9][0-9]{0,9})$`).MatchString(mark) {
		return fmt.Errorf("invalid fwmark")
	}
	m, err := strconv.ParseUint(mark, 0, 32)
	if err != nil || m == 0 {
		return fmt.Errorf("invalid fwmark")
	}
	if _, ok := values["TPROXY_RULE_PRIORITY"]; ok {
		if err := number("TPROXY_RULE_PRIORITY", 1, 32765); err != nil {
			return err
		}
	}
	if ip, err := netip.ParseAddr(values["PI_LAN_IP"]); err != nil || !ip.Is4() {
		return fmt.Errorf("invalid PI_LAN_IP")
	}
	for _, value := range strings.Fields(values["SELF_ORIGIN_NETS"]) {
		if prefix, err := netip.ParsePrefix(value); err == nil && prefix.Addr().Is4() {
			continue
		}
		if addr, err := netip.ParseAddr(value); err != nil || !addr.Is4() {
			return fmt.Errorf("invalid SELF_ORIGIN_NETS")
		}
	}
	if v := values["WG_RP_FILTER"]; v != "" && v != "yes" && v != "no" {
		return fmt.Errorf("invalid WG_RP_FILTER")
	}
	return nil
}
