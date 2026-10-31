package engine

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
)

var validDomainRegex = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$`)

// ProtectedPosture holds the dynamically discovered protected IPs, subnets, and ports of the appliance.
type ProtectedPosture struct {
	ApplianceIPs     []string `json:"applianceIps"`
	GatewayAndHaIPs  []string `json:"gatewayAndHaIps"`
	AntiLockoutPorts []int    `json:"antiLockoutPorts"`
}

// DiscoverProtectedPosture collects all local OS interface IPs, configured gateway IPs, HA peer/VIPs,
// and anti-lockout management ports so the kernel guard can refuse any self-disruptive action.
func DiscoverProtectedPosture() ProtectedPosture {
	posture := ProtectedPosture{
		ApplianceIPs:     []string{},
		GatewayAndHaIPs:  []string{},
		AntiLockoutPorts: []int{2966, 22, 9876},
	}

	seenAppliance := make(map[string]bool)
	seenGw := make(map[string]bool)
	seenPort := map[int]bool{2966: true, 22: true, 9876: true}

	addApplianceIP := func(raw string) {
		ipStr := strings.TrimSpace(strings.Split(raw, "/")[0])
		if parsed := net.ParseIP(ipStr); parsed != nil && !parsed.IsLoopback() && !parsed.IsUnspecified() {
			canon := parsed.String()
			if !seenAppliance[canon] {
				seenAppliance[canon] = true
				posture.ApplianceIPs = append(posture.ApplianceIPs, canon)
			}
		}
	}

	addGwIP := func(raw string) {
		ipStr := strings.TrimSpace(strings.Split(raw, "/")[0])
		if parsed := net.ParseIP(ipStr); parsed != nil && !parsed.IsLoopback() && !parsed.IsUnspecified() {
			canon := parsed.String()
			if !seenGw[canon] {
				seenGw[canon] = true
				posture.GatewayAndHaIPs = append(posture.GatewayAndHaIPs, canon)
			}
		}
	}

	// 1. Live OS network interfaces
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			addApplianceIP(a.String())
		}
	}

	// 2. Inspect state.json for configured interfaces, gateways, HA peers, and anti-lockout ports
	statePaths := []string{
		"/etc/axonwall/state.json",
		"/var/lib/axonwall/state.json",
	}
	for _, p := range statePaths {
		data, err := os.ReadFile(p)
		if err != nil || len(data) == 0 {
			continue
		}
		var state struct {
			System struct {
				AntiLockout struct {
					Ports []int `json:"ports"`
				} `json:"antiLockout"`
			} `json:"system"`
			Interfaces []struct {
				IPv4Address string `json:"ipv4Address"`
				IPv6Address string `json:"ipv6Address"`
				IPv4Gateway string `json:"ipv4Gateway"`
				IPv6Gateway string `json:"ipv6Gateway"`
				Gateway     string `json:"gateway"`
			} `json:"interfaces"`
			Gateways []struct {
				GatewayIP string `json:"gatewayIp"`
				Address   string `json:"address"`
			} `json:"gateways"`
			Routes []struct {
				Gateway string `json:"gateway"`
			} `json:"routes"`
			HA struct {
				PeerIP        string `json:"peerIp"`
				PeerAddress   string `json:"peerAddress"`
				VrrpInstances []struct {
					VirtualIPs []string `json:"virtualIps"`
				} `json:"vrrpInstances"`
			} `json:"ha"`
		}
		if err := json.Unmarshal(data, &state); err == nil {
			for _, port := range state.System.AntiLockout.Ports {
				if port > 0 && port <= 65535 && !seenPort[port] {
					seenPort[port] = true
					posture.AntiLockoutPorts = append(posture.AntiLockoutPorts, port)
				}
			}
			for _, iface := range state.Interfaces {
				if iface.IPv4Address != "" {
					addApplianceIP(iface.IPv4Address)
				}
				if iface.IPv6Address != "" {
					addApplianceIP(iface.IPv6Address)
				}
				if iface.IPv4Gateway != "" {
					addGwIP(iface.IPv4Gateway)
				}
				if iface.IPv6Gateway != "" {
					addGwIP(iface.IPv6Gateway)
				}
				if iface.Gateway != "" {
					addGwIP(iface.Gateway)
				}
			}
			for _, gw := range state.Gateways {
				if gw.GatewayIP != "" {
					addGwIP(gw.GatewayIP)
				}
				if gw.Address != "" {
					addGwIP(gw.Address)
				}
			}
			for _, rt := range state.Routes {
				if rt.Gateway != "" {
					addGwIP(rt.Gateway)
				}
			}
			if state.HA.PeerIP != "" {
				addGwIP(state.HA.PeerIP)
			}
			if state.HA.PeerAddress != "" {
				addGwIP(state.HA.PeerAddress)
			}
			for _, vrrp := range state.HA.VrrpInstances {
				for _, vip := range vrrp.VirtualIPs {
					addApplianceIP(vip)
				}
			}
			break
		}
	}

	return posture
}

// ParseTargetIPOrCIDR parses either a single host IP or a CIDR string into (net.IP, *net.IPNet, isIPv6, prefixLen).
func ParseTargetIPOrCIDR(target string) (net.IP, *net.IPNet, bool, int, string, error) {
	trimmed := strings.TrimSpace(target)
	if trimmed == "" {
		return nil, nil, false, 0, "", fmt.Errorf("empty target IP/CIDR")
	}

	if strings.Contains(trimmed, "/") {
		ip, ipNet, err := net.ParseCIDR(trimmed)
		if err != nil {
			return nil, nil, false, 0, "", fmt.Errorf("invalid CIDR '%s': %w", trimmed, err)
		}
		ones, bits := ipNet.Mask.Size()
		if ip4 := ip.To4(); ip4 != nil {
			if bits == 128 {
				if ones < 96 {
					return nil, nil, false, 0, "", fmt.Errorf("invalid IPv4-mapped IPv6 CIDR prefix /%d in '%s'", ones, trimmed)
				}
				ones -= 96
			}
			mask := net.CIDRMask(ones, 32)
			maskedIP := ip4.Mask(mask)
			ipNet = &net.IPNet{IP: maskedIP, Mask: mask}
			if ones == 32 {
				return maskedIP, ipNet, false, 32, maskedIP.String(), nil
			}
			return maskedIP, ipNet, false, ones, ipNet.String(), nil
		}
		isV6 := true
		if ones == 128 {
			return ip, ipNet, isV6, ones, ip.String(), nil
		}
		return ip, ipNet, isV6, ones, ipNet.String(), nil
	}

	ip := net.ParseIP(trimmed)
	if ip == nil {
		return nil, nil, false, 0, "", fmt.Errorf("invalid IP address '%s'", trimmed)
	}
	if v4 := ip.To4(); v4 != nil {
		mask := net.CIDRMask(32, 32)
		return v4, &net.IPNet{IP: v4, Mask: mask}, false, 32, v4.String(), nil
	}
	mask := net.CIDRMask(128, 128)
	return ip, &net.IPNet{IP: ip, Mask: mask}, true, 128, ip.String(), nil
}

func ipNetsOverlap(a, b *net.IPNet) bool {
	return a.Contains(b.IP) || b.Contains(a.IP)
}

// ValidateTargetSafety enforces hardcoded kernel anti-lockout and blast-radius invariants on a target IP/CIDR.
func ValidateTargetSafety(
	target string,
	callerIP string,
	port int,
	maxIPv4Prefix int,
	maxIPv6Prefix int,
) (normalized string, isIPv6 bool, prefixLen int, err error) {
	ip, targetNet, isV6, ones, canon, err := ParseTargetIPOrCIDR(target)
	if err != nil {
		return "", false, 0, err
	}

	if maxIPv4Prefix <= 0 {
		maxIPv4Prefix = 24
	}
	if maxIPv6Prefix <= 0 {
		maxIPv6Prefix = 64
	}

	// 1. Blast-radius prefix bounds
	if ones == 0 {
		return "", false, 0, fmt.Errorf("safety guard rejected target '%s': default route (/0) is strictly prohibited", target)
	}
	if !isV6 && ones < maxIPv4Prefix {
		return "", false, 0, fmt.Errorf("safety guard rejected target '%s': prefix /%d is broader than allowed /%d blast-radius limit", target, ones, maxIPv4Prefix)
	}
	if isV6 && ones < maxIPv6Prefix {
		return "", false, 0, fmt.Errorf("safety guard rejected target '%s': prefix /%d is broader than allowed /%d blast-radius limit", target, ones, maxIPv6Prefix)
	}

	// 2. Hardcoded special-purpose address checks
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return "", false, 0, fmt.Errorf("safety guard rejected target '%s': loopback, link-local, multicast, and unspecified addresses are strictly immune", target)
	}

	immutableCIDRs := []string{
		"0.0.0.0/8",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"224.0.0.0/4",
		"255.255.255.255/32",
		"::1/128",
		"fe80::/10",
		"ff00::/8",
	}
	for _, rawCidr := range immutableCIDRs {
		if _, pNet, parseErr := net.ParseCIDR(rawCidr); parseErr == nil {
			if ipNetsOverlap(targetNet, pNet) {
				return "", false, 0, fmt.Errorf("safety guard rejected target '%s': overlaps immutable protected range %s", target, rawCidr)
			}
		}
	}

	// 3. Check live appliance interface IPs, gateways, HA peers, and anti-lockout ports
	posture := DiscoverProtectedPosture()
	for _, appIPStr := range posture.ApplianceIPs {
		if appIP := net.ParseIP(appIPStr); appIP != nil && targetNet.Contains(appIP) {
			return "", false, 0, fmt.Errorf("safety guard rejected target '%s': overlaps local appliance interface IP %s", target, appIPStr)
		}
	}
	for _, gwIPStr := range posture.GatewayAndHaIPs {
		if gwIP := net.ParseIP(gwIPStr); gwIP != nil && targetNet.Contains(gwIP) {
			return "", false, 0, fmt.Errorf("safety guard rejected target '%s': overlaps upstream gateway or HA peer IP %s", target, gwIPStr)
		}
	}

	// 4. Caller IP self-lockout protection
	cleanCaller := strings.TrimPrefix(strings.TrimSpace(callerIP), "::ffff:")
	if cleanCaller != "" && cleanCaller != "127.0.0.1" && cleanCaller != "::1" {
		if cIP := net.ParseIP(cleanCaller); cIP != nil && targetNet.Contains(cIP) {
			return "", false, 0, fmt.Errorf("safety guard rejected target '%s': overlaps MCP client source IP %s (self-lockout prevented)", target, cleanCaller)
		}
	}

	// 5. Anti-lockout port protection
	if port > 0 {
		for _, protectedPort := range posture.AntiLockoutPorts {
			if port == protectedPort {
				return "", false, 0, fmt.Errorf("safety guard rejected port %d: anti-lockout management port cannot be blocked, shaped, or redirected", port)
			}
		}
	}

	return canon, isV6, ones, nil
}

// ValidateRedirectDestination verifies a DNAT honeypot or policy-route destination string ("ip" or "ip:port").
func ValidateRedirectDestination(dest string) (hostIP string, port int, isV6 bool, normalized string, err error) {
	trimmed := strings.TrimSpace(dest)
	if trimmed == "" {
		return "", 0, false, "", fmt.Errorf("empty redirect destination")
	}

	isProhibitedRedirectIP := func(ip net.IP) bool {
		if ip == nil || ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
			return true
		}
		posture := DiscoverProtectedPosture()
		ipStr := ip.String()
		for _, selfIP := range posture.ApplianceIPs {
			if selfIP == ipStr {
				return true
			}
		}
		for _, gwIP := range posture.GatewayAndHaIPs {
			if gwIP == ipStr {
				return true
			}
		}
		return false
	}

	// Check if host:port
	if h, pStr, splitErr := net.SplitHostPort(trimmed); splitErr == nil {
		var p int
		if _, scanErr := fmt.Sscanf(pStr, "%d", &p); scanErr != nil || p < 1 || p > 65535 {
			return "", 0, false, "", fmt.Errorf("invalid redirect port '%s'", pStr)
		}
		parsedIP := net.ParseIP(h)
		if isProhibitedRedirectIP(parsedIP) {
			return "", 0, false, "", fmt.Errorf("invalid or prohibited redirect target IP '%s'", h)
		}
		v6 := parsedIP.To4() == nil
		if v6 {
			return parsedIP.String(), p, true, fmt.Sprintf("[%s]:%d", parsedIP.String(), p), nil
		}
		return parsedIP.String(), p, false, fmt.Sprintf("%s:%d", parsedIP.String(), p), nil
	}

	parsedIP := net.ParseIP(trimmed)
	if isProhibitedRedirectIP(parsedIP) {
		return "", 0, false, "", fmt.Errorf("invalid or prohibited redirect target IP '%s'", trimmed)
	}
	v6 := parsedIP.To4() == nil
	return parsedIP.String(), 0, v6, parsedIP.String(), nil
}

// IsMcpSubsystemEnabled checks if the MCP control plane is enabled on this system.
// It checks AXONWALL_DISABLE_MCP / AXONWALL_MCP_ENABLED environment variables
// and the persistent /var/lib/axonwall/mcp-settings.json configuration file.
// The MCP server is disabled by default and must be explicitly enabled.
func IsMcpSubsystemEnabled() (bool, string) {
	if dis := os.Getenv("AXONWALL_DISABLE_MCP"); dis == "1" || strings.EqualFold(dis, "true") {
		return false, "MCP server is disabled via AXONWALL_DISABLE_MCP environment variable"
	}
	if en := os.Getenv("AXONWALL_MCP_ENABLED"); en != "" {
		if strings.EqualFold(en, "true") || en == "1" {
			return true, ""
		}
		if strings.EqualFold(en, "false") || en == "0" {
			return false, "MCP server is disabled via AXONWALL_MCP_ENABLED=false environment variable"
		}
	}

	settingsPath := os.Getenv("AXONWALL_MCP_SETTINGS_PATH")
	if settingsPath == "" {
		settingsPath = "/var/lib/axonwall/mcp-settings.json"
	}

	if data, err := os.ReadFile(settingsPath); err == nil {
		var cfg struct {
			Enabled        *bool  `json:"enabled"`
			DisabledReason string `json:"disabledReason"`
		}
		if jsonErr := json.Unmarshal(data, &cfg); jsonErr == nil && cfg.Enabled != nil {
			if !*cfg.Enabled {
				reason := cfg.DisabledReason
				if reason == "" {
					reason = "MCP server is disabled by administrator policy"
				}
				return false, reason
			}
			return true, ""
		}
	}

	return false, "MCP server is disabled by default; must be explicitly enabled via Web Console or AXONWALL_MCP_ENABLED=true"
}

