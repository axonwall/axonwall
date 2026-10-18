package main

import (
	"bufio"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/skip2/go-qrcode"
	"golang.org/x/crypto/scrypt"
)

var currentSessionUser = "admin"

// ANSI color escape codes for terminal styling
const (
	colorReset  = "\033[0m"
	colorBold   = "\033[1m"
	colorDim    = "\033[2m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorCyan   = "\033[36m"
	colorWhite  = "\033[37m"
)

type InterfaceInfo struct {
	Name    string
	MAC     string
	Carrier string
	Speed   string
	IPs     []string
}

func getSystemInfo() (hostname, osName, kernel, uptime, loadAvg, memStr string) {
	hostname, _ = os.Hostname()
	if hostname == "" {
		hostname = "axonwall"
	}

	// OS Pretty Name
	if data, err := os.ReadFile("/etc/os-release"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "PRETTY_NAME=") {
				osName = strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), "\"")
				break
			}
		}
	}
	if osName == "" {
		osName = "Debian GNU/Linux 13 (Trixie)"
	}

	// Kernel version
	if data, err := os.ReadFile("/proc/version"); err == nil {
		fields := strings.Fields(string(data))
		if len(fields) >= 3 {
			kernel = fields[2]
		}
	}
	if kernel == "" {
		kernel = "Linux 6.12"
	}

	// Uptime
	if data, err := os.ReadFile("/proc/uptime"); err == nil {
		fields := strings.Fields(string(data))
		if len(fields) > 0 {
			if sec, err := strconv.ParseFloat(fields[0], 64); err == nil {
				d := time.Duration(sec) * time.Second
				days := int(d.Hours()) / 24
				hours := int(d.Hours()) % 24
				mins := int(d.Minutes()) % 60
				if days > 0 {
					uptime = fmt.Sprintf("%dd %dh %dm", days, hours, mins)
				} else {
					uptime = fmt.Sprintf("%dh %dm", hours, mins)
				}
			}
		}
	}
	if uptime == "" {
		uptime = "Active"
	}

	// Load Average
	if data, err := os.ReadFile("/proc/loadavg"); err == nil {
		fields := strings.Fields(string(data))
		if len(fields) >= 3 {
			loadAvg = fmt.Sprintf("%s, %s, %s", fields[0], fields[1], fields[2])
		}
	}

	// Memory Usage
	if data, err := os.ReadFile("/proc/meminfo"); err == nil {
		var memTotal, memAvailable uint64
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "MemTotal:") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					memTotal, _ = strconv.ParseUint(fields[1], 10, 64)
				}
			} else if strings.HasPrefix(line, "MemAvailable:") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					memAvailable, _ = strconv.ParseUint(fields[1], 10, 64)
				}
			}
		}
		if memTotal > 0 {
			memUsed := memTotal - memAvailable
			memPct := (float64(memUsed) / float64(memTotal)) * 100.0
			memStr = fmt.Sprintf("%.1f%% (%d / %d MB)", memPct, memUsed/1024, memTotal/1024)
		}
	}

	return
}

func getInterfaces() []InterfaceInfo {
	var list []InterfaceInfo
	ifaces, err := net.Interfaces()
	if err != nil {
		return list
	}

	for _, iface := range ifaces {
		// Ignore loopback
		if (iface.Flags & net.FlagLoopback) != 0 {
			continue
		}

		info := InterfaceInfo{
			Name: iface.Name,
			MAC:  iface.HardwareAddr.String(),
		}

		// Carrier link status
		carrierFile := filepath.Join("/sys/class/net", iface.Name, "carrier")
		if data, err := os.ReadFile(carrierFile); err == nil && strings.TrimSpace(string(data)) == "1" {
			info.Carrier = "UP"
		} else {
			info.Carrier = "DOWN"
		}

		// Speed
		speedFile := filepath.Join("/sys/class/net", iface.Name, "speed")
		if data, err := os.ReadFile(speedFile); err == nil {
			sp := strings.TrimSpace(string(data))
			if sp != "" && sp != "-1" {
				info.Speed = sp + " Mbps"
			} else {
				info.Speed = "-"
			}
		} else {
			info.Speed = "-"
		}

		// IPs
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			info.IPs = append(info.IPs, addr.String())
		}

		list = append(list, info)
	}

	return list
}

func getInterfaceAssignments() (wan, lan, opt1, opt2 string) {
	wan = "eth0"
	lan = "eth1"
	if data, err := os.ReadFile("/etc/axonwall/interfaces.conf"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "WAN_INTERFACE=") {
				wan = strings.TrimPrefix(line, "WAN_INTERFACE=")
			} else if strings.HasPrefix(line, "LAN_INTERFACE=") {
				lan = strings.TrimPrefix(line, "LAN_INTERFACE=")
			} else if strings.HasPrefix(line, "OPT1_INTERFACE=") {
				opt1 = strings.TrimPrefix(line, "OPT1_INTERFACE=")
			} else if strings.HasPrefix(line, "OPT2_INTERFACE=") {
				opt2 = strings.TrimPrefix(line, "OPT2_INTERFACE=")
			}
		}
	}
	// Fallback to state.json if opt1 or opt2 are empty in interfaces.conf
	if opt1 == "" || opt2 == "" {
		for _, p := range []string{"/var/lib/axonwall/state.json", "/etc/axonwall/state.json"} {
			if data, err := os.ReadFile(p); err == nil {
				var st map[string]interface{}
				if err := json.Unmarshal(data, &st); err == nil {
					if ifaces, ok := st["interfaces"].([]interface{}); ok {
						for _, item := range ifaces {
							if m, ok := item.(map[string]interface{}); ok {
								n, _ := m["name"].(string)
								d, _ := m["device"].(string)
								if d != "" {
									if n == "opt1" && opt1 == "" {
										opt1 = d
									} else if n == "opt2" && opt2 == "" {
										opt2 = d
									} else if n == "lan" && lan == "" {
										lan = d
									} else if n == "wan" && wan == "" {
										wan = d
									}
								}
							}
						}
					}
				}
				break
			}
		}
	}
	// Fallback to detecting physical interfaces if still empty
	if opt1 == "" || opt2 == "" {
		allIfaces := getInterfaces()
		var unassigned []string
		for _, ifc := range allIfaces {
			if ifc.Name != wan && ifc.Name != lan {
				unassigned = append(unassigned, ifc.Name)
			}
		}
		if opt1 == "" && len(unassigned) > 0 {
			opt1 = unassigned[0]
		}
		if opt2 == "" && len(unassigned) > 1 {
			opt2 = unassigned[1]
		}
	}
	return
}

func triggerDhcpClient(dev string) {
	if dev == "" {
		return
	}
	_ = exec.Command("ip", "link", "set", dev, "up").Run()
	if udhcpcPath, err := exec.LookPath("udhcpc"); err == nil {
		pidFile := "/var/run/udhcpc." + dev + ".pid"
		_ = exec.Command(udhcpcPath, "-b", "-i", dev, "-p", pidFile).Run()
		return
	}
	if dhclientPath, err := exec.LookPath("dhclient"); err == nil {
		_ = exec.Command(dhclientPath, "-1", "-v", dev).Run()
		return
	}
}

func releaseDhcpLease(dev string) {
	if dev == "" {
		return
	}
	if dhclientPath, err := exec.LookPath("dhclient"); err == nil {
		_ = exec.Command(dhclientPath, "-r", dev).Run()
	}
	// Signal the recorded pid directly instead of interpolating dev
	// into a root `sh -c` string.
	pidFile := "/var/run/udhcpc." + dev + ".pid"
	if data, err := os.ReadFile(pidFile); err == nil {
		if pid, err := strconv.Atoi(strings.TrimSpace(string(data))); err == nil && pid > 0 {
			if proc, err := os.FindProcess(pid); err == nil {
				_ = proc.Signal(syscall.SIGTERM)
			}
		}
	}
}

// guessGateway calculates a recommended default gateway IPv4 address given a host IP and CIDR prefix.
// It fills the first three octets based upon the static IP and guesses the 4th octet based upon the subnet mask:
// - In standard /24 through /30 subnets, it selects the first usable IP (net+1); if the host is already net+1, it selects the last usable IP.
// - In /31 point-to-point subnets (RFC 3021), it selects the other paired host (even->odd, odd->even).
// - In larger networks (e.g. /16, /8), it preserves the first three octets of the host IP and defaults to .1 (or .254 if host is .1).
func guessGateway(ipStr string, cidr int) string {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return ""
	}
	ipv4 := ip.To4()
	if ipv4 == nil {
		return ""
	}

	b0, b1, b2, b3 := ipv4[0], ipv4[1], ipv4[2], ipv4[3]

	// RFC 3021 /31 point-to-point link
	if cidr == 31 {
		if b3%2 == 0 {
			return fmt.Sprintf("%d.%d.%d.%d", b0, b1, b2, b3+1)
		}
		return fmt.Sprintf("%d.%d.%d.%d", b0, b1, b2, b3-1)
	}

	// For subnets with cidr in [24, 30]
	if cidr >= 24 && cidr <= 30 {
		blockSize := 1 << (32 - cidr)
		maskByte := byte(256 - blockSize)
		netStart := b3 & maskByte
		firstUsable := netStart + 1
		lastUsable := netStart + byte(blockSize) - 2

		// If user configured the first usable IP as their host IP, guess the last usable IP
		if b3 == firstUsable {
			return fmt.Sprintf("%d.%d.%d.%d", b0, b1, b2, lastUsable)
		}
		// Otherwise, default to the first usable IP
		return fmt.Sprintf("%d.%d.%d.%d", b0, b1, b2, firstUsable)
	}

	// For larger subnets (e.g. /16, /8) or fallback, keep first 3 octets and guess .1 (or .254 if IP ends in .1)
	if b3 == 1 {
		return fmt.Sprintf("%d.%d.%d.254", b0, b1, b2)
	}
	return fmt.Sprintf("%d.%d.%d.1", b0, b1, b2)
}

func cidrToNetmask(cidr int) string {
	if cidr < 0 || cidr > 32 {
		return "255.255.255.0"
	}
	mask := net.CIDRMask(cidr, 32)
	return fmt.Sprintf("%d.%d.%d.%d", mask[0], mask[1], mask[2], mask[3])
}

type NetworkConfig struct {
	WanDevice  string
	WanMode    string // "dhcp" or "static"
	WanIP      string // e.g. "203.0.113.10/24"
	WanGateway string // e.g. "203.0.113.1"
	WanDNS1    string
	WanDNS2    string

	LanDevice  string
	LanMode    string // "static" or "dhcp"
	LanIP      string // e.g. "192.168.1.1/24"
	LanDHCP    bool

	Opt1Device string
	Opt1Mode   string // "dhcp", "static", or ""
	Opt1IP     string

	Opt2Device string
	Opt2Mode   string // "dhcp", "static", or ""
	Opt2IP     string
}

func readCurrentNetworkConfig() NetworkConfig {
	cfg := NetworkConfig{
		WanDevice: "eth0",
		WanMode:   "dhcp",
		LanDevice: "eth1",
		LanMode:   "static",
		LanIP:     "192.168.1.1/24",
		LanDHCP:   true,
		WanDNS1:   "1.1.1.1",
		WanDNS2:   "8.8.8.8",
	}

	if data, err := os.ReadFile("/etc/axonwall/interfaces.conf"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "#") || !strings.Contains(line, "=") {
				continue
			}
			parts := strings.SplitN(line, "=", 2)
			k, v := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
			switch k {
			case "WAN_INTERFACE":
				if v != "" {
					cfg.WanDevice = v
				}
			case "WAN_MODE":
				if v != "" {
					cfg.WanMode = v
				}
			case "WAN_IPV4_ADDRESS":
				cfg.WanIP = v
			case "WAN_IPV4_GATEWAY":
				cfg.WanGateway = v
			case "WAN_DNS1":
				if v != "" {
					cfg.WanDNS1 = v
				}
			case "WAN_DNS2":
				if v != "" {
					cfg.WanDNS2 = v
				}
			case "LAN_INTERFACE":
				if v != "" {
					cfg.LanDevice = v
				}
			case "LAN_MODE":
				if v != "" {
					cfg.LanMode = v
				}
			case "LAN_IPV4_ADDRESS":
				if v != "" {
					cfg.LanIP = v
				}
			case "LAN_DHCP_ENABLED":
				cfg.LanDHCP = strings.ToLower(v) == "true" || v == "1"
			case "OPT1_INTERFACE":
				cfg.Opt1Device = v
			case "OPT1_MODE":
				cfg.Opt1Mode = v
			case "OPT1_IPV4_ADDRESS":
				cfg.Opt1IP = v
			case "OPT2_INTERFACE":
				cfg.Opt2Device = v
			case "OPT2_MODE":
				cfg.Opt2Mode = v
			case "OPT2_IPV4_ADDRESS":
				cfg.Opt2IP = v
			}
		}
	}
	return cfg
}

func updateStateJSON(cfg NetworkConfig) {
	statePath := "/etc/axonwall/state.json"
	_ = os.MkdirAll("/etc/axonwall", 0755)
	_ = os.MkdirAll("/var/lib/axonwall", 0755)

	var state map[string]interface{}
	if data, err := os.ReadFile(statePath); err == nil {
		_ = json.Unmarshal(data, &state)
	} else if dataVar, errVar := os.ReadFile("/var/lib/axonwall/state.json"); errVar == nil {
		_ = json.Unmarshal(dataVar, &state)
	}
	if state == nil {
		state = make(map[string]interface{})
	}
	if _, ok := state["version"]; !ok {
		state["version"] = 1
	}

	rawIfaces, _ := state["interfaces"].([]interface{})
	ifacesMap := make(map[string]map[string]interface{})
	var originalOrder []string
	for _, raw := range rawIfaces {
		if ifaceMap, ok := raw.(map[string]interface{}); ok {
			if name, ok := ifaceMap["name"].(string); ok {
				ifacesMap[name] = ifaceMap
				originalOrder = append(originalOrder, name)
			}
		}
	}

	setIface := func(name, device, ifType string, enabled bool, ipAddr, gw, desc string) {
		entry, exists := ifacesMap[name]
		if !exists {
			entry = make(map[string]interface{})
		}
		entry["name"] = name
		entry["device"] = device
		entry["type"] = ifType
		entry["enabled"] = enabled
		entry["description"] = desc
		entry["mtu"] = 1500
		if ifType == "static" && ipAddr != "" {
			entry["ipv4Address"] = ipAddr
		} else {
			delete(entry, "ipv4Address")
		}
		if ifType == "static" && gw != "" {
			entry["ipv4Gateway"] = gw
		} else {
			delete(entry, "ipv4Gateway")
		}
		ifacesMap[name] = entry
	}

	setIface("wan", cfg.WanDevice, cfg.WanMode, true, cfg.WanIP, cfg.WanGateway, "WAN Gateway")
	setIface("lan", cfg.LanDevice, cfg.LanMode, true, cfg.LanIP, "", "LAN Network")
	if cfg.Opt1Device != "" {
		setIface("opt1", cfg.Opt1Device, cfg.Opt1Mode, true, cfg.Opt1IP, "", "OPT1 (Attached Network / Non-authoritative)")
	}
	if cfg.Opt2Device != "" {
		setIface("opt2", cfg.Opt2Device, cfg.Opt2Mode, true, cfg.Opt2IP, "", "OPT2 (Attached Network / Non-authoritative)")
	}

	var updatedList []interface{}
	seen := make(map[string]bool)
	for _, name := range []string{"wan", "lan", "opt1", "opt2"} {
		if entry, ok := ifacesMap[name]; ok {
			updatedList = append(updatedList, entry)
			seen[name] = true
		}
	}
	for _, name := range originalOrder {
		if !seen[name] {
			if entry, ok := ifacesMap[name]; ok {
				updatedList = append(updatedList, entry)
				seen[name] = true
			}
		}
	}
	state["interfaces"] = updatedList

	// Ensure antiLockout includes LAN and any configured OPT1/OPT2 interfaces
	allowedIfaces := []string{"lan"}
	if cfg.Opt1Device != "" {
		allowedIfaces = append(allowedIfaces, "opt1")
	}
	if cfg.Opt2Device != "" {
		allowedIfaces = append(allowedIfaces, "opt2")
	}
	sysMap, _ := state["system"].(map[string]interface{})
	if sysMap == nil {
		sysMap = make(map[string]interface{})
	}
	alMap, _ := sysMap["antiLockout"].(map[string]interface{})
	if alMap == nil {
		alMap = make(map[string]interface{})
	}
	alMap["enabled"] = true
	alMap["interface"] = "lan"
	var alIfaceList []interface{}
	for _, it := range allowedIfaces {
		alIfaceList = append(alIfaceList, it)
	}
	alMap["interfaces"] = alIfaceList
	alMap["ports"] = []interface{}{22, 80, 443, 2966, 3000}
	sysMap["antiLockout"] = alMap
	state["system"] = sysMap

	if out, err := json.MarshalIndent(state, "", "  "); err == nil {
		_ = os.WriteFile("/etc/axonwall/state.json", out, 0600)
		_ = os.WriteFile("/var/lib/axonwall/state.json", out, 0600)
	}

	writeSystemYamlAntiLockout(allowedIfaces)

	// Also write /etc/axonwall/interfaces.yaml and /var/lib/axonwall/etc-axonwall/interfaces.yaml
	var yamlBuilder strings.Builder
	yamlBuilder.WriteString("# ============================================================================\n")
	yamlBuilder.WriteString("# Axonwall Firewall Configuration — /etc/axonwall/interfaces.yaml\n")
	yamlBuilder.WriteString("# Physical & Logical Interfaces, VLANs, Bridges, and LACP Bonds\n")
	yamlBuilder.WriteString("# ============================================================================\n\n")
	yamlBuilder.WriteString("interfaces:\n")

	writeYamlIface := func(name, device, ifType, ipAddr, gw, desc string) {
		yamlBuilder.WriteString(fmt.Sprintf("  - name: %s\n", name))
		yamlBuilder.WriteString(fmt.Sprintf("    device: %s\n", device))
		yamlBuilder.WriteString(fmt.Sprintf("    type: %s\n", ifType))
		yamlBuilder.WriteString("    enabled: true\n")
		if ifType == "static" && ipAddr != "" {
			yamlBuilder.WriteString(fmt.Sprintf("    ipv4Address: %s\n", ipAddr))
		}
		if ifType == "static" && gw != "" {
			yamlBuilder.WriteString(fmt.Sprintf("    ipv4Gateway: %s\n", gw))
		}
		yamlBuilder.WriteString("    mtu: 1500\n")
		yamlBuilder.WriteString(fmt.Sprintf("    description: %q\n", desc))
	}

	writeYamlIface("wan", cfg.WanDevice, cfg.WanMode, cfg.WanIP, cfg.WanGateway, "WAN Gateway")
	writeYamlIface("lan", cfg.LanDevice, cfg.LanMode, cfg.LanIP, "", "LAN Network")
	if cfg.Opt1Device != "" {
		writeYamlIface("opt1", cfg.Opt1Device, cfg.Opt1Mode, cfg.Opt1IP, "", "OPT1 (Attached Network / Non-authoritative)")
	}
	if cfg.Opt2Device != "" {
		writeYamlIface("opt2", cfg.Opt2Device, cfg.Opt2Mode, cfg.Opt2IP, "", "OPT2 (Attached Network / Non-authoritative)")
	}

	// Preserve existing VLANs, bridges, bonds/laggs, and VRFs from existing file
	existingYaml, _ := os.ReadFile("/etc/axonwall/interfaces.yaml")
	if len(existingYaml) == 0 {
		existingYaml, _ = os.ReadFile("/var/lib/axonwall/etc-axonwall/interfaces.yaml")
	}
	extraSections := ""
	if len(existingYaml) > 0 {
		str := string(existingYaml)
		for _, sec := range []string{"\nvlans:", "\nbridges:", "\nbonds:", "\nlaggs:", "\nvirtualIps:", "\nvrfs:"} {
			idx := strings.Index(str, sec)
			if idx != -1 {
				extraSections = strings.TrimSpace(str[idx+1:])
				break
			}
		}
	}
	if extraSections != "" {
		yamlBuilder.WriteString(extraSections)
		yamlBuilder.WriteString("\n")
	} else {
		yamlBuilder.WriteString("vlans: []\n")
		yamlBuilder.WriteString("bridges: []\n")
		yamlBuilder.WriteString("laggs: []\n")
	}

	yamlBytes := []byte(yamlBuilder.String())
	_ = os.MkdirAll("/etc/axonwall", 0755)
	_ = os.WriteFile("/etc/axonwall/interfaces.yaml", yamlBytes, 0644)
	_ = os.MkdirAll("/var/lib/axonwall/etc-axonwall", 0755)
	_ = os.WriteFile("/var/lib/axonwall/etc-axonwall/interfaces.yaml", yamlBytes, 0644)
}

func persistNetworkInterfaces(cfg NetworkConfig) {
	// 1. Write /etc/axonwall/interfaces.conf
	var conf strings.Builder
	conf.WriteString(fmt.Sprintf("WAN_INTERFACE=%s\n", cfg.WanDevice))
	conf.WriteString(fmt.Sprintf("WAN_MODE=%s\n", cfg.WanMode))
	conf.WriteString(fmt.Sprintf("WAN_IPV4_ADDRESS=%s\n", cfg.WanIP))
	conf.WriteString(fmt.Sprintf("WAN_IPV4_GATEWAY=%s\n", cfg.WanGateway))
	conf.WriteString(fmt.Sprintf("WAN_DNS1=%s\n", cfg.WanDNS1))
	conf.WriteString(fmt.Sprintf("WAN_DNS2=%s\n", cfg.WanDNS2))
	conf.WriteString(fmt.Sprintf("LAN_INTERFACE=%s\n", cfg.LanDevice))
	conf.WriteString(fmt.Sprintf("LAN_MODE=%s\n", cfg.LanMode))
	conf.WriteString(fmt.Sprintf("LAN_IPV4_ADDRESS=%s\n", cfg.LanIP))
	conf.WriteString(fmt.Sprintf("LAN_DHCP_ENABLED=%t\n", cfg.LanDHCP))
	conf.WriteString(fmt.Sprintf("OPT1_INTERFACE=%s\n", cfg.Opt1Device))
	conf.WriteString(fmt.Sprintf("OPT1_MODE=%s\n", cfg.Opt1Mode))
	conf.WriteString(fmt.Sprintf("OPT1_IPV4_ADDRESS=%s\n", cfg.Opt1IP))
	conf.WriteString(fmt.Sprintf("OPT2_INTERFACE=%s\n", cfg.Opt2Device))
	conf.WriteString(fmt.Sprintf("OPT2_MODE=%s\n", cfg.Opt2Mode))
	conf.WriteString(fmt.Sprintf("OPT2_IPV4_ADDRESS=%s\n", cfg.Opt2IP))

	_ = os.MkdirAll("/etc/axonwall", 0755)
	_ = os.WriteFile("/etc/axonwall/interfaces.conf", []byte(conf.String()), 0644)

	// 2. Write /etc/network/interfaces and /etc/network/interfaces.d/axonwall
	var ifaces strings.Builder
	ifaces.WriteString("# /etc/network/interfaces -- Generated by Axonwall\n")
	ifaces.WriteString("# This file is managed by Axonwall. Manual changes will be overwritten.\n\n")
	ifaces.WriteString("auto lo\n")
	ifaces.WriteString("iface lo inet loopback\n\n")

	// WAN
	if cfg.WanDevice != "" {
		ifaces.WriteString(fmt.Sprintf("# WAN Interface\nauto %s\n", cfg.WanDevice))
		if cfg.WanMode == "static" && cfg.WanIP != "" {
			ipParts := strings.Split(cfg.WanIP, "/")
			ipAddr := ipParts[0]
			netmask := "255.255.255.0"
			if len(ipParts) > 1 {
				if c, err := strconv.Atoi(ipParts[1]); err == nil {
					netmask = cidrToNetmask(c)
				}
			}
			ifaces.WriteString(fmt.Sprintf("iface %s inet static\n", cfg.WanDevice))
			ifaces.WriteString(fmt.Sprintf("    address %s\n", ipAddr))
			ifaces.WriteString(fmt.Sprintf("    netmask %s\n", netmask))
			if cfg.WanGateway != "" {
				ifaces.WriteString(fmt.Sprintf("    gateway %s\n", cfg.WanGateway))
			}
			if cfg.WanDNS1 != "" || cfg.WanDNS2 != "" {
				dnsList := []string{}
				if cfg.WanDNS1 != "" {
					dnsList = append(dnsList, cfg.WanDNS1)
				}
				if cfg.WanDNS2 != "" {
					dnsList = append(dnsList, cfg.WanDNS2)
				}
				ifaces.WriteString(fmt.Sprintf("    dns-nameservers %s\n", strings.Join(dnsList, " ")))
			}
		} else {
			ifaces.WriteString(fmt.Sprintf("iface %s inet dhcp\n", cfg.WanDevice))
		}
		ifaces.WriteString("\n")
	}

	// LAN
	if cfg.LanDevice != "" {
		ifaces.WriteString(fmt.Sprintf("# LAN Interface\nauto %s\n", cfg.LanDevice))
		if cfg.LanMode == "dhcp" {
			ifaces.WriteString(fmt.Sprintf("iface %s inet dhcp\n", cfg.LanDevice))
		} else {
			ipAddr := "192.168.1.1"
			netmask := "255.255.255.0"
			if cfg.LanIP != "" {
				ipParts := strings.Split(cfg.LanIP, "/")
				ipAddr = ipParts[0]
				if len(ipParts) > 1 {
					if c, err := strconv.Atoi(ipParts[1]); err == nil {
						netmask = cidrToNetmask(c)
					}
				}
			}
			ifaces.WriteString(fmt.Sprintf("iface %s inet static\n", cfg.LanDevice))
			ifaces.WriteString(fmt.Sprintf("    address %s\n", ipAddr))
			ifaces.WriteString(fmt.Sprintf("    netmask %s\n", netmask))
		}
		ifaces.WriteString("\n")
	}

	// OPT1
	if cfg.Opt1Device != "" {
		ifaces.WriteString(fmt.Sprintf("# OPT1 Interface\nauto %s\n", cfg.Opt1Device))
		if cfg.Opt1Mode == "static" && cfg.Opt1IP != "" {
			ipParts := strings.Split(cfg.Opt1IP, "/")
			ipAddr := ipParts[0]
			netmask := "255.255.255.0"
			if len(ipParts) > 1 {
				if c, err := strconv.Atoi(ipParts[1]); err == nil {
					netmask = cidrToNetmask(c)
				}
			}
			ifaces.WriteString(fmt.Sprintf("iface %s inet static\n", cfg.Opt1Device))
			ifaces.WriteString(fmt.Sprintf("    address %s\n", ipAddr))
			ifaces.WriteString(fmt.Sprintf("    netmask %s\n", netmask))
		} else {
			ifaces.WriteString(fmt.Sprintf("iface %s inet dhcp\n", cfg.Opt1Device))
		}
		ifaces.WriteString("\n")
	}

	// OPT2
	if cfg.Opt2Device != "" {
		ifaces.WriteString(fmt.Sprintf("# OPT2 Interface\nauto %s\n", cfg.Opt2Device))
		if cfg.Opt2Mode == "static" && cfg.Opt2IP != "" {
			ipParts := strings.Split(cfg.Opt2IP, "/")
			ipAddr := ipParts[0]
			netmask := "255.255.255.0"
			if len(ipParts) > 1 {
				if c, err := strconv.Atoi(ipParts[1]); err == nil {
					netmask = cidrToNetmask(c)
				}
			}
			ifaces.WriteString(fmt.Sprintf("iface %s inet static\n", cfg.Opt2Device))
			ifaces.WriteString(fmt.Sprintf("    address %s\n", ipAddr))
			ifaces.WriteString(fmt.Sprintf("    netmask %s\n", netmask))
		} else {
			ifaces.WriteString(fmt.Sprintf("iface %s inet dhcp\n", cfg.Opt2Device))
		}
		ifaces.WriteString("\n")
	}

	_ = os.MkdirAll("/etc/network", 0755)
	_ = os.WriteFile("/etc/network/interfaces", []byte(ifaces.String()), 0644)
	if _, err := os.Stat("/etc/network/interfaces.d"); err == nil {
		_ = os.WriteFile("/etc/network/interfaces.d/axonwall", []byte(ifaces.String()), 0644)
	}

	// 3. Update Web UI state
	updateStateJSON(cfg)

	// 4. Sync /usr/share/axonwall/lockdown.nft and live nftables anti-lockout rules so configured LAN/OPT interfaces are immediately reachable
	reconcileConsoleAntiLockoutNft(cfg)
}

func writeSystemYamlAntiLockout(allowedIfaces []string) {
	if len(allowedIfaces) == 0 {
		allowedIfaces = []string{"lan"}
	}
	var yList []string
	for _, item := range allowedIfaces {
		yList = append(yList, fmt.Sprintf("      - %s", item))
	}
	newAntiLockoutBlock := fmt.Sprintf("  antiLockout:\n    enabled: true\n    interface: %s\n    interfaces:\n%s\n    ports:\n      - 22\n      - 80\n      - 443\n      - 2966\n      - 3000", allowedIfaces[0], strings.Join(yList, "\n"))

	for _, yamlPath := range []string{"/etc/axonwall/system.yaml", "/var/lib/axonwall/etc-axonwall/system.yaml"} {
		_ = os.MkdirAll(filepath.Dir(yamlPath), 0755)
		if yamlData, err := os.ReadFile(yamlPath); err == nil && len(strings.TrimSpace(string(yamlData))) > 0 {
			content := string(yamlData)
			if idx := strings.Index(content, "  antiLockout:"); idx != -1 {
				prefix := strings.TrimRight(content[:idx], "\n")
				updated := prefix + "\n" + newAntiLockoutBlock + "\n"
				_ = os.WriteFile(yamlPath, []byte(updated), 0644)
				continue
			}
		}
		hostname, _ := os.Hostname()
		if hostname == "" {
			hostname = "axonwall"
		}
		defaultYaml := fmt.Sprintf("# ============================================================================\n# Axonwall Firewall Configuration — /etc/axonwall/system.yaml\n# ============================================================================\n\nsystem:\n  hostname: %s\n  domain: local\n  timezone: UTC\n  flowtableOffload: true\n  dnsServers:\n    - 1.1.1.1\n    - 8.8.8.8\n%s\n", hostname, newAntiLockoutBlock)
		_ = os.WriteFile(yamlPath, []byte(defaultYaml), 0644)
	}
}

func reconcileConsoleAntiLockoutNft(cfg NetworkConfig) {
	lockdownPath := "/usr/share/axonwall/lockdown.nft"
	internalHasLink := false
	for _, dev := range []string{cfg.LanDevice, cfg.Opt1Device, cfg.Opt2Device} {
		if dev == "" {
			continue
		}
		if cData, cErr := os.ReadFile(filepath.Join("/sys/class/net", dev, "carrier")); cErr == nil && strings.TrimSpace(string(cData)) == "1" {
			internalHasLink = true
			break
		}
	}

	if lData, lErr := os.ReadFile(lockdownPath); lErr == nil {
		content := string(lData)
		newElements := `elements = { "wan0" }`
		if internalHasLink && cfg.WanDevice != "" && cfg.WanDevice != "wan0" && cfg.WanDevice != cfg.LanDevice && cfg.WanDevice != cfg.Opt1Device && cfg.WanDevice != cfg.Opt2Device {
			newElements = fmt.Sprintf(`elements = { "wan0", %q }`, cfg.WanDevice)
		}
		var updatedLines []string
		for _, line := range strings.Split(content, "\n") {
			if strings.Contains(line, "elements = {") {
				indent := line[:strings.Index(line, "elements")]
				updatedLines = append(updatedLines, indent+newElements)
			} else {
				updatedLines = append(updatedLines, line)
			}
		}
		_ = os.WriteFile(lockdownPath, []byte(strings.Join(updatedLines, "\n")), 0644)
	}

	// Ensure wan_interfaces set in live nftables does not block LAN/OPT interfaces
	for _, dev := range []string{cfg.LanDevice, cfg.Opt1Device, cfg.Opt2Device} {
		if dev != "" {
			_ = exec.Command("nft", "delete", "element", "inet", "axonwall", "wan_interfaces", fmt.Sprintf("{ %q }", dev)).Run()
		}
	}

	currentRulesOut, _ := exec.Command("nft", "list", "chain", "inet", "axonwall", "input").CombinedOutput()
	currentRules := string(currentRulesOut)
	for _, entry := range []struct {
		role string
		dev  string
	}{
		{"lan", cfg.LanDevice},
		{"opt1", cfg.Opt1Device},
		{"opt2", cfg.Opt2Device},
	} {
		if entry.dev == "" || entry.dev == cfg.WanDevice {
			continue
		}
		if !strings.Contains(currentRules, fmt.Sprintf(`iifname %q tcp dport`, entry.dev)) {
			_ = exec.Command(
				"nft", "insert", "rule", "inet", "axonwall", "input",
				"iifname", entry.dev,
				"tcp", "dport", "{ 22, 80, 443, 2966, 3000 }",
				"accept", "comment", fmt.Sprintf("\"anti-lockout-%s\"", entry.role),
			).Run()
		}
	}
}

func getWanIP() (string, string) {
	wan, _, _, _ := getInterfaceAssignments()
	ifaces := getInterfaces()
	for _, iface := range ifaces {
		if iface.Name == wan {
			for _, ip := range iface.IPs {
				if strings.Contains(ip, ".") && !strings.HasPrefix(ip, "127.") {
					return wan, strings.Split(ip, "/")[0]
				}
			}
			return wan, ""
		}
	}
	return wan, ""
}

func getPrimaryManagementIP() string {
	wan, lan, opt1, opt2 := getInterfaceAssignments()
	ifaces := getInterfaces()

	extractIPv4 := func(info InterfaceInfo) string {
		for _, ip := range info.IPs {
			if strings.Contains(ip, ".") && !strings.HasPrefix(ip, "127.") {
				return strings.Split(ip, "/")[0]
			}
		}
		return ""
	}

	// 1. Search LAN interface first (management is strictly allowed on LAN)
	for _, iface := range ifaces {
		if iface.Name == lan {
			if ip := extractIPv4(iface); ip != "" {
				return ip
			}
		}
	}

	// 2. Search OPT1 or OPT2 interfaces if assigned and UP
	for _, target := range []string{opt1, opt2} {
		if target == "" {
			continue
		}
		for _, iface := range ifaces {
			if iface.Name == target && iface.Carrier == "UP" {
				if ip := extractIPv4(iface); ip != "" {
					return ip
				}
			}
		}
	}

	// 3. Fallback to any non-WAN interface with an IPv4 address
	for _, iface := range ifaces {
		if iface.Name != wan && iface.Carrier == "UP" {
			if ip := extractIPv4(iface); ip != "" {
				return ip
			}
		}
	}

	// 4. Default LAN IP when no interface has an active lease/address yet
	return "192.168.1.1"
}

func clearScreen() {
	fmt.Print("\033[H\033[2J")
}

func getAdminCredentials() (string, string) {
	adminUser := "admin"
	adminPass := "axonwall"
	foundPass := false

	// 1. Check /etc/axonwall/admin.env first
	if data, err := os.ReadFile("/etc/axonwall/admin.env"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "LOCAL_ADMIN_USER=") {
				adminUser = strings.TrimPrefix(line, "LOCAL_ADMIN_USER=")
			} else if strings.HasPrefix(line, "LOCAL_ADMIN_PASSWORD=") {
				adminPass = strings.TrimPrefix(line, "LOCAL_ADMIN_PASSWORD=")
				foundPass = true
			}
		}
		if foundPass {
			return adminUser, adminPass
		}
	}

	// 2. Check /etc/axonwall/axonwall.env
	if data, err := os.ReadFile("/etc/axonwall/axonwall.env"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "LOCAL_ADMIN_USER=") {
				adminUser = strings.TrimPrefix(line, "LOCAL_ADMIN_USER=")
			} else if strings.HasPrefix(line, "LOCAL_ADMIN_PASSWORD=") {
				adminPass = strings.TrimPrefix(line, "LOCAL_ADMIN_PASSWORD=")
				foundPass = true
			}
		}
		if foundPass {
			return adminUser, adminPass
		}
	}

	// 3. Fallback to /etc/axonwall/initial-admin-password
	if data, err := os.ReadFile("/etc/axonwall/initial-admin-password"); err == nil {
		p := strings.TrimSpace(string(data))
		if p != "" {
			adminPass = p
		}
	}

	return adminUser, adminPass
}

func hashPassword(pass string) (string, error) {
	saltBytes := make([]byte, 16)
	if _, err := rand.Read(saltBytes); err != nil {
		return "", err
	}
	saltHex := hex.EncodeToString(saltBytes)
	// scrypt N=16384, r=8, p=1, keyLen=64 to match Node.js crypto.scryptSync(pass, salt, 64)
	dk, err := scrypt.Key([]byte(pass), []byte(saltHex), 16384, 8, 1, 64)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("scrypt$%s$%s", saltHex, hex.EncodeToString(dk)), nil
}

func verifyPassword(inputPass, expectedPassOrHash string) bool {
	if strings.HasPrefix(expectedPassOrHash, "scrypt$") {
		parts := strings.Split(expectedPassOrHash, "$")
		if len(parts) == 3 {
			salt := parts[1]
			expectedHash := parts[2]
			dk, err := scrypt.Key([]byte(inputPass), []byte(salt), 16384, 8, 1, 64)
			if err != nil {
				return false
			}
			derivedHex := hex.EncodeToString(dk)
			return subtle.ConstantTimeCompare([]byte(derivedHex), []byte(expectedHash)) == 1
		}
		return false
	}
	return subtle.ConstantTimeCompare([]byte(inputPass), []byte(expectedPassOrHash)) == 1
}

func readPassword(reader *bufio.Reader, prompt string) (string, error) {
	fmt.Print(prompt)
	cmd := exec.Command("stty", "-echo")
	cmd.Stdin = os.Stdin
	_ = cmd.Run()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	stopSig := make(chan struct{})
	defer func() {
		close(stopSig)
		signal.Stop(sigChan)
		restore := exec.Command("stty", "echo")
		restore.Stdin = os.Stdin
		_ = restore.Run()
		fmt.Println()
	}()

	go func() {
		select {
		case <-sigChan:
			restore := exec.Command("stty", "echo")
			restore.Stdin = os.Stdin
			_ = restore.Run()
			fmt.Println()
			os.Exit(130)
		case <-stopSig:
			return
		}
	}()

	line, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(line), nil
}

func authenticateConsole(reader *bufio.Reader) (string, bool) {
	clearScreen()
	hostname, osName, _, _, _, _ := getSystemInfo()
	primaryIP := getPrimaryManagementIP()

	fmt.Printf("%s%s", colorCyan, colorBold)
	fmt.Println("================================================================================")
	fmt.Println("                       Axonwall Appliance Console Login                         ")
	fmt.Println("================================================================================")
	fmt.Printf("%s", colorReset)
	fmt.Printf(" Hostname: %s\n", hostname)
	fmt.Printf(" Platform: %s\n", osName)
	fmt.Printf(" Web Management Console (LAN): https://%s:2966\n", primaryIP)
	wanDev, wanIP := getWanIP()
	if wanIP != "" {
		fmt.Printf(" WAN Status (%s): %s (Web/SSH Inbound Blocked)\n", wanDev, wanIP)
	}
	fmt.Println("--------------------------------------------------------------------------------")
	fmt.Println(" Authentication required. Please enter appliance credentials to proceed.")
	if isLiveMode() {
		fmt.Printf(" %s[Live ISO Mode: Default Credentials: admin / axonwall]%s\n", colorYellow, colorReset)
	}
	fmt.Println("--------------------------------------------------------------------------------")
	fmt.Println()

	fmt.Print(" Username: ")
	username, err := reader.ReadString('\n')
	if err != nil {
		if err == io.EOF {
			os.Exit(0)
		}
		time.Sleep(1 * time.Second)
		return "", false
	}
	username = strings.TrimSpace(username)
	if username == "" {
		return "", false
	}

	password, err := readPassword(reader, " Password: ")
	if err != nil {
		if err == io.EOF {
			os.Exit(0)
		}
		time.Sleep(1 * time.Second)
		return "", false
	}

	expectedUser, expectedPass := getAdminCredentials()

	// Verify constant-time match for configured administrator account
	userMatches := subtle.ConstantTimeCompare([]byte(username), []byte(expectedUser)) == 1
	passMatches := verifyPassword(password, expectedPass)

	if userMatches && passMatches {
		fmt.Printf("\n%s[✓] Access granted. Initializing console session...%s\n", colorGreen, colorReset)
		time.Sleep(300 * time.Millisecond)
		return username, true
	}

	time.Sleep(1500 * time.Millisecond) // Throttling brute-force attempts
	fmt.Printf("\n%s[!] Login incorrect.%s\n\n", colorRed, colorReset)
	time.Sleep(1 * time.Second)
	return "", false
}

func isLiveMode() bool {
	if _, err := os.Stat("/usr/local/bin/axonwall-install"); err == nil {
		if data, err := os.ReadFile("/proc/cmdline"); err == nil {
			cmd := string(data)
			if strings.Contains(cmd, "slot=A") || strings.Contains(cmd, "slot=B") || strings.Contains(cmd, "root=LABEL=axon_root") {
				return false
			}
		}
		return true
	}
	return false
}

func printHeader() {
	clearScreen()
	hostname, osName, kernel, uptime, loadAvg, memStr := getSystemInfo()
	primaryIP := getPrimaryManagementIP()

	fmt.Printf("%s%s", colorCyan, colorBold)
	fmt.Println("  █████╗ ██╗  ██╗ ██████╗ ███╗   ██╗██╗    ██╗ █████╗ ██╗     ██╗     ")
	fmt.Println(" ██╔══██╗╚██╗██╔╝██╔═══██╗████╗  ██║██║    ██║██╔══██╗██║     ██║     ")
	fmt.Println(" ███████║ ╚███╔╝ ██║   ██║██╔██╗ ██║██║ █╗ ██║███████║██║     ██║     ")
	fmt.Println(" ██╔══██║ ██╔██╗ ██║   ██║██║╚██╗██║██║███╗██║██╔══██║██║     ██║     ")
	fmt.Println(" ██║  ██║██╔╝ ██╗╚██████╔╝██║ ╚████║╚███╔███╔╝██║  ██║███████╗███████╗")
	fmt.Println(" ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝ ╚══╝╚══╝ ╚═╝  ╚═╝╚══════╝╚══════╝")
	fmt.Printf("%s", colorReset)
	fmt.Printf("           %sEnterprise Linux Next-Generation Firewall%s\n\n", colorBold, colorReset)

	fmt.Printf(" %sHost:%s %-18s %sOS:%s %-25s %sUptime:%s %s\n",
		colorDim, colorReset, hostname,
		colorDim, colorReset, osName,
		colorDim, colorReset, uptime)

	fmt.Printf(" %sKernel:%s %-16s %sLoad:%s %-23s %sMemory:%s %s\n",
		colorDim, colorReset, kernel,
		colorDim, colorReset, loadAvg,
		colorDim, colorReset, memStr)

	fmt.Println("--------------------------------------------------------------------------------")
	fmt.Printf(" %sWeb Console (LAN):%s %shttps://%s:2966%s\n",
		colorBold, colorReset,
		colorGreen+colorBold, primaryIP, colorReset)
	wanDev, wanIP := getWanIP()
	if wanIP != "" {
		fmt.Printf(" %sWAN Interface (%s):%s %s  %s[Inbound Web/SSH Blocked]%s\n",
			colorBold, wanDev, colorReset,
			wanIP,
			colorRed+colorBold, colorReset)
	}
	fmt.Printf(" %sConsole User:%s %s%s%s (Authenticated)\n",
		colorBold, colorReset,
		colorCyan+colorBold, currentSessionUser, colorReset)
	fmt.Println("--------------------------------------------------------------------------------")
	if isLiveMode() {
		fmt.Printf(" %s⚡ LIVE INSTALLATION MEDIA DETECTED%s\n", colorYellow+colorBold, colorReset)
		fmt.Printf(" %sTo install Axonwall to permanent disk storage, select Option [12] or [I]%s\n", colorCyan+colorBold, colorReset)
		fmt.Println("--------------------------------------------------------------------------------")
	}

	// Interfaces Summary Table
	fmt.Printf(" %s%-14s %-10s %-12s %-19s %s%s\n",
		colorDim, "INTERFACE", "CARRIER", "SPEED", "MAC ADDRESS", "IP ADDRESSES", colorReset)

	wan, lan, opt1, opt2 := getInterfaceAssignments()
	ifaces := getInterfaces()
	for _, iface := range ifaces {
		carrierTag := colorRed + "[DOWN]" + colorReset
		if iface.Carrier == "UP" {
			carrierTag = colorGreen + "[ UP ]" + colorReset
		}

		ipDisplay := "-"
		if len(iface.IPs) > 0 {
			ipDisplay = strings.Join(iface.IPs, ", ")
		}

		role := ""
		switch iface.Name {
		case wan:
			role = " (WAN)"
		case lan:
			role = " (LAN)"
		case opt1:
			role = " (OPT1)"
		case opt2:
			role = " (OPT2)"
		}

		ifaceLabel := fmt.Sprintf("%-14s", iface.Name+role)
		fmt.Printf(" %s %-19s %-12s %-19s %s\n",
			colorBold+ifaceLabel+colorReset,
			carrierTag,
			iface.Speed,
			iface.MAC,
			colorCyan+ipDisplay+colorReset,
		)
	}

	fmt.Println("================================================================================")
	fmt.Println("  1) Interfaces Overview & Physical Link Status")
	fmt.Println("  2) Assign Network Interfaces (WAN, LAN, OPT1, OPT2)")
	fmt.Println("  3) Configure Interface IP & DHCP (WAN, LAN, OPT1, OPT2)")
	fmt.Println("  4) Reset Web Admin Password")
	fmt.Println("  5) Break-Glass Disable / Reset TOTP MFA")
	fmt.Println("  6) Network Diagnostics (Ping, DNS Lookup)")
	fmt.Println("  7) Display Web Console Scannable QR Code")
	fmt.Println("  8) Restart Axonwall Core Services")
	fmt.Println("  9) Drop to Root Shell")
	fmt.Println(" 10) Reboot Appliance")
	fmt.Println(" 11) Power Off System")
	if isLiveMode() {
		fmt.Printf(" %s12) Install Axonwall OS to Storage Disk (A/B + RAID + OpenZFS) [Press I]%s\n", colorGreen+colorBold, colorReset)
	} else if _, err := os.Stat("/usr/local/bin/axonwall-install"); err == nil {
		fmt.Println(" 12) Run Axonwall Disk Installer Utility")
	}
	fmt.Printf("  %sA) Manage Anti-Lockout / Allowed Management Interfaces (LAN, OPT1, OPT2)%s\n", colorYellow, colorReset)
	fmt.Printf("  %sE) Edit / Validate / Apply /etc/axonwall/*.yaml Configuration Files%s\n", colorCyan, colorReset)
	fmt.Println("  0) Logout / Lock Console")
	fmt.Println("================================================================================")
	if isLiveMode() {
		fmt.Print(" Enter option [0-12, A, E, or I]: ")
	} else {
		fmt.Print(" Enter option [0-11, A, or E]: ")
	}
}

func actionInstallToDisk(reader *bufio.Reader) {
	clearScreen()
	installerPath := "/usr/local/bin/axonwall-install"
	if _, err := os.Stat(installerPath); err != nil {
		fmt.Printf("%s[!] Installer utility '%s' not found on this system.%s\n", colorRed, installerPath, colorReset)
		fmt.Println("If Axonwall OS is already installed on permanent storage, re-installation is not required.")
		pause(reader)
		return
	}

	fmt.Printf("%s=== Axonwall Appliance Disk Installer ===%s\n\n", colorCyan+colorBold, colorReset)
	fmt.Println("This interactive utility installs Axonwall OS to permanent storage with:")
	fmt.Println("  • A/B Dual-Root redundancy (Zero-downtime atomic firmware upgrades)")
	fmt.Println("  • Multi-Disk System RAID-1 Mirroring (optional)")
	fmt.Println("  • OpenZFS Storage Pool ('tank') with Mirror / RAIDZ redundancy (optional)")
	fmt.Printf("\n%sWARNING: All existing data on the chosen target disk(s) will be partitioned!%s\n\n", colorYellow+colorBold, colorReset)
	fmt.Print("Launch installer now? (y/N): ")

	ans, _ := reader.ReadString('\n')
	if strings.ToLower(strings.TrimSpace(ans)) != "y" {
		fmt.Println("Installation cancelled.")
		pause(reader)
		return
	}

	cmd := exec.Command("/bin/sh", installerPath)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	_ = cmd.Run()

	pause(reader)
}

func pause(reader *bufio.Reader) {
	fmt.Printf("\n%sPress [Enter] to return to the menu...%s", colorDim, colorReset)
	_, _ = reader.ReadString('\n')
}

func actionInterfacesOverview(reader *bufio.Reader) {
	clearScreen()
	fmt.Println("=== Network Interfaces Detailed Diagnostic ===")
	cmd := exec.Command("ip", "-br", "-c", "addr")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	_ = cmd.Run()

	fmt.Println("\n--- Routing Table ---")
	cmdRoute := exec.Command("ip", "route", "show")
	cmdRoute.Stdout = os.Stdout
	cmdRoute.Stderr = os.Stderr
	_ = cmdRoute.Run()

	pause(reader)
}

func actionAssignInterfaces(reader *bufio.Reader) {
	clearScreen()
	fmt.Println("=== Assign Network Interfaces (WAN, LAN, OPT1, OPT2) ===")
	fmt.Println("Detecting physical network devices...")
	fmt.Println()

	ifaces := getInterfaces()
	for i, iface := range ifaces {
		carrierTag := colorRed + "NO LINK" + colorReset
		if iface.Carrier == "UP" {
			carrierTag = colorGreen + "CARRIER UP (" + iface.Speed + ")" + colorReset
		}
		fmt.Printf(" [%d] %s (%s) - %s\n", i+1, iface.Name, iface.MAC, carrierTag)
	}

	currentWan := "eth0"
	currentLan := "eth1"
	currentOpt1 := ""
	currentOpt2 := ""
	if data, err := os.ReadFile("/etc/axonwall/interfaces.conf"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "WAN_INTERFACE=") {
				currentWan = strings.TrimPrefix(line, "WAN_INTERFACE=")
			} else if strings.HasPrefix(line, "LAN_INTERFACE=") {
				currentLan = strings.TrimPrefix(line, "LAN_INTERFACE=")
			} else if strings.HasPrefix(line, "OPT1_INTERFACE=") {
				currentOpt1 = strings.TrimPrefix(line, "OPT1_INTERFACE=")
			} else if strings.HasPrefix(line, "OPT2_INTERFACE=") {
				currentOpt2 = strings.TrimPrefix(line, "OPT2_INTERFACE=")
			}
		}
	}

	fmt.Printf("\nEnter WAN interface name [%s]: ", currentWan)
	wanIface, _ := reader.ReadString('\n')
	wanIface = strings.TrimSpace(wanIface)
	if wanIface == "" {
		wanIface = currentWan
	}

	fmt.Printf("Enter LAN interface name [%s]: ", currentLan)
	lanIface, _ := reader.ReadString('\n')
	lanIface = strings.TrimSpace(lanIface)
	if lanIface == "" {
		lanIface = currentLan
	}

	opt1Prompt := "none"
	if currentOpt1 != "" {
		opt1Prompt = currentOpt1
	}
	fmt.Printf("Enter OPT1 interface name (Attached / Non-authoritative) [%s]: ", opt1Prompt)
	opt1Iface, _ := reader.ReadString('\n')
	opt1Iface = strings.TrimSpace(opt1Iface)
	if opt1Iface == "" {
		opt1Iface = currentOpt1
	} else if strings.ToLower(opt1Iface) == "none" || opt1Iface == "-" {
		opt1Iface = ""
	}

	opt2Prompt := "none"
	if currentOpt2 != "" {
		opt2Prompt = currentOpt2
	}
	fmt.Printf("Enter OPT2 interface name (Attached / Non-authoritative) [%s]: ", opt2Prompt)
	opt2Iface, _ := reader.ReadString('\n')
	opt2Iface = strings.TrimSpace(opt2Iface)
	if opt2Iface == "" {
		opt2Iface = currentOpt2
	} else if strings.ToLower(opt2Iface) == "none" || opt2Iface == "-" {
		opt2Iface = ""
	}

	if wanIface != "" || lanIface != "" || opt1Iface != "" || opt2Iface != "" {
		fmt.Printf("\n%sSaving interface assignments...%s\n", colorYellow, colorReset)
		cfg := readCurrentNetworkConfig()
		if wanIface != "" {
			cfg.WanDevice = wanIface
		}
		if lanIface != "" {
			cfg.LanDevice = lanIface
		}
		cfg.Opt1Device = opt1Iface
		cfg.Opt2Device = opt2Iface
		persistNetworkInterfaces(cfg)

		fmt.Printf("%s[✓] Successfully assigned interfaces.%s\n", colorGreen, colorReset)
		fmt.Printf("    WAN:  %s\n    LAN:  %s\n    OPT1: %s\n    OPT2: %s\n",
			wanIface, lanIface, valueOrNone(opt1Iface), valueOrNone(opt2Iface))
	} else {
		fmt.Println("No changes made.")
	}

	pause(reader)
}

func valueOrNone(s string) string {
	if s == "" {
		return "<none>"
	}
	return s
}

func parseAndValidateIPv4AndCIDR(rawIP, defaultCIDR string, reader *bufio.Reader) (string, string, bool) {
	extractedCIDR := ""
	if strings.Contains(rawIP, "/") {
		parts := strings.SplitN(rawIP, "/", 2)
		rawIP = strings.TrimSpace(parts[0])
		extractedCIDR = strings.TrimSpace(parts[1])
	}
	parsedIP := net.ParseIP(rawIP)
	if parsedIP == nil || parsedIP.To4() == nil {
		fmt.Printf("%s[!] Invalid IPv4 address: %s%s\n", colorRed, rawIP, colorReset)
		return "", "", false
	}

	promptDefault := defaultCIDR
	if extractedCIDR != "" {
		promptDefault = extractedCIDR
	}
	fmt.Printf("Enter Subnet Mask in CIDR notation [%s]: ", promptDefault)
	cidr, _ := reader.ReadString('\n')
	cidr = strings.TrimSpace(cidr)
	if cidr == "" {
		cidr = promptDefault
	}
	cidrNum, err := strconv.Atoi(cidr)
	if err != nil || cidrNum < 1 || cidrNum > 32 {
		fmt.Printf("%s[!] Invalid CIDR prefix length (must be 1..32): %s%s\n", colorRed, cidr, colorReset)
		return "", "", false
	}
	return parsedIP.To4().String(), strconv.Itoa(cidrNum), true
}

func actionConfigureInterfaceIP(reader *bufio.Reader) {
	clearScreen()
	fmt.Println("=== Configure Interface IP Address & DHCP ===")

	currentIP := getPrimaryManagementIP()
	fmt.Printf("Current Primary Management IP: %s\n\n", currentIP)

	fmt.Println("Select interface to configure:")
	fmt.Println("  1) WAN  (Internet Uplink - DHCP Client or Static IPv4 & Default Gateway)")
	fmt.Println("  2) LAN  (Primary Internal Network with Authoritative DHCP)")
	fmt.Println("  3) OPT1 (Attached Network - NON-authoritative DHCP client/static)")
	fmt.Println("  4) OPT2 (Attached Network - NON-authoritative DHCP client/static)")
	fmt.Print("\nEnter choice [1-4] (default 1): ")
	ifChoice, _ := reader.ReadString('\n')
	ifChoice = strings.TrimSpace(ifChoice)

	ifName := "wan"
	defaultDevice := "eth0"
	isWan := true
	isOpt := false
	if ifChoice == "2" {
		ifName = "lan"
		defaultDevice = "eth1"
		isWan = false
	} else if ifChoice == "3" {
		ifName = "opt1"
		defaultDevice = "eth2"
		isWan = false
		isOpt = true
	} else if ifChoice == "4" {
		ifName = "opt2"
		defaultDevice = "eth3"
		isWan = false
		isOpt = true
	}

	// Try reading device mapping from interfaces.conf
	if data, err := os.ReadFile("/etc/axonwall/interfaces.conf"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if ifName == "wan" && strings.HasPrefix(line, "WAN_INTERFACE=") {
				val := strings.TrimPrefix(line, "WAN_INTERFACE=")
				if val != "" {
					defaultDevice = val
				}
			} else if ifName == "lan" && strings.HasPrefix(line, "LAN_INTERFACE=") {
				val := strings.TrimPrefix(line, "LAN_INTERFACE=")
				if val != "" {
					defaultDevice = val
				}
			} else if ifName == "opt1" && strings.HasPrefix(line, "OPT1_INTERFACE=") {
				val := strings.TrimPrefix(line, "OPT1_INTERFACE=")
				if val != "" {
					defaultDevice = val
				}
			} else if ifName == "opt2" && strings.HasPrefix(line, "OPT2_INTERFACE=") {
				val := strings.TrimPrefix(line, "OPT2_INTERFACE=")
				if val != "" {
					defaultDevice = val
				}
			}
		}
	}

	fmt.Printf("\nEnter %s physical network device [%s]: ", strings.ToUpper(ifName), defaultDevice)
	iface, _ := reader.ReadString('\n')
	iface = strings.TrimSpace(iface)
	if iface == "" {
		iface = defaultDevice
	}

	if isWan {
		fmt.Printf("\n%s=== Configure WAN Interface (%s) ===%s\n", colorCyan, iface, colorReset)
		fmt.Println("Select IPv4 configuration mode:")
		fmt.Println("  1) DHCP Client (Dynamic IP from ISP / upstream router - Default)")
		fmt.Println("  2) Static IPv4 (Fixed IP, Subnet Mask, Gateway & DNS)")
		fmt.Print("\nEnter mode [1-2] (default 1): ")
		modeChoice, _ := reader.ReadString('\n')
		modeChoice = strings.TrimSpace(modeChoice)

		if modeChoice != "2" {
			// DHCP Client
			fmt.Printf("\nConfiguring WAN (%s) as DHCP client...\n", iface)
			triggerDhcpClient(iface)
			cfg := readCurrentNetworkConfig()
			cfg.WanDevice = iface
			cfg.WanMode = "dhcp"
			cfg.WanIP = ""
			cfg.WanGateway = ""
			persistNetworkInterfaces(cfg)
			fmt.Printf("%s[✓] WAN interface %s set to UP in DHCP client mode (configuration persisted).%s\n", colorGreen, iface, colorReset)
			pause(reader)
			return
		}

		// Static IPv4 for WAN
		fmt.Print("\nEnter Static WAN IPv4 Address (e.g. 203.0.113.10): ")
		wanIPInput, _ := reader.ReadString('\n')
		wanIPInput = strings.TrimSpace(wanIPInput)
		if wanIPInput == "" {
			fmt.Println("IP address cannot be empty.")
			pause(reader)
			return
		}

		wanIP, cidr, ok := parseAndValidateIPv4AndCIDR(wanIPInput, "24", reader)
		if !ok {
			pause(reader)
			return
		}

		cidrNum, _ := strconv.Atoi(cidr)
		guessedGw := guessGateway(wanIP, cidrNum)

		fmt.Printf("Enter Upstream Default Gateway IPv4 [%s]: ", guessedGw)
		gateway, _ := reader.ReadString('\n')
		gateway = strings.TrimSpace(gateway)
		if gateway == "" {
			gateway = guessedGw
		} else if !strings.Contains(gateway, ".") {
			// User entered only the last octet (e.g. "1" or "254")
			parts := strings.Split(wanIP, ".")
			if len(parts) == 4 {
				gateway = fmt.Sprintf("%s.%s.%s.%s", parts[0], parts[1], parts[2], gateway)
			}
		} else if strings.HasPrefix(gateway, ".") {
			// User entered e.g. ".1" or ".254"
			parts := strings.Split(wanIP, ".")
			if len(parts) == 4 {
				gateway = fmt.Sprintf("%s.%s.%s%s", parts[0], parts[1], parts[2], gateway)
			}
		}

		if gateway != "" {
			if gwIP := net.ParseIP(gateway); gwIP == nil || gwIP.To4() == nil {
				fmt.Printf("%s[!] Invalid Gateway IPv4 address: %s%s\n", colorRed, gateway, colorReset)
				pause(reader)
				return
			}
		}

		fmt.Print("Enter Primary DNS Server [1.1.1.1]: ")
		dns1, _ := reader.ReadString('\n')
		dns1 = strings.TrimSpace(dns1)
		if dns1 == "" {
			dns1 = "1.1.1.1"
		}

		fmt.Print("Enter Secondary DNS Server [8.8.8.8]: ")
		dns2, _ := reader.ReadString('\n')
		dns2 = strings.TrimSpace(dns2)
		if dns2 == "" {
			dns2 = "8.8.8.8"
		}

		cidrFull := fmt.Sprintf("%s/%s", wanIP, cidr)
		fmt.Printf("\nApplying Static WAN %s with Gateway %s to %s...\n", cidrFull, gateway, iface)

		releaseDhcpLease(iface)
		_ = exec.Command("ip", "link", "set", iface, "up").Run()
		_ = exec.Command("ip", "addr", "flush", "dev", iface).Run()
		cmd := exec.Command("ip", "addr", "add", cidrFull, "dev", iface)
		if out, err := cmd.CombinedOutput(); err != nil {
			fmt.Printf("%s[!] Failed to assign IP address: %s%s\n", colorRed, string(out), colorReset)
			pause(reader)
			return
		}

		if gateway != "" {
			_ = exec.Command("ip", "route", "del", "default", "dev", iface).Run()
			cmdGw := exec.Command("ip", "route", "add", "default", "via", gateway, "dev", iface)
			if _, err := cmdGw.CombinedOutput(); err != nil {
				_ = exec.Command("ip", "route", "replace", "default", "via", gateway, "dev", iface).Run()
			}
		}

		resolvContent := fmt.Sprintf("# Generated by Axonwall Console\nnameserver %s\nnameserver %s\n", dns1, dns2)
		_ = os.WriteFile("/etc/resolv.conf", []byte(resolvContent), 0644)

		// Persist configuration across reboots
		cfg := readCurrentNetworkConfig()
		cfg.WanDevice = iface
		cfg.WanMode = "static"
		cfg.WanIP = cidrFull
		cfg.WanGateway = gateway
		cfg.WanDNS1 = dns1
		cfg.WanDNS2 = dns2
		persistNetworkInterfaces(cfg)

		fmt.Printf("%s[✓] Static WAN IP %s assigned to %s successfully.%s\n", colorGreen, cidrFull, iface, colorReset)
		if gateway != "" {
			fmt.Printf("%s[✓] Default gateway set to %s via %s.%s\n", colorGreen, gateway, iface, colorReset)
		}
		fmt.Printf("%s[✓] DNS resolvers configured: %s, %s.%s\n", colorGreen, dns1, dns2, colorReset)
		fmt.Printf("%s[✓] Configuration persisted to /etc/network/interfaces and /etc/axonwall/interfaces.conf.%s\n", colorGreen, colorReset)
		fmt.Printf("%s[✓] DHCP Server is DISABLED on WAN interface.%s\n", colorGreen, colorReset)
		pause(reader)
		return
	}

	if isOpt {
		fmt.Printf("\n%s[!] NOTE: %s is an attached network interface.%s\n", colorYellow, strings.ToUpper(ifName), colorReset)
		fmt.Println("    To prevent network conflicts, Axonwall does NOT serve DHCP on attached networks by default.")
		fmt.Println("\nSelect IP configuration mode:")
		fmt.Println("  1) DHCP Client (Get IP from existing upstream network DHCP server)")
		fmt.Println("  2) Static IPv4")
		fmt.Print("Enter mode [1-2] (default 1): ")
		modeChoice, _ := reader.ReadString('\n')
		modeChoice = strings.TrimSpace(modeChoice)

		if modeChoice != "2" {
			// DHCP Client mode
			fmt.Printf("\nConfiguring %s (%s) as DHCP client on attached network...\n", strings.ToUpper(ifName), iface)
			triggerDhcpClient(iface)
			cfg := readCurrentNetworkConfig()
			if ifName == "opt1" {
				cfg.Opt1Device = iface
				cfg.Opt1Mode = "dhcp"
				cfg.Opt1IP = ""
			} else {
				cfg.Opt2Device = iface
				cfg.Opt2Mode = "dhcp"
				cfg.Opt2IP = ""
			}
			persistNetworkInterfaces(cfg)
			fmt.Printf("%s[✓] Interface %s set to UP in DHCP client mode (configuration persisted).%s\n", colorGreen, iface, colorReset)
			fmt.Printf("%s[✓] Authoritative DHCP Server is DISABLED for %s.%s\n", colorGreen, strings.ToUpper(ifName), colorReset)
			pause(reader)
			return
		}
	}

	defaultIP := "192.168.1.1"
	if isOpt {
		defaultIP = "10.0.50.1"
	}

	fmt.Printf("Enter new IPv4 Address [%s]: ", defaultIP)
	newIPInput, _ := reader.ReadString('\n')
	newIPInput = strings.TrimSpace(newIPInput)
	if newIPInput == "" {
		newIPInput = defaultIP
	}

	newIP, cidr, ok := parseAndValidateIPv4AndCIDR(newIPInput, "24", reader)
	if !ok {
		pause(reader)
		return
	}

	enableDHCP := false
	if !isOpt {
		fmt.Print("Enable authoritative DHCP Server on this subnet? (Y/n): ")
		dhcpAns, _ := reader.ReadString('\n')
		dhcpAns = strings.ToLower(strings.TrimSpace(dhcpAns))
		enableDHCP = dhcpAns != "n"
	} else {
		fmt.Printf("%sEnable authoritative DHCP Server on %s? (y/N) [Default: N for attached networks]: %s", colorYellow, strings.ToUpper(ifName), colorReset)
		dhcpAns, _ := reader.ReadString('\n')
		dhcpAns = strings.ToLower(strings.TrimSpace(dhcpAns))
		enableDHCP = dhcpAns == "y"
	}

	cidrFull := fmt.Sprintf("%s/%s", newIP, cidr)
	fmt.Printf("\nApplying %s to interface %s...\n", cidrFull, iface)

	// Release any DHCP lease, flush old address, and assign new address
	releaseDhcpLease(iface)
	_ = exec.Command("ip", "link", "set", iface, "up").Run()
	_ = exec.Command("ip", "addr", "flush", "dev", iface).Run()
	cmd := exec.Command("ip", "addr", "add", cidrFull, "dev", iface)
	if out, err := cmd.CombinedOutput(); err == nil {
		cfg := readCurrentNetworkConfig()
		if ifName == "lan" {
			cfg.LanDevice = iface
			cfg.LanMode = "static"
			cfg.LanIP = cidrFull
			cfg.LanDHCP = enableDHCP
		} else if ifName == "opt1" {
			cfg.Opt1Device = iface
			cfg.Opt1Mode = "static"
			cfg.Opt1IP = cidrFull
		} else if ifName == "opt2" {
			cfg.Opt2Device = iface
			cfg.Opt2Mode = "static"
			cfg.Opt2IP = cidrFull
		}
		persistNetworkInterfaces(cfg)

		fmt.Printf("%s[✓] IP Address %s assigned to %s successfully.%s\n", colorGreen, cidrFull, iface, colorReset)
		fmt.Printf("%s[✓] Configuration persisted to /etc/network/interfaces and /etc/axonwall/interfaces.conf.%s\n", colorGreen, colorReset)
		if enableDHCP {
			fmt.Printf("%s[✓] DHCP range enabled for %s.%s\n", colorGreen, iface, colorReset)
		} else {
			fmt.Printf("%s[✓] Authoritative DHCP Server is DISABLED for %s (Safe for attached networks).%s\n", colorGreen, strings.ToUpper(ifName), colorReset)
		}
	} else {
		fmt.Printf("%s[!] Failed to assign IP address: %s%s\n", colorRed, string(out), colorReset)
	}

	pause(reader)
}

func actionResetAdminPassword(reader *bufio.Reader) {
	clearScreen()
	fmt.Println("=== Reset Web Admin Password ===")
	fmt.Println("This resets the break-glass local administrator credentials.")
	newPass, err := readPassword(reader, "\nEnter new password for admin: ")
	if err != nil {
		fmt.Printf("%s[!] Error reading password: %v%s\n", colorRed, err, colorReset)
		pause(reader)
		return
	}

	if len(newPass) < 8 {
		fmt.Printf("%s[!] Error: Password must be at least 8 characters long.%s\n", colorRed, colorReset)
		pause(reader)
		return
	}

	hashed, err := hashPassword(newPass)
	if err != nil {
		fmt.Printf("%s[!] Error generating password hash: %v%s\n", colorRed, err, colorReset)
		pause(reader)
		return
	}

	// Update local credential environment override in /etc/axonwall/admin.env
	_ = os.MkdirAll("/etc/axonwall", 0755)
	_ = os.MkdirAll("/var/lib/axonwall", 0755)
	envContent := fmt.Sprintf("LOCAL_ADMIN_USER=admin\nLOCAL_ADMIN_PASSWORD=%s\n", hashed)
	if err := os.WriteFile("/etc/axonwall/admin.env", []byte(envContent), 0640); err == nil {
		_ = os.Chmod("/etc/axonwall/admin.env", 0640)
		_ = exec.Command("chown", "root:axonwall", "/etc/axonwall/admin.env").Run()
		_ = os.Remove("/etc/axonwall/initial-admin-password")
		timestamp := []byte(time.Now().UTC().Format(time.RFC3339))
		_ = os.WriteFile("/etc/axonwall/.password_changed", timestamp, 0644)
		_ = os.WriteFile("/var/lib/axonwall/.password_changed", timestamp, 0644)

		fmt.Printf("\n%s[✓] Admin password updated successfully (hashed with scrypt).%s\n", colorGreen, colorReset)
		fmt.Println("Restarting Web UI to apply new credentials...")
		_ = exec.Command("systemctl", "restart", "axonwall-ui").Run()
		fmt.Printf("%s[✓] Web UI reloaded.%s\n", colorGreen, colorReset)
	} else {
		fmt.Printf("%s[!] Failed to save credentials: %v%s\n", colorRed, err, colorReset)
	}

	pause(reader)
}

func actionResetMFA(reader *bufio.Reader) {
	clearScreen()
	fmt.Println("=== Break-Glass Disable / Reset TOTP MFA ===")
	fmt.Println("This will clear any active MFA secret for the local admin account,")
	fmt.Println("allowing direct password login in emergency lockout scenarios.")
	fmt.Print("\nAre you sure you want to disable MFA? (y/N): ")
	ans, _ := reader.ReadString('\n')
	if strings.ToLower(strings.TrimSpace(ans)) == "y" {
		mfaEnvPath := "/etc/axonwall/mfa.env"
		_ = os.Remove(mfaEnvPath)

		stripMfaFromEnv := func(path string) {
			data, err := os.ReadFile(path)
			if err != nil {
				return
			}
			var lines []string
			for _, l := range strings.Split(string(data), "\n") {
				if !strings.HasPrefix(strings.TrimSpace(l), "LOCAL_ADMIN_MFA_SECRET=") {
					lines = append(lines, l)
				}
			}
			_ = os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0640)
			_ = os.Chmod(path, 0640)
			_ = exec.Command("chown", "root:axonwall", path).Run()
		}
		stripMfaFromEnv("/etc/axonwall/admin.env")
		stripMfaFromEnv("/etc/axonwall/axonwall.env")

		fmt.Printf("\n%s[✓] MFA enforcement removed. Admin login will now only require username/password.%s\n", colorGreen, colorReset)
		_ = exec.Command("systemctl", "restart", "axonwall-ui").Run()
	} else {
		fmt.Println("Cancelled.")
	}

	pause(reader)
}

func actionManageAntiLockout(reader *bufio.Reader) {
	clearScreen()
	fmt.Printf("%s=== Manage Anti-Lockout Protected Interfaces ===%s\n\n", colorCyan+colorBold, colorReset)
	fmt.Println("Anti-Lockout ensures web GUI (2966/443/80) and SSH (22) management ports remain")
	fmt.Println("accessible to administrators regardless of restrictive user firewall rules.")
	fmt.Println()

	wan, lan, opt1, opt2 := getInterfaceAssignments()

	// Read current anti-lockout config from /etc/axonwall/system.yaml or state.json
	currentIfaces := []string{"lan"}
	statePath := "/var/lib/axonwall/state.json"
	var state map[string]interface{}
	if data, err := os.ReadFile(statePath); err == nil {
		_ = json.Unmarshal(data, &state)
	}
	if state == nil {
		if data, err := os.ReadFile("/etc/axonwall/state.json"); err == nil {
			_ = json.Unmarshal(data, &state)
		}
	}
	if state != nil {
		if sys, ok := state["system"].(map[string]interface{}); ok {
			if al, ok := sys["antiLockout"].(map[string]interface{}); ok {
				if ifList, ok := al["interfaces"].([]interface{}); ok && len(ifList) > 0 {
					var loaded []string
					for _, item := range ifList {
						if s, ok := item.(string); ok && s != "" {
							loaded = append(loaded, s)
						}
					}
					if len(loaded) > 0 {
						currentIfaces = loaded
					}
				} else if single, ok := al["interface"].(string); ok && single != "" {
					currentIfaces = []string{single}
				}
			}
		}
	}

	isAllowed := func(name string) bool {
		for _, item := range currentIfaces {
			if strings.EqualFold(item, name) {
				return true
			}
		}
		return false
	}

	fmt.Println("Current Anti-Lockout Interface Status:")
	formatStatus := func(name, role, dev string) {
		status := colorRed + "[BLOCKED]" + colorReset
		if isAllowed(role) {
			status = colorGreen + "[PERMITTED (Web: 2966 / SSH: 22)]" + colorReset
		}
		if dev == "" {
			dev = "unassigned"
		}
		fmt.Printf("  • %-6s (NIC: %-8s) : %s\n", strings.ToUpper(role), dev, status)
	}

	formatStatus("LAN", "lan", lan)
	formatStatus("OPT1", "opt1", opt1)
	formatStatus("OPT2", "opt2", opt2)
	fmt.Printf("  • WAN    (NIC: %-8s) : %s\n", wan, colorRed+"[BLOCKED - WAN access restricted]"+colorReset)
	fmt.Println()

	fmt.Println("Options:")
	fmt.Println("  1) Toggle OPT1 in Anti-Lockout")
	fmt.Println("  2) Toggle OPT2 in Anti-Lockout")
	fmt.Println("  3) Permit ALL Internal Interfaces (LAN + OPT1 + OPT2)")
	fmt.Println("  4) Reset to Default (LAN only)")
	fmt.Println("  Q) Return to Main Menu")
	fmt.Print("\nEnter choice [1-4, Q]: ")

	ans, _ := reader.ReadString('\n')
	ans = strings.TrimSpace(strings.ToUpper(ans))

	toggle := func(name string) {
		found := false
		var next []string
		for _, item := range currentIfaces {
			if strings.EqualFold(item, name) {
				found = true
			} else {
				next = append(next, item)
			}
		}
		if !found {
			next = append(next, name)
		}
		// Ensure LAN is always present as baseline safety
		hasLan := false
		for _, item := range next {
			if strings.EqualFold(item, "lan") {
				hasLan = true
				break
			}
		}
		if !hasLan {
			next = append([]string{"lan"}, next...)
		}
		currentIfaces = next
	}

	switch ans {
	case "1":
		toggle("opt1")
	case "2":
		toggle("opt2")
	case "3":
		currentIfaces = []string{"lan", "opt1", "opt2"}
	case "4":
		currentIfaces = []string{"lan"}
	default:
		return
	}

	// Persist to state.json
	if state == nil {
		state = make(map[string]interface{})
	}
	sys, ok := state["system"].(map[string]interface{})
	if !ok {
		sys = make(map[string]interface{})
	}
	al, ok := sys["antiLockout"].(map[string]interface{})
	if !ok {
		al = make(map[string]interface{})
	}
	al["enabled"] = true
	al["interface"] = currentIfaces[0]
	var ifaceInterfaces []interface{}
	for _, it := range currentIfaces {
		ifaceInterfaces = append(ifaceInterfaces, it)
	}
	al["interfaces"] = ifaceInterfaces
	al["ports"] = []interface{}{22, 80, 443, 2966, 3000}
	sys["antiLockout"] = al
	state["system"] = sys

	// Ensure all current interfaces are present in NetworkConfig and persisted to interfaces.conf / interfaces.yaml / state.json
	cfg := readCurrentNetworkConfig()
	if cfg.LanDevice == "" && lan != "" {
		cfg.LanDevice = lan
	}
	if cfg.Opt1Device == "" && opt1 != "" {
		cfg.Opt1Device = opt1
		if cfg.Opt1Mode == "" {
			cfg.Opt1Mode = "dhcp"
		}
	}
	if cfg.Opt2Device == "" && opt2 != "" {
		cfg.Opt2Device = opt2
		if cfg.Opt2Mode == "" {
			cfg.Opt2Mode = "dhcp"
		}
	}
	persistNetworkInterfaces(cfg)

	// Refresh state from state.json after persistNetworkInterfaces
	if data, err := os.ReadFile(statePath); err == nil {
		var refreshed map[string]interface{}
		if err := json.Unmarshal(data, &refreshed); err == nil {
			state = refreshed
			if s, ok := state["system"].(map[string]interface{}); ok {
				s["antiLockout"] = al
			} else {
				state["system"] = sys
			}
		}
	}

	if out, err := json.MarshalIndent(state, "", "  "); err == nil {
		_ = os.WriteFile(statePath, out, 0600)
		_ = os.WriteFile("/etc/axonwall/state.json", out, 0600)
		_ = os.WriteFile("/var/lib/axonwall/etc-axonwall/state.json", out, 0600)
	}

	// Update /etc/axonwall/system.yaml and /var/lib/axonwall/etc-axonwall/system.yaml
	writeSystemYamlAntiLockout(currentIfaces)

	// Recompile and apply ruleset via axonwallctl or axonwalld
	fmt.Printf("\n%sApplying new Anti-Lockout ruleset...%s\n", colorCyan, colorReset)
	if err := exec.Command("axonwallctl", "apply", "--no-confirm").Run(); err != nil {
		// Fallback: trigger axonwalld or direct nft reload
		_ = exec.Command("pkill", "-HUP", "axonwalld").Run()
	}

	// Ensure immediate nftables rules are present at the top of chain input for zero-downtime access
	devMap := map[string]string{
		"lan":  lan,
		"opt1": opt1,
		"opt2": opt2,
	}
	currentRulesOut, _ := exec.Command("nft", "list", "chain", "inet", "axonwall", "input").CombinedOutput()
	currentRules := string(currentRulesOut)
	for _, ifName := range currentIfaces {
		dev := devMap[strings.ToLower(ifName)]
		if dev != "" {
			_ = exec.Command("nft", "delete", "element", "inet", "axonwall", "wan_interfaces", fmt.Sprintf("{ %q }", dev)).Run()
			if !strings.Contains(currentRules, fmt.Sprintf(`iifname %q tcp dport`, dev)) {
				_ = exec.Command("nft", "insert", "rule", "inet", "axonwall", "input", "iifname", dev, "tcp", "dport", "{ 22, 80, 443, 2966, 3000 }", "accept", "comment", fmt.Sprintf("\"anti-lockout-%s\"", ifName)).Run()
			}
		}
	}

	fmt.Printf("\n%s[✓] Anti-Lockout updated successfully!%s\n", colorGreen, colorReset)
	fmt.Printf("Permitted Interfaces: %s%s%s\n", colorCyan+colorBold, strings.Join(currentIfaces, ", "), colorReset)
	pause(reader)
}

func actionDiagnostics(reader *bufio.Reader) {
	clearScreen()
	fmt.Println("=== Network Diagnostics ===")
	fmt.Print("Enter target IP or hostname to test [8.8.8.8]: ")
	target, _ := reader.ReadString('\n')
	target = strings.TrimSpace(target)
	if target == "" {
		target = "8.8.8.8"
	}
	if strings.HasPrefix(target, "-") || strings.ContainsAny(target, " \t;&|\\$*{}[]()<>\"'`\n\r") {
		fmt.Printf("%s[!] Invalid target hostname or IP address.%s\n", colorRed, colorReset)
		pause(reader)
		return
	}

	fmt.Printf("\n--- ICMP Ping (%s) ---\n", target)
	cmd := exec.Command("ping", "-c", "4", target)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	_ = cmd.Run()

	fmt.Printf("\n--- DNS Lookup (%s) ---\n", target)
	cmdDNS := exec.Command("host", "-W", "2", target)
	cmdDNS.Stdout = os.Stdout
	cmdDNS.Stderr = os.Stderr
	_ = cmdDNS.Run()

	pause(reader)
}

func actionDisplayQRCode(reader *bufio.Reader) {
	clearScreen()
	primaryIP := getPrimaryManagementIP()
	managementURL := fmt.Sprintf("https://%s:2966", primaryIP)

	fmt.Println("=== Web Console Management QR Code ===")
	fmt.Printf("Scan this QR code with a phone or tablet on the LAN to open the dashboard:\n\n")

	qr, err := qrcode.New(managementURL, qrcode.Medium)
	if err == nil {
		fmt.Println(qr.ToSmallString(false))
	} else {
		fmt.Printf("[!] Could not render QR: %v\n", err)
	}

	fmt.Printf("Management URL: %s%s%s\n", colorGreen+colorBold, managementURL, colorReset)
	pause(reader)
}

func actionRestartServices(reader *bufio.Reader) {
	clearScreen()
	fmt.Println("=== Restart Core Services ===")
	fmt.Println("Restarting axonwalld, axonwall-ui, and axonwall-controller...")

	services := []string{"axonwalld", "axonwall-ui", "axonwall-controller", "nftables"}
	isOpenRC := false
	if _, err := os.Stat("/sbin/openrc"); err == nil {
		isOpenRC = true
	}

	for _, s := range services {
		fmt.Printf("Restarting %s... ", s)
		var cmd *exec.Cmd
		if isOpenRC {
			cmd = exec.Command("/sbin/rc-service", s, "restart")
		} else {
			cmd = exec.Command("systemctl", "restart", s)
		}
		if err := cmd.Run(); err == nil {
			fmt.Printf("%s[OK]%s\n", colorGreen, colorReset)
		} else {
			fmt.Printf("%s[FAILED]%s\n", colorRed, colorReset)
		}
	}

	pause(reader)
}

func actionEditYamlConfigs(reader *bufio.Reader) {
	clearScreen()
	fmt.Printf("%s=== /etc/axonwall/*.yaml Declarative Configuration ===%s\n\n", colorCyan+colorBold, colorReset)
	domains := []string{
		"system",
		"interfaces",
		"firewall",
		"routing",
		"services",
		"vpn",
		"security",
		"ha",
		"storage",
		"k3s",
	}
	for i, d := range domains {
		path := fmt.Sprintf("/etc/axonwall/%s.yaml", d)
		statusStr := colorDim + "(not initialized yet)" + colorReset
		if info, err := os.Stat(path); err == nil {
			statusStr = fmt.Sprintf("%s(%d bytes, modified %s)%s", colorGreen, info.Size(), info.ModTime().Format("15:04:05"), colorReset)
		}
		fmt.Printf(" [%2d] %-28s %s\n", i+1, path, statusStr)
	}
	fmt.Println()
	fmt.Println("  [V] Run `axonwallctl validate`")
	fmt.Println("  [D] Run `axonwallctl diff`")
	fmt.Println("  [A] Run `axonwallctl apply`")
	fmt.Println("  [Q] Return to Console Menu")
	fmt.Print("\nSelect file [1-10] to edit or action [V/D/A/Q]: ")

	choice, _ := reader.ReadString('\n')
	choice = strings.TrimSpace(choice)
	upper := strings.ToUpper(choice)

	switch upper {
	case "Q", "":
		return
	case "V":
		fmt.Println()
		cmd := exec.Command("axonwallctl", "validate")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		_ = cmd.Run()
		pause(reader)
		return
	case "D":
		fmt.Println()
		cmd := exec.Command("axonwallctl", "diff")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		_ = cmd.Run()
		pause(reader)
		return
	case "A":
		fmt.Println()
		cmd := exec.Command("axonwallctl", "apply")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		_ = cmd.Run()
		pause(reader)
		return
	}

	idx, err := strconv.Atoi(choice)
	if err == nil && idx >= 1 && idx <= len(domains) {
		dom := domains[idx-1]
		cmd := exec.Command("axonwallctl", "edit", dom)
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			// Fallback to direct editor if axonwallctl is not in PATH
			editor := os.Getenv("EDITOR")
			if editor == "" {
				editor = "vi"
			}
			edCmd := exec.Command(editor, fmt.Sprintf("/etc/axonwall/%s.yaml", dom))
			edCmd.Stdin = os.Stdin
			edCmd.Stdout = os.Stdout
			edCmd.Stderr = os.Stderr
			_ = edCmd.Run()
		}
		pause(reader)
	}
}

func main() {
	reader := bufio.NewReader(os.Stdin)

	for {
		// Require authentication before entering console menu
		user, ok := authenticateConsole(reader)
		if !ok {
			continue
		}
		currentSessionUser = user

		// Check for auto-install kernel boot flag
		if isLiveMode() {
			if data, err := os.ReadFile("/proc/cmdline"); err == nil {
				cmd := string(data)
				if strings.Contains(cmd, "axonwall_install=1") || strings.Contains(cmd, "axonwall.install=1") {
					actionInstallToDisk(reader)
				}
			}
		}

		sessionActive := true
		for sessionActive {
			printHeader()
			choice, err := reader.ReadString('\n')
			if err != nil {
				if err == io.EOF {
					os.Exit(0)
				}
				time.Sleep(1 * time.Second)
				sessionActive = false
				break
			}
			choice = strings.TrimSpace(choice)

			switch strings.ToUpper(choice) {
			case "1":
				actionInterfacesOverview(reader)
			case "2":
				actionAssignInterfaces(reader)
			case "3":
				actionConfigureInterfaceIP(reader)
			case "4":
				actionResetAdminPassword(reader)
			case "5":
				actionResetMFA(reader)
			case "6":
				actionDiagnostics(reader)
			case "7":
				actionDisplayQRCode(reader)
			case "8":
				actionRestartServices(reader)
			case "9":
				clearScreen()
				fmt.Printf("%sDropping to root shell. Type 'exit' to return to Axonwall Console.%s\n\n", colorYellow, colorReset)
				shellPath := "/bin/bash"
				if _, err := os.Stat(shellPath); err != nil {
					shellPath = "/bin/sh"
				}
				shell := exec.Command(shellPath)
				shell.Stdin = os.Stdin
				shell.Stdout = os.Stdout
				shell.Stderr = os.Stderr
				_ = shell.Run()
			case "10":
				fmt.Print("\nAre you sure you want to reboot the appliance? (y/N): ")
				ans, _ := reader.ReadString('\n')
				if strings.ToLower(strings.TrimSpace(ans)) == "y" {
					fmt.Println("Rebooting appliance...")
					// Try OpenRC / systemctl / standard reboot
					_ = exec.Command("systemctl", "reboot").Run()
					_ = exec.Command("/sbin/reboot").Run()
					_ = exec.Command("reboot").Run()
					// Block while system shuts down
					for {
						time.Sleep(1 * time.Second)
					}
				}
			case "11":
				fmt.Print("\nAre you sure you want to power off the appliance? (y/N): ")
				ans, _ := reader.ReadString('\n')
				if strings.ToLower(strings.TrimSpace(ans)) == "y" {
					fmt.Println("Powering off...")
					// Try OpenRC / systemctl / poweroff
					_ = exec.Command("systemctl", "poweroff").Run()
					_ = exec.Command("/sbin/poweroff").Run()
					_ = exec.Command("poweroff").Run()
					_ = exec.Command("/sbin/halt", "-p").Run()
					_ = exec.Command("halt", "-p").Run()
					// Block while system halts
					for {
						time.Sleep(1 * time.Second)
					}
				}
			case "12", "I", "INSTALL":
				actionInstallToDisk(reader)
			case "A", "ANTILOCKOUT", "LOCKOUT":
				actionManageAntiLockout(reader)
			case "E", "YAML":
				actionEditYamlConfigs(reader)
			case "0":
				fmt.Printf("\n%s[✓] Logged out. Locking console...%s\n", colorYellow, colorReset)
				time.Sleep(500 * time.Millisecond)
				sessionActive = false
			default:
				fmt.Println("Invalid selection. Press [Enter] to continue...")
				_, _ = reader.ReadString('\n')
			}
		}
	}
}
