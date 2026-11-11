package engine

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// SysfsRoot and ProcSysNetRoot allow unit tests to override kernel filesystem roots.
var (
	SysfsNetRoot   = "/sys/class/net"
	ProcSysNetRoot = "/proc/sys/net"
)

var validNetdevNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.\-]{0,14}$`)

// ValidNetdevName validates a Linux network interface name (max 15 chars, no traversal or leading dash).
func ValidNetdevName(name string) bool {
	name = strings.TrimSpace(name)
	if name == "" || strings.Contains(name, "..") {
		return false
	}
	return validNetdevNameRe.MatchString(name)
}

// BridgeSpec describes a host Linux bridge configuration.
type BridgeSpec struct {
	Name             string   `json:"name"`
	Members          []string `json:"members"`
	VlanFiltering    bool     `json:"vlanFiltering"`
	DisableNetfilter bool     `json:"disableNetfilter"`
	IsolateHostStack bool     `json:"isolateHostStack"`
	AddressCIDR      string   `json:"addressCidr"`
}

// ValidateBridgeSpec checks a BridgeSpec for safety and valid interface names.
func ValidateBridgeSpec(spec BridgeSpec) error {
	if !ValidNetdevName(spec.Name) {
		return fmt.Errorf("invalid bridge name %q", spec.Name)
	}
	for _, m := range spec.Members {
		if !ValidNetdevName(m) {
			return fmt.Errorf("invalid bridge member interface %q", m)
		}
	}
	if spec.AddressCIDR != "" {
		if _, _, err := net.ParseCIDR(spec.AddressCIDR); err != nil {
			return fmt.Errorf("invalid bridge address CIDR %q: %w", spec.AddressCIDR, err)
		}
	}
	return nil
}

// BuildWanBridgeHostIsolationNft returns an nftables bridge table ruleset that prevents
// the host's own L3 stack from emitting frames onto the delegated WAN bridge.
func BuildWanBridgeHostIsolationNft(wanBridge string) string {
	if !ValidNetdevName(wanBridge) {
		wanBridge = "br-wan"
	}
	return fmt.Sprintf(`table bridge axonwall_wan {
	chain output {
		type filter hook output priority 0; policy accept;
		oifname %q drop comment "prevent-host-l3-leak-on-wan-bridge"
	}
}
`, wanBridge)
}

// HardenDelegatedWAN hardens WAN-delegated host interfaces and bridges so the host stack
// never acquires an IPv4/IPv6 address or responds to ARP/ND on the ISP segment.
func HardenDelegatedWAN(devs ...string) error {
	return hardenDelegatedWANWithRoots(ProcSysNetRoot, true, devs...)
}

func hardenDelegatedWANWithRoots(procSysNetRoot string, runIpCmds bool, devs ...string) error {
	if len(devs) == 0 {
		return fmt.Errorf("no devices specified for HardenDelegatedWAN")
	}
	for _, rawDev := range devs {
		dev := strings.TrimSpace(rawDev)
		if !ValidNetdevName(dev) {
			return fmt.Errorf("invalid network device name %q", rawDev)
		}

		sysctls := []struct {
			relPath string
			val     string
		}{
			{filepath.Join("ipv6", "conf", dev, "disable_ipv6"), "1"},
			{filepath.Join("ipv6", "conf", dev, "accept_ra"), "0"},
			{filepath.Join("ipv4", "conf", dev, "arp_ignore"), "8"},
		}

		for _, s := range sysctls {
			fullPath := filepath.Join(procSysNetRoot, s.relPath)
			_ = os.MkdirAll(filepath.Dir(fullPath), 0755)
			if err := os.WriteFile(fullPath, []byte(s.val+"\n"), 0644); err != nil {
				// A-M30: a failed sysctl write used to be swallowed on
				// live systems, so hardening could silently do nothing
				// and return nil. Only tolerate the failure when the
				// interface's sysctl directory does not exist yet (the
				// interface is not created, or the feature is compiled
				// out); when the directory exists, the write itself
				// failed and the host is not isolated.
				if _, statErr := os.Stat(filepath.Dir(fullPath)); statErr == nil {
					return fmt.Errorf("failed to write sysctl %s: %w", fullPath, err)
				}
			}
		}

		if runIpCmds {
			// A-M30: the flush and link-up used to be discarded, so a
			// hardening step that never ran still reported success.
			if out, err := exec.Command("ip", "addr", "flush", "dev", dev).CombinedOutput(); err != nil {
				return fmt.Errorf("failed to flush addresses on %s: %s (%w)", dev, strings.TrimSpace(string(out)), err)
			}
			if out, err := exec.Command("ip", "link", "set", "dev", dev, "up").CombinedOutput(); err != nil {
				return fmt.Errorf("failed to bring up %s: %s (%w)", dev, strings.TrimSpace(string(out)), err)
			}
		}
	}
	return nil
}

// EnsureBridge creates and configures a Linux bridge according to BridgeSpec.
func EnsureBridge(spec BridgeSpec) error {
	if err := ValidateBridgeSpec(spec); err != nil {
		return err
	}

	// 1. Create bridge if it doesn't exist
	if err := exec.Command("ip", "link", "show", "dev", spec.Name).Run(); err != nil {
		if out, err := exec.Command("ip", "link", "add", "name", spec.Name, "type", "bridge").CombinedOutput(); err != nil {
			// Ignore "File exists" race
			if !strings.Contains(string(out), "File exists") {
				return fmt.Errorf("ip link add bridge %s failed: %s (%w)", spec.Name, strings.TrimSpace(string(out)), err)
			}
		}
	}

	// 2. Configure bridge sysfs attributes
	// A-M30: attribute failures used to be discarded, so the bridge
	// could come up without the requested filtering/STP/netfilter state.
	bridgeSysDir := filepath.Join(SysfsNetRoot, spec.Name, "bridge")
	writeBridgeAttr := func(name, val string) error {
		if err := os.WriteFile(filepath.Join(bridgeSysDir, name), []byte(val+"\n"), 0644); err != nil {
			return fmt.Errorf("failed to write bridge attribute %s=%s on %s: %w", name, val, spec.Name, err)
		}
		return nil
	}
	if spec.DisableNetfilter {
		for _, nfFile := range []string{"nf_call_iptables", "nf_call_ip6tables", "nf_call_arptables"} {
			if err := writeBridgeAttr(nfFile, "0"); err != nil {
				return err
			}
		}
		if out, err := exec.Command("ip", "link", "set", "dev", spec.Name, "type", "bridge",
			"nf_call_iptables", "0", "nf_call_ip6tables", "0", "nf_call_arptables", "0").CombinedOutput(); err != nil {
			return fmt.Errorf("failed to disable netfilter on bridge %s: %s (%w)", spec.Name, strings.TrimSpace(string(out)), err)
		}
	}

	vlanVal := "0"
	if spec.VlanFiltering {
		vlanVal = "1"
	}
	if err := writeBridgeAttr("vlan_filtering", vlanVal); err != nil {
		return err
	}
	if out, err := exec.Command("ip", "link", "set", "dev", spec.Name, "type", "bridge", "vlan_filtering", vlanVal).CombinedOutput(); err != nil {
		return fmt.Errorf("failed to set vlan_filtering=%s on bridge %s: %s (%w)", vlanVal, spec.Name, strings.TrimSpace(string(out)), err)
	}

	// Disable STP on WAN/LAN appliance bridges by default to avoid forwarding delay
	if err := writeBridgeAttr("stp_state", "0"); err != nil {
		return err
	}

	// 3. Enslave member interfaces and bring them up
	// A-M30: a renamed/removed member used to be silently skipped, so
	// the bridge came up empty and address-less while reporting success.
	for _, member := range spec.Members {
		if _, err := net.InterfaceByName(member); err != nil {
			return fmt.Errorf("bridge member interface %q does not exist: %w", member, err)
		}
		if out, err := exec.Command("ip", "link", "set", "dev", member, "master", spec.Name).CombinedOutput(); err != nil {
			return fmt.Errorf("failed to enslave %s to bridge %s: %s (%w)", member, spec.Name, strings.TrimSpace(string(out)), err)
		}
		if out, err := exec.Command("ip", "link", "set", "dev", member, "up").CombinedOutput(); err != nil {
			return fmt.Errorf("failed to bring up bridge member %s: %s (%w)", member, strings.TrimSpace(string(out)), err)
		}
	}

	// 4. Configure optional IPv4/IPv6 CIDR address on the bridge
	if spec.AddressCIDR != "" {
		out, _ := exec.Command("ip", "addr", "show", "dev", spec.Name).CombinedOutput()
		if !strings.Contains(string(out), spec.AddressCIDR) {
			if out, err := exec.Command("ip", "addr", "add", spec.AddressCIDR, "dev", spec.Name).CombinedOutput(); err != nil {
				return fmt.Errorf("failed to assign %s to bridge %s: %s (%w)", spec.AddressCIDR, spec.Name, strings.TrimSpace(string(out)), err)
			}
		}
	}

	// 5. Bring bridge link up
	if out, err := exec.Command("ip", "link", "set", "dev", spec.Name, "up").CombinedOutput(); err != nil {
		return fmt.Errorf("ip link set %s up failed: %s (%w)", spec.Name, strings.TrimSpace(string(out)), err)
	}

	// 6. Isolate host stack if requested (e.g., on br-wan)
	if spec.IsolateHostStack {
		if err := HardenDelegatedWAN(spec.Name); err != nil {
			return fmt.Errorf("failed to isolate host stack on bridge %s: %w", spec.Name, err)
		}
		nftRules := BuildWanBridgeHostIsolationNft(spec.Name)
		cmd := exec.Command("nft", "-f", "-")
		cmd.Stdin = strings.NewReader(nftRules)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("failed to apply host-isolation nft rules on bridge %s: %s (%w)", spec.Name, strings.TrimSpace(string(out)), err)
		}
	}

	return nil
}

// SetEdgeWanPortGate gates or opens the Edge VM's WAN tap port on the host bridge for HA fencing.
// When forwarding is true (MASTER), sets bridge port state to "forwarding".
// When forwarding is false (BACKUP/FAULT), sets bridge port state to "disabled".
func SetEdgeWanPortGate(tapDev string, forwarding bool) error {
	if !ValidNetdevName(tapDev) {
		return fmt.Errorf("invalid tap device name %q", tapDev)
	}
	state := "disabled"
	if forwarding {
		state = "forwarding"
	}
	if out, err := exec.Command("bridge", "link", "set", "dev", tapDev, "state", state).CombinedOutput(); err != nil {
		return fmt.Errorf("bridge link set dev %s state %s failed: %s (%w)", tapDev, state, strings.TrimSpace(string(out)), err)
	}
	return nil
}

// AttachTapToBridge ensures a TAP interface is up, enslaved to bridgeName, and optionally configured with an untagged PVID VLAN.
func AttachTapToBridge(tapDev, bridgeName string, vlanTag int) error {
	if !ValidNetdevName(tapDev) {
		return fmt.Errorf("invalid tap device name %q", tapDev)
	}
	if !ValidNetdevName(bridgeName) {
		return fmt.Errorf("invalid bridge name %q", bridgeName)
	}
	if vlanTag < 0 || vlanTag > 4094 {
		return fmt.Errorf("invalid VLAN tag %d (must be 0..4094)", vlanTag)
	}

	// Create tap if it does not already exist
	if err := exec.Command("ip", "link", "show", "dev", tapDev).Run(); err != nil {
		_ = exec.Command("ip", "tuntap", "add", "dev", tapDev, "mode", "tap").Run()
	}

	if out, err := exec.Command("ip", "link", "set", "dev", tapDev, "master", bridgeName).CombinedOutput(); err != nil {
		return fmt.Errorf("failed to attach tap %s to bridge %s: %s (%w)", tapDev, bridgeName, strings.TrimSpace(string(out)), err)
	}

	if out, err := exec.Command("ip", "link", "set", "dev", tapDev, "up").CombinedOutput(); err != nil {
		return fmt.Errorf("failed to bring tap %s up: %s (%w)", tapDev, strings.TrimSpace(string(out)), err)
	}

	if vlanTag > 0 {
		vidStr := strconv.Itoa(vlanTag)
		if out, err := exec.Command("bridge", "vlan", "add", "vid", vidStr, "dev", tapDev, "pvid", "untagged").CombinedOutput(); err != nil {
			return fmt.Errorf("failed to set bridge vlan %d on %s: %s (%w)", vlanTag, tapDev, strings.TrimSpace(string(out)), err)
		}
	}

	return nil
}

// NetdevConfigBundle represents `/etc/axonwall/managed/netdev_config.json` emitted by @axonwall/lib.
type NetdevConfigBundle struct {
	Vlans []struct {
		Parent      string `json:"parent"`
		Tag         int    `json:"tag"`
		Mtu         int    `json:"mtu,omitempty"`
		Description string `json:"description,omitempty"`
	} `json:"vlans"`
	Bonds []struct {
		Name   string   `json:"name"`
		Mode   string   `json:"mode"`
		Slaves []string `json:"slaves"`
		Mtu    int      `json:"mtu,omitempty"`
	} `json:"bonds"`
	Bridges []struct {
		Name          string `json:"name"`
		VlanFiltering bool   `json:"vlanFiltering"`
		Ipv4Address   string `json:"ipv4Address,omitempty"`
		Members       []struct {
			Device string `json:"device"`
		} `json:"members"`
	} `json:"bridges"`
	Vrfs []struct {
		Name       string   `json:"name"`
		TableId    int      `json:"tableId"`
		Interfaces []string `json:"interfaces"`
	} `json:"vrfs"`
	VirtualIps []struct {
		Ip        string `json:"ip"`
		Interface string `json:"interface"`
	} `json:"virtualIps"`
}

// ApplyNetdevBundleJSON reconciles declarative VLANs, LACP/Active-Backup Bonds, Bridges, VRFs, and VIPs.
func ApplyNetdevBundleJSON(rawJSON []byte, unmarshalFn func([]byte, any) error) error {
	var cfg NetdevConfigBundle
	if err := unmarshalFn(rawJSON, &cfg); err != nil {
		return fmt.Errorf("invalid netdev_config.json: %w", err)
	}

	// Validate all names up front before running any ip commands
	for _, b := range cfg.Bonds {
		if !ValidNetdevName(b.Name) {
			return fmt.Errorf("invalid bond name %q", b.Name)
		}
		for _, sl := range b.Slaves {
			if !ValidNetdevName(sl) {
				return fmt.Errorf("invalid bond slave %q", sl)
			}
		}
	}
	for _, v := range cfg.Vlans {
		if !ValidNetdevName(v.Parent) || v.Tag < 1 || v.Tag > 4094 {
			return fmt.Errorf("invalid VLAN %s.%d", v.Parent, v.Tag)
		}
	}
	for _, vrf := range cfg.Vrfs {
		if !ValidNetdevName(vrf.Name) || vrf.TableId < 1 || vrf.TableId > 65535 {
			return fmt.Errorf("invalid VRF %q (table %d)", vrf.Name, vrf.TableId)
		}
	}

	if _, err := exec.LookPath("ip"); err != nil {
		return nil
	}

	// 1. Bonds
	for _, b := range cfg.Bonds {
		mode := b.Mode
		if mode == "" {
			mode = "802.3ad"
		}
		if err := exec.Command("ip", "link", "show", "dev", b.Name).Run(); err != nil {
			_ = exec.Command("ip", "link", "add", b.Name, "type", "bond", "mode", mode).Run()
		}
		for _, sl := range b.Slaves {
			_ = exec.Command("ip", "link", "set", "dev", sl, "down").Run()
			_ = exec.Command("ip", "link", "set", "dev", sl, "master", b.Name).Run()
			_ = exec.Command("ip", "link", "set", "dev", sl, "up").Run()
		}
		if b.Mtu >= 576 && b.Mtu <= 9216 {
			_ = exec.Command("ip", "link", "set", "dev", b.Name, "mtu", strconv.Itoa(b.Mtu)).Run()
		}
		_ = exec.Command("ip", "link", "set", "dev", b.Name, "up").Run()
	}

	// 2. 802.1Q VLAN sub-interfaces
	for _, v := range cfg.Vlans {
		vlanDev := fmt.Sprintf("%s.%d", v.Parent, v.Tag)
		if !ValidNetdevName(vlanDev) {
			continue
		}
		if err := exec.Command("ip", "link", "show", "dev", vlanDev).Run(); err != nil {
			_ = exec.Command("ip", "link", "add", "link", v.Parent, "name", vlanDev, "type", "vlan", "id", strconv.Itoa(v.Tag)).Run()
		}
		if v.Mtu >= 576 && v.Mtu <= 9216 {
			_ = exec.Command("ip", "link", "set", "dev", vlanDev, "mtu", strconv.Itoa(v.Mtu)).Run()
		}
		_ = exec.Command("ip", "link", "set", "dev", vlanDev, "up").Run()
	}

	// 3. VRFs
	for _, vrf := range cfg.Vrfs {
		if err := exec.Command("ip", "link", "show", "dev", vrf.Name).Run(); err != nil {
			_ = exec.Command("ip", "link", "add", vrf.Name, "type", "vrf", "table", strconv.Itoa(vrf.TableId)).Run()
		}
		_ = exec.Command("ip", "link", "set", "dev", vrf.Name, "up").Run()
		for _, iface := range vrf.Interfaces {
			if ValidNetdevName(iface) {
				_ = exec.Command("ip", "link", "set", "dev", iface, "master", vrf.Name).Run()
			}
		}
	}

	// 4. Bridges (best-effort when member interfaces exist on host)
	for _, br := range cfg.Bridges {
		var members []string
		for _, m := range br.Members {
			if ValidNetdevName(m.Device) {
				if _, err := net.InterfaceByName(m.Device); err == nil {
					members = append(members, m.Device)
				}
			}
		}
		_ = EnsureBridge(BridgeSpec{
			Name:          br.Name,
			Members:       members,
			VlanFiltering: br.VlanFiltering,
			AddressCIDR:   br.Ipv4Address,
		})
	}

	// 5. Virtual IP Aliases
	for _, vip := range cfg.VirtualIps {
		if !ValidNetdevName(vip.Interface) || vip.Ip == "" {
			continue
		}
		addrStr := strings.TrimSpace(vip.Ip)
		if !strings.Contains(addrStr, "/") {
			if parsed := net.ParseIP(addrStr); parsed != nil {
				if parsed.To4() != nil {
					addrStr += "/32"
				} else {
					addrStr += "/128"
				}
			}
		}
		if _, _, err := net.ParseCIDR(addrStr); err == nil {
			_ = exec.Command("ip", "addr", "replace", addrStr, "dev", vip.Interface).Run()
		}
	}

	return nil
}
