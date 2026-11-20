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

// SysfsNetRoot, ProcSysNetRoot, and AxonwallEtcDir allow unit tests to override filesystem roots.
var (
	SysfsNetRoot   = "/sys/class/net"
	ProcSysNetRoot = "/proc/sys/net"
	AxonwallEtcDir = "/etc/axonwall"
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

// NetdevVlanBundle accepts both @axonwall/lib TypeScript field names (`parentInterface`, `vlanInterface`)
// and legacy Go field names (`parent`).
type NetdevVlanBundle struct {
	ParentInterface string `json:"parentInterface"`
	Parent          string `json:"parent"`
	VlanInterface   string `json:"vlanInterface"`
	Tag             int    `json:"tag"`
	Mtu             int    `json:"mtu,omitempty"`
	Description     string `json:"description,omitempty"`
}

func (v NetdevVlanBundle) EffectiveParent() string {
	if p := strings.TrimSpace(v.ParentInterface); p != "" {
		return p
	}
	return strings.TrimSpace(v.Parent)
}

func (v NetdevVlanBundle) EffectiveVlanInterface() string {
	if vi := strings.TrimSpace(v.VlanInterface); vi != "" {
		return vi
	}
	p := v.EffectiveParent()
	if p == "" {
		return ""
	}
	return fmt.Sprintf("%s.%d", p, v.Tag)
}

// NetdevBondBundle accepts both @axonwall/lib (`members`) and legacy Go (`slaves`) field names.
type NetdevBondBundle struct {
	Name    string   `json:"name"`
	Mode    string   `json:"mode"`
	Members []string `json:"members"`
	Slaves  []string `json:"slaves"`
	Mtu     int      `json:"mtu,omitempty"`
}

func (b NetdevBondBundle) EffectiveMembers() []string {
	if len(b.Members) > 0 {
		return b.Members
	}
	return b.Slaves
}

// NetdevBridgeMemberBundle accepts both @axonwall/lib (`interface`) and legacy Go (`device`) field names.
type NetdevBridgeMemberBundle struct {
	Interface string `json:"interface"`
	Device    string `json:"device"`
}

func (m NetdevBridgeMemberBundle) EffectiveDevice() string {
	if dev := strings.TrimSpace(m.Interface); dev != "" {
		return dev
	}
	return strings.TrimSpace(m.Device)
}

// NetdevVirtualIpBundle accepts both CIDR `ip` strings and separate `ip` + `subnetBits`.
type NetdevVirtualIpBundle struct {
	Ip         string `json:"ip"`
	SubnetBits int    `json:"subnetBits,omitempty"`
	Interface  string `json:"interface"`
}

// NetdevConfigBundle represents `/etc/axonwall/managed/netdev_config.json` emitted by @axonwall/lib.
type NetdevConfigBundle struct {
	Vlans   []NetdevVlanBundle `json:"vlans"`
	Bonds   []NetdevBondBundle `json:"bonds"`
	Bridges []struct {
		Name          string                     `json:"name"`
		VlanFiltering bool                       `json:"vlanFiltering"`
		Ipv4Address   string                     `json:"ipv4Address,omitempty"`
		Members       []NetdevBridgeMemberBundle `json:"members"`
	} `json:"bridges"`
	Vrfs []struct {
		Name       string   `json:"name"`
		TableId    int      `json:"tableId"`
		Interfaces []string `json:"interfaces"`
	} `json:"vrfs"`
	VirtualIps []NetdevVirtualIpBundle `json:"virtualIps"`
}

func resolveLogicalInterfaceDev(ifaceOrDev string) string {
	cand := strings.TrimSpace(ifaceOrDev)
	if cand == "" {
		return ""
	}
	if _, err := net.InterfaceByName(cand); err == nil {
		return cand
	}
	lowerCand := strings.ToLower(cand)
	for _, confPath := range []string{filepath.Join(AxonwallEtcDir, "interfaces.conf"), "/var/lib/axonwall/etc-axonwall/interfaces.conf"} {
		data, err := os.ReadFile(confPath)
		if err != nil {
			continue
		}
		rawKv := make(map[string]string)
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") || !strings.Contains(line, "=") {
				continue
			}
			parts := strings.SplitN(line, "=", 2)
			rawKv[strings.TrimSpace(parts[0])] = strings.TrimSpace(strings.Trim(parts[1], `"`))
		}
		if lowerCand == "wan" && rawKv["WAN_INTERFACE"] != "" {
			return rawKv["WAN_INTERFACE"]
		}
		if lowerCand == "lan" && rawKv["LAN_INTERFACE"] != "" {
			return rawKv["LAN_INTERFACE"]
		}
		if lowerCand == "opt1" && rawKv["OPT1_INTERFACE"] != "" {
			return rawKv["OPT1_INTERFACE"]
		}
		if lowerCand == "opt2" && rawKv["OPT2_INTERFACE"] != "" {
			return rawKv["OPT2_INTERFACE"]
		}
		for k, v := range rawKv {
			if strings.HasPrefix(k, "IFACE_") && strings.HasSuffix(k, "_DEVICE") && v != "" {
				keyBase := strings.TrimSuffix(strings.TrimPrefix(k, "IFACE_"), "_DEVICE")
				logicalName := strings.TrimSpace(rawKv["IFACE_"+keyBase+"_NAME"])
				if logicalName == "" {
					logicalName = strings.ToLower(keyBase)
				}
				if strings.EqualFold(logicalName, lowerCand) {
					return v
				}
			}
		}
		break
	}
	return cand
}

func formatVirtualIpCIDR(vip NetdevVirtualIpBundle) string {
	addrStr := strings.TrimSpace(vip.Ip)
	if addrStr == "" {
		return ""
	}
	if strings.Contains(addrStr, "/") {
		return addrStr
	}
	parsed := net.ParseIP(addrStr)
	if parsed == nil {
		return addrStr
	}
	if parsed.To4() != nil {
		if vip.SubnetBits >= 1 && vip.SubnetBits <= 32 {
			return fmt.Sprintf("%s/%d", addrStr, vip.SubnetBits)
		}
		return addrStr + "/32"
	}
	if vip.SubnetBits >= 1 && vip.SubnetBits <= 128 {
		return fmt.Sprintf("%s/%d", addrStr, vip.SubnetBits)
	}
	return addrStr + "/128"
}

var validBondModes = map[string]bool{
	"balance-rr":    true,
	"active-backup": true,
	"balance-xor":   true,
	"broadcast":     true,
	"802.3ad":       true,
	"balance-tlb":   true,
	"balance-alb":   true,
}

// runIpCmd runs one `ip` invocation and returns a wrapped error with
// the command's output. A-H4 (round 3): ApplyNetdevBundleJSON used to
// discard every ip failure with `_ =` and return nil, so a bundle
// could be recorded as applied while its topology did not exist.
func runIpCmd(args ...string) error {
	if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
		return fmt.Errorf("ip %s failed: %s (%w)", strings.Join(args, " "), strings.TrimSpace(string(out)), err)
	}
	return nil
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
		mode := b.Mode
		if mode == "" {
			mode = "802.3ad"
		}
		if !validBondModes[mode] {
			return fmt.Errorf("invalid bond mode %q for bond %q (valid: balance-rr, active-backup, balance-xor, broadcast, 802.3ad, balance-tlb, balance-alb)", b.Mode, b.Name)
		}
		// A-H4 (round 3) mode validation above is kept; member
		// iteration uses main's EffectiveMembers (fc576368) so
		// both `members` (lib) and `slaves` (legacy) are honoured.
		for _, sl := range b.EffectiveMembers() {
			if !ValidNetdevName(sl) {
				return fmt.Errorf("invalid bond slave %q", sl)
			}
		}
	}
	for _, v := range cfg.Vlans {
		parent := v.EffectiveParent()
		vlanDev := v.EffectiveVlanInterface()
		if !ValidNetdevName(parent) || v.Tag < 1 || v.Tag > 4094 || !ValidNetdevName(vlanDev) {
			return fmt.Errorf("invalid VLAN %s.%d", parent, v.Tag)
		}
	}
	for _, vrf := range cfg.Vrfs {
		if !ValidNetdevName(vrf.Name) || vrf.TableId < 1 || vrf.TableId > 65535 {
			return fmt.Errorf("invalid VRF %q (table %d)", vrf.Name, vrf.TableId)
		}
		for _, iface := range vrf.Interfaces {
			if !ValidNetdevName(iface) {
				return fmt.Errorf("invalid VRF member interface %q", iface)
			}
		}
	}
	for _, vip := range cfg.VirtualIps {
		if !ValidNetdevName(vip.Interface) || strings.TrimSpace(vip.Ip) == "" {
			return fmt.Errorf("invalid virtual IP %q on interface %q", vip.Ip, vip.Interface)
		}
	}

	if _, err := exec.LookPath("ip"); err != nil {
		// A-H4 (round 3): with no `ip` binary the whole bundle used
		// to "apply" with nothing done and return nil.
		return fmt.Errorf("cannot apply netdev bundle: ip command not found (%v)", err)
	}

	// 1. Bonds
	for _, b := range cfg.Bonds {
		mode := b.Mode
		if mode == "" {
			mode = "802.3ad"
		}
		if err := exec.Command("ip", "link", "show", "dev", b.Name).Run(); err != nil {
			if out, err := exec.Command("ip", "link", "add", b.Name, "type", "bond", "mode", mode).CombinedOutput(); err != nil {
				if !strings.Contains(string(out), "File exists") {
					return fmt.Errorf("failed to create bond %s (mode %s): %s (%w)", b.Name, mode, strings.TrimSpace(string(out)), err)
				}
			}
		}
		// A-H4 (round 3): enslave failures fail the apply instead
		// of being discarded. Members come from main's
		// EffectiveMembers (fc576368).
		for _, sl := range b.EffectiveMembers() {
			if err := runIpCmd("link", "set", "dev", sl, "down"); err != nil {
				return fmt.Errorf("failed to enslave %s into bond %s: %w", sl, b.Name, err)
			}
			if err := runIpCmd("link", "set", "dev", sl, "master", b.Name); err != nil {
				return fmt.Errorf("failed to enslave %s into bond %s: %w", sl, b.Name, err)
			}
			if err := runIpCmd("link", "set", "dev", sl, "up"); err != nil {
				return fmt.Errorf("failed to bring up bond slave %s: %w", sl, err)
			}
		}
		if b.Mtu >= 576 && b.Mtu <= 9216 {
			if err := runIpCmd("link", "set", "dev", b.Name, "mtu", strconv.Itoa(b.Mtu)); err != nil {
				return fmt.Errorf("failed to set MTU on bond %s: %w", b.Name, err)
			}
		}
		if err := runIpCmd("link", "set", "dev", b.Name, "up"); err != nil {
			return fmt.Errorf("failed to bring up bond %s: %w", b.Name, err)
		}
	}

	// 2. 802.1Q VLAN sub-interfaces
	for _, v := range cfg.Vlans {
		// Parent/device names come from main's Effective*
		// accessors (fc576368) so lib field names work; the
		// parent-existence check and error-checked creation are
		// A-H4 (round 3).
		parent := v.EffectiveParent()
		vlanDev := v.EffectiveVlanInterface()
		// A-H4: the parent was never existence-checked, so a VLAN
		// on a renamed/missing parent failed silently.
		if err := exec.Command("ip", "link", "show", "dev", parent).Run(); err != nil {
			return fmt.Errorf("cannot create VLAN %s: parent interface %s does not exist (%v)", vlanDev, parent, err)
		}
		if err := exec.Command("ip", "link", "show", "dev", vlanDev).Run(); err != nil {
			if err := runIpCmd("link", "add", "link", parent, "name", vlanDev, "type", "vlan", "id", strconv.Itoa(v.Tag)); err != nil {
				return fmt.Errorf("failed to create VLAN %s: %w", vlanDev, err)
			}
		}
		if v.Mtu >= 576 && v.Mtu <= 9216 {
			if err := runIpCmd("link", "set", "dev", vlanDev, "mtu", strconv.Itoa(v.Mtu)); err != nil {
				return fmt.Errorf("failed to set MTU on VLAN %s: %w", vlanDev, err)
			}
		}
		if err := runIpCmd("link", "set", "dev", vlanDev, "up"); err != nil {
			return fmt.Errorf("failed to bring up VLAN %s: %w", vlanDev, err)
		}
	}

	// 3. VRFs
	for _, vrf := range cfg.Vrfs {
		if err := exec.Command("ip", "link", "show", "dev", vrf.Name).Run(); err != nil {
			if err := runIpCmd("link", "add", vrf.Name, "type", "vrf", "table", strconv.Itoa(vrf.TableId)); err != nil {
				return fmt.Errorf("failed to create VRF %s: %w", vrf.Name, err)
			}
		}
		if err := runIpCmd("link", "set", "dev", vrf.Name, "up"); err != nil {
			return fmt.Errorf("failed to bring up VRF %s: %w", vrf.Name, err)
		}
		for _, iface := range vrf.Interfaces {
			// Logical names resolve via main's
			// resolveLogicalInterfaceDev (fc576368); the
			// assignment failure fails the apply per A-H4
			// (round 3) instead of being discarded. An
			// unresolvable name is skipped as on main — the
			// up-front validation loop already rejected
			// invalid member names.
			dev := resolveLogicalInterfaceDev(iface)
			if ValidNetdevName(dev) {
				if err := runIpCmd("link", "set", "dev", dev, "master", vrf.Name); err != nil {
					return fmt.Errorf("failed to assign %s to VRF %s: %w", dev, vrf.Name, err)
				}
			}
		}
	}

	// 4. Bridges (best-effort when member interfaces exist on host)
	for _, br := range cfg.Bridges {
		var members []string
		for _, m := range br.Members {
			dev := resolveLogicalInterfaceDev(m.EffectiveDevice())
			if ValidNetdevName(dev) {
				if _, err := net.InterfaceByName(dev); err == nil {
					members = append(members, dev)
				}
			}
		}
		// A-H4: the hardened EnsureBridge error used to be
		// discarded here, throwing away the round-2 A-M30 fix.
		if err := EnsureBridge(BridgeSpec{
			Name:          br.Name,
			Members:       members,
			VlanFiltering: br.VlanFiltering,
			AddressCIDR:   br.Ipv4Address,
		}); err != nil {
			return fmt.Errorf("failed to reconcile bridge %s: %w", br.Name, err)
		}
	}

	// 5. Virtual IP Aliases
	for _, vip := range cfg.VirtualIps {
		// Interface resolves via main's resolveLogicalInterfaceDev
		// (fc576368) and the CIDR via main's formatVirtualIpCIDR
		// (fc576368), which subsumes the branch's bare-IP /32//128
		// defaulting and adds subnetBits. A-H4 (round 3): an
		// invalid VIP or a failed `ip addr replace` fails the
		// apply instead of being silently skipped/discarded.
		dev := resolveLogicalInterfaceDev(vip.Interface)
		if !ValidNetdevName(dev) || strings.TrimSpace(vip.Ip) == "" {
			return fmt.Errorf("invalid virtual IP %q on interface %q", vip.Ip, vip.Interface)
		}
		addrStr := formatVirtualIpCIDR(vip)
		if _, _, err := net.ParseCIDR(addrStr); err != nil {
			return fmt.Errorf("invalid virtual IP %q on interface %s: %w", vip.Ip, vip.Interface, err)
		}
		if err := runIpCmd("addr", "replace", addrStr, "dev", dev); err != nil {
			return fmt.Errorf("failed to assign VIP %s to %s: %w", addrStr, dev, err)
		}
	}

	return nil
}
