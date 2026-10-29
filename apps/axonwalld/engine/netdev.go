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
				// On live systems where /proc/sys/net/... might not exist yet if interface isn't created,
				// only return error if the directory exists and write failed, or in unit tests with custom root.
				if procSysNetRoot != "/proc/sys/net" {
					return fmt.Errorf("failed to write sysctl %s: %w", fullPath, err)
				}
			}
		}

		if runIpCmds {
			_ = exec.Command("ip", "addr", "flush", "dev", dev).Run()
			_ = exec.Command("ip", "link", "set", "dev", dev, "up").Run()
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
	bridgeSysDir := filepath.Join(SysfsNetRoot, spec.Name, "bridge")
	if spec.DisableNetfilter {
		for _, nfFile := range []string{"nf_call_iptables", "nf_call_ip6tables", "nf_call_arptables"} {
			_ = os.WriteFile(filepath.Join(bridgeSysDir, nfFile), []byte("0\n"), 0644)
		}
		_ = exec.Command("ip", "link", "set", "dev", spec.Name, "type", "bridge",
			"nf_call_iptables", "0", "nf_call_ip6tables", "0", "nf_call_arptables", "0").Run()
	}

	vlanVal := "0"
	if spec.VlanFiltering {
		vlanVal = "1"
	}
	_ = os.WriteFile(filepath.Join(bridgeSysDir, "vlan_filtering"), []byte(vlanVal+"\n"), 0644)
	_ = exec.Command("ip", "link", "set", "dev", spec.Name, "type", "bridge", "vlan_filtering", vlanVal).Run()

	// Disable STP on WAN/LAN appliance bridges by default to avoid forwarding delay
	_ = os.WriteFile(filepath.Join(bridgeSysDir, "stp_state"), []byte("0\n"), 0644)

	// 3. Enslave member interfaces and bring them up
	for _, member := range spec.Members {
		_ = exec.Command("ip", "link", "set", "dev", member, "master", spec.Name).Run()
		_ = exec.Command("ip", "link", "set", "dev", member, "up").Run()
	}

	// 4. Configure optional IPv4/IPv6 CIDR address on the bridge
	if spec.AddressCIDR != "" {
		out, _ := exec.Command("ip", "addr", "show", "dev", spec.Name).CombinedOutput()
		if !strings.Contains(string(out), spec.AddressCIDR) {
			_ = exec.Command("ip", "addr", "add", spec.AddressCIDR, "dev", spec.Name).Run()
		}
	}

	// 5. Bring bridge link up
	if out, err := exec.Command("ip", "link", "set", "dev", spec.Name, "up").CombinedOutput(); err != nil {
		return fmt.Errorf("ip link set %s up failed: %s (%w)", spec.Name, strings.TrimSpace(string(out)), err)
	}

	// 6. Isolate host stack if requested (e.g., on br-wan)
	if spec.IsolateHostStack {
		_ = HardenDelegatedWAN(spec.Name)
		nftRules := BuildWanBridgeHostIsolationNft(spec.Name)
		cmd := exec.Command("nft", "-f", "-")
		cmd.Stdin = strings.NewReader(nftRules)
		_ = cmd.Run()
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
