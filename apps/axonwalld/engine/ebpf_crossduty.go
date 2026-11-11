package engine

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type NetdevTrafficStats struct {
	Device    string `json:"device"`
	OperState string `json:"operState"`
	RxBytes   uint64 `json:"rxBytes"`
	TxBytes   uint64 `json:"txBytes"`
	RxPackets uint64 `json:"rxPackets"`
	TxPackets uint64 `json:"txPackets"`
	RxDropped uint64 `json:"rxDropped"`
	TxDropped uint64 `json:"txDropped"`
	XdpProgAttached bool `json:"xdpProgAttached"`
}

type VirtWorkloadEbpfSummary struct {
	Kind              string               `json:"kind"` // "vm" or "lxc"
	ID                int                  `json:"id"`
	Name              string               `json:"name"`
	Status            string               `json:"status"`
	PID               int                  `json:"pid"`
	BpfTokenEnabled   bool                 `json:"bpfTokenEnabled"`
	BpfTokenProfileID string               `json:"bpfTokenProfileId,omitempty"`
	BpfTokenPreset    string               `json:"bpfTokenPreset,omitempty"`
	Netdevs           []NetdevTrafficStats `json:"netdevs"`
}

type VirtEbpfTelemetry struct {
	Timestamp     string                    `json:"timestamp"`
	Workloads     []VirtWorkloadEbpfSummary `json:"workloads"`
	BridgeStats   []NetdevTrafficStats      `json:"bridgeStats"`
	IommuEnabled  bool                      `json:"iommuEnabled"`
	IommuGroups   int                       `json:"iommuGroups"`
}

type K3sEbpfTelemetry struct {
	Timestamp        string                      `json:"timestamp"`
	Cluster          K3sClusterStatus            `json:"cluster"`
	CniInterfaces    []NetdevTrafficStats        `json:"cniInterfaces"`
	BpfTokenProfiles []BpfTokenDelegationProfile `json:"bpfTokenProfiles"`
}

func readUint64Sysfs(path string) uint64 {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	v, _ := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	return v
}

// ReadNetdevTrafficStats reads kernel /sys/class/net/<dev> statistics & XDP attachment state.
func ReadNetdevTrafficStats(dev string) (NetdevTrafficStats, bool) {
	if !ValidNetdevName(dev) {
		return NetdevTrafficStats{}, false
	}
	base := filepath.Join("/sys/class/net", dev)
	if _, err := os.Stat(base); err != nil {
		return NetdevTrafficStats{}, false
	}
	oper := readSysctlFileTrimmed(filepath.Join(base, "operstate"), "unknown")
	statsDir := filepath.Join(base, "statistics")

	// Check if XDP program is attached via /sys/class/net/<dev>/xdp/prog_id (Linux 5.8+)
	xdpAttached := readUint64Sysfs(filepath.Join(base, "xdp", "prog_id")) > 0

	return NetdevTrafficStats{
		Device:          dev,
		OperState:       oper,
		RxBytes:         readUint64Sysfs(filepath.Join(statsDir, "rx_bytes")),
		TxBytes:         readUint64Sysfs(filepath.Join(statsDir, "tx_bytes")),
		RxPackets:       readUint64Sysfs(filepath.Join(statsDir, "rx_packets")),
		TxPackets:       readUint64Sysfs(filepath.Join(statsDir, "tx_packets")),
		RxDropped:       readUint64Sysfs(filepath.Join(statsDir, "rx_dropped")),
		TxDropped:       readUint64Sysfs(filepath.Join(statsDir, "tx_dropped")),
		XdpProgAttached: xdpAttached,
	}, true
}

func (m *VirtManager) GetEbpfTelemetry() VirtEbpfTelemetry {
	vms := m.ListVMs()
	cts := m.ListContainers()
	profiles := GetDefaultBpfTokenManager().ListProfiles()

	profileByTarget := make(map[string]BpfTokenDelegationProfile)
	for _, p := range profiles {
		if p.TargetRef != "" {
			profileByTarget[p.TargetRef] = p
		}
	}

	m.mu.RLock()
	vmSpecCopy := make(map[int]CompiledVmSpec, len(m.vmSpecs))
	for k, v := range m.vmSpecs {
		vmSpecCopy[k] = v
	}
	m.mu.RUnlock()

	var workloads []VirtWorkloadEbpfSummary
	bridgeSeen := make(map[string]bool)

	for _, vm := range vms {
		var netdevs []NetdevTrafficStats
		if spec, ok := vmSpecCopy[vm.VMID]; ok {
			for _, tap := range extractTapDevicesFromArgs(spec.Args) {
				if st, exists := ReadNetdevTrafficStats(tap); exists {
					netdevs = append(netdevs, st)
				}
			}
			for _, br := range spec.Bridges {
				bridgeSeen[br] = true
			}
		}
		workloads = append(workloads, VirtWorkloadEbpfSummary{
			Kind:    "vm",
			ID:      vm.VMID,
			Name:    vm.Name,
			Status:  vm.Status,
			PID:     vm.PID,
			Netdevs: netdevs,
		})
	}

	for _, ct := range cts {
		var netdevs []NetdevTrafficStats
		for idx := 0; idx < 4; idx++ {
			candidate := fmt.Sprintf("veth%d_%d", ct.CTID, idx)
			if st, exists := ReadNetdevTrafficStats(candidate); exists {
				netdevs = append(netdevs, st)
			}
		}
		targetKey := fmt.Sprintf("ct-%d", ct.CTID)
		prof, hasProf := profileByTarget[targetKey]
		workloads = append(workloads, VirtWorkloadEbpfSummary{
			Kind:              "lxc",
			ID:                ct.CTID,
			Name:              ct.Name,
			Status:            ct.Status,
			PID:               ct.PID,
			BpfTokenEnabled:   hasProf && prof.Enabled,
			BpfTokenProfileID: prof.ID,
			BpfTokenPreset:    prof.Preset,
			Netdevs:           netdevs,
		})
	}

	for _, commonBr := range []string{"br0", "br-lan", "br-wan", "vmbr0"} {
		bridgeSeen[commonBr] = true
	}
	var bridgeStats []NetdevTrafficStats
	for br := range bridgeSeen {
		if st, exists := ReadNetdevTrafficStats(br); exists {
			bridgeStats = append(bridgeStats, st)
		}
	}

	iommuGroups := 0
	if entries, err := os.ReadDir("/sys/kernel/iommu_groups"); err == nil {
		iommuGroups = len(entries)
	}

	return VirtEbpfTelemetry{
		Timestamp:    time.Now().UTC().Format(time.RFC3339),
		Workloads:    workloads,
		BridgeStats:  bridgeStats,
		IommuEnabled: iommuGroups > 0,
		IommuGroups:  iommuGroups,
	}
}

func (m *K3sManager) GetEbpfTelemetry() K3sEbpfTelemetry {
	status := m.GetStatus()
	var cniStats []NetdevTrafficStats
	for _, dev := range []string{"flannel-wg", "flannel-wg-v6", "flannel.1", "cni0", "cilium_host", "cilium_net", "cilium_wg0"} {
		if st, exists := ReadNetdevTrafficStats(dev); exists {
			cniStats = append(cniStats, st)
		}
	}

	var k3sProfiles []BpfTokenDelegationProfile
	for _, p := range GetDefaultBpfTokenManager().ListProfiles() {
		if p.TargetKind == "k3s-pod" || p.TargetKind == "standalone" {
			k3sProfiles = append(k3sProfiles, p)
		}
	}

	return K3sEbpfTelemetry{
		Timestamp:        time.Now().UTC().Format(time.RFC3339),
		Cluster:          status,
		CniInterfaces:    cniStats,
		BpfTokenProfiles: k3sProfiles,
	}
}
