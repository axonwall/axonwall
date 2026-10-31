package engine

import (
	"log/slog"
	"os"
	"sync"
	"time"
)

// EdgeHATransitionPayload is sent by the Axonwall Hub (or VRRP election) when an Edge NGFW
// transitions between active (MASTER) and hot-standby (BACKUP).
type EdgeHATransitionPayload struct {
	Role         string `json:"role"`                   // "active" | "standby"
	Placement    string `json:"placement,omitempty"`    // "hosted" | "dedicated"
	WanDevice    string `json:"wanDevice,omitempty"`    // default "eth0"
	LanDevice    string `json:"lanDevice,omitempty"`    // default "eth1"
	SharedWanMac string `json:"sharedWanMac,omitempty"` // optional shared WAN MAC
	LanVipV4     string `json:"lanVipV4,omitempty"`     // e.g. "10.0.0.1/24"
	LanVipV6     string `json:"lanVipV6,omitempty"`     // e.g. "fd00::1/64"
}

// EdgeHAEngine manages active/standby state, WAN self-fencing, and LAN VIP ownership
// across both hosted (QEMU VM on Axonwall host) and dedicated (bare-metal SKU) placements.
type EdgeHAEngine struct {
	mu         sync.RWMutex
	placement  string
	role       string
	lastLanDev string
	lastVipV4  string
	lastVipV6  string
}

func NewEdgeHAEngine(placement, initialRole string) *EdgeHAEngine {
	if placement == "" {
		placement = "hosted"
	}
	if initialRole == "" {
		initialRole = "active"
	}
	return &EdgeHAEngine{
		placement: placement,
		role:      initialRole,
	}
}

func (h *EdgeHAEngine) Role() string {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.role
}

func (h *EdgeHAEngine) Placement() string {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.placement
}

// Promote transitions the Edge NGFW into the active forwarding router role:
//  1. Unfences the WAN interface (brings link up)
//  2. Assigns the shared LAN gateway VIPs (IPv4 + IPv6) on the LAN interface
func (h *EdgeHAEngine) Promote(netEngine *EdgeNetworkEngine, p EdgeHATransitionPayload) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if p.Placement != "" {
		h.placement = p.Placement
	}
	wanDev := p.WanDevice
	if wanDev == "" {
		wanDev = "eth0"
	}
	lanDev := p.LanDevice
	if lanDev == "" {
		lanDev = "eth1"
	}

	slog.Info("Promoting Edge NGFW to ACTIVE master", "placement", h.placement, "wan", wanDev, "lan", lanDev)
	_ = netEngine.SetLinkUp(wanDev, true)

	if p.LanVipV4 != "" {
		_ = netEngine.ConfigureInterface(EdgeInterfaceSpec{
			Name:    "lan-vip4",
			Device:  lanDev,
			Address: p.LanVipV4,
			MTU:     1500,
			Enabled: true,
		})
	}
	if p.LanVipV6 != "" {
		_ = netEngine.ConfigureInterface(EdgeInterfaceSpec{
			Name:    "lan-vip6",
			Device:  lanDev,
			Address: p.LanVipV6,
			MTU:     1500,
			Enabled: true,
		})
	}

	h.lastLanDev = lanDev
	if p.LanVipV4 != "" {
		h.lastVipV4 = p.LanVipV4
	}
	if p.LanVipV6 != "" {
		h.lastVipV6 = p.LanVipV6
	}
	h.role = "active"
	return nil
}

// Demote transitions the Edge NGFW into hot-standby mode:
//  1. Fences the WAN interface first (admin-down so the shared WAN MAC never appears twice on the ISP segment)
//  2. Removes shared LAN VIPs from the LAN interface to prevent ARP/NDP split-brain
//  3. Marks HA state as "standby"
func (h *EdgeHAEngine) Demote(netEngine *EdgeNetworkEngine, p EdgeHATransitionPayload) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if p.Placement != "" {
		h.placement = p.Placement
	}
	wanDev := p.WanDevice
	if wanDev == "" {
		wanDev = "eth0"
	}
	lanDev := p.LanDevice
	if lanDev == "" {
		lanDev = h.lastLanDev
	}
	if lanDev == "" {
		lanDev = "eth1"
	}
	vip4 := p.LanVipV4
	if vip4 == "" {
		vip4 = h.lastVipV4
	}
	vip6 := p.LanVipV6
	if vip6 == "" {
		vip6 = h.lastVipV6
	}

	slog.Info("Demoting Edge NGFW to HOT STANDBY (fencing WAN link & releasing LAN VIPs)", "placement", h.placement, "wan", wanDev, "lan", lanDev)
	_ = netEngine.SetLinkUp(wanDev, false)
	if vip4 != "" {
		_ = netEngine.RemoveAddress(lanDev, vip4)
	}
	if vip6 != "" {
		_ = netEngine.RemoveAddress(lanDev, vip6)
	}
	h.role = "standby"
	return nil
}

// StartHardwareWatchdog pets /dev/watchdog (e.g. QEMU i6300esb or Intel iTCO_wdt) every 10s.
// If the device does not exist, it returns cleanly without error.
func StartHardwareWatchdog(stopCh <-chan struct{}) {
	var wdFile *os.File
	for _, dev := range []string{"/dev/watchdog", "/dev/watchdog0"} {
		f, err := os.OpenFile(dev, os.O_WRONLY, 0)
		if err == nil {
			wdFile = f
			slog.Info("Attached to hardware/virtual watchdog device", "device", dev)
			break
		}
	}
	if wdFile == nil {
		return
	}

	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		defer func() {
			// Write 'V' magic close character only on intentional shutdown
			_, _ = wdFile.Write([]byte("V"))
			_ = wdFile.Close()
		}()

		_, _ = wdFile.Write([]byte("1"))
		for {
			select {
			case <-stopCh:
				return
			case <-ticker.C:
				_, _ = wdFile.Write([]byte("1"))
			}
		}
	}()
}
