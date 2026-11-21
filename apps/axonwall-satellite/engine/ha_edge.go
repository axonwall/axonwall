package engine

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
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
	lastWanDev string
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
	// C-M3: program shared WAN MAC onto wanDev before unfencing WAN.
	if mac := strings.TrimSpace(p.SharedWanMac); mac != "" {
		if err := netEngine.SetLinkMAC(wanDev, mac); err != nil {
			return fmt.Errorf("promote: failed to set shared WAN MAC %s on %s: %w", mac, wanDev, err)
		}
	}
	// A-M11: every kernel operation is checked, and the recorded
	// role changes only after all of them succeed. The old code
	// discarded every error and recorded "active" unconditionally,
	// so the hub believed a node held the gateway VIP when the VIP
	// assignment had silently failed.
	if err := netEngine.SetLinkUp(wanDev, true); err != nil {
		return fmt.Errorf("promote: failed to unfence WAN %s: %w", wanDev, err)
	}

	var errs []error
	var assigned []string
	if p.LanVipV4 != "" {
		if err := netEngine.ConfigureInterface(EdgeInterfaceSpec{
			Name:    "lan-vip4",
			Device:  lanDev,
			Address: p.LanVipV4,
			Enabled: true,
		}); err != nil {
			errs = append(errs, fmt.Errorf("promote: failed to assign LAN VIP %s on %s: %w", p.LanVipV4, lanDev, err))
		} else {
			assigned = append(assigned, p.LanVipV4)
		}
	}
	if p.LanVipV6 != "" {
		if err := netEngine.ConfigureInterface(EdgeInterfaceSpec{
			Name:    "lan-vip6",
			Device:  lanDev,
			Address: p.LanVipV6,
			Enabled: true,
		}); err != nil {
			errs = append(errs, fmt.Errorf("promote: failed to assign LAN VIP %s on %s: %w", p.LanVipV6, lanDev, err))
		} else {
			assigned = append(assigned, p.LanVipV6)
		}
	}
	if len(errs) > 0 {
		// A-M41 (round 2): roll back the half-applied kernel state.
		// Without this, a v4-OK/v6-failed Promote returned an error
		// with the role unchanged ("standby") while the v4 VIP was
		// live on the interface and the WAN was unfenced. Remove
		// any VIP that was assigned and re-fence the WAN so the
		// recorded role matches the kernel state.
		for _, vip := range assigned {
			if rerr := netEngine.RemoveAddress(lanDev, vip); rerr != nil {
				errs = append(errs, fmt.Errorf("promote: rollback failed to remove LAN VIP %s from %s: %w", vip, lanDev, rerr))
			}
		}
		if rerr := netEngine.SetLinkUp(wanDev, false); rerr != nil {
			errs = append(errs, fmt.Errorf("promote: rollback failed to re-fence WAN %s: %w", wanDev, rerr))
		}
		// Role and remembered VIPs stay as they were: the node is
		// not active if its VIPs are not actually assigned.
		return errors.Join(errs...)
	}

	h.lastWanDev = wanDev
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
	priorRole := h.role

	if p.Placement != "" {
		h.placement = p.Placement
	}
	wanDev := p.WanDevice
	if wanDev == "" {
		wanDev = h.lastWanDev
	}
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
	// A-M11: same fail-closed shape as Promote. If the WAN fence
	// fails, the node is not standby; if a VIP removal fails, the
	// VIP is still live on this node and the role must not claim
	// otherwise — a "standby" node still holding the VIP alongside
	// the new active node is exactly the split-brain this guards.
	if err := netEngine.SetLinkUp(wanDev, false); err != nil {
		return fmt.Errorf("demote: failed to fence WAN %s: %w", wanDev, err)
	}
	var errs []error
	if vip4 != "" {
		if err := netEngine.RemoveAddress(lanDev, vip4); err != nil {
			errs = append(errs, fmt.Errorf("demote: failed to remove LAN VIP %s from %s: %w", vip4, lanDev, err))
		}
	}
	if vip6 != "" {
		if err := netEngine.RemoveAddress(lanDev, vip6); err != nil {
			errs = append(errs, fmt.Errorf("demote: failed to remove LAN VIP %s from %s: %w", vip6, lanDev, err))
		}
	}
	if len(errs) > 0 {
		// A-M41 (round 2): only bring WAN back up if this node was previously
		// "active". If the node was already "standby", a failed VIP removal must
		// NOT unfence the standby WAN link and trigger dual-active split-brain.
		if priorRole == "active" {
			if rerr := netEngine.SetLinkUp(wanDev, true); rerr != nil {
				errs = append(errs, fmt.Errorf("demote: rollback failed to restore WAN %s: %w", wanDev, rerr))
			}
		}
		return errors.Join(errs...)
	}
	h.lastWanDev = wanDev
	h.lastLanDev = lanDev
	if vip4 != "" {
		h.lastVipV4 = vip4
	}
	if vip6 != "" {
		h.lastVipV6 = vip6
	}
	h.role = "standby"
	return nil
}

func sameHAAddrOrCIDR(a, b string) bool {
	a = strings.TrimSpace(a)
	b = strings.TrimSpace(b)
	if a == "" || b == "" {
		return false
	}
	if a == b {
		return true
	}
	aIP, _, aErr := net.ParseCIDR(a)
	if aErr != nil {
		aIP = net.ParseIP(a)
	}
	bIP, _, bErr := net.ParseCIDR(b)
	if bErr != nil {
		bIP = net.ParseIP(b)
	}
	return aIP != nil && bIP != nil && aIP.Equal(bIP)
}

// PrepareSyncedInterface enforces standby fencing when a hub SYNC_INTERFACES
// payload arrives while this node is in "standby" HA role: WAN stays admin-down
// and shared LAN VIPs are stripped before kernel application.
func (h *EdgeHAEngine) PrepareSyncedInterface(iface EdgeInterfaceSpec) (EdgeInterfaceSpec, bool) {
	h.mu.RLock()
	role := h.role
	wanDev := h.lastWanDev
	lanDev := h.lastLanDev
	vip4 := h.lastVipV4
	vip6 := h.lastVipV6
	h.mu.RUnlock()

	if role != "standby" {
		return iface, true
	}

	dev := strings.TrimSpace(iface.Device)
	isWan := (wanDev != "" && dev == wanDev) || (wanDev == "" && strings.EqualFold(strings.TrimSpace(iface.Name), "wan"))
	if isWan {
		iface.Enabled = false
	}

	// R4-A-L3: the old `lanDev == "" || dev == lanDev` treated every
	// non-WAN interface as LAN when the LAN device was unknown (the
	// node never went through a Promote/Demote transition), so a VIP
	// on any interface was silently stripped. Require an explicit
	// device match; the only backstop is the interface name itself —
	// Promote creates the VIP interfaces as `lan-vip4`/`lan-vip6`,
	// so a lan-vip-named interface is by definition the LAN VIP
	// interface even when the device name differs across the pair.
	isLan := (lanDev != "" && dev == lanDev) ||
		strings.HasPrefix(strings.ToLower(strings.TrimSpace(iface.Name)), "lan-vip")
	if isLan {
		if sameHAAddrOrCIDR(iface.Address, vip4) || sameHAAddrOrCIDR(iface.Address, vip6) {
			iface.Address = ""
		}
		if sameHAAddrOrCIDR(iface.IPv6Address, vip6) || sameHAAddrOrCIDR(iface.IPv6Address, vip4) {
			iface.IPv6Address = ""
		}
		if iface.Address == "" && iface.IPv6Address == "" &&
			strings.HasPrefix(strings.ToLower(strings.TrimSpace(iface.Name)), "lan-vip") {
			return iface, false
		}
	}

	return iface, true
}

// ApplySyncedInterface applies a hub-pushed EdgeInterfaceSpec while preserving HA standby fencing.
//
// R4-A-L3: the old code returned nil when the interface was dropped
// by fencing, so the hub's SYNC ack claimed success for an interface
// that was never applied. A dropped lan-vip interface is now an
// error, which the SYNC_INTERFACES handler joins into the ack.
func (h *EdgeHAEngine) ApplySyncedInterface(netEngine *EdgeNetworkEngine, iface EdgeInterfaceSpec) error {
	filtered, apply := h.PrepareSyncedInterface(iface)
	if !apply {
		return fmt.Errorf("standby fencing dropped lan-vip interface %q on device %q: shared VIP addresses were stripped and the interface carries no address", iface.Name, iface.Device)
	}
	return netEngine.ConfigureInterface(filtered)
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
