package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/axonwall/axonwall/apps/axonwalld/engine"
)

// LiveNetAddrSnapshot records one IPv4 address present on a kernel interface
// before a candidate bundle is applied.
type LiveNetAddrSnapshot struct {
	CIDR      string `json:"cidr"`
	Dynamic   bool   `json:"dynamic,omitempty"`
	Secondary bool   `json:"secondary,omitempty"`
}

// LiveNetIfaceSnapshot records the kernel link state, addresses, and DHCP
// client status of one physical/logical device prior to an apply.
type LiveNetIfaceSnapshot struct {
	Device      string                `json:"device"`
	IsUp        bool                  `json:"isUp"`
	Addresses   []LiveNetAddrSnapshot `json:"addresses,omitempty"`
	DhcpRunning bool                  `json:"dhcpRunning,omitempty"`
	Role        string                `json:"role,omitempty"`
}

// LiveRouteNexthop records one nexthop of an ECMP / multipath default route.
type LiveRouteNexthop struct {
	Gateway string `json:"gateway,omitempty"`
	Device  string `json:"device"`
	Weight  int    `json:"weight,omitempty"`
}

// LiveDefaultRoute records one IPv4 default route active prior to an apply.
type LiveDefaultRoute struct {
	Gateway  string             `json:"gateway,omitempty"`
	Device   string             `json:"device"`
	Metric   int                `json:"metric,omitempty"`
	Protocol string             `json:"protocol,omitempty"`
	Nexthops []LiveRouteNexthop `json:"nexthops,omitempty"`
}

// LiveNetSnapshot captures live kernel IPv4 addressing, link-up state, DHCP
// client ownership, and default routes before an unconfirmed bundle runs.
type LiveNetSnapshot struct {
	CapturedAt    string                 `json:"capturedAt"`
	Interfaces    []LiveNetIfaceSnapshot `json:"interfaces"`
	DefaultRoutes []LiveDefaultRoute     `json:"defaultRoutes,omitempty"`
}

// ExternalFileEntry records one bundle-managed file outside /etc/axonwall
// (e.g. /etc/network/interfaces, /etc/kea/kea-dhcp4.conf, unbound drop-ins).
type ExternalFileEntry struct {
	Path       string `json:"path"`
	Existed    bool   `json:"existed"`
	Mode       uint32 `json:"mode,omitempty"`
	BackupName string `json:"backupName,omitempty"`
}

// ExternalBundleMeta is the persisted rollback manifest for external files and
// service reloads triggered by an unconfirmed bundle.
type ExternalBundleMeta struct {
	Files          []ExternalFileEntry `json:"files,omitempty"`
	ReloadServices []string            `json:"reloadServices,omitempty"`
}

type ipAddrShowEntry struct {
	Ifname   string   `json:"ifname"`
	Flags    []string `json:"flags"`
	AddrInfo []struct {
		Family    string `json:"family"`
		Local     string `json:"local"`
		Prefixlen int    `json:"prefixlen"`
		Scope     string `json:"scope"`
		Dynamic   bool   `json:"dynamic"`
		Secondary bool   `json:"secondary"`
	} `json:"addr_info"`
}

type ipRouteShowEntry struct {
	Dst      string `json:"dst"`
	Gateway  string `json:"gateway"`
	Dev      string `json:"dev"`
	Metric   int    `json:"metric"`
	Protocol string `json:"protocol"`
	Nexthops []struct {
		Gateway string `json:"gateway"`
		Dev     string `json:"dev"`
		Weight  int    `json:"weight"`
	} `json:"nexthops,omitempty"`
}

var dynamicVirtualIfacePrefixes = []string{
	"tailscale",
	"wg",
	"veth",
	"tap",
	"cni",
	"flannel",
	"cilium",
	"lxc",
	"docker",
	"virbr",
	"vmbr",
	"tun",
	"ovpn",
	"xfrm",
	"ifb_",
	"kube-ipvs",
	"nodelocaldns",
	"br-",
}

// isDynamicVirtualIface reports whether dev is a runtime overlay/VPN/container/VM
// virtual interface whose lifecycle is managed outside interfaces.yaml and must
// not be torn down by generic IPv4 rollback.
func isDynamicVirtualIface(dev string) bool {
	lower := strings.ToLower(strings.TrimSpace(dev))
	for _, prefix := range dynamicVirtualIfacePrefixes {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	return false
}

func liveNetSnapshotPath(bundleDir string) string {
	return filepath.Join(bundleDir, "lkg-net-snapshot.json")
}

func externalBundleDir(bundleDir string) string {
	return filepath.Join(bundleDir, "lkg-external")
}

func externalBundleMetaPath(bundleDir string) string {
	return filepath.Join(externalBundleDir(bundleDir), "meta.json")
}

func readBootDeviceRoles() map[string]string {
	roles := make(map[string]string)
	config := make(map[string]string)
	if data, err := os.ReadFile(filepath.Join(axonwallEtcDir(), "interfaces.conf")); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "#") || !strings.Contains(line, "=") {
				continue
			}
			parts := strings.SplitN(line, "=", 2)
			config[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	for _, spec := range loadAllBootInterfaces(config) {
		if spec.Device != "" && spec.Role != "" {
			roles[spec.Device] = spec.Role
		}
	}
	return roles
}

// readLiveNetState queries `ip -j -4` for live interfaces and default routes.
// Returns (nil, false) cleanly when `ip -j` prints empty/non-JSON output (such
// as under minimal test fakes).
func readLiveNetState() (*LiveNetSnapshot, bool) {
	addrOut, err := exec.Command("ip", "-j", "-4", "addr", "show").Output()
	if err != nil {
		return nil, false
	}
	trimmed := bytes.TrimSpace(addrOut)
	if len(trimmed) == 0 || trimmed[0] != '[' {
		return nil, false
	}
	var rawIfaces []ipAddrShowEntry
	if err := json.Unmarshal(trimmed, &rawIfaces); err != nil {
		return nil, false
	}

	var defaultRoutes []LiveDefaultRoute
	defaultRouteDevs := make(map[string]bool)
	if routeOut, rErr := exec.Command("ip", "-j", "-4", "route", "show", "default").Output(); rErr == nil {
		routeTrimmed := bytes.TrimSpace(routeOut)
		if len(routeTrimmed) > 0 && routeTrimmed[0] == '[' {
			var rawRoutes []ipRouteShowEntry
			if json.Unmarshal(routeTrimmed, &rawRoutes) == nil {
				for _, r := range rawRoutes {
					if len(r.Nexthops) > 0 {
						var hops []LiveRouteNexthop
						for _, nh := range r.Nexthops {
							nhDev := strings.TrimSpace(nh.Dev)
							nhGw := strings.TrimSpace(nh.Gateway)
							if nhDev == "" || !isValidNetdev(nhDev) {
								continue
							}
							if nhGw != "" && net.ParseIP(nhGw) == nil {
								continue
							}
							hops = append(hops, LiveRouteNexthop{
								Gateway: nhGw,
								Device:  nhDev,
								Weight:  nh.Weight,
							})
							defaultRouteDevs[nhDev] = true
						}
						if len(hops) > 0 {
							defaultRoutes = append(defaultRoutes, LiveDefaultRoute{
								Metric:   r.Metric,
								Protocol: strings.TrimSpace(r.Protocol),
								Nexthops: hops,
							})
						}
						continue
					}
					dev := strings.TrimSpace(r.Dev)
					gw := strings.TrimSpace(r.Gateway)
					if dev == "" || !isValidNetdev(dev) {
						continue
					}
					if gw != "" && net.ParseIP(gw) == nil {
						continue
					}
					defaultRoutes = append(defaultRoutes, LiveDefaultRoute{
						Gateway:  gw,
						Device:   dev,
						Metric:   r.Metric,
						Protocol: strings.TrimSpace(r.Protocol),
					})
					defaultRouteDevs[dev] = true
				}
			}
		}
	}

	devRoles := readBootDeviceRoles()
	snap := &LiveNetSnapshot{
		CapturedAt:    time.Now().UTC().Format(time.RFC3339),
		Interfaces:    make([]LiveNetIfaceSnapshot, 0, len(rawIfaces)),
		DefaultRoutes: defaultRoutes,
	}

	for _, raw := range rawIfaces {
		dev := strings.TrimSpace(raw.Ifname)
		if dev == "" || dev == "lo" || !isValidNetdev(dev) || isExternallyManagedHostIface(dev) || isDynamicVirtualIface(dev) {
			continue
		}
		role := devRoles[dev]
		if role == "" && defaultRouteDevs[dev] {
			role = "wan"
		}
		var addrs []LiveNetAddrSnapshot
		for _, a := range raw.AddrInfo {
			if a.Family != "inet" || a.Local == "" || a.Scope == "host" || a.Scope == "link" {
				continue
			}
			addrs = append(addrs, LiveNetAddrSnapshot{
				CIDR:      fmt.Sprintf("%s/%d", a.Local, a.Prefixlen),
				Dynamic:   a.Dynamic,
				Secondary: a.Secondary,
			})
		}
		snap.Interfaces = append(snap.Interfaces, LiveNetIfaceSnapshot{
			Device:      dev,
			IsUp:        slices.Contains(raw.Flags, "UP"),
			Addresses:   addrs,
			DhcpRunning: dhcpClientRunning(dev),
			Role:        role,
		})
	}

	return snap, true
}

func captureLiveNetSnapshot(bundleDir string) {
	if currentRuntimeMode == engine.ModeDev {
		return
	}
	snap, ok := readLiveNetState()
	if !ok {
		return
	}
	if err := os.MkdirAll(bundleDir, 0700); err != nil {
		return
	}
	data, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return
	}
	_ = os.WriteFile(liveNetSnapshotPath(bundleDir), data, 0600)
}

func defaultRouteKey(r LiveDefaultRoute) string {
	if len(r.Nexthops) > 0 {
		parts := make([]string, 0, len(r.Nexthops))
		for _, nh := range r.Nexthops {
			w := nh.Weight
			if w <= 0 {
				w = 1
			}
			parts = append(parts, fmt.Sprintf("%s|%s|%d", nh.Gateway, nh.Device, w))
		}
		return fmt.Sprintf("mp:%s|m=%d", strings.Join(parts, ","), r.Metric)
	}
	return fmt.Sprintf("%s|%s|m=%d", r.Gateway, r.Device, r.Metric)
}

func buildDefaultRouteArgs(verb string, r LiveDefaultRoute) []string {
	args := []string{"route", verb, "default"}
	if len(r.Nexthops) > 0 {
		for _, nh := range r.Nexthops {
			args = append(args, "nexthop")
			if nh.Gateway != "" {
				args = append(args, "via", nh.Gateway)
			}
			args = append(args, "dev", nh.Device)
			if nh.Weight > 0 {
				args = append(args, "weight", fmt.Sprintf("%d", nh.Weight))
			}
		}
	} else {
		if r.Gateway != "" {
			args = append(args, "via", r.Gateway)
		}
		args = append(args, "dev", r.Device)
	}
	if r.Metric > 0 {
		args = append(args, "metric", fmt.Sprintf("%d", r.Metric))
	}
	return args
}

func restoreLiveNetSnapshot(bundleDir string) bool {
	if currentRuntimeMode == engine.ModeDev {
		return false
	}
	data, err := os.ReadFile(liveNetSnapshotPath(bundleDir))
	if err != nil || len(data) == 0 {
		return false
	}
	var snapshot LiveNetSnapshot
	if err := json.Unmarshal(data, &snapshot); err != nil {
		return false
	}
	current, ok := readLiveNetState()
	if !ok {
		return false
	}

	restoredRoles := readBootDeviceRoles()
	snapByDev := make(map[string]LiveNetIfaceSnapshot, len(snapshot.Interfaces))
	for _, ifc := range snapshot.Interfaces {
		snapByDev[ifc.Device] = ifc
	}
	curByDev := make(map[string]LiveNetIfaceSnapshot, len(current.Interfaces))
	for _, ifc := range current.Interfaces {
		curByDev[ifc.Device] = ifc
	}

	// Phase A: remove any non-secondary IPv4 addresses added after the snapshot
	// and bring down any device that was down/unassigned before the apply.
	// Never touch dynamic virtual/overlay/container interfaces (Tailscale, WG, K3s veth/CNI, VM taps).
	for _, cur := range current.Interfaces {
		if isDynamicVirtualIface(cur.Device) {
			continue
		}
		snap, existed := snapByDev[cur.Device]
		snapAddrs := make(map[string]bool, len(snap.Addresses))
		for _, a := range snap.Addresses {
			snapAddrs[a.CIDR] = true
		}
		for _, addr := range cur.Addresses {
			if addr.Secondary || snapAddrs[addr.CIDR] {
				continue
			}
			if out, err := exec.Command("ip", "addr", "del", addr.CIDR, "dev", cur.Device).CombinedOutput(); err != nil {
				log.Printf("[Agent] Rollback: failed to remove added address %s on %s: %v (%s)", addr.CIDR, cur.Device, err, strings.TrimSpace(string(out)))
			}
		}
		if !existed || !snap.DhcpRunning {
			if dhcpClientRunning(cur.Device) {
				stopDhcpClient(cur.Device)
			}
		}
		if !existed || !snap.IsUp {
			if cur.IsUp {
				if dhcpClientRunning(cur.Device) {
					stopDhcpClient(cur.Device)
				}
				if out, err := exec.Command("ip", "link", "set", cur.Device, "down").CombinedOutput(); err != nil {
					log.Printf("[Agent] Rollback: failed to bring down %s: %v (%s)", cur.Device, err, strings.TrimSpace(string(out)))
				}
			}
		}
	}

	// Phase B: restore pre-apply link UP state, static IPs, and DHCP clients.
	for _, snap := range snapshot.Interfaces {
		if snap.IsUp {
			_ = exec.Command("ip", "link", "set", snap.Device, "up").Run()
		}
		cur := curByDev[snap.Device]
		curAddrs := make(map[string]bool, len(cur.Addresses))
		for _, a := range cur.Addresses {
			curAddrs[a.CIDR] = true
		}
		missingDynamic := false
		for _, addr := range snap.Addresses {
			if addr.Secondary {
				continue
			}
			if addr.Dynamic {
				if !curAddrs[addr.CIDR] {
					missingDynamic = true
				}
				continue
			}
			if !curAddrs[addr.CIDR] {
				if out, err := exec.Command("ip", "addr", "replace", addr.CIDR, "dev", snap.Device).CombinedOutput(); err != nil {
					log.Printf("[Agent] Rollback: failed to restore static address %s on %s: %v (%s)", addr.CIDR, snap.Device, err, strings.TrimSpace(string(out)))
				}
			}
		}
		if snap.DhcpRunning && (!dhcpClientRunning(snap.Device) || missingDynamic) {
			role := restoredRoles[snap.Device]
			if role == "" {
				role = snap.Role
			}
			if role == "" {
				role = "lan"
			}
			rebindOrStartDhcpClient(snap.Device, role)
		}
	}

	// Phase C: delete newly added default routes and restore pre-apply default routes.
	snapRoutes := make(map[string]bool, len(snapshot.DefaultRoutes))
	for _, r := range snapshot.DefaultRoutes {
		snapRoutes[defaultRouteKey(r)] = true
	}
	curRoutes := make(map[string]bool, len(current.DefaultRoutes))
	for _, r := range current.DefaultRoutes {
		curRoutes[defaultRouteKey(r)] = true
	}

	for _, curRoute := range current.DefaultRoutes {
		if snapRoutes[defaultRouteKey(curRoute)] {
			continue
		}
		args := buildDefaultRouteArgs("del", curRoute)
		if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			log.Printf("[Agent] Rollback: failed to delete added default route (%v): %v (%s)", args, err, strings.TrimSpace(string(out)))
		}
	}
	for _, snapRoute := range snapshot.DefaultRoutes {
		if curRoutes[defaultRouteKey(snapRoute)] {
			continue
		}
		args := buildDefaultRouteArgs("replace", snapRoute)
		if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			log.Printf("[Agent] Rollback: failed to restore default route (%v): %v (%s)", args, err, strings.TrimSpace(string(out)))
		}
	}

	return true
}

func isCoveredByLkgConfigSnapshot(cleanPath string) bool {
	if !isSnapshotEligibleName(filepath.Base(cleanPath)) {
		return false
	}
	if cleanPath == "/etc/axonwall" || strings.HasPrefix(cleanPath, "/etc/axonwall/") {
		return true
	}
	for _, dir := range append(append([]string(nil), lkgConfigSrcDirs...), lkgConfigDstDirs...) {
		d := filepath.Clean(dir)
		if d == "/" || d == "." {
			continue
		}
		if cleanPath == d || strings.HasPrefix(cleanPath, d+"/") {
			return true
		}
	}
	return false
}

func loadExternalBundleMeta(bundleDir string) ExternalBundleMeta {
	var meta ExternalBundleMeta
	if data, err := os.ReadFile(externalBundleMetaPath(bundleDir)); err == nil && len(data) > 0 {
		_ = json.Unmarshal(data, &meta)
	}
	return meta
}

func saveExternalBundleMeta(bundleDir string, meta ExternalBundleMeta) error {
	if err := os.MkdirAll(externalBundleDir(bundleDir), 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(externalBundleMetaPath(bundleDir), data, 0600)
}

func snapshotExternalBundleFiles(bundleDir string, validatedFiles []validatedBundleFile, mergeIntoExisting bool) {
	extDir := externalBundleDir(bundleDir)
	if !mergeIntoExisting {
		_ = os.RemoveAll(extDir)
	}
	if err := os.MkdirAll(extDir, 0700); err != nil {
		return
	}

	var meta ExternalBundleMeta
	if mergeIntoExisting {
		meta = loadExternalBundleMeta(bundleDir)
	}

	recorded := make(map[string]bool, len(meta.Files))
	for _, entry := range meta.Files {
		recorded[entry.Path] = true
	}

	for _, vf := range validatedFiles {
		if isCoveredByLkgConfigSnapshot(vf.cleanPath) || recorded[vf.cleanPath] {
			continue
		}
		recorded[vf.cleanPath] = true
		fi, err := os.Lstat(vf.cleanPath)
		if err != nil {
			if os.IsNotExist(err) {
				meta.Files = append(meta.Files, ExternalFileEntry{
					Path:    vf.cleanPath,
					Existed: false,
				})
			}
			continue
		}
		if (fi.Mode()&os.ModeSymlink) != 0 || fi.IsDir() {
			continue
		}
		data, rErr := os.ReadFile(vf.cleanPath)
		if rErr != nil {
			continue
		}
		backupName := fmt.Sprintf("file-%d.bak", len(meta.Files))
		if wErr := os.WriteFile(filepath.Join(extDir, backupName), data, 0600); wErr != nil {
			continue
		}
		meta.Files = append(meta.Files, ExternalFileEntry{
			Path:       vf.cleanPath,
			Existed:    true,
			Mode:       uint32(fi.Mode().Perm()),
			BackupName: backupName,
		})
	}

	_ = saveExternalBundleMeta(bundleDir, meta)
}

func recordPendingReloadServices(bundleDir string, services []string) {
	if len(services) == 0 {
		return
	}
	meta := loadExternalBundleMeta(bundleDir)
	seen := make(map[string]bool, len(meta.ReloadServices))
	for _, svc := range meta.ReloadServices {
		if svc != "" {
			seen[svc] = true
		}
	}
	for _, svc := range services {
		svc = strings.TrimSpace(svc)
		if svc != "" && !seen[svc] {
			seen[svc] = true
			meta.ReloadServices = append(meta.ReloadServices, svc)
		}
	}
	_ = saveExternalBundleMeta(bundleDir, meta)
}

func restoreExternalBundleFiles(bundleDir string) ([]string, bool) {
	metaPath := externalBundleMetaPath(bundleDir)
	data, err := os.ReadFile(metaPath)
	if err != nil || len(data) == 0 {
		return nil, false
	}
	var meta ExternalBundleMeta
	if err := json.Unmarshal(data, &meta); err != nil {
		return nil, false
	}

	extDir := externalBundleDir(bundleDir)
	for _, entry := range meta.Files {
		if fi, lerr := os.Lstat(entry.Path); lerr == nil && (fi.Mode()&os.ModeSymlink) != 0 {
			continue
		}
		if !entry.Existed {
			if err := os.Remove(entry.Path); err != nil && !os.IsNotExist(err) {
				log.Printf("[Agent] Rollback: failed to remove added file %s: %v", entry.Path, err)
			}
			continue
		}
		if entry.BackupName == "" {
			continue
		}
		backupData, rErr := os.ReadFile(filepath.Join(extDir, entry.BackupName))
		if rErr != nil {
			log.Printf("[Agent] Rollback: failed to read backup for %s: %v", entry.Path, rErr)
			continue
		}
		mode := os.FileMode(entry.Mode).Perm()
		if mode == 0 {
			mode = 0644
		}
		_ = os.MkdirAll(filepath.Dir(entry.Path), 0755)
		f, oErr := os.OpenFile(entry.Path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|syscall.O_NOFOLLOW, mode)
		if oErr != nil {
			log.Printf("[Agent] Rollback: failed to restore %s: %v", entry.Path, oErr)
			continue
		}
		if _, wErr := f.Write(backupData); wErr != nil {
			_ = f.Close()
			log.Printf("[Agent] Rollback: failed writing restored %s: %v", entry.Path, wErr)
			continue
		}
		_ = f.Chmod(mode)
		_ = f.Close()
	}

	return meta.ReloadServices, true
}

func clearPendingRollbackSnapshots(bundleDir string) {
	_ = os.Remove(liveNetSnapshotPath(bundleDir))
	_ = os.RemoveAll(externalBundleDir(bundleDir))
}
