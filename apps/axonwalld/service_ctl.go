package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/axonwall/axonwall/apps/axonwalld/engine"
)

// serviceCommandTimeout bounds every systemctl/service invocation made
// on behalf of bundle/API callers (A-M2). A hung unit must delay one
// operation, never wedge the agent API forever. Package variable so
// tests can shorten it.
var serviceCommandTimeout = 90 * time.Second

// managedServices is the allowlist of units the daemon may reload,
// restart, or stop on behalf of bundle/API callers (audit D-S03). Before
// this list existed, any name surviving a "/" check reached systemctl as
// argv, so a name like "--all" was parsed as a systemctl OPTION and any
// unit on the box could be bounced by a socket caller.
var managedServices = map[string]bool{
	"suricata": true, "crowdsec": true, "crowdsec-firewall-bouncer": true,
	"kea-dhcp4-server": true, "kea-dhcp6-server": true, "kea-dhcp-ddns-server": true,
	"kea-dhcp4": true, "kea-dhcp6": true, "kea-dhcp-ddns": true,
	"radvd": true, "avahi-daemon": true, "miniupnpd": true,
	"unbound": true, "frr": true, "caddy": true, "headscale": true,
	"keepalived": true, "conntrackd": true, "nftables": true,
	"ssh": true, "sshd": true,
	"slapd": true, "sssd": true, "chrony": true, "chronyd": true,
	"wg-quick@wg0": true, "rosenpass": true,
	"haproxy": true, "freeradius": true, "radiusd": true,
	"openvpn": true, "openvpn@server": true,
	"strongswan": true, "strongswan-starter": true,
	"smbd": true, "smb": true, "nmbd": true, "nmb": true, "wsdd": true, "minio": true,
	"nfs-server": true, "nfs-kernel-server": true, "tgt": true, "rtslib-fb-targetctl": true, "target": true,
	"k3s": true, "k3s-agent": true, "libvirtd": true, "nut-server": true, "nut-monitor": true, "nut-client": true, "snmpd": true,
	"tailscaled": true, "ntopng": true, "eluvix": true,
	"clamav-freshclam": true, "clamav-daemon": true, "vector": true,
	"NetworkManager": true, "systemd-networkd": true, "systemd-resolved": true,
}

var distroServiceAliases = map[string][]string{
	"kea-dhcp4-server":     {"kea-dhcp4-server", "kea-dhcp4"},
	"kea-dhcp4":            {"kea-dhcp4", "kea-dhcp4-server"},
	"kea-dhcp6-server":     {"kea-dhcp6-server", "kea-dhcp6"},
	"kea-dhcp6":            {"kea-dhcp6", "kea-dhcp6-server"},
	"kea-dhcp-ddns-server": {"kea-dhcp-ddns-server", "kea-dhcp-ddns"},
	"kea-dhcp-ddns":        {"kea-dhcp-ddns", "kea-dhcp-ddns-server"},
	"smbd":                 {"smbd", "smb"},
	"smb":                  {"smb", "smbd"},
	"nmbd":                 {"nmbd", "nmb"},
	"nmb":                  {"nmb", "nmbd"},
	"chrony":               {"chrony", "chronyd"},
	"chronyd":              {"chronyd", "chrony"},
	"freeradius":           {"freeradius", "radiusd"},
	"radiusd":              {"radiusd", "freeradius"},
	"ssh":                  {"ssh", "sshd"},
	"sshd":                 {"sshd", "ssh"},
	"nfs-kernel-server":    {"nfs-kernel-server", "nfs-server"},
	"nfs-server":           {"nfs-server", "nfs-kernel-server"},
	"rtslib-fb-targetctl":  {"rtslib-fb-targetctl", "target", "tgt"},
	"target":               {"target", "rtslib-fb-targetctl", "tgt"},
	"tgt":                  {"tgt", "rtslib-fb-targetctl", "target"},
	"nut-client":           {"nut-client", "nut-monitor"},
	"nut-monitor":          {"nut-monitor", "nut-client"},
	"strongswan":           {"strongswan", "strongswan-starter"},
	"strongswan-starter":   {"strongswan-starter", "strongswan"},
}

func isSafeInstanceToken(tok string) bool {
	if tok == "" || len(tok) > 64 {
		return false
	}
	for _, r := range tok {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_') {
			return false
		}
	}
	return true
}

func validServiceName(svc string) bool {
	unit := strings.TrimSuffix(svc, ".service")
	if managedServices[unit] {
		return true
	}
	if strings.HasPrefix(unit, "wg-quick@") && isSafeInstanceToken(strings.TrimPrefix(unit, "wg-quick@")) {
		return true
	}
	if strings.HasPrefix(unit, "openvpn@") && isSafeInstanceToken(strings.TrimPrefix(unit, "openvpn@")) {
		return true
	}
	if strings.HasPrefix(unit, "openvpn-server@") && isSafeInstanceToken(strings.TrimPrefix(unit, "openvpn-server@")) {
		return true
	}
	if strings.HasPrefix(unit, "openvpn-client@") && isSafeInstanceToken(strings.TrimPrefix(unit, "openvpn-client@")) {
		return true
	}
	return false
}

func systemdUnitFileExists(unit string) bool {
	base := strings.TrimSuffix(unit, ".service")
	candidates := []string{base + ".service"}
	if idx := strings.IndexByte(base, '@'); idx >= 0 {
		candidates = append(candidates, base[:idx+1]+".service")
	}
	dirs := []string{
		"/etc/systemd/system",
		"/run/systemd/system",
		"/usr/lib/systemd/system",
		"/lib/systemd/system",
	}
	for _, dir := range dirs {
		for _, c := range candidates {
			if _, err := os.Stat(filepath.Join(dir, c)); err == nil {
				return true
			}
		}
	}
	return false
}

func resolveDistroServiceUnit(svc string) string {
	hasSuffix := strings.HasSuffix(svc, ".service")
	unit := strings.TrimSuffix(svc, ".service")
	if systemdUnitFileExists(unit) {
		return svc
	}
	candidates := distroServiceAliases[unit]
	if engine.DetectOSFamily() == "arch" && len(candidates) > 0 {
		for _, c := range candidates {
			if c != unit && systemdUnitFileExists(c) {
				if hasSuffix {
					return c + ".service"
				}
				return c
			}
		}
	}
	for _, c := range candidates {
		if systemdUnitFileExists(c) {
			if hasSuffix {
				return c + ".service"
			}
			return c
		}
	}
	return svc
}

var openRCServiceAliases = map[string]string{
	"kea-dhcp4-server":     "kea-dhcp4",
	"kea-dhcp6-server":     "kea-dhcp6",
	"kea-dhcp-ddns-server": "kea-dhcp-ddns",
	"ssh":                  "sshd",
	"chrony":               "chronyd",
	"smbd":                 "samba",
	"nmbd":                 "samba",
	"nfs-kernel-server":    "nfs",
	"freeradius":           "radiusd",
}

func resolveOpenRCServiceName(unit string) string {
	base := strings.TrimSuffix(unit, ".service")
	for _, prefix := range []string{"openvpn-client@", "openvpn-server@", "openvpn@"} {
		if strings.HasPrefix(base, prefix) {
			inst := strings.TrimPrefix(base, prefix)
			if isSafeInstanceToken(inst) {
				return "openvpn." + inst
			}
		}
	}
	if strings.HasPrefix(base, "wg-quick@") {
		inst := strings.TrimPrefix(base, "wg-quick@")
		if isSafeInstanceToken(inst) {
			return "wg-quick." + inst
		}
	}
	if candidates, ok := distroServiceAliases[base]; ok {
		for _, c := range candidates {
			if _, err := os.Stat(filepath.Join("/etc/init.d", c)); err == nil {
				return c
			}
		}
	}
	if mapped, ok := openRCServiceAliases[base]; ok {
		return mapped
	}
	return base
}

func hasSystemdOrFakeSystemctl() bool {
	p, err := exec.LookPath("systemctl")
	if err != nil {
		return false
	}
	if engine.IsSystemdRunning() {
		return true
	}
	clean := filepath.Clean(p)
	return clean != "/usr/bin/systemctl" && clean != "/bin/systemctl"
}

func keaHasActiveInterfaces() bool {
	raw, err := os.ReadFile("/etc/kea/kea-dhcp4.conf")
	if err != nil {
		return false
	}
	var parsed struct {
		Dhcp4 struct {
			InterfacesConfig struct {
				Interfaces []string `json:"interfaces"`
			} `json:"interfaces-config"`
		} `json:"Dhcp4"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return false
	}
	return len(parsed.Dhcp4.InterfacesConfig.Interfaces) > 0
}

func keaHasActiveInterfaces6() bool {
	raw, err := os.ReadFile("/etc/kea/kea-dhcp6.conf")
	if err != nil {
		return false
	}
	var parsed struct {
		Dhcp6 struct {
			InterfacesConfig struct {
				Interfaces []string `json:"interfaces"`
			} `json:"interfaces-config"`
		} `json:"Dhcp6"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return false
	}
	return len(parsed.Dhcp6.InterfacesConfig.Interfaces) > 0
}

// wireguardConfDir and dhcpProcRoot are package variables so tests can
// redirect them into temp directories; production defaults are unchanged.
var (
	wireguardConfDir = "/etc/wireguard"
	dhcpProcRoot     = "/proc"
)

func normalizeCIDRList(raw []string) []string {
	seen := make(map[string]bool, len(raw))
	out := make([]string, 0, len(raw))
	for _, entry := range raw {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		ip, ipNet, err := net.ParseCIDR(entry)
		if err != nil || ip == nil || ipNet == nil {
			continue
		}
		ones, _ := ipNet.Mask.Size()
		norm := fmt.Sprintf("%s/%d", ip.String(), ones)
		if !seen[norm] {
			seen[norm] = true
			out = append(out, norm)
		}
	}
	sort.Strings(out)
	return out
}

func parseWireGuardInterfaceAddrAndPort(confData []byte) (cidrs []string, listenPort string) {
	inInterface := false
	var rawAddrs []string
	for _, line := range strings.Split(string(confData), "\n") {
		line = strings.TrimSpace(line)
		if idx := strings.IndexAny(line, "#;"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			inInterface = strings.EqualFold(line, "[Interface]")
			continue
		}
		if !inInterface {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(parts[0]))
		val := strings.TrimSpace(parts[1])
		switch key {
		case "address":
			for _, part := range strings.Split(val, ",") {
				if trimmed := strings.TrimSpace(part); trimmed != "" {
					rawAddrs = append(rawAddrs, trimmed)
				}
			}
		case "listenport":
			listenPort = val
		}
	}
	return normalizeCIDRList(rawAddrs), listenPort
}

func trySyncLiveWireGuard(ctx context.Context, iface string) ([]byte, bool, error) {
	if !isSafeInstanceToken(iface) {
		return nil, false, nil
	}
	wgPath, err := exec.LookPath("wg")
	if err != nil {
		return nil, false, nil
	}
	wgQuickPath, err := exec.LookPath("wg-quick")
	if err != nil {
		return nil, false, nil
	}
	confPath := filepath.Join(wireguardConfDir, iface+".conf")
	confData, err := os.ReadFile(confPath)
	if err != nil {
		return nil, false, nil
	}
	portOut, err := exec.CommandContext(ctx, wgPath, "show", iface, "listen-port").Output()
	if err != nil {
		return nil, false, nil
	}
	livePort := strings.TrimSpace(string(portOut))

	addrOut, err := exec.CommandContext(ctx, "ip", "-j", "addr", "show", "dev", iface).Output()
	if err != nil {
		return nil, false, nil
	}
	trimmedAddr := bytes.TrimSpace(addrOut)
	if len(trimmedAddr) == 0 || trimmedAddr[0] != '[' {
		return nil, false, nil
	}
	var parsedIfaces []ipAddrShowEntry
	if err := json.Unmarshal(trimmedAddr, &parsedIfaces); err != nil {
		return nil, false, nil
	}
	var rawLiveCIDRs []string
	for _, entry := range parsedIfaces {
		for _, a := range entry.AddrInfo {
			if a.Local == "" || a.Scope == "link" || a.Scope == "host" {
				continue
			}
			rawLiveCIDRs = append(rawLiveCIDRs, fmt.Sprintf("%s/%d", a.Local, a.Prefixlen))
		}
	}
	liveCIDRs := normalizeCIDRList(rawLiveCIDRs)
	confCIDRs, confPort := parseWireGuardInterfaceAddrAndPort(confData)

	if confPort != livePort || !slices.Equal(confCIDRs, liveCIDRs) {
		return nil, false, nil
	}

	stripOut, stripErr := exec.CommandContext(ctx, wgQuickPath, "strip", confPath).CombinedOutput()
	if stripErr != nil {
		return stripOut, true, fmt.Errorf("wg-quick strip %s: %w (%s)", iface, stripErr, strings.TrimSpace(string(stripOut)))
	}
	tmpFile, tmpErr := os.CreateTemp("", "axonwall-wg-sync-*")
	if tmpErr != nil {
		return nil, true, fmt.Errorf("wg syncconf temp file for %s: %w", iface, tmpErr)
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)
	if _, wErr := tmpFile.Write(stripOut); wErr != nil {
		_ = tmpFile.Close()
		return nil, true, fmt.Errorf("wg syncconf temp write for %s: %w", iface, wErr)
	}
	_ = tmpFile.Chmod(0600)
	_ = tmpFile.Close()

	syncOut, syncErr := exec.CommandContext(ctx, wgPath, "syncconf", iface, tmpPath).CombinedOutput()
	if syncErr != nil {
		return syncOut, true, fmt.Errorf("wg syncconf %s: %w (%s)", iface, syncErr, strings.TrimSpace(string(syncOut)))
	}
	return syncOut, true, nil
}

func reloadOrRestartService(svc string) ([]byte, error) {
	if !validServiceName(svc) {
		return nil, fmt.Errorf("service %q is not in the managed-services allowlist", svc)
	}
	unit := strings.TrimSuffix(svc, ".service")
	if (unit == "kea-dhcp4-server" || unit == "kea-dhcp4") && !keaHasActiveInterfaces() {
		return stopSystemService(svc)
	}
	if (unit == "kea-dhcp6-server" || unit == "kea-dhcp6") && !keaHasActiveInterfaces6() {
		return stopSystemService(svc)
	}
	resolvedSvc := resolveDistroServiceUnit(svc)
	ctx, cancel := context.WithTimeout(context.Background(), serviceCommandTimeout)
	defer cancel()
	if strings.HasPrefix(unit, "wg-quick@") {
		iface := strings.TrimPrefix(unit, "wg-quick@")
		if out, handled, err := trySyncLiveWireGuard(ctx, iface); handled {
			return out, err
		}
	}
	if hasSystemdOrFakeSystemctl() {
		return exec.CommandContext(ctx, "systemctl", "--no-ask-password", "reload-or-restart", resolvedSvc).CombinedOutput()
	}
	rcUnit := resolveOpenRCServiceName(resolvedSvc)
	if _, err := exec.LookPath("rc-service"); err == nil {
		return exec.CommandContext(ctx, "rc-service", rcUnit, "restart").CombinedOutput()
	}
	return exec.CommandContext(ctx, "service", rcUnit, "restart").CombinedOutput()
}

func stopSystemService(svc string) ([]byte, error) {
	if !validServiceName(svc) {
		return nil, fmt.Errorf("service %q is not in the managed-services allowlist", svc)
	}
	resolvedSvc := resolveDistroServiceUnit(svc)
	ctx, cancel := context.WithTimeout(context.Background(), serviceCommandTimeout)
	defer cancel()
	if hasSystemdOrFakeSystemctl() {
		return exec.CommandContext(ctx, "systemctl", "--no-ask-password", "stop", resolvedSvc).CombinedOutput()
	}
	rcUnit := resolveOpenRCServiceName(resolvedSvc)
	if _, err := exec.LookPath("rc-service"); err == nil {
		return exec.CommandContext(ctx, "rc-service", rcUnit, "stop").CombinedOutput()
	}
	return exec.CommandContext(ctx, "service", rcUnit, "stop").CombinedOutput()
}

// dhcpPidFilesForDev lists the pidfiles a DHCP client for one device
// writes. The daemon-global dhcpcd pidfiles are deliberately NOT in
// this list (M5): a dhcpcd daemon managing any interface at all used
// to make every later DHCP WAN look "already running", so the second
// WAN never got a client.
func dhcpPidFilesForDev(dev string) []string {
	return []string{
		"/var/run/dhclient." + dev + ".pid",
		"/run/dhclient." + dev + ".pid",
		"/var/run/dhcpcd/" + dev + ".pid",
		"/var/run/dhcpcd/" + dev + "-4.pid",
		"/var/run/dhcpcd-" + dev + ".pid",
		"/var/run/dhcpcd-" + dev + "-4.pid",
		"/run/dhcpcd/" + dev + ".pid",
		"/run/dhcpcd/" + dev + "-4.pid",
		"/run/dhcpcd-" + dev + ".pid",
		"/run/dhcpcd-" + dev + "-4.pid",
		"/var/run/udhcpc." + dev + ".pid",
		"/run/udhcpc." + dev + ".pid",
	}
}

// pidBelongsToDhcpClient reports whether pid is a live process whose
// command line names a DHCP client. A pidfile whose pid was recycled
// by an unrelated process must not count as a running client (M5).
// When the command line cannot be read, liveness (signal 0) alone is
// the verdict, matching the old behaviour.
func pidBelongsToDhcpClient(pid int) bool {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	if err := proc.Signal(syscall.Signal(0)); err != nil {
		return false
	}
	cmdline, err := os.ReadFile(filepath.Join(dhcpProcRoot, strconv.Itoa(pid), "cmdline"))
	if err != nil {
		return true
	}
	return strings.Contains(strings.ToLower(string(cmdline)), "dhcp")
}

// dhcpProcessHasNoGateway inspects /proc/<pid>/cmdline to determine whether pid
// is a dhcpcd process and whether it was invoked with -G (no default route).
func dhcpProcessHasNoGateway(pid int) (isDhcpcd bool, hasNoGateway bool) {
	cmdline, err := os.ReadFile(filepath.Join(dhcpProcRoot, strconv.Itoa(pid), "cmdline"))
	if err != nil || len(cmdline) == 0 {
		return false, false
	}
	parts := strings.Split(string(cmdline), "\x00")
	var args []string
	for _, p := range parts {
		if p != "" {
			args = append(args, p)
		}
	}
	if len(args) == 0 {
		return false, false
	}
	for _, a := range args {
		if strings.Contains(strings.ToLower(filepath.Base(a)), "dhcpcd") {
			isDhcpcd = true
			break
		}
	}
	if !isDhcpcd {
		return false, false
	}
	return true, slices.Contains(args, "-G")
}

// dhcpClientRunningForDev reports whether a DHCP client started by
// the system is already alive for dev, based on the clients'
// per-device pidfiles. It is split out from dhcpClientRunning so
// tests can point it at temp pidfiles.
func dhcpClientRunningForDev(dev string, pidFiles []string) bool {
	for _, pidFile := range pidFiles {
		data, err := os.ReadFile(pidFile)
		if err != nil {
			continue
		}
		pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
		if err != nil || pid <= 0 {
			continue
		}
		if pidBelongsToDhcpClient(pid) {
			return true
		}
	}
	return false
}

// dhcpClientRunning reports whether a DHCP client started by the system
// networking path (ifup/dhcpcd, dhclient, udhcpc, or an earlier boot-apply) is
// already alive for dev, based on the clients' per-device pidfiles.
// A running dhcpcd daemon for ANOTHER device does not count: dhcpcd
// is asked to manage a new device with `dhcpcd -4 <dev>` even when
// the daemon already exists (M5).
func dhcpClientRunning(dev string) bool {
	return dhcpClientRunningForDev(dev, dhcpPidFilesForDev(dev))
}

type dhcpLaunchRecord struct {
	role              string
	allowDefaultRoute bool
	startedAt         time.Time
}

type dhcpDevController struct {
	opMu     sync.Mutex
	cancelMu sync.Mutex
	cancel   context.CancelFunc
	done     chan struct{}
}

var (
	dhcpLaunchMu       sync.Mutex
	dhcpRecentLaunch   = make(map[string]dhcpLaunchRecord)
	dhcpDevControllers = make(map[string]*dhcpDevController)
	dhcpRebindWindow   = 5 * time.Second
)

func getDhcpDevController(dev string) *dhcpDevController {
	dhcpLaunchMu.Lock()
	defer dhcpLaunchMu.Unlock()
	ctrl := dhcpDevControllers[dev]
	if ctrl == nil {
		ctrl = &dhcpDevController{}
		dhcpDevControllers[dev] = ctrl
	}
	return ctrl
}

func normalizeDhcpRole(role string) string {
	r := strings.ToLower(strings.TrimSpace(role))
	if r == "" {
		return "wan"
	}
	return r
}

func dhcpClientNeedsRebindForPidFiles(dev, role string, allowDefaultRoute bool, pidFiles []string) bool {
	role = normalizeDhcpRole(role)
	wantNoGateway := !allowDefaultRoute && role != "wan"

	for _, pidFile := range pidFiles {
		data, err := os.ReadFile(pidFile)
		if err != nil {
			continue
		}
		pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
		if err != nil || pid <= 0 || !pidBelongsToDhcpClient(pid) {
			continue
		}
		if isDhcpcd, hasNoGateway := dhcpProcessHasNoGateway(pid); isDhcpcd {
			return hasNoGateway != wantNoGateway
		}
	}

	dhcpLaunchMu.Lock()
	rec, ok := dhcpRecentLaunch[dev]
	dhcpLaunchMu.Unlock()
	if ok {
		recNoGateway := !rec.allowDefaultRoute && rec.role != "wan"
		return recNoGateway != wantNoGateway || rec.role != role
	}
	return false
}

func dhcpClientNeedsRebind(dev, role string, allowDefaultRoute bool) bool {
	return dhcpClientNeedsRebindForPidFiles(dev, role, allowDefaultRoute, dhcpPidFilesForDev(dev))
}

func cancelDhcpLaunch(ctrl *dhcpDevController) {
	ctrl.cancelMu.Lock()
	prevCancel := ctrl.cancel
	prevDone := ctrl.done
	ctrl.cancel = nil
	ctrl.done = nil
	ctrl.cancelMu.Unlock()

	if prevCancel != nil {
		prevCancel()
	}
	if prevDone != nil {
		<-prevDone
	}
}

func startDhcpClientProcess(dev, role string, allowDefaultRoute bool) {
	if !isValidNetdev(dev) {
		return
	}
	ctrl := getDhcpDevController(dev)
	ctrl.opMu.Lock()
	defer ctrl.opMu.Unlock()
	startDhcpClientProcessLocked(ctrl, dev, role, allowDefaultRoute)
}

func startDhcpClientProcessLocked(ctrl *dhcpDevController, dev, role string, allowDefaultRoute bool) {
	role = normalizeDhcpRole(role)
	cancelDhcpLaunch(ctrl)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	ctrl.cancelMu.Lock()
	ctrl.cancel = cancel
	ctrl.done = done
	ctrl.cancelMu.Unlock()

	dhcpLaunchMu.Lock()
	dhcpRecentLaunch[dev] = dhcpLaunchRecord{
		role:              role,
		allowDefaultRoute: allowDefaultRoute,
		startedAt:         time.Now(),
	}
	dhcpLaunchMu.Unlock()

	useNoGateway := !allowDefaultRoute && role != "wan"

	go func() {
		defer close(done)
		defer cancel()
		if dhcpcdPath, err := exec.LookPath("dhcpcd"); err == nil {
			var cmd *exec.Cmd
			if useNoGateway {
				cmd = exec.CommandContext(ctx, dhcpcdPath, "-4", "-G", "-C", "resolv.conf", dev)
			} else {
				cmd = exec.CommandContext(ctx, dhcpcdPath, "-4", dev)
			}
			cmd.WaitDelay = 500 * time.Millisecond
			_ = cmd.Run()
		} else if dhclientPath, err := exec.LookPath("dhclient"); err == nil {
			cmd := exec.CommandContext(ctx, dhclientPath, "-1", "-v", "-pf", "/run/dhclient."+dev+".pid", dev)
			cmd.WaitDelay = 500 * time.Millisecond
			_ = cmd.Run()
		}
		if ctx.Err() != nil {
			return
		}
		// After DHCP client negotiates lease, re-reconcile static routes
		if err := ReconcileStaticRoutes(); err != nil {
			log.Printf("[Agent] Post-DHCP static route reconciliation: %v", err)
		}
	}()
}

// stopDhcpClient stops the running DHCP daemon for dev cleanly without sending
// a DHCPRELEASE packet (`dhcpcd -x`), preserving the upstream ISP lease across
// unconfirmed Commit-Confirm applies and rollbacks.
func stopDhcpClient(dev string) {
	if !isValidNetdev(dev) {
		return
	}
	ctrl := getDhcpDevController(dev)
	ctrl.opMu.Lock()
	defer ctrl.opMu.Unlock()
	stopDhcpClientLocked(ctrl, dev)
}

func stopDhcpClientLocked(ctrl *dhcpDevController, dev string) {
	cancelDhcpLaunch(ctrl)

	dhcpLaunchMu.Lock()
	delete(dhcpRecentLaunch, dev)
	dhcpLaunchMu.Unlock()

	if dhcpcdPath, err := exec.LookPath("dhcpcd"); err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		cmd := exec.CommandContext(ctx, dhcpcdPath, "-x", dev)
		cmd.WaitDelay = 500 * time.Millisecond
		_ = cmd.Run()
		cancel()
	}
	for _, pidFile := range []string{
		"/var/run/dhclient." + dev + ".pid",
		"/run/dhclient." + dev + ".pid",
		"/var/run/udhcpc." + dev + ".pid",
		"/run/udhcpc." + dev + ".pid",
	} {
		data, err := os.ReadFile(pidFile)
		if err != nil {
			continue
		}
		pid, pErr := strconv.Atoi(strings.TrimSpace(string(data)))
		if pErr == nil && pid > 0 && pidBelongsToDhcpClient(pid) {
			if proc, fErr := os.FindProcess(pid); fErr == nil {
				_ = proc.Signal(syscall.SIGTERM)
			}
		}
	}
}

func triggerDhcpClient(dev, role string, allowDefaultRoute bool) {
	if !isValidNetdev(dev) {
		return
	}
	role = normalizeDhcpRole(role)
	ctrl := getDhcpDevController(dev)
	ctrl.opMu.Lock()
	defer ctrl.opMu.Unlock()

	needsRebind := dhcpClientNeedsRebind(dev, role, allowDefaultRoute)
	if !needsRebind {
		dhcpLaunchMu.Lock()
		rec, recentlyLaunched := dhcpRecentLaunch[dev]
		dhcpLaunchMu.Unlock()
		if recentlyLaunched && rec.role == role && rec.allowDefaultRoute == allowDefaultRoute && time.Since(rec.startedAt) < dhcpRebindWindow {
			return
		}
		if dhcpClientRunning(dev) {
			log.Printf("[Agent] DHCP client already running on %s; not starting another", dev)
			return
		}
	} else if dhcpClientRunning(dev) {
		stopDhcpClientLocked(ctrl, dev)
	}
	startDhcpClientProcessLocked(ctrl, dev, role, allowDefaultRoute)
}

// rebindOrStartDhcpClient forces DHCP acquisition/rebind for dev under the
// requested role and default-route policy, replacing any running DHCP client
// (whose -G / resolv.conf flags may reflect a previous role or topology) while
// deduplicating rapid back-to-back calls with identical effective options.
func rebindOrStartDhcpClient(dev, role string, allowDefaultRoute bool) {
	if !isValidNetdev(dev) {
		return
	}
	role = normalizeDhcpRole(role)
	ctrl := getDhcpDevController(dev)
	ctrl.opMu.Lock()
	defer ctrl.opMu.Unlock()

	needsRebind := dhcpClientNeedsRebind(dev, role, allowDefaultRoute)
	if !needsRebind {
		dhcpLaunchMu.Lock()
		rec, recentlyLaunched := dhcpRecentLaunch[dev]
		dhcpLaunchMu.Unlock()
		if recentlyLaunched && rec.role == role && rec.allowDefaultRoute == allowDefaultRoute && time.Since(rec.startedAt) < dhcpRebindWindow {
			return
		}
	}

	if dhcpClientRunning(dev) {
		stopDhcpClientLocked(ctrl, dev)
	}
	startDhcpClientProcessLocked(ctrl, dev, role, allowDefaultRoute)
}

func releaseDhcpLease(dev string) {
	if !isValidNetdev(dev) {
		return
	}
	ctrl := getDhcpDevController(dev)
	ctrl.opMu.Lock()
	defer ctrl.opMu.Unlock()

	cancelDhcpLaunch(ctrl)

	dhcpLaunchMu.Lock()
	delete(dhcpRecentLaunch, dev)
	dhcpLaunchMu.Unlock()
	if dhcpcdPath, err := exec.LookPath("dhcpcd"); err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = exec.CommandContext(ctx, dhcpcdPath, "-k", dev).Run()
		_ = exec.CommandContext(ctx, dhcpcdPath, "-x", dev).Run()
		cancel()
	}
	if dhclientPath, err := exec.LookPath("dhclient"); err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = exec.CommandContext(ctx, dhclientPath, "-r", dev).Run()
		cancel()
	}
}
