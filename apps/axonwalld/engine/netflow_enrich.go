package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type cachedHostEntry struct {
	name      string
	expiresAt time.Time
}

type threatPrefixEntry struct {
	alias  string
	prefix netip.Prefix
}

type ifAliasKey struct {
	exporterIP string
	ifIndex    uint32
}

type k3sWorkloadInfo struct {
	Namespace   string
	PodName     string
	ServiceName string
	Workload    string
}

type bgpRouteEntry struct {
	Prefix  netip.Prefix
	PeerAs  uint32
	AsPath  []uint32
	NextHop string
}

type natTupleInfo struct {
	PostSrcIP   string
	PostSrcPort uint16
	PostDstIP   string
	PostDstPort uint16
}

type FlowEnricher struct {
	mu             sync.RWMutex
	cfg            NetFlowEnrichmentPayload
	localHost      string
	staticHosts    map[string]string
	keaLeasesHosts map[string]string
	dnsCache       map[string]cachedHostEntry
	ifAliases      map[ifAliasKey]string
	localIfByIndex map[uint32]string
	internalNets   []netip.Prefix
	threatNets     []threatPrefixEntry
	k3sPodPrefix   netip.Prefix
	k3sSvcPrefix   netip.Prefix
	k3sIPMap       map[string]k3sWorkloadInfo
	bgpRoutes      []bgpRouteEntry
	natIndex       map[string]natTupleInfo
	customApps     map[uint16]string
	keaLastRead    time.Time
	keaLeasesPath  string
	lastGeoAutoUpd time.Time

	geoip    *GeoIPManager
	librenms *LibreNMSManager
	netbox   *NetBoxManager
	k3s      *K3sManager

	ptrQueue chan string
}

func NewFlowEnricher(k3s *K3sManager, netbox *NetBoxManager, librenms *LibreNMSManager) *FlowEnricher {
	e := &FlowEnricher{
		staticHosts:    make(map[string]string),
		keaLeasesHosts: make(map[string]string),
		dnsCache:       make(map[string]cachedHostEntry),
		ifAliases:      make(map[ifAliasKey]string),
		localIfByIndex: make(map[uint32]string),
		k3sIPMap:       make(map[string]k3sWorkloadInfo),
		natIndex:       make(map[string]natTupleInfo),
		customApps:     make(map[uint16]string),
		keaLeasesPath:  "/var/lib/kea/kea-leases4.csv",
		geoip:          NewGeoIPManager(),
		librenms:       librenms,
		netbox:         netbox,
		k3s:            k3s,
		ptrQueue:       make(chan string, 512),
	}
	e.refreshLocalInterfaces()
	go e.ptrWorker()
	return e
}

func (e *FlowEnricher) UpdateBundle(b *NetFlowRuntimeBundle) {
	if b == nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.cfg = b.Config.Enrichment
	e.localHost = b.LocalHostname
	e.staticHosts = make(map[string]string)
	for _, sh := range b.StaticHostMap {
		if sh.IP != "" && sh.Hostname != "" {
			e.staticHosts[sh.IP] = sh.Hostname
		}
	}
	e.ifAliases = make(map[ifAliasKey]string)
	for _, ep := range b.Config.ExporterProfiles {
		for idxStr, alias := range ep.IfIndexAliases {
			var idx uint32
			if _, err := fmt.Sscanf(idxStr, "%d", &idx); err == nil && idx > 0 {
				e.ifAliases[ifAliasKey{exporterIP: ep.IP, ifIndex: idx}] = alias
			}
		}
	}
	e.internalNets = nil
	for _, cidr := range b.Config.Enrichment.InternalCidrs {
		if p, err := netip.ParsePrefix(strings.TrimSpace(cidr)); err == nil {
			e.internalNets = append(e.internalNets, p)
		}
	}
	if p, err := netip.ParsePrefix(strings.TrimSpace(b.K3sCidrs.PodCIDR)); err == nil {
		e.k3sPodPrefix = p
	}
	if p, err := netip.ParsePrefix(strings.TrimSpace(b.K3sCidrs.ServiceCIDR)); err == nil {
		e.k3sSvcPrefix = p
	}
	e.threatNets = nil
	for _, th := range b.ThreatCidrs {
		raw := strings.TrimSpace(th.Entry)
		if !strings.Contains(raw, "/") {
			if addr, err := netip.ParseAddr(raw); err == nil {
				bits := 32
				if addr.Is6() {
					bits = 128
				}
				e.threatNets = append(e.threatNets, threatPrefixEntry{
					alias:  th.Alias,
					prefix: netip.PrefixFrom(addr, bits),
				})
			}
		} else if p, err := netip.ParsePrefix(raw); err == nil {
			e.threatNets = append(e.threatNets, threatPrefixEntry{alias: th.Alias, prefix: p})
		}
	}
	e.customApps = make(map[uint16]string)
	for k, v := range b.Config.Enrichment.CustomPortApps {
		var port uint16
		if _, err := fmt.Sscanf(k, "%d", &port); err == nil && port > 0 && strings.TrimSpace(v) != "" {
			e.customApps[port] = strings.TrimSpace(v)
		}
	}
}

func (e *FlowEnricher) refreshLocalInterfaces() {
	ifaces, err := net.Interfaces()
	if err != nil {
		return
	}
	m := make(map[uint32]string, len(ifaces))
	for _, ifc := range ifaces {
		if ifc.Index > 0 {
			m[uint32(ifc.Index)] = ifc.Name
		}
	}
	e.mu.Lock()
	e.localIfByIndex = m
	e.mu.Unlock()
}

func (e *FlowEnricher) RefreshExternalCaches(ctx context.Context) {
	e.refreshLocalInterfaces()
	e.mu.RLock()
	cfg := e.cfg
	e.mu.RUnlock()

	if cfg.KeaDHCPLeases && e.keaLeasesPath != "" {
		if leases := readActiveKeaLeases(e.keaLeasesPath); len(leases) > 0 {
			e.mu.Lock()
			e.keaLeasesHosts = make(map[string]string, len(leases))
			for _, l := range leases {
				ip := strings.Split(l.Address, "/")[0]
				if ip != "" && l.Description != "" {
					e.keaLeasesHosts[ip] = l.Description
				}
			}
			e.keaLastRead = time.Now()
			e.mu.Unlock()
		}
	}

	if cfg.NetBoxInventory && e.netbox != nil {
		subCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		inv := e.netbox.ExportInventory(subCtx)
		cancel()
		if inv != nil && inv.Available {
			e.mu.Lock()
			for _, dev := range inv.Devices {
				ip := strings.Split(dev.PrimaryIP, "/")[0]
				if ip != "" && dev.Name != "" {
					e.staticHosts[ip] = dev.Name
				}
			}
			e.mu.Unlock()
		}
	}

	e.geoip.Refresh(cfg.GeoIPCityDBPath, cfg.GeoIPAsnDBPath)
	if cfg.GeoIPAutoUpdate && (cfg.GeoIPCityDownloadURL != "" || cfg.GeoIPAsnDownloadURL != "") {
		interval := time.Duration(maxInt(1, cfg.GeoIPUpdateIntervalHrs)) * time.Hour
		e.mu.RLock()
		lastAuto := e.lastGeoAutoUpd
		e.mu.RUnlock()
		if lastAuto.IsZero() || time.Since(lastAuto) >= interval {
			e.mu.Lock()
			e.lastGeoAutoUpd = time.Now()
			e.mu.Unlock()
			go func(cURL, aURL, cPath, aPath string) {
				uCtx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
				defer cancel()
				_ = e.geoip.UpdateFromURLs(uCtx, cURL, aURL, cPath, aPath)
			}(cfg.GeoIPCityDownloadURL, cfg.GeoIPAsnDownloadURL, cfg.GeoIPCityDBPath, cfg.GeoIPAsnDBPath)
		}
	}

	if cfg.K3sPodServiceTagging && e.k3s != nil {
		nextK3s := make(map[string]k3sWorkloadInfo)
		subCtx, cancel := context.WithTimeout(ctx, 2500*time.Millisecond)
		podsResp, pErr := e.k3s.ListResources(subCtx, "pods", "", "")
		svcsResp, sErr := e.k3s.ListResources(subCtx, "services", "", "")
		cancel()
		if pErr == nil && podsResp != nil {
			for _, it := range podsResp.Items {
				if ip, _ := it.Summary["podIP"].(string); ip != "" {
					wl := it.OwnerRef
					if wl == "" {
						wl = it.Name
					}
					nextK3s[strings.TrimSpace(ip)] = k3sWorkloadInfo{
						Namespace: it.Namespace,
						PodName:   it.Name,
						Workload:  wl,
					}
				}
			}
		}
		if sErr == nil && svcsResp != nil {
			for _, it := range svcsResp.Items {
				if ip, _ := it.Summary["clusterIP"].(string); ip != "" && ip != "None" {
					nextK3s[strings.TrimSpace(ip)] = k3sWorkloadInfo{
						Namespace:   it.Namespace,
						ServiceName: it.Name,
						Workload:    it.Name,
					}
				}
			}
		}
		if len(nextK3s) > 0 {
			e.mu.Lock()
			e.k3sIPMap = nextK3s
			e.mu.Unlock()
		}
	}

	if cfg.FrrBgpLookup {
		if bin, lerr := exec.LookPath("vtysh"); lerr == nil && bin != "" {
			var combined []bgpRouteEntry
			for _, cmdArg := range []string{"show ip bgp json", "show bgp ipv6 unicast json"} {
				bCtx, bCancel := context.WithTimeout(ctx, 2*time.Second)
				out, oerr := exec.CommandContext(bCtx, bin, "-c", cmdArg).Output()
				bCancel()
				if oerr == nil && len(out) > 0 {
					combined = append(combined, ParseFRRBgpJSON(out)...)
				}
			}
			if len(combined) > 0 {
				sort.Slice(combined, func(i, j int) bool {
					return combined[i].Prefix.Bits() > combined[j].Prefix.Bits()
				})
				e.mu.Lock()
				e.bgpRoutes = combined
				e.mu.Unlock()
			}
		}
	}

	if cfg.LibreNMSIfNames && e.librenms != nil {
		subCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		snap := e.librenms.GetTopologySnapshot(subCtx)
		cancel()
		if snap != nil && snap.Available {
			devIPByID := make(map[int]string)
			for _, d := range snap.Devices {
				if d.IP != "" {
					devIPByID[d.DeviceID] = d.IP
				}
				if d.IP != "" && d.Hostname != "" {
					e.mu.Lock()
					e.staticHosts[d.IP] = d.Hostname
					e.mu.Unlock()
				}
			}
			e.mu.Lock()
			for _, p := range snap.Ports {
				if ip := devIPByID[p.DeviceID]; ip != "" && p.PortID > 0 && p.IfName != "" {
					if _, exists := e.ifAliases[ifAliasKey{exporterIP: ip, ifIndex: uint32(p.PortID)}]; !exists {
						e.ifAliases[ifAliasKey{exporterIP: ip, ifIndex: uint32(p.PortID)}] = p.IfName
					}
				}
			}
			e.mu.Unlock()
		}
	}
}

func (e *FlowEnricher) ptrWorker() {
	for ip := range e.ptrQueue {
		ctx, cancel := context.WithTimeout(context.Background(), 1200*time.Millisecond)
		names, err := net.DefaultResolver.LookupAddr(ctx, ip)
		cancel()
		name := ""
		if err == nil && len(names) > 0 {
			name = strings.TrimSuffix(names[0], ".")
		}
		e.mu.RLock()
		ttlSec := e.cfg.DNSCacheTTLSec
		e.mu.RUnlock()
		if ttlSec <= 0 {
			ttlSec = 3600
		}
		e.mu.Lock()
		e.dnsCache[ip] = cachedHostEntry{
			name:      name,
			expiresAt: time.Now().Add(time.Duration(ttlSec) * time.Second),
		}
		e.mu.Unlock()
	}
}

func (e *FlowEnricher) UpdateConntrackNAT(entries map[string]natTupleInfo) {
	if len(entries) == 0 {
		return
	}
	e.mu.Lock()
	e.natIndex = entries
	e.mu.Unlock()
}

// ParseFRRBgpJSON decodes `vtysh -c "show ip bgp json"` into longest-prefix-first BGP entries.
func ParseFRRBgpJSON(raw []byte) []bgpRouteEntry {
	var doc struct {
		Routes map[string][]struct {
			BestPath bool   `json:"bestpath"`
			Valid    bool   `json:"valid"`
			Path     string `json:"path"`
			Nexthops []struct {
				IP string `json:"ip"`
			} `json:"nexthops"`
		} `json:"routes"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil
	}
	var out []bgpRouteEntry
	for pfxStr, paths := range doc.Routes {
		pfx, err := netip.ParsePrefix(strings.TrimSpace(pfxStr))
		if err != nil || len(paths) == 0 {
			continue
		}
		chosen := paths[0]
		for _, p := range paths {
			if p.BestPath || p.Valid {
				chosen = p
				break
			}
		}
		var asPath []uint32
		for _, tok := range strings.Fields(chosen.Path) {
			if v, err := strconv.ParseUint(strings.Trim(tok, "{},"), 10, 32); err == nil && v > 0 {
				asPath = append(asPath, uint32(v))
			}
		}
		var peerAs uint32
		if len(asPath) > 0 {
			peerAs = asPath[0]
		}
		nextHop := ""
		if len(chosen.Nexthops) > 0 {
			nextHop = chosen.Nexthops[0].IP
		}
		out = append(out, bgpRouteEntry{
			Prefix:  pfx,
			PeerAs:  peerAs,
			AsPath:  asPath,
			NextHop: nextHop,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Prefix.Bits() > out[j].Prefix.Bits()
	})
	return out
}

func (e *FlowEnricher) Enrich(f *FlowRecord) {
	if f == nil {
		return
	}
	e.mu.RLock()
	cfg := e.cfg
	internalNets := e.internalNets
	threatNets := e.threatNets
	k3sPod := e.k3sPodPrefix
	k3sSvc := e.k3sSvcPrefix
	k3sMap := e.k3sIPMap
	bgpRoutes := e.bgpRoutes
	natIdx := e.natIndex
	customApps := e.customApps
	e.mu.RUnlock()

	if f.AppName == "" {
		f.AppName = classifyAppByPort(f.Protocol, f.DstPort, f.SrcPort, customApps)
	}
	if f.InIfName == "" && f.InIfIndex > 0 {
		f.InIfName = e.lookupIfName(f.ExporterIP, f.InIfIndex)
	}
	if f.OutIfName == "" && f.OutIfIndex > 0 {
		f.OutIfName = e.lookupIfName(f.ExporterIP, f.OutIfIndex)
	}

	if f.SrcHost == "" {
		f.SrcHost = e.resolveHost(f.SrcIP, cfg.ReverseDNS)
	}
	if f.DstHost == "" {
		f.DstHost = e.resolveHost(f.DstIP, cfg.ReverseDNS)
	}

	srcAddr, errS := netip.ParseAddr(f.SrcIP)
	dstAddr, errD := netip.ParseAddr(f.DstIP)
	srcInternal := errS == nil && (isInPrefixes(srcAddr, internalNets) || srcAddr.IsPrivate() || srcAddr.IsLoopback())
	dstInternal := errD == nil && (isInPrefixes(dstAddr, internalNets) || dstAddr.IsPrivate() || dstAddr.IsLoopback())

	switch {
	case srcInternal && dstInternal:
		f.Direction = "internal"
	case !srcInternal && dstInternal:
		f.Direction = "ingress"
	case srcInternal && !dstInternal:
		f.Direction = "egress"
	default:
		f.Direction = "transit"
	}

	if cfg.K3sPodServiceTagging {
		if wl, ok := k3sMap[f.SrcIP]; ok {
			f.K3sNamespace = firstNonEmpty(f.K3sNamespace, wl.Namespace)
			f.K3sWorkload = firstNonEmpty(f.K3sWorkload, wl.Workload)
			f.K3sPodName = firstNonEmpty(f.K3sPodName, wl.PodName)
			f.K3sServiceName = firstNonEmpty(f.K3sServiceName, wl.ServiceName)
		} else if wl, ok := k3sMap[f.DstIP]; ok {
			f.K3sNamespace = firstNonEmpty(f.K3sNamespace, wl.Namespace)
			f.K3sWorkload = firstNonEmpty(f.K3sWorkload, wl.Workload)
			f.K3sPodName = firstNonEmpty(f.K3sPodName, wl.PodName)
			f.K3sServiceName = firstNonEmpty(f.K3sServiceName, wl.ServiceName)
		} else if f.K3sNamespace == "" {
			if errS == nil && ((k3sPod.IsValid() && k3sPod.Contains(srcAddr)) || (k3sSvc.IsValid() && k3sSvc.Contains(srcAddr))) {
				f.K3sNamespace = "k3s-pod/svc"
			} else if errD == nil && ((k3sPod.IsValid() && k3sPod.Contains(dstAddr)) || (k3sSvc.IsValid() && k3sSvc.Contains(dstAddr))) {
				f.K3sNamespace = "k3s-pod/svc"
			}
		}
	}

	if cfg.GeoIPAsn {
		if errS == nil && !srcInternal {
			if c, city, lat, lon, ok := e.geoip.LookupCity(srcAddr); ok {
				if f.SrcCountry == "" {
					f.SrcCountry = c
				}
				if f.SrcCity == "" {
					f.SrcCity = city
				}
				if f.SrcLat == 0 && f.SrcLon == 0 {
					f.SrcLat, f.SrcLon = lat, lon
				}
			}
			if asn, org, ok := e.geoip.LookupASN(srcAddr); ok {
				if f.SrcAsn == 0 {
					f.SrcAsn = asn
				}
				if f.SrcOrg == "" {
					f.SrcOrg = org
				}
			}
		}
		if errD == nil && !dstInternal {
			if c, city, lat, lon, ok := e.geoip.LookupCity(dstAddr); ok {
				if f.DstCountry == "" {
					f.DstCountry = c
				}
				if f.DstCity == "" {
					f.DstCity = city
				}
				if f.DstLat == 0 && f.DstLon == 0 {
					f.DstLat, f.DstLon = lat, lon
				}
			}
			if asn, org, ok := e.geoip.LookupASN(dstAddr); ok {
				if f.DstAsn == 0 {
					f.DstAsn = asn
				}
				if f.DstOrg == "" {
					f.DstOrg = org
				}
			}
		}
		if f.SrcCountry == "" && errS == nil {
			f.SrcCountry, f.SrcOrg = classifyGeoAndOrg(srcAddr, srcInternal)
		}
		if f.DstCountry == "" && errD == nil {
			f.DstCountry, f.DstOrg = classifyGeoAndOrg(dstAddr, dstInternal)
		}
	}

	if cfg.FrrBgpLookup && len(bgpRoutes) > 0 && f.PeerAs == 0 {
		targetAddr := dstAddr
		targetValid := errD == nil && !dstInternal
		if !targetValid && errS == nil && !srcInternal {
			targetAddr = srcAddr
			targetValid = true
		}
		if targetValid {
			for _, br := range bgpRoutes {
				if br.Prefix.Contains(targetAddr) {
					f.PeerAs = br.PeerAs
					f.AsPath = br.AsPath
					f.BgpNextHop = br.NextHop
					break
				}
			}
		}
	}

	if cfg.NatConntrackCorrelation && f.PostNatSrcIP == "" && f.PostNatDstIP == "" && len(natIdx) > 0 {
		key := fmt.Sprintf("%d|%s|%d|%s|%d", f.Protocol, f.SrcIP, f.SrcPort, f.DstIP, f.DstPort)
		if nt, ok := natIdx[key]; ok {
			f.PostNatSrcIP = nt.PostSrcIP
			f.PostNatSrcPort = nt.PostSrcPort
			f.PostNatDstIP = nt.PostDstIP
			f.PostNatDstPort = nt.PostDstPort
		}
	}

	if cfg.ThreatIntelMatch && f.ThreatMatch == "" {
		for _, tn := range threatNets {
			if (errS == nil && tn.prefix.Contains(srcAddr)) || (errD == nil && tn.prefix.Contains(dstAddr)) {
				f.ThreatMatch = tn.alias
				break
			}
		}
	}
}

func (e *FlowEnricher) lookupIfName(exporterIP string, ifIndex uint32) string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if alias, ok := e.ifAliases[ifAliasKey{exporterIP: exporterIP, ifIndex: ifIndex}]; ok {
		return alias
	}
	if exporterIP == "127.0.0.1" || exporterIP == "::1" {
		if n, ok := e.localIfByIndex[ifIndex]; ok {
			return n
		}
	}
	if n, ok := e.localIfByIndex[ifIndex]; ok {
		return n
	}
	return fmt.Sprintf("if%d", ifIndex)
}

func (e *FlowEnricher) resolveHost(ip string, reverseDNS bool) string {
	if ip == "" {
		return ""
	}
	e.mu.RLock()
	if h, ok := e.staticHosts[ip]; ok {
		e.mu.RUnlock()
		return h
	}
	if h, ok := e.keaLeasesHosts[ip]; ok {
		e.mu.RUnlock()
		return h
	}
	if ce, ok := e.dnsCache[ip]; ok && time.Now().Before(ce.expiresAt) {
		e.mu.RUnlock()
		return ce.name
	}
	e.mu.RUnlock()

	if reverseDNS {
		select {
		case e.ptrQueue <- ip:
		default:
		}
	}
	return ""
}

func isInPrefixes(addr netip.Addr, list []netip.Prefix) bool {
	for _, p := range list {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

func classifyGeoAndOrg(addr netip.Addr, isInternal bool) (string, string) {
	if isInternal {
		return "LAN", "Private / Internal"
	}
	if addr.Is4() {
		b := addr.As4()
		switch {
		case b[0] == 1 && b[1] == 1 && b[2] == 1:
			return "US", "Cloudflare DNS (AS13335)"
		case b[0] == 8 && (b[1] == 8):
			return "US", "Google DNS (AS15169)"
		case b[0] == 9 && b[1] == 9:
			return "CH", "Quad9 DNS (AS19281)"
		case b[0] == 104 && b[1] >= 16 && b[1] <= 31:
			return "US", "Cloudflare Edge (AS13335)"
		case b[0] == 52 || b[0] == 54 || b[0] == 3:
			return "US", "Amazon AWS (AS16509)"
		case b[0] == 13 && b[1] >= 64:
			return "US", "Microsoft Azure (AS8075)"
		case b[0] == 198 && b[1] == 51 && b[2] == 100:
			return "XX", "TEST-NET-2"
		case b[0] == 203 && b[1] == 0 && b[2] == 113:
			return "XX", "TEST-NET-3"
		}
	}
	return "EXT", "Public Internet"
}

func classifyAppByPort(proto uint8, dstPort, srcPort uint16, custom map[uint16]string) string {
	if proto == 1 {
		return "ICMP"
	}
	if proto == 58 {
		return "ICMPv6"
	}
	if proto == 50 || proto == 51 {
		return "IPsec-ESP"
	}
	if proto == 47 {
		return "GRE"
	}
	for _, p := range []uint16{dstPort, srcPort} {
		if p == 0 {
			continue
		}
		if app, ok := custom[p]; ok {
			return app
		}
	}
	apps := map[uint16]string{
		20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
		53: "DNS", 67: "DHCP", 68: "DHCP", 80: "HTTP", 88: "Kerberos",
		123: "NTP", 137: "NetBIOS", 139: "SMB", 161: "SNMP", 162: "SNMP-Trap",
		179: "BGP", 389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS",
		500: "IKEv2", 514: "Syslog", 587: "SMTP-Sub", 636: "LDAPS",
		853: "DoT", 993: "IMAPS", 1194: "OpenVPN", 1433: "MSSQL",
		1812: "RADIUS", 2049: "NFS", 2055: "NetFlow", 2379: "etcd",
		2966: "Axonwall-API", 3000: "Axonwall-UI", 3260: "iSCSI", 3306: "MariaDB",
		3389: "RDP", 4500: "IPsec-NAT-T", 4739: "IPFIX", 5432: "PostgreSQL",
		5900: "VNC", 6343: "sFlow", 6379: "Redis/Valkey", 6443: "Kubernetes-API",
		8080: "HTTP-Alt", 8123: "ClickHouse-HTTP", 8443: "HTTPS-Alt",
		9000: "ClickHouse", 9090: "Prometheus", 9100: "NodeExporter",
		51820: "WireGuard", 51821: "Headscale-WG",
	}
	if name, ok := apps[dstPort]; ok {
		return name
	}
	if dstPort == 0 && srcPort > 0 {
		if name, ok := apps[srcPort]; ok {
			return name
		}
	}
	if name, ok := apps[srcPort]; ok {
		return name
	}
	if dstPort > 0 {
		return fmt.Sprintf("Port/%d", dstPort)
	}
	return netflowProtocolName(proto)
}

func (e *FlowEnricher) GeoDatabasesPresent() (cityPresent, asnPresent bool) {
	cityLoaded, asnLoaded, _ := e.geoip.Status()
	return cityLoaded, asnLoaded
}

func (e *FlowEnricher) RuntimeStats() (cityLoaded, asnLoaded bool, geoUpdatedAt string, bgpPrefixes, k3sWorkloads int) {
	cityLoaded, asnLoaded, geoUpdatedAt = e.geoip.Status()
	e.mu.RLock()
	bgpPrefixes = len(e.bgpRoutes)
	k3sWorkloads = len(e.k3sIPMap)
	e.mu.RUnlock()
	return cityLoaded, asnLoaded, geoUpdatedAt, bgpPrefixes, k3sWorkloads
}

func (e *FlowEnricher) TriggerGeoIPUpdate(ctx context.Context) error {
	e.mu.RLock()
	cfg := e.cfg
	e.mu.RUnlock()
	return e.geoip.UpdateFromURLs(ctx, cfg.GeoIPCityDownloadURL, cfg.GeoIPAsnDownloadURL, cfg.GeoIPCityDBPath, cfg.GeoIPAsnDBPath)
}
