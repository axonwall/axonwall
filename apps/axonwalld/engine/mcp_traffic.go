package engine

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// unboundMcpSinkholePath and unboundControlBinary are vars (not
	// consts) so tests can redirect the sinkhole config and reload
	// command; the production values are unchanged.
	unboundControlBinary = "unbound-control"
)

var unboundMcpSinkholePath = "/etc/unbound/unbound.conf.d/mcp-sinkhole.conf"

// mcpStateFilePath is a var (not a const) so tests can redirect persisted
// lease state into a temp dir; the production value is unchanged.
var mcpStateFilePath = "/var/lib/axonwall/mcp-tactical-state.json"

var safeIfaceRegex = regexp.MustCompile(`^[a-zA-Z0-9_.-]{1,15}$`)

// McpAuditMeta holds the AI agent justification and threat provenance for an action.
type McpAuditMeta struct {
	Reason           string  `json:"reason"`
	IncidentID       string  `json:"incidentId,omitempty"`
	MitreTechniqueID string  `json:"mitreTechniqueId,omitempty"`
	Confidence       float64 `json:"confidence,omitempty"`
}

// McpTacticalLease represents a single active, TTL-bounded kernel traffic control rule created via MCP.
type McpTacticalLease struct {
	ID               string                 `json:"id"`
	Kind             string                 `json:"kind"` // "blackhole" | "shape" | "redirect" | "dns_sinkhole"
	CreatedAt        string                 `json:"createdAt"`
	ExpiresAt        string                 `json:"expiresAt"`
	TTLSeconds       int                    `json:"ttlSeconds"`
	CreatedByKeyID   string                 `json:"createdByKeyId"`
	CreatedByKeyName string                 `json:"createdByKeyName"`
	TargetSummary    string                 `json:"targetSummary"`
	Parameters       map[string]interface{} `json:"parameters"`
	Audit            McpAuditMeta           `json:"audit"`
	// Internal kernel tracking fields
	ClassID          int    `json:"classId,omitempty"`
	FwMark           int    `json:"fwMark,omitempty"`
	NormalizedTarget string `json:"normalizedTarget,omitempty"`
	IsIPv6           bool   `json:"isIpv6,omitempty"`
}

// McpBlackholeReq is the daemon payload for tactical L3/L4 blackholing.
type McpBlackholeReq struct {
	Target                string       `json:"target"`
	Mode                  string       `json:"mode"`      // "nft_drop" | "nft_reject" | "route_blackhole"
	Direction             string       `json:"direction"` // "both" | "inbound" | "outbound"
	Protocol              string       `json:"protocol"`  // "any" | "tcp" | "udp" | "icmp"
	Port                  int          `json:"port,omitempty"`
	KillActiveConnections bool         `json:"killActiveConnections"`
	TTLSeconds            int          `json:"ttlSeconds"`
	CallerIP              string       `json:"callerIp,omitempty"`
	MaxIPv4PrefixLen      int          `json:"maxIpv4PrefixLen,omitempty"`
	MaxIPv6PrefixLen      int          `json:"maxIpv6PrefixLen,omitempty"`
	KeyID                 string       `json:"keyId"`
	KeyName               string       `json:"keyName"`
	Audit                 McpAuditMeta `json:"audit"`
}

// McpShapeReq is the daemon payload for tactical traffic shaping / tarpitting.
type McpShapeReq struct {
	Target            string       `json:"target"`
	Interface         string       `json:"interface"`
	Direction         string       `json:"direction"` // "both" | "egress" | "ingress"
	RateKbps          int          `json:"rateKbps"`
	CeilKbps          int          `json:"ceilKbps,omitempty"`
	LatencyMs         int          `json:"latencyMs,omitempty"`
	JitterMs          int          `json:"jitterMs,omitempty"`
	PacketLossPercent float64      `json:"packetLossPercent,omitempty"`
	DscpMark          *int         `json:"dscpMark,omitempty"`
	TTLSeconds        int          `json:"ttlSeconds"`
	CallerIP          string       `json:"callerIp,omitempty"`
	MaxIPv4PrefixLen  int          `json:"maxIpv4PrefixLen,omitempty"`
	MaxIPv6PrefixLen  int          `json:"maxIpv6PrefixLen,omitempty"`
	KeyID             string       `json:"keyId"`
	KeyName           string       `json:"keyName"`
	Audit             McpAuditMeta `json:"audit"`
}

// McpRedirectReq is the daemon payload for attacker-scoped deception DNAT or policy routing.
type McpRedirectReq struct {
	Source            string       `json:"source"`
	OriginalDstIP     string       `json:"originalDstIp,omitempty"`
	OriginalDstPort   int          `json:"originalDstPort,omitempty"`
	Protocol          string       `json:"protocol"`     // "tcp" | "udp" | "any"
	RedirectType      string       `json:"redirectType"` // "dnat_honeypot" | "policy_route"
	TargetDestination string       `json:"targetDestination"`
	MasqueradeReturn  bool         `json:"masqueradeReturn"`
	TTLSeconds        int          `json:"ttlSeconds"`
	CallerIP          string       `json:"callerIp,omitempty"`
	MaxIPv4PrefixLen  int          `json:"maxIpv4PrefixLen,omitempty"`
	MaxIPv6PrefixLen  int          `json:"maxIpv6PrefixLen,omitempty"`
	KeyID             string       `json:"keyId"`
	KeyName           string       `json:"keyName"`
	Audit             McpAuditMeta `json:"audit"`
}

// McpDnsSinkholeReq is the daemon payload for DNS sinkholing via Unbound.
type McpDnsSinkholeReq struct {
	Domain            string       `json:"domain"`
	SinkholeIP        string       `json:"sinkholeIp"`
	IncludeSubdomains bool         `json:"includeSubdomains"`
	TTLSeconds        int          `json:"ttlSeconds"`
	KeyID             string       `json:"keyId"`
	KeyName           string       `json:"keyName"`
	Audit             McpAuditMeta `json:"audit"`
}

// ConntrackFlow represents an active tracked connection in the Linux kernel.
type ConntrackFlow struct {
	Protocol string `json:"protocol"`
	State    string `json:"state,omitempty"`
	SrcIP    string `json:"srcIp"`
	DstIP    string `json:"dstIp"`
	SrcPort  int    `json:"srcPort,omitempty"`
	DstPort  int    `json:"dstPort,omitempty"`
	Packets  uint64 `json:"packets"`
	Bytes    uint64 `json:"bytes"`
	Assured  bool   `json:"assured"`
	Mark     string `json:"mark,omitempty"`
	ReplyDst string `json:"replyDst,omitempty"`
}

// McpTrafficManager manages the isolated `table inet axonwall_mcp` ruleset, tactical `tc` classes,
// kernel blackhole routes, Unbound DNS sinkholes, and TTL expiration janitor.
type McpTrafficManager struct {
	mu         sync.Mutex
	leases     map[string]*McpTacticalLease
	stopTicker chan struct{}
	// reservedClassIDs holds tc class / policy-routing table IDs that
	// are allocated but not yet covered by a lease in m.leases: either
	// allocated and still in kernel setup, or freed by a delete whose
	// kernel cleanup has not finished yet. See allocClassIDLocked.
	reservedClassIDs map[int]struct{}
	// reconcileDirty is set when a kernel rebuild fails (M9): the
	// lease records changed but the kernel table may not match them.
	// The janitor retries the rebuild on every tick until it lands
	// instead of forgetting the failure. Guarded by mu.
	reconcileDirty bool
}

// mcpClassIDRange is the shared pool for tc classes (shape) and
// policy-routing tables (redirect). Both namespaces draw from it so
// one allocator covers every kernel artifact keyed by ClassID.
const (
	mcpClassIDMin = 500
	mcpClassIDMax = 9000
)

// allocClassIDLocked returns the lowest ID in the pool that is neither
// held by a live lease nor reserved, and reserves it. Callers hold
// m.mu. The reservation is what makes scan-based allocation safe
// across the alloc-then-unlock-then-insert shape of Shape/Redirect:
// without it, two concurrent creations could both scan the same free
// ID before either inserted its lease. The reservation is released
// when the lease is inserted (the leases map then covers the ID), or
// after kernel cleanup when a lease is deleted, so a freed ID is
// never recycled underneath a cleanup that deletes artifacts by ID.
// A-L5: the old counter wrapped 9000 -> 500 without any in-use check,
// so a new lease could reuse a live lease's ID and reverting either
// one then deleted both leases' enforcement.
func (m *McpTrafficManager) allocClassIDLocked() (int, error) {
	used := make(map[int]struct{}, len(m.leases)+len(m.reservedClassIDs))
	for _, l := range m.leases {
		if l.ClassID != 0 {
			used[l.ClassID] = struct{}{}
		}
	}
	for id := range m.reservedClassIDs {
		used[id] = struct{}{}
	}
	for id := mcpClassIDMin; id <= mcpClassIDMax; id++ {
		if _, ok := used[id]; !ok {
			if m.reservedClassIDs == nil {
				m.reservedClassIDs = make(map[int]struct{})
			}
			m.reservedClassIDs[id] = struct{}{}
			return id, nil
		}
	}
	return 0, fmt.Errorf("no free MCP class/table ID in range %d-%d", mcpClassIDMin, mcpClassIDMax)
}

// reserveClassIDLocked marks id as reserved (no-op for 0, which means
// "no kernel artifact"). Callers hold m.mu.
func (m *McpTrafficManager) reserveClassIDLocked(id int) {
	if id == 0 {
		return
	}
	if m.reservedClassIDs == nil {
		m.reservedClassIDs = make(map[int]struct{})
	}
	m.reservedClassIDs[id] = struct{}{}
}

// releaseClassIDLocked frees a reservation. Callers hold m.mu.
func (m *McpTrafficManager) releaseClassIDLocked(id int) {
	delete(m.reservedClassIDs, id)
}

func NewMcpTrafficManager() *McpTrafficManager {
	mgr := &McpTrafficManager{
		leases:           make(map[string]*McpTacticalLease),
		reservedClassIDs: make(map[int]struct{}),
		stopTicker:       make(chan struct{}),
	}
	mgr.loadState()
	if err := mgr.ReconcileKernelState(); err != nil {
		log.Printf("[MCP Traffic] Initial kernel reconciliation warning: %v", err)
		// M9: the startup rebuild failed, so the leases reloaded from
		// disk are listed as active with a stale (or empty) kernel
		// table. Mark it dirty so the janitor retries the rebuild
		// until it lands instead of waiting for a lease event.
		mgr.reconcileDirty = true
	}
	go mgr.janitorLoop()
	return mgr
}

// ReconcileDirty reports whether a kernel rebuild failed and has not
// yet been retried to success (M9). The stale-enforcement state is
// surfaced to the API alongside the lease list.
func (m *McpTrafficManager) ReconcileDirty() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.reconcileDirty
}

func generateLeaseID() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return "mcp_lease_" + hex.EncodeToString(b)
}

func (m *McpTrafficManager) loadState() {
	m.mu.Lock()
	defer m.mu.Unlock()

	data, err := os.ReadFile(mcpStateFilePath)
	if err != nil || len(data) == 0 {
		return
	}

	var list []*McpTacticalLease
	if err := json.Unmarshal(data, &list); err != nil {
		log.Printf("[MCP Traffic] Failed to parse %s: %v", mcpStateFilePath, err)
		return
	}

	now := time.Now().UTC()
	for _, l := range list {
		exp, err := time.Parse(time.RFC3339, l.ExpiresAt)
		if err == nil && exp.After(now) {
			m.leases[l.ID] = l
			// A-L5: no counter to restore — allocation scans the
			// live leases, so a restart can never reissue an ID
			// that a reloaded lease still holds.
		}
	}
}

func (m *McpTrafficManager) saveStateLocked() {
	list := make([]*McpTacticalLease, 0, len(m.leases))
	for _, l := range m.leases {
		list = append(list, l)
	}
	sort.Slice(list, func(i, j int) bool {
		return list[i].CreatedAt > list[j].CreatedAt
	})

	_ = os.MkdirAll(filepath.Dir(mcpStateFilePath), 0700)
	if data, err := json.MarshalIndent(list, "", "  "); err == nil {
		_ = os.WriteFile(mcpStateFilePath, data, 0600)
	}
}

func (m *McpTrafficManager) janitorLoop() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-m.stopTicker:
			return
		case <-ticker.C:
			m.purgeExpiredLeases()
		}
	}
}

func (m *McpTrafficManager) purgeExpiredLeases() {
	m.mu.Lock()
	now := time.Now().UTC()
	expired := []*McpTacticalLease{}
	for _, l := range m.leases {
		exp, err := time.Parse(time.RFC3339, l.ExpiresAt)
		if err != nil || !exp.After(now) {
			expired = append(expired, l)
			delete(m.leases, l.ID)
			// A-L5: hold each ID reserved until its kernel cleanup
			// finishes (see allocClassIDLocked).
			m.reserveClassIDLocked(l.ClassID)
		}
	}
	if len(expired) == 0 {
		m.mu.Unlock()
		// M9: even a tick with nothing to expire retries a
		// previously failed rebuild (see retryDirtyReconcile).
		m.retryDirtyReconcile()
		return
	}
	m.saveStateLocked()
	m.mu.Unlock()

	for _, l := range expired {
		log.Printf("[MCP Janitor] Expiring tactical lease %s (%s: %s)", l.ID, l.Kind, l.TargetSummary)
		m.cleanupKernelArtifactsForLease(l)
	}
	m.mu.Lock()
	for _, l := range expired {
		m.releaseClassIDLocked(l.ClassID)
	}
	m.mu.Unlock()
	// A-M13: a failed rebuild must not pass silently — the expired leases
	// are gone from the records, but the kernel table may still enforce them.
	if err := m.ReconcileKernelState(); err != nil {
		log.Printf("[MCP Traffic] Janitor kernel reconciliation failed (kernel table may still enforce expired leases): %v", err)
		// M9: keep the failure sticky. The next tick finds no
		// expired leases left, so without a dirty flag nothing
		// would ever retry the rebuild and the expired leases
		// could stay enforced indefinitely.
		m.mu.Lock()
		m.reconcileDirty = true
		m.mu.Unlock()
		return
	}
	m.mu.Lock()
	m.reconcileDirty = false
	m.mu.Unlock()
}

// retryDirtyReconcile retries a previously failed kernel rebuild
// (M9). It runs at the end of every janitor tick, including ticks
// with nothing to expire, so a failed rebuild is retried until it
// lands instead of being forgotten after one log line.
func (m *McpTrafficManager) retryDirtyReconcile() {
	m.mu.Lock()
	dirty := m.reconcileDirty
	m.mu.Unlock()
	if !dirty {
		return
	}
	if err := m.ReconcileKernelState(); err != nil {
		log.Printf("[MCP Traffic] Retrying failed kernel reconciliation (kernel table may still be stale): %v", err)
		return
	}
	m.mu.Lock()
	m.reconcileDirty = false
	m.mu.Unlock()
	log.Printf("[MCP Traffic] Previously failed kernel reconciliation succeeded on retry")
}

// ListLeases returns all currently active tactical leases with updated remaining TTL seconds.
func (m *McpTrafficManager) ListLeases() []*McpTacticalLease {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now().UTC()
	out := make([]*McpTacticalLease, 0, len(m.leases))
	for _, l := range m.leases {
		exp, err := time.Parse(time.RFC3339, l.ExpiresAt)
		if err != nil || !exp.After(now) {
			continue
		}
		copyLease := *l
		copyLease.TTLSeconds = int(exp.Sub(now).Seconds())
		out = append(out, &copyLease)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].CreatedAt > out[j].CreatedAt
	})
	return out
}

// ReconcileKernelState rebuilds `table inet axonwall_mcp`, active blackhole routes, `tc` shaping filters,
// and Unbound DNS sinkhole configs from the active lease map.
func (m *McpTrafficManager) ReconcileKernelState() error {
	m.mu.Lock()
	leases := m.activeLeasesLocked()
	m.mu.Unlock()
	return m.reconcileKernelStateWith(leases)
}

// activeLeasesLocked returns the currently unexpired leases. Callers
// hold m.mu.
func (m *McpTrafficManager) activeLeasesLocked() []*McpTacticalLease {
	leases := make([]*McpTacticalLease, 0, len(m.leases))
	now := time.Now().UTC()
	for _, l := range m.leases {
		if exp, err := time.Parse(time.RFC3339, l.ExpiresAt); err == nil && exp.After(now) {
			leases = append(leases, l)
		}
	}
	return leases
}

// reconcileKernelStateWith rebuilds the kernel table from an explicit
// lease set instead of the live map, so RevertLease/FlushAllLeases
// can rebuild the post-delete table BEFORE deleting any record (M8).
func (m *McpTrafficManager) reconcileKernelStateWith(leases []*McpTacticalLease) error {

	posture := DiscoverProtectedPosture()
	protectedV4 := []string{"127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4"}
	protectedV6 := []string{"::1/128", "fe80::/10", "ff00::/8"}

	for _, ipStr := range append(posture.ApplianceIPs, posture.GatewayAndHaIPs...) {
		if parsed := net.ParseIP(ipStr); parsed != nil {
			if parsed.IsLoopback() || parsed.IsLinkLocalUnicast() || parsed.IsLinkLocalMulticast() || parsed.IsMulticast() {
				continue
			}
			if parsed.To4() != nil {
				protectedV4 = append(protectedV4, parsed.String())
			} else {
				protectedV6 = append(protectedV6, parsed.String())
			}
		}
	}

	portStrs := []string{}
	for _, p := range posture.AntiLockoutPorts {
		portStrs = append(portStrs, strconv.Itoa(p))
	}
	antiLockoutPortSet := strings.Join(portStrs, ", ")
	if antiLockoutPortSet == "" {
		antiLockoutPortSet = "2966, 22, 9876"
	}

	// Build isolated `table inet axonwall_mcp`
	var nft strings.Builder
	nft.WriteString("table inet axonwall_mcp {}\n")
	nft.WriteString("flush table inet axonwall_mcp\n")
	nft.WriteString("table inet axonwall_mcp {\n")

	// Protected immunity sets
	nft.WriteString("  set mcp_protected_v4 {\n    type ipv4_addr;\n    flags interval;\n    auto-merge;\n")
	if len(protectedV4) > 0 {
		nft.WriteString(fmt.Sprintf("    elements = { %s };\n", strings.Join(protectedV4, ", ")))
	}
	nft.WriteString("  }\n")

	nft.WriteString("  set mcp_protected_v6 {\n    type ipv6_addr;\n    flags interval;\n    auto-merge;\n")
	if len(protectedV6) > 0 {
		nft.WriteString(fmt.Sprintf("    elements = { %s };\n", strings.Join(protectedV6, ", ")))
	}
	nft.WriteString("  }\n")

	// Prerouting DNAT chain (runs before standard dstnat so attacker-scoped deception DNAT works cleanly)
	nft.WriteString("  chain mcp_prerouting {\n")
	nft.WriteString("    type nat hook prerouting priority dstnat - 15; policy accept;\n")
	nft.WriteString("    iif \"lo\" accept\n")
	nft.WriteString(fmt.Sprintf("    tcp dport { %s } accept comment \"mcp-anti-lockout-bypass\"\n", antiLockoutPortSet))
	nft.WriteString("    ip saddr @mcp_protected_v4 accept\n")
	nft.WriteString("    ip6 saddr @mcp_protected_v6 accept\n")

	// Mangle prerouting chain (for packet marking: tc shaping / tarpit / policy routing + DSCP)
	var mangleRules []string
	var filterRulesIn []string
	var filterRulesOut []string
	var postroutingRules []string

	for _, l := range leases {
		family := "ip"
		if l.IsIPv6 {
			family = "ip6"
		}
		target := l.NormalizedTarget

		switch l.Kind {
		case "blackhole":
			mode, _ := l.Parameters["mode"].(string)
			dir, _ := l.Parameters["direction"].(string)
			proto, _ := l.Parameters["protocol"].(string)
			portFloat, _ := l.Parameters["port"].(float64)
			portInt, _ := l.Parameters["port"].(int)
			port := portInt
			if port == 0 && portFloat > 0 {
				port = int(portFloat)
			}

			verdict := "counter drop"
			if mode == "nft_reject" {
				verdict = "counter reject"
			}

			// M7 (defence in depth): a lease with an unrecognised
			// direction must fail the reconcile instead of silently
			// emitting no rule. Creation now rejects these, so this
			// can only fire for a lease persisted before the fix —
			// and a revert of that lease reconciles the set without
			// it, so it stays removable.
			switch dir {
			case "", "both", "inbound", "outbound":
			default:
				return fmt.Errorf("lease %s has unrecognised blackhole direction %q", l.ID, dir)
			}

			protoMatch := ""
			if proto == "tcp" || proto == "udp" {
				if port > 0 {
					protoMatch = fmt.Sprintf("%s dport %d ", proto, port)
				} else {
					protoMatch = fmt.Sprintf("meta l4proto %s ", proto)
				}
			} else if proto == "icmp" {
				if l.IsIPv6 {
					protoMatch = "meta l4proto ipv6-icmp "
				} else {
					protoMatch = "meta l4proto icmp "
				}
			} else if port > 0 {
				protoMatch = fmt.Sprintf("meta l4proto { tcp, udp } th dport %d ", port)
			}

			if dir == "both" || dir == "inbound" || dir == "" {
				filterRulesIn = append(filterRulesIn,
					fmt.Sprintf("    %s saddr %s %s%s comment \"%s\"", family, target, protoMatch, verdict, l.ID))
			}
			if dir == "both" || dir == "outbound" {
				filterRulesOut = append(filterRulesOut,
					fmt.Sprintf("    %s daddr %s %s%s comment \"%s\"", family, target, protoMatch, verdict, l.ID))
			}

		case "shape":
			shapeDir, _ := l.Parameters["direction"].(string)
			if shapeDir == "" {
				shapeDir = "both"
			}
			// M7 (defence in depth): see the blackhole case above.
			switch shapeDir {
			case "both", "ingress", "inbound", "egress", "outbound":
			default:
				return fmt.Errorf("lease %s has unrecognised shape direction %q", l.ID, shapeDir)
			}
			if l.FwMark > 0 {
				if shapeDir == "both" || shapeDir == "ingress" || shapeDir == "inbound" {
					mangleRules = append(mangleRules,
						fmt.Sprintf("    %s saddr %s meta mark set 0x%x counter comment \"%s\"", family, target, l.FwMark, l.ID))
				}
				if shapeDir == "both" || shapeDir == "egress" || shapeDir == "outbound" {
					mangleRules = append(mangleRules,
						fmt.Sprintf("    %s daddr %s meta mark set 0x%x counter comment \"%s\"", family, target, l.FwMark, l.ID))
				}
			}
			if dscpVal, ok := l.Parameters["dscpMark"]; ok && dscpVal != nil {
				var dscp int
				switch v := dscpVal.(type) {
				case float64:
					dscp = int(v)
				case int:
					dscp = v
				}
				if dscp >= 0 && dscp <= 63 {
					mangleRules = append(mangleRules,
						fmt.Sprintf("    %s saddr %s %s dscp set %d comment \"%s-dscp\"", family, target, family, dscp, l.ID))
				}
			}

		case "redirect":
			rType, _ := l.Parameters["redirectType"].(string)
			proto, _ := l.Parameters["protocol"].(string)
			origDstIP, _ := l.Parameters["originalDstIp"].(string)
			origPortFloat, _ := l.Parameters["originalDstPort"].(float64)
			origPortInt, _ := l.Parameters["originalDstPort"].(int)
			origPort := origPortInt
			if origPort == 0 && origPortFloat > 0 {
				origPort = int(origPortFloat)
			}
			dest, _ := l.Parameters["targetDestination"].(string)
			masq, _ := l.Parameters["masqueradeReturn"].(bool)

			if rType == "dnat_honeypot" {
				hostIP, _, destV6, normDest, err := ValidateRedirectDestination(dest)
				if err == nil && destV6 == l.IsIPv6 {
					var matchParts []string
					matchParts = append(matchParts, fmt.Sprintf("%s saddr %s", family, target))
					if origDstIP != "" {
						if _, _, dV6, _, normOrigDst, dErr := ParseTargetIPOrCIDR(origDstIP); dErr == nil && dV6 == l.IsIPv6 {
							matchParts = append(matchParts, fmt.Sprintf("%s daddr %s", family, normOrigDst))
						}
					}
					if proto == "tcp" || proto == "udp" {
						if origPort > 0 {
							matchParts = append(matchParts, fmt.Sprintf("%s dport %d", proto, origPort))
						} else {
							matchParts = append(matchParts, fmt.Sprintf("meta l4proto %s", proto))
						}
					} else if origPort > 0 {
						matchParts = append(matchParts, fmt.Sprintf("meta l4proto { tcp, udp } th dport %d", origPort))
					}

					nft.WriteString(fmt.Sprintf("    %s counter dnat %s to %s comment \"%s\"\n",
						strings.Join(matchParts, " "), family, normDest, l.ID))

					if masq && hostIP != "" {
						postroutingRules = append(postroutingRules,
							fmt.Sprintf("    %s saddr %s %s daddr %s counter masquerade comment \"%s\"", family, target, family, hostIP, l.ID))
					}
				}
			} else if rType == "policy_route" && l.FwMark > 0 {
				mangleRules = append(mangleRules,
					fmt.Sprintf("    %s saddr %s meta mark set 0x%x counter comment \"%s\"", family, target, l.FwMark, l.ID))
			}
		}
	}

	nft.WriteString("  }\n\n")

	// Mangle chain
	nft.WriteString("  chain mcp_mangle {\n")
	nft.WriteString("    type filter hook prerouting priority mangle - 5; policy accept;\n")
	nft.WriteString("    iif \"lo\" accept\n")
	nft.WriteString(fmt.Sprintf("    tcp dport { %s } accept\n", antiLockoutPortSet))
	nft.WriteString("    ip saddr @mcp_protected_v4 accept\n")
	nft.WriteString("    ip6 saddr @mcp_protected_v6 accept\n")
	for _, r := range mangleRules {
		nft.WriteString(r + "\n")
	}
	nft.WriteString("  }\n\n")

	// Input filter chain
	nft.WriteString("  chain mcp_input {\n")
	nft.WriteString("    type filter hook input priority filter - 5; policy accept;\n")
	nft.WriteString("    iif \"lo\" accept\n")
	nft.WriteString(fmt.Sprintf("    tcp dport { %s } accept comment \"mcp-anti-lockout-input\"\n", antiLockoutPortSet))
	nft.WriteString("    ip saddr @mcp_protected_v4 accept\n")
	nft.WriteString("    ip6 saddr @mcp_protected_v6 accept\n")
	for _, r := range filterRulesIn {
		nft.WriteString(r + "\n")
	}
	nft.WriteString("  }\n\n")

	// Forward filter chain
	nft.WriteString("  chain mcp_forward {\n")
	nft.WriteString("    type filter hook forward priority filter - 5; policy accept;\n")
	nft.WriteString("    ip saddr @mcp_protected_v4 accept\n")
	nft.WriteString("    ip daddr @mcp_protected_v4 accept\n")
	nft.WriteString("    ip6 saddr @mcp_protected_v6 accept\n")
	nft.WriteString("    ip6 daddr @mcp_protected_v6 accept\n")
	for _, r := range filterRulesIn {
		nft.WriteString(r + "\n")
	}
	for _, r := range filterRulesOut {
		nft.WriteString(r + "\n")
	}
	nft.WriteString("  }\n\n")

	// Output filter chain
	nft.WriteString("  chain mcp_output {\n")
	nft.WriteString("    type filter hook output priority filter - 5; policy accept;\n")
	nft.WriteString("    oif \"lo\" accept\n")
	nft.WriteString("    ip daddr @mcp_protected_v4 accept\n")
	nft.WriteString("    ip6 daddr @mcp_protected_v6 accept\n")
	for _, r := range filterRulesOut {
		nft.WriteString(r + "\n")
	}
	nft.WriteString("  }\n\n")

	// Postrouting chain for Honeypot DNAT return masquerading
	nft.WriteString("  chain mcp_postrouting {\n")
	nft.WriteString("    type nat hook postrouting priority srcnat - 5; policy accept;\n")
	for _, r := range postroutingRules {
		nft.WriteString(r + "\n")
	}
	nft.WriteString("  }\n")
	nft.WriteString("}\n")

	// Apply nftables script atomically via stdin.
	// A-M13: validate the complete replacement script before touching the
	// live table, then apply it. Either failure is returned to the caller
	// instead of being logged away while the lease is reported as active.
	checkCmd := exec.Command("nft", "-c", "-f", "-")
	checkCmd.Stdin = strings.NewReader(nft.String())
	if out, err := checkCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("nftables validation failed: %v (%s)", err, strings.TrimSpace(string(out)))
	}
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(nft.String())
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("nftables apply failed: %v (%s)", err, strings.TrimSpace(string(out)))
	}

	// Reconcile Unbound DNS sinkhole configuration. A-M10: a failed
	// sinkhole reconcile fails the whole rebuild — the lease create
	// paths already drop the lease on any ReconcileKernelState error
	// (A-M13), so a sinkhole lease no longer reports active while
	// DNS is not sinkholed.
	if err := m.reconcileDnsSinkholes(leases); err != nil {
		return err
	}

	return nil
}

// reconcileDnsSinkholes writes the Unbound sinkhole config for the
// active dns_sinkhole leases and reloads Unbound. It returns an error
// instead of logging failures away (A-M10): a config write failure
// (disk full, perms) or a failed `unbound-control reload` (Unbound
// down, bad generated config) used to leave the lease stored,
// persisted, and listed as active while the domain kept resolving.
// The reload runs only when sinkhole state actually changes, so an
// unrelated lease create does not fail just because Unbound is down:
// with no sinkhole leases and no sinkhole file on disk there is
// nothing to reconcile.
func (m *McpTrafficManager) reconcileDnsSinkholes(leases []*McpTacticalLease) error {
	var lines []string
	lines = append(lines, "# Auto-generated by Axonwall MCP Tactical Traffic Engine")
	lines = append(lines, "server:")

	count := 0
	for _, l := range leases {
		if l.Kind != "dns_sinkhole" {
			continue
		}
		domain, _ := l.Parameters["domain"].(string)
		sinkholeIP, _ := l.Parameters["sinkholeIp"].(string)
		includeSub, _ := l.Parameters["includeSubdomains"].(bool)
		if !validDomainRegex.MatchString(domain) {
			continue
		}
		if net.ParseIP(sinkholeIP) == nil {
			sinkholeIP = "0.0.0.0"
		}
		zoneType := "transparent"
		if includeSub {
			zoneType = "redirect"
		}
		lines = append(lines, fmt.Sprintf("  local-zone: \"%s.\" %s", domain, zoneType))
		lines = append(lines, fmt.Sprintf("  local-data: \"%s. 60 IN A %s\"", domain, sinkholeIP))
		count++
	}

	if count == 0 {
		if err := os.Remove(unboundMcpSinkholePath); err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return fmt.Errorf("failed to remove stale dns sinkhole config %s: %w", unboundMcpSinkholePath, err)
		}
		// A stale config was removed: reload so Unbound drops the
		// sinkhole instead of serving it until the next restart.
	} else {
		if err := os.MkdirAll(filepath.Dir(unboundMcpSinkholePath), 0755); err != nil {
			return fmt.Errorf("failed to create unbound config dir %s: %w", filepath.Dir(unboundMcpSinkholePath), err)
		}
		if err := os.WriteFile(unboundMcpSinkholePath, []byte(strings.Join(lines, "\n")+"\n"), 0644); err != nil {
			return fmt.Errorf("failed to write dns sinkhole config %s: %w", unboundMcpSinkholePath, err)
		}
	}
	if out, err := exec.Command(unboundControlBinary, "reload").CombinedOutput(); err != nil {
		return fmt.Errorf("unbound-control reload failed: %v (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (m *McpTrafficManager) cleanupKernelArtifactsForLease(l *McpTacticalLease) {
	if l.Kind == "blackhole" {
		if mode, _ := l.Parameters["mode"].(string); mode == "route_blackhole" && l.NormalizedTarget != "" {
			if l.IsIPv6 {
				_ = exec.Command("ip", "-6", "route", "del", "blackhole", l.NormalizedTarget).Run()
			} else {
				_ = exec.Command("ip", "route", "del", "blackhole", l.NormalizedTarget).Run()
			}
		}
	} else if l.Kind == "shape" && l.ClassID > 0 {
		iface, _ := l.Parameters["interface"].(string)
		dev := resolveKernelDevice(iface)
		if dev != "" {
			classMinor := strconv.Itoa(l.ClassID)
			markStr := fmt.Sprintf("0x%x", l.FwMark)
			proto := "ip"
			if l.IsIPv6 {
				proto = "ipv6"
			}
			_ = exec.Command("tc", "filter", "del", "dev", dev, "parent", "1:", "protocol", proto, "prio", "10", "handle", markStr, "fw", "flowid", "1:"+classMinor).Run()
			_ = exec.Command("tc", "qdisc", "del", "dev", dev, "parent", "1:"+classMinor).Run()
			_ = exec.Command("tc", "class", "del", "dev", dev, "classid", "1:"+classMinor).Run()
		}
	} else if l.Kind == "redirect" {
		if rType, _ := l.Parameters["redirectType"].(string); rType == "policy_route" && l.FwMark > 0 {
			markHex := fmt.Sprintf("0x%x", l.FwMark)
			if l.IsIPv6 {
				_ = exec.Command("ip", "-6", "rule", "del", "fwmark", markHex, "table", strconv.Itoa(l.ClassID)).Run()
			} else {
				_ = exec.Command("ip", "rule", "del", "fwmark", markHex, "table", strconv.Itoa(l.ClassID)).Run()
			}
		}
	}
}

func resolveKernelDevice(logicalOrDev string) string {
	cleaned := strings.TrimSpace(logicalOrDev)
	if cleaned == "" {
		cleaned = "wan"
	}
	// Check live interfaces first
	if _, err := net.InterfaceByName(cleaned); err == nil && safeIfaceRegex.MatchString(cleaned) {
		return cleaned
	}
	// Check state.json mapping
	for _, p := range []string{"/etc/axonwall/state.json", "/var/lib/axonwall/state.json"} {
		if data, err := os.ReadFile(p); err == nil && len(data) > 0 {
			var st struct {
				Interfaces []struct {
					Name   string `json:"name"`
					Device string `json:"device"`
				} `json:"interfaces"`
			}
			if json.Unmarshal(data, &st) == nil {
				for _, iface := range st.Interfaces {
					if strings.EqualFold(iface.Name, cleaned) && safeIfaceRegex.MatchString(iface.Device) {
						return iface.Device
					}
				}
			}
		}
	}
	if safeIfaceRegex.MatchString(cleaned) {
		return cleaned
	}
	return ""
}

// BlackholeTraffic validates and enforces an immediate L3/L4 blackhole + optional active conntrack kill.
func (m *McpTrafficManager) BlackholeTraffic(req McpBlackholeReq) (*McpTacticalLease, error) {
	normTarget, isV6, _, err := ValidateTargetSafety(
		req.Target,
		req.CallerIP,
		req.Port,
		req.MaxIPv4PrefixLen,
		req.MaxIPv6PrefixLen,
	)
	if err != nil {
		return nil, err
	}

	if req.TTLSeconds < 10 {
		req.TTLSeconds = 3600
	}
	if req.TTLSeconds > 604800 {
		req.TTLSeconds = 604800
	}
	if req.Mode == "" {
		req.Mode = "nft_drop"
	}
	if req.Direction == "" {
		req.Direction = "both"
	}
	// M7: an unrecognised direction used to be accepted and then
	// match no rule branch in ReconcileKernelState, so the lease was
	// stored and reported as active while the kernel enforced
	// nothing for it.
	switch req.Direction {
	case "both", "inbound", "outbound":
	default:
		return nil, fmt.Errorf("invalid blackhole direction %q: must be both, inbound, or outbound", req.Direction)
	}
	if req.Protocol == "" {
		req.Protocol = "any"
	}

	now := time.Now().UTC()
	lease := &McpTacticalLease{
		ID:               generateLeaseID(),
		Kind:             "blackhole",
		CreatedAt:        now.Format(time.RFC3339),
		ExpiresAt:        now.Add(time.Duration(req.TTLSeconds) * time.Second).Format(time.RFC3339),
		TTLSeconds:       req.TTLSeconds,
		CreatedByKeyID:   req.KeyID,
		CreatedByKeyName: req.KeyName,
		TargetSummary:    fmt.Sprintf("Blackhole %s (%s, %s)", normTarget, req.Mode, req.Direction),
		NormalizedTarget: normTarget,
		IsIPv6:           isV6,
		Parameters: map[string]interface{}{
			"target":                normTarget,
			"mode":                  req.Mode,
			"direction":             req.Direction,
			"protocol":              req.Protocol,
			"port":                  req.Port,
			"killActiveConnections": req.KillActiveConnections,
		},
		Audit: req.Audit,
	}

	if req.Mode == "route_blackhole" {
		var out []byte
		var cmdErr error
		if isV6 {
			out, cmdErr = exec.Command("ip", "-6", "route", "replace", "blackhole", normTarget, "metric", "50").CombinedOutput()
		} else {
			out, cmdErr = exec.Command("ip", "route", "replace", "blackhole", normTarget, "metric", "50").CombinedOutput()
		}
		if cmdErr != nil {
			log.Printf("[MCP Traffic] ip route blackhole warning for %s: %v (%s)", normTarget, cmdErr, strings.TrimSpace(string(out)))
		}
	}

	// Terminate active conntrack sessions immediately to sever established C2 channels
	if req.KillActiveConnections {
		hostOnly := strings.Split(normTarget, "/")[0]
		if net.ParseIP(hostOnly) != nil {
			_ = exec.Command("conntrack", "-D", "-s", normTarget).Run()
			_ = exec.Command("conntrack", "-D", "-d", normTarget).Run()
		}
	}

	m.mu.Lock()
	m.leases[lease.ID] = lease
	// A-L5: the leases map now covers this ID, so the allocation
	// reservation is released (no-op when ClassID is 0).
	m.releaseClassIDLocked(lease.ClassID)
	m.saveStateLocked()
	m.mu.Unlock()

	// A-M13: a lease whose kernel rules failed to land must not be stored,
	// persisted, or returned as active. Remove it, clean up any artifacts
	// applied before the reconcile, and fail the creation; a best-effort
	// healing reconcile rebuilds the table for the remaining leases.
	if err := m.ReconcileKernelState(); err != nil {
		m.mu.Lock()
		delete(m.leases, lease.ID)
		// A-L5: hold the ID reserved until kernel cleanup finishes,
		// so a concurrent creation cannot recycle it underneath
		// cleanupKernelArtifactsForLease (which deletes by ID).
		m.reserveClassIDLocked(lease.ClassID)
		m.saveStateLocked()
		m.mu.Unlock()
		m.cleanupKernelArtifactsForLease(lease)
		m.mu.Lock()
		m.releaseClassIDLocked(lease.ClassID)
		m.mu.Unlock()
		if herr := m.ReconcileKernelState(); herr != nil {
			log.Printf("[MCP Traffic] Warning: healing kernel reconciliation also failed after lease %s creation failure: %v", lease.ID, herr)
		}
		return nil, fmt.Errorf("kernel reconcile failed for lease %s: %w", lease.ID, err)
	}
	return lease, nil
}

// ShapeTraffic validates and applies a dynamic per-IP/subnet Linux `tc` HTB bandwidth limit and/or `netem` latency tarpit.
func (m *McpTrafficManager) ShapeTraffic(req McpShapeReq) (*McpTacticalLease, error) {
	normTarget, isV6, _, err := ValidateTargetSafety(
		req.Target,
		req.CallerIP,
		0,
		req.MaxIPv4PrefixLen,
		req.MaxIPv6PrefixLen,
	)
	if err != nil {
		return nil, err
	}

	if req.RateKbps < 8 {
		return nil, fmt.Errorf("rateKbps must be at least 8 kbps")
	}
	if req.CeilKbps < req.RateKbps {
		req.CeilKbps = req.RateKbps
	}
	if req.LatencyMs < 0 || req.LatencyMs > 5000 {
		return nil, fmt.Errorf("latencyMs must be between 0 and 5000 ms")
	}
	// M7: same direction validation as BlackholeTraffic (see there).
	if req.Direction == "" {
		req.Direction = "both"
	}
	switch req.Direction {
	case "both", "ingress", "inbound", "egress", "outbound":
	default:
		return nil, fmt.Errorf("invalid shape direction %q: must be both, ingress, inbound, egress, or outbound", req.Direction)
	}
	if req.TTLSeconds < 10 {
		req.TTLSeconds = 3600
	}

	m.mu.Lock()
	classID, allocErr := m.allocClassIDLocked()
	if allocErr != nil {
		m.mu.Unlock()
		return nil, allocErr
	}
	fwMark := 0x2000 + classID
	m.mu.Unlock()

	dev := resolveKernelDevice(req.Interface)
	if dev != "" {
		// Ensure a root HTB qdisc exists on dev if none is active, then attach the tactical class + netem leaf
		_ = exec.Command("tc", "qdisc", "add", "dev", dev, "root", "handle", "1:", "htb", "default", "99").Run()
		_ = exec.Command("tc", "class", "add", "dev", dev, "parent", "1:", "classid", "1:1", "htb", "rate", "10000mbit", "ceil", "10000mbit").Run()

		classStr := fmt.Sprintf("1:%d", classID)
		rateStr := fmt.Sprintf("%dkbit", req.RateKbps)
		ceilStr := fmt.Sprintf("%dkbit", req.CeilKbps)
		_ = exec.Command("tc", "class", "replace", "dev", dev, "parent", "1:1", "classid", classStr, "htb", "rate", rateStr, "ceil", ceilStr, "prio", "7").Run()

		if req.LatencyMs > 0 || req.PacketLossPercent > 0 {
			netemArgs := []string{"qdisc", "replace", "dev", dev, "parent", classStr, "handle", fmt.Sprintf("%d:", classID), "netem"}
			if req.LatencyMs > 0 {
				netemArgs = append(netemArgs, "delay", fmt.Sprintf("%dms", req.LatencyMs))
				if req.JitterMs > 0 {
					netemArgs = append(netemArgs, fmt.Sprintf("%dms", req.JitterMs))
				}
			}
			if req.PacketLossPercent > 0 {
				netemArgs = append(netemArgs, "loss", fmt.Sprintf("%.1f%%", req.PacketLossPercent))
			}
			_ = exec.Command("tc", netemArgs...).Run()
		} else {
			_ = exec.Command("tc", "qdisc", "replace", "dev", dev, "parent", classStr, "handle", fmt.Sprintf("%d:", classID), "fq_codel").Run()
		}

		proto := "ip"
		if isV6 {
			proto = "ipv6"
		}
		_ = exec.Command("tc", "filter", "add", "dev", dev, "parent", "1:", "protocol", proto, "prio", "10", "handle", fmt.Sprintf("0x%x", fwMark), "fw", "flowid", classStr).Run()
	}

	now := time.Now().UTC()
	summary := fmt.Sprintf("Throttle %s to %d kbps", normTarget, req.RateKbps)
	if req.LatencyMs > 0 {
		summary += fmt.Sprintf(" + %dms tarpit delay", req.LatencyMs)
	}

	lease := &McpTacticalLease{
		ID:               generateLeaseID(),
		Kind:             "shape",
		CreatedAt:        now.Format(time.RFC3339),
		ExpiresAt:        now.Add(time.Duration(req.TTLSeconds) * time.Second).Format(time.RFC3339),
		TTLSeconds:       req.TTLSeconds,
		CreatedByKeyID:   req.KeyID,
		CreatedByKeyName: req.KeyName,
		TargetSummary:    summary,
		ClassID:          classID,
		FwMark:           fwMark,
		NormalizedTarget: normTarget,
		IsIPv6:           isV6,
		Parameters: map[string]interface{}{
			"target":            normTarget,
			"interface":         req.Interface,
			"direction":         req.Direction,
			"rateKbps":          req.RateKbps,
			"ceilKbps":          req.CeilKbps,
			"latencyMs":         req.LatencyMs,
			"jitterMs":          req.JitterMs,
			"packetLossPercent": req.PacketLossPercent,
			"dscpMark":          req.DscpMark,
		},
		Audit: req.Audit,
	}

	m.mu.Lock()
	m.leases[lease.ID] = lease
	// A-L5: the leases map now covers this ID, so the allocation
	// reservation is released (no-op when ClassID is 0).
	m.releaseClassIDLocked(lease.ClassID)
	m.saveStateLocked()
	m.mu.Unlock()

	// A-M13: a lease whose kernel rules failed to land must not be stored,
	// persisted, or returned as active. Remove it, clean up any artifacts
	// applied before the reconcile, and fail the creation; a best-effort
	// healing reconcile rebuilds the table for the remaining leases.
	if err := m.ReconcileKernelState(); err != nil {
		m.mu.Lock()
		delete(m.leases, lease.ID)
		// A-L5: hold the ID reserved until kernel cleanup finishes,
		// so a concurrent creation cannot recycle it underneath
		// cleanupKernelArtifactsForLease (which deletes by ID).
		m.reserveClassIDLocked(lease.ClassID)
		m.saveStateLocked()
		m.mu.Unlock()
		m.cleanupKernelArtifactsForLease(lease)
		m.mu.Lock()
		m.releaseClassIDLocked(lease.ClassID)
		m.mu.Unlock()
		if herr := m.ReconcileKernelState(); herr != nil {
			log.Printf("[MCP Traffic] Warning: healing kernel reconciliation also failed after lease %s creation failure: %v", lease.ID, herr)
		}
		return nil, fmt.Errorf("kernel reconcile failed for lease %s: %w", lease.ID, err)
	}
	return lease, nil
}

// RedirectTraffic steers traffic from an attacker source IP/CIDR to a deception honeypot (DNAT) or policy route gateway.
func (m *McpTrafficManager) RedirectTraffic(req McpRedirectReq) (*McpTacticalLease, error) {
	normSource, isV6, _, err := ValidateTargetSafety(
		req.Source,
		req.CallerIP,
		req.OriginalDstPort,
		req.MaxIPv4PrefixLen,
		req.MaxIPv6PrefixLen,
	)
	if err != nil {
		return nil, err
	}

	destHostIP, _, destV6, normDest, err := ValidateRedirectDestination(req.TargetDestination)
	if err != nil {
		return nil, err
	}
	if isV6 != destV6 {
		return nil, fmt.Errorf("address family mismatch between source (%s) and redirect destination (%s)", normSource, normDest)
	}

	if req.TTLSeconds < 10 {
		req.TTLSeconds = 3600
	}
	if req.RedirectType == "" {
		req.RedirectType = "dnat_honeypot"
	}
	if req.Protocol == "" {
		req.Protocol = "tcp"
	}

	m.mu.Lock()
	tableID, allocErr := m.allocClassIDLocked()
	if allocErr != nil {
		m.mu.Unlock()
		return nil, allocErr
	}
	fwMark := 0x4000 + tableID
	m.mu.Unlock()

	if req.RedirectType == "policy_route" {
		tableStr := strconv.Itoa(tableID)
		markHex := fmt.Sprintf("0x%x", fwMark)
		if isV6 {
			_ = exec.Command("ip", "-6", "route", "replace", "default", "via", destHostIP, "table", tableStr).Run()
			_ = exec.Command("ip", "-6", "rule", "add", "fwmark", markHex, "table", tableStr).Run()
		} else {
			_ = exec.Command("ip", "route", "replace", "default", "via", destHostIP, "table", tableStr).Run()
			_ = exec.Command("ip", "rule", "add", "fwmark", markHex, "table", tableStr).Run()
		}
	}

	now := time.Now().UTC()
	lease := &McpTacticalLease{
		ID:               generateLeaseID(),
		Kind:             "redirect",
		CreatedAt:        now.Format(time.RFC3339),
		ExpiresAt:        now.Add(time.Duration(req.TTLSeconds) * time.Second).Format(time.RFC3339),
		TTLSeconds:       req.TTLSeconds,
		CreatedByKeyID:   req.KeyID,
		CreatedByKeyName: req.KeyName,
		TargetSummary:    fmt.Sprintf("Redirect %s -> %s (%s)", normSource, normDest, req.RedirectType),
		ClassID:          tableID,
		FwMark:           fwMark,
		NormalizedTarget: normSource,
		IsIPv6:           isV6,
		Parameters: map[string]interface{}{
			"source":            normSource,
			"originalDstIp":     req.OriginalDstIP,
			"originalDstPort":   req.OriginalDstPort,
			"protocol":          req.Protocol,
			"redirectType":      req.RedirectType,
			"targetDestination": normDest,
			"masqueradeReturn":  req.MasqueradeReturn,
		},
		Audit: req.Audit,
	}

	m.mu.Lock()
	m.leases[lease.ID] = lease
	// A-L5: the leases map now covers this ID, so the allocation
	// reservation is released (no-op when ClassID is 0).
	m.releaseClassIDLocked(lease.ClassID)
	m.saveStateLocked()
	m.mu.Unlock()

	// A-M13: a lease whose kernel rules failed to land must not be stored,
	// persisted, or returned as active. Remove it, clean up any artifacts
	// applied before the reconcile, and fail the creation; a best-effort
	// healing reconcile rebuilds the table for the remaining leases.
	if err := m.ReconcileKernelState(); err != nil {
		m.mu.Lock()
		delete(m.leases, lease.ID)
		// A-L5: hold the ID reserved until kernel cleanup finishes,
		// so a concurrent creation cannot recycle it underneath
		// cleanupKernelArtifactsForLease (which deletes by ID).
		m.reserveClassIDLocked(lease.ClassID)
		m.saveStateLocked()
		m.mu.Unlock()
		m.cleanupKernelArtifactsForLease(lease)
		m.mu.Lock()
		m.releaseClassIDLocked(lease.ClassID)
		m.mu.Unlock()
		if herr := m.ReconcileKernelState(); herr != nil {
			log.Printf("[MCP Traffic] Warning: healing kernel reconciliation also failed after lease %s creation failure: %v", lease.ID, herr)
		}
		return nil, fmt.Errorf("kernel reconcile failed for lease %s: %w", lease.ID, err)
	}
	return lease, nil
}

// SinkholeDNS creates a TTL-bounded Unbound DNS local-zone override for a malicious domain.
func (m *McpTrafficManager) SinkholeDNS(req McpDnsSinkholeReq) (*McpTacticalLease, error) {
	domain := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(req.Domain), "."))
	if !validDomainRegex.MatchString(domain) {
		return nil, fmt.Errorf("invalid domain name '%s'", req.Domain)
	}
	if strings.HasSuffix(domain, ".axonwall.local") || domain == "localhost" {
		return nil, fmt.Errorf("safety guard rejected DNS sinkhole for internal appliance domain '%s'", domain)
	}
	sinkIP := strings.TrimSpace(req.SinkholeIP)
	if sinkIP == "" {
		sinkIP = "0.0.0.0"
	}
	parsedSinkIP := net.ParseIP(sinkIP)
	if parsedSinkIP == nil || parsedSinkIP.To4() == nil {
		return nil, fmt.Errorf("invalid sinkhole IP '%s': must be a valid IPv4 address", sinkIP)
	}
	if sinkIP != "0.0.0.0" && sinkIP != "127.0.0.1" && !parsedSinkIP.IsPrivate() && !parsedSinkIP.IsLoopback() {
		return nil, fmt.Errorf("disallowed sinkhole IP '%s': must be 0.0.0.0, loopback, or RFC1918 private IPv4", sinkIP)
	}
	if req.TTLSeconds < 10 {
		req.TTLSeconds = 3600
	}

	now := time.Now().UTC()
	lease := &McpTacticalLease{
		ID:               generateLeaseID(),
		Kind:             "dns_sinkhole",
		CreatedAt:        now.Format(time.RFC3339),
		ExpiresAt:        now.Add(time.Duration(req.TTLSeconds) * time.Second).Format(time.RFC3339),
		TTLSeconds:       req.TTLSeconds,
		CreatedByKeyID:   req.KeyID,
		CreatedByKeyName: req.KeyName,
		TargetSummary:    fmt.Sprintf("DNS Sinkhole %s -> %s", domain, sinkIP),
		NormalizedTarget: domain,
		Parameters: map[string]interface{}{
			"domain":            domain,
			"sinkholeIp":        sinkIP,
			"includeSubdomains": req.IncludeSubdomains,
		},
		Audit: req.Audit,
	}

	m.mu.Lock()
	m.leases[lease.ID] = lease
	// A-L5: the leases map now covers this ID, so the allocation
	// reservation is released (no-op when ClassID is 0).
	m.releaseClassIDLocked(lease.ClassID)
	m.saveStateLocked()
	m.mu.Unlock()

	// A-M13: a lease whose kernel rules failed to land must not be stored,
	// persisted, or returned as active. Remove it, clean up any artifacts
	// applied before the reconcile, and fail the creation; a best-effort
	// healing reconcile rebuilds the table for the remaining leases.
	if err := m.ReconcileKernelState(); err != nil {
		m.mu.Lock()
		delete(m.leases, lease.ID)
		// A-L5: hold the ID reserved until kernel cleanup finishes,
		// so a concurrent creation cannot recycle it underneath
		// cleanupKernelArtifactsForLease (which deletes by ID).
		m.reserveClassIDLocked(lease.ClassID)
		m.saveStateLocked()
		m.mu.Unlock()
		m.cleanupKernelArtifactsForLease(lease)
		m.mu.Lock()
		m.releaseClassIDLocked(lease.ClassID)
		m.mu.Unlock()
		if herr := m.ReconcileKernelState(); herr != nil {
			log.Printf("[MCP Traffic] Warning: healing kernel reconciliation also failed after lease %s creation failure: %v", lease.ID, herr)
		}
		return nil, fmt.Errorf("kernel reconcile failed for lease %s: %w", lease.ID, err)
	}
	return lease, nil
}

// RevertLease removes a specific tactical lease by ID and cleans up its kernel state immediately.
func (m *McpTrafficManager) RevertLease(leaseID string) (*McpTacticalLease, error) {
	m.mu.Lock()
	lease, exists := m.leases[leaseID]
	if !exists {
		m.mu.Unlock()
		return nil, fmt.Errorf("tactical lease '%s' not found or already expired", leaseID)
	}
	// M8: rebuild the kernel table WITHOUT the lease first, and only
	// delete the record once the rebuild lands. The old code deleted
	// the record (and saved state) before the rebuild, so a failed
	// rebuild left the lease enforced in the kernel with no record
	// and no way to address it except a daemon restart.
	remaining := make([]*McpTacticalLease, 0, len(m.leases))
	for _, l := range m.activeLeasesLocked() {
		if l.ID != leaseID {
			remaining = append(remaining, l)
		}
	}
	m.mu.Unlock()

	if err := m.reconcileKernelStateWith(remaining); err != nil {
		// A-M13: a failed rebuild means the kernel table may still
		// enforce the lease. A healing rebuild is attempted for the
		// remaining leases; if it also fails, the record is kept so
		// the lease stays listed and revertable.
		if herr := m.reconcileKernelStateWith(remaining); herr != nil {
			log.Printf("[MCP Traffic] Warning: healing kernel reconciliation also failed while reverting lease %s: %v", lease.ID, herr)
			return nil, fmt.Errorf("kernel reconcile failed while reverting lease %s: %w", lease.ID, err)
		}
		log.Printf("[MCP Traffic] Healing kernel reconciliation succeeded while reverting lease %s after an initial failure", lease.ID)
	}

	m.mu.Lock()
	delete(m.leases, leaseID)
	// A-L5: hold the ID reserved until kernel cleanup finishes (see
	// allocClassIDLocked).
	m.reserveClassIDLocked(lease.ClassID)
	m.saveStateLocked()
	m.mu.Unlock()

	m.cleanupKernelArtifactsForLease(lease)
	m.mu.Lock()
	m.releaseClassIDLocked(lease.ClassID)
	m.mu.Unlock()
	return lease, nil
}

// FlushAllLeases is the emergency panic switch: clears all MCP tactical leases and flushes kernel artifacts.
// It returns the number of leases cleared. On a failed kernel rebuild
// it returns 0 and an error: no record is cleared, so the leases stay
// listed and revertable instead of vanishing while the kernel may
// still enforce them (M8).
func (m *McpTrafficManager) FlushAllLeases() (int, error) {
	m.mu.Lock()
	all := make([]*McpTacticalLease, 0, len(m.leases))
	for _, l := range m.leases {
		all = append(all, l)
	}
	m.mu.Unlock()

	// M8: rebuild the kernel table empty FIRST; only when it lands
	// are the records cleared (same reasoning as RevertLease).
	if err := m.reconcileKernelStateWith(nil); err != nil {
		if herr := m.reconcileKernelStateWith(nil); herr != nil {
			log.Printf("[MCP Traffic] Warning: healing kernel reconciliation also failed after flush: %v", herr)
			return 0, fmt.Errorf("kernel reconcile failed while flushing %d leases: %w", len(all), err)
		}
		log.Printf("[MCP Traffic] Healing kernel reconciliation succeeded while flushing after an initial failure")
	}

	m.mu.Lock()
	m.leases = make(map[string]*McpTacticalLease)
	// A-L5: hold every cleared ID reserved until its kernel cleanup
	// finishes (see allocClassIDLocked).
	for _, l := range all {
		m.reserveClassIDLocked(l.ClassID)
	}
	m.saveStateLocked()
	m.mu.Unlock()

	for _, l := range all {
		m.cleanupKernelArtifactsForLease(l)
	}
	m.mu.Lock()
	for _, l := range all {
		m.releaseClassIDLocked(l.ClassID)
	}
	m.mu.Unlock()
	return len(all), nil
}

// QueryActiveFlows parses `/proc/net/nf_conntrack` (or `conntrack -L`) to return live connection flows.
func (m *McpTrafficManager) QueryActiveFlows(srcFilter, dstFilter, protoFilter, stateFilter string, portFilter int, minBytes uint64, limit int) []ConntrackFlow {
	if limit <= 0 || limit > 500 {
		limit = 100
	}

	var lines []string
	if data, err := os.ReadFile("/proc/net/nf_conntrack"); err == nil && len(data) > 0 {
		lines = strings.Split(string(data), "\n")
	} else if out, err := exec.Command("conntrack", "-L").Output(); err == nil && len(out) > 0 {
		lines = strings.Split(string(out), "\n")
	}

	flows := []ConntrackFlow{}
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}

		flow := ConntrackFlow{
			Assured: strings.Contains(line, "[ASSURED]"),
		}
		// Extract protocol (field 2 in nf_conntrack or field 0 in conntrack -L)
		if fields[0] == "ipv4" || fields[0] == "ipv6" {
			if len(fields) > 2 {
				flow.Protocol = fields[2]
			}
			if len(fields) > 5 && !strings.Contains(fields[5], "=") {
				flow.State = fields[5]
			}
		} else {
			flow.Protocol = fields[0]
			if len(fields) > 3 && !strings.Contains(fields[3], "=") {
				flow.State = fields[3]
			}
		}

		seenSrc := false
		seenDst := false
		seenPackets := false
		seenBytes := false

		for _, tok := range fields {
			if !strings.Contains(tok, "=") {
				continue
			}
			kv := strings.SplitN(tok, "=", 2)
			k, v := kv[0], kv[1]
			switch k {
			case "src":
				if !seenSrc {
					flow.SrcIP = v
					seenSrc = true
				}
			case "dst":
				if !seenDst {
					flow.DstIP = v
					seenDst = true
				} else if flow.ReplyDst == "" {
					flow.ReplyDst = v
				}
			case "sport":
				if flow.SrcPort == 0 {
					flow.SrcPort, _ = strconv.Atoi(v)
				}
			case "dport":
				if flow.DstPort == 0 {
					flow.DstPort, _ = strconv.Atoi(v)
				}
			case "packets":
				if !seenPackets {
					flow.Packets, _ = strconv.ParseUint(v, 10, 64)
					seenPackets = true
				}
			case "bytes":
				if !seenBytes {
					flow.Bytes, _ = strconv.ParseUint(v, 10, 64)
					seenBytes = true
				}
			case "mark":
				flow.Mark = v
			}
		}

		if flow.SrcIP == "" || flow.DstIP == "" {
			continue
		}
		if protoFilter != "" && protoFilter != "any" && !strings.EqualFold(flow.Protocol, protoFilter) {
			continue
		}
		if stateFilter != "" && !strings.EqualFold(flow.State, stateFilter) {
			continue
		}
		if srcFilter != "" && flow.SrcIP != srcFilter {
			continue
		}
		if dstFilter != "" && flow.DstIP != dstFilter {
			continue
		}
		if portFilter > 0 && flow.SrcPort != portFilter && flow.DstPort != portFilter {
			continue
		}
		if minBytes > 0 && flow.Bytes < minBytes {
			continue
		}

		flows = append(flows, flow)
	}

	sort.Slice(flows, func(i, j int) bool {
		return flows[i].Bytes > flows[j].Bytes
	})
	if len(flows) > limit {
		flows = flows[:limit]
	}
	return flows
}

// InspectHostContext aggregates ARP neighbor state, DHCP lease metadata, active conntrack sessions,
// recent Suricata EVE alerts, and active MCP tactical leases for a given IP address.
func (m *McpTrafficManager) InspectHostContext(ipStr string) (map[string]interface{}, error) {
	ipStr = strings.TrimSpace(ipStr)
	parsed := net.ParseIP(ipStr)
	if parsed == nil {
		return nil, fmt.Errorf("invalid IP address '%s'", ipStr)
	}
	canonIP := parsed.String()

	result := map[string]interface{}{
		"ipAddress":      canonIP,
		"arpNeighbor":    nil,
		"dhcpLease":      nil,
		"activeFlows":    []ConntrackFlow{},
		"suricataAlerts": []map[string]interface{}{},
		"activeLeases":   []*McpTacticalLease{},
	}

	// 1. Check ARP / NDP table (`ip -j neigh show to <ip>`)
	if out, err := exec.Command("ip", "-j", "neigh", "show", "to", canonIP).Output(); err == nil && len(out) > 0 {
		var neigh []map[string]interface{}
		if json.Unmarshal(out, &neigh) == nil && len(neigh) > 0 {
			result["arpNeighbor"] = neigh[0]
		}
	}

	// 2. Check Kea DHCPv4 leases CSV (/var/lib/kea/kea-leases4.csv)
	if f, err := os.Open("/var/lib/kea/kea-leases4.csv"); err == nil {
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, canonIP+",") {
				parts := strings.Split(line, ",")
				if len(parts) >= 9 {
					result["dhcpLease"] = map[string]string{
						"ip":       parts[0],
						"mac":      parts[1],
						"hostname": parts[8],
						"expire":   parts[4],
					}
				}
			}
		}
		_ = f.Close()
	}

	// 3. Active Conntrack Flows involving this IP
	srcFlows := m.QueryActiveFlows(canonIP, "", "", "", 0, 0, 25)
	dstFlows := m.QueryActiveFlows("", canonIP, "", "", 0, 0, 25)
	result["activeFlows"] = append(srcFlows, dstFlows...)

	// 4. Recent Suricata EVE alerts involving this IP
	if f, err := os.Open("/var/log/suricata/eve.json"); err == nil {
		var alerts []map[string]interface{}
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := scanner.Text()
			if !strings.Contains(line, canonIP) {
				continue
			}
			var ev map[string]interface{}
			if json.Unmarshal([]byte(line), &ev) == nil {
				if ev["src_ip"] == canonIP || ev["dest_ip"] == canonIP {
					alerts = append(alerts, ev)
					if len(alerts) > 50 {
						alerts = alerts[1:]
					}
				}
			}
		}
		_ = f.Close()
		result["suricataAlerts"] = alerts
	}

	// 5. Active MCP tactical leases covering this IP
	activeLeases := []*McpTacticalLease{}
	for _, l := range m.ListLeases() {
		if l.NormalizedTarget == canonIP {
			activeLeases = append(activeLeases, l)
			continue
		}
		if _, cidrNet, err := net.ParseCIDR(l.NormalizedTarget); err == nil && cidrNet.Contains(parsed) {
			activeLeases = append(activeLeases, l)
		}
	}
	result["activeLeases"] = activeLeases

	return result, nil
}

// CapturePacketSample runs a strictly bounded tcpdump packet capture (max 100 packets, max 15s) and returns parsed packets.
func (m *McpTrafficManager) CapturePacketSample(iface, srcIP, dstIP, proto string, port, maxPackets, durationSec int) ([]CapturedPacket, error) {
	if maxPackets < 1 {
		maxPackets = 20
	}
	if maxPackets > 100 {
		maxPackets = 100
	}
	if durationSec < 1 {
		durationSec = 5
	}
	if durationSec > 15 {
		durationSec = 15
	}

	dev := resolveKernelDevice(iface)
	if dev == "" {
		dev = "any"
	}

	var bpfParts []string
	if proto != "" && proto != "any" {
		p := strings.ToLower(proto)
		if p == "tcp" || p == "udp" || p == "icmp" || p == "icmp6" || p == "arp" {
			bpfParts = append(bpfParts, p)
		}
	}
	if srcIP != "" {
		if net.ParseIP(srcIP) == nil {
			return nil, fmt.Errorf("invalid srcIp filter '%s'", srcIP)
		}
		bpfParts = append(bpfParts, fmt.Sprintf("src host %s", srcIP))
	}
	if dstIP != "" {
		if net.ParseIP(dstIP) == nil {
			return nil, fmt.Errorf("invalid dstIp filter '%s'", dstIP)
		}
		bpfParts = append(bpfParts, fmt.Sprintf("dst host %s", dstIP))
	}
	if port > 0 && port <= 65535 {
		bpfParts = append(bpfParts, fmt.Sprintf("port %d", port))
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(durationSec)*time.Second)
	defer cancel()

	args := []string{"-i", dev, "-nn", "-l", "-tt", "-c", strconv.Itoa(maxPackets)}
	if len(bpfParts) > 0 {
		args = append(args, strings.Join(bpfParts, " and "))
	}

	cmd := exec.CommandContext(ctx, "tcpdump", args...)
	out, _ := cmd.Output()

	ipPortRegex := regexp.MustCompile(`^(\d+\.\d+)\s+IP6?\s+([0-9a-fA-F.:]+)\.([0-9]+)\s+>\s+([0-9a-fA-F.:]+)\.([0-9]+):\s+(.*)$`)
	packets := []CapturedPacket{}
	idx := 1

	for _, line := range strings.Split(string(out), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		var pkt CapturedPacket
		pkt.Index = idx
		if matches := ipPortRegex.FindStringSubmatch(trimmed); len(matches) >= 7 {
			tsSec, _ := strconv.ParseFloat(matches[1], 64)
			pkt.Timestamp = time.Unix(int64(tsSec), int64((tsSec-float64(int64(tsSec)))*1e9)).Format("15:04:05.000000")
			pkt.SrcIP = matches[2]
			pkt.SrcPort = matches[3]
			pkt.DstIP = matches[4]
			pkt.DstPort = matches[5]
			pkt.Info = matches[6]
			pkt.Length = len(trimmed)
			if pkt.SrcPort == "53" || pkt.DstPort == "53" {
				pkt.Protocol = "DNS"
			} else if pkt.SrcPort == "443" || pkt.DstPort == "443" {
				pkt.Protocol = "TLS"
			} else if strings.Contains(pkt.Info, "Flags") {
				pkt.Protocol = "TCP"
			} else {
				pkt.Protocol = "UDP"
			}
		} else {
			pkt.Timestamp = time.Now().Format("15:04:05.000000")
			pkt.SrcIP = dev
			pkt.DstIP = "kernel"
			pkt.Protocol = "RAW"
			pkt.Info = trimmed
			pkt.Length = len(trimmed)
		}
		packets = append(packets, pkt)
		idx++
	}

	return packets, nil
}
