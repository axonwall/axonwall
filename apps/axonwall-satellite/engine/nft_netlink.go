package engine

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"syscall"
)

// Netfilter Netlink & nf_tables kernel ABI constants (from <linux/netfilter/nfnetlink.h> and <linux/netfilter/nf_tables.h>)
const (
	nfnetlinkV0        = 0
	nfnlSubsysNftables = 10
	nfnlMsgBatchBegin  = 0x10 // NLMSG_MIN_TYPE
	nfnlMsgBatchEnd    = 0x11 // NLMSG_MIN_TYPE + 1
	nlaFNested         = 0x8000
	nlaFNetByteorder   = 0x4000

	nfprotoUnspec = 0
	nfprotoInet   = 1
	nfprotoIPv4   = 2
	nfprotoIPv6   = 10

	nfInetPreRouting  = 0
	nfInetLocalIn     = 1
	nfInetForward     = 2
	nfInetLocalOut    = 3
	nfInetPostRouting = 4
	nfNetdevIngress   = 0

	nfDrop   = 0
	nfAccept = 1

	// Immediate-verdict codes for non-terminal verdicts (negative values
	// in the kernel's nft_verdict, expressed as uint32).
	nftReturn = 0xfffffffb // NFT_RETURN (-5)
	nftGoto   = 0xfffffffc // NFT_GOTO (-4)
	nftJump   = 0xfffffffd // NFT_JUMP (-3)

	nftRegVerdict = 0
	nftReg1       = 1
	nftReg2       = 2
	nftReg32_00   = 8
	nftReg32_01   = 9

	nftContinue = 0xffffffff // -1 as uint32
	nftBreak    = 0xfffffffe // -2 as uint32

	// nf_tables_msg_types
	nftMsgNewTable     = 0
	nftMsgDelTable     = 2
	nftMsgNewChain     = 3
	nftMsgNewRule      = 6
	nftMsgNewSet       = 9
	nftMsgNewSetElem   = 12
	nftMsgNewFlowtable = 22

	// nft_table_attributes
	nftaTableName  = 1
	nftaTableFlags = 2

	// nft_chain_attributes
	nftaChainTable  = 1
	nftaChainName   = 3
	nftaChainHook   = 4
	nftaChainPolicy = 5
	nftaChainType   = 7

	// nft_hook_attributes
	nftaHookHooknum  = 1
	nftaHookPriority = 2

	// nft_set_attributes
	nftaSetTable   = 1
	nftaSetName    = 2
	nftaSetFlags   = 3
	nftaSetKeyType = 4
	nftaSetKeyLen  = 5
	nftaSetID      = 10

	// nft_set_elem_list_attributes
	nftaSetElemListTable    = 1
	nftaSetElemListSet      = 2
	nftaSetElemListElements = 3

	// nft_set_elem_attributes
	nftaSetElemKey   = 1
	nftaSetElemFlags = 3

	// nft_flowtable_attributes
	nftaFlowtableTable = 1
	nftaFlowtableName  = 2
	nftaFlowtableHook  = 3
	nftaFlowtableFlags = 7

	// nft_flowtable_hook_attributes
	nftaFlowtableHookNum      = 1
	nftaFlowtableHookPriority = 2
	nftaFlowtableHookDevs     = 3

	// nft_device_attributes
	nftaDeviceName = 1

	// nft_rule_attributes
	nftaRuleTable       = 1
	nftaRuleChain       = 2
	nftaRuleExpressions = 4
	nftaRuleUserdata    = 7

	// nft_list_attributes
	nftaListElem = 1

	// nft_expr_attributes
	nftaExprName = 1
	nftaExprData = 2

	// nft_data_attributes & nft_verdict_attributes
	nftaDataValue   = 1
	nftaDataVerdict = 2
	nftaVerdictCode = 1
	nftaVerdictChain = 2

	// nft_reject_types (NFT_REJECT_ICMP_UNREACH / TCP_RST / ICMPX_UNREACH)
	nftRejectIcmpUnreach  = 0
	nftRejectTcpReset     = 1
	nftRejectIcmpxUnreach = 2

	// nft_reject_attributes
	nftaRejectType     = 1
	nftaRejectIcmpCode = 2

	// nft_immediate_attributes
	nftaImmediateDreg = 1
	nftaImmediateData = 2

	// nft_meta_attributes & keys
	nftaMetaDreg   = 1
	nftaMetaKey    = 2
	nftMetaIIfName = 6
	nftMetaOIfName = 7
	nftMetaNFProto = 16
	nftMetaL4Proto = 17

	// nft_payload_attributes & bases
	nftaPayloadDreg           = 1
	nftaPayloadBase           = 2
	nftaPayloadOffset         = 3
	nftaPayloadLen            = 4
	nftPayloadLLHeader        = 0
	nftPayloadNetworkHeader   = 1
	nftPayloadTransportHeader = 2

	// nft_cmp_attributes & ops
	nftaCmpSreg = 1
	nftaCmpOp   = 2
	nftaCmpData = 3
	nftCmpEq    = 0

	// nft_lookup_attributes
	nftaLookupSet  = 1
	nftaLookupSreg = 2

	// nft_bitwise_attributes
	nftaBitwiseSreg = 1
	nftaBitwiseDreg = 2
	nftaBitwiseLen  = 3
	nftaBitwiseMask = 4
	nftaBitwiseXor  = 5

	// nft_ct_attributes & keys
	nftaCtDreg = 1
	nftaCtKey  = 2
	nftCtState = 0
	// nf_conntrack state bitmask values:
	// IP_CT_ESTABLISHED=0 (bit 1 -> 2), IP_CT_RELATED=1 (bit 2 -> 4), IP_CT_NEW=2 (bit 3 -> 8), INVALID=bit 0 -> 1
	nfCtStateInvalidBit     = 1 << 0
	nfCtStateEstablishedBit = (1 << 1) | (1 << 2) // ESTABLISHED | RELATED
	nfCtStateNewBit         = 1 << 3

	// nft_limit_attributes
	nftaLimitRate  = 1
	nftaLimitUnit  = 2
	nftaLimitBurst = 3
	nftaLimitType  = 4

	// nft_log_attributes
	nftaLogPrefix = 2
	nftaLogLevel  = 5

	// nft_masq_attributes
	nftaMasqFlags = 1

	// nft_offload_attributes
	nftaFlowTableName = 1
)

// NftCompiledBatch holds the serialized netlink messages for an atomic nf_tables transaction.
type NftCompiledBatch struct {
	TableName  string
	Sets       []NftSetSpec
	Flowtables []NftFlowtableSpec
	Chains     []NftChainSpec
	Rules      []NftRuleSpec
	RawMsgs    [][]byte
}

type NftSetSpec struct {
	Name     string
	KeyType  string // ipv4_addr, ipv6_addr, ether_addr
	KeyLen   uint32
	Interval bool
	SetID    uint32
	// ElementSpecs holds the raw `elements = { ... }` entries as written
	// in the script; Elements holds the same entries resolved to key
	// bytes (with End set for interval elements) once the set closes.
	ElementSpecs []string
	Elements     []NftSetElement
}

// NftSetElement is one initial element of a named set: a single key, or a
// half-open interval [Key, End) for interval sets (CIDRs and ranges).
type NftSetElement struct {
	Key []byte
	End []byte // nil for a singleton element
}

type NftFlowtableSpec struct {
	Name      string
	HookNum   uint32
	Priority  int32
	Devices   []string
	HwOffload bool
}

type NftChainSpec struct {
	Name     string
	Type     string // filter, nat
	Hook     string // input, forward, output, postrouting
	HookNum  uint32
	Priority int32
	Policy   uint32 // nfAccept or nfDrop
}

type NftRuleSpec struct {
	Chain       string
	RawLine     string
	Comment     string
	Expressions [][]byte
}

// splitSetElementEntries splits a raw `elements = { ... }` body on commas,
// dropping empty entries and trailing semicolons/quotes.
func splitSetElementEntries(body string) []string {
	var out []string
	for _, e := range strings.Split(body, ",") {
		e = strings.TrimSpace(e)
		e = strings.TrimSuffix(e, ";")
		e = strings.Trim(e, `"`)
		e = strings.TrimSpace(e)
		if e != "" {
			out = append(out, e)
		}
	}
	return out
}

// resolveSetElements converts a set's raw element strings into key bytes
// once the set's key type is known. CIDRs and ranges become half-open
// intervals [network, broadcast+1); singletons in an interval set become
// [addr, addr+1), matching AddSetElementNetlink. A prefix or range in a
// non-interval set is an error: the kernel would reject it, so failing
// compilation (and falling back to the nft binary) is the honest outcome.
func resolveSetElements(s *NftSetSpec) error {
	if len(s.ElementSpecs) == 0 {
		return nil
	}
	keyLen := int(s.KeyLen)
	if keyLen == 0 {
		// No `type` line was seen; mirror the serializer's ipv4 default.
		s.KeyType = "ipv4_addr"
		s.KeyLen = 4
		keyLen = 4
	}
	parseKey := func(text string) ([]byte, error) {
		switch s.KeyType {
		case "ipv6_addr":
			ip := net.ParseIP(text)
			if ip == nil || ip.To4() != nil {
				return nil, fmt.Errorf("invalid IPv6 address %q", text)
			}
			return []byte(ip.To16()), nil
		case "ether_addr":
			hw, err := net.ParseMAC(text)
			if err != nil {
				return nil, fmt.Errorf("invalid MAC %q: %w", text, err)
			}
			return []byte(hw), nil
		default:
			ip := net.ParseIP(text)
			if ip == nil || ip.To4() == nil {
				return nil, fmt.Errorf("invalid IPv4 address %q", text)
			}
			return []byte(ip.To4()), nil
		}
	}
	for _, entry := range s.ElementSpecs {
		if strings.Contains(entry, " - ") || (strings.Contains(entry, "-") && !strings.Contains(entry, "/") && !strings.Contains(entry, ":")) {
			// Range `10.0.0.1 - 10.0.0.10` (the "-" check excludes
			// IPv6 addresses and CIDRs, which contain ":" or "/").
			parts := strings.SplitN(entry, "-", 2)
			if len(parts) != 2 {
				return fmt.Errorf("malformed set element range %q", entry)
			}
			if !s.Interval {
				return fmt.Errorf("range element %q requires an interval set", entry)
			}
			start, err := parseKey(strings.TrimSpace(parts[0]))
			if err != nil {
				return err
			}
			endIP, err := parseKey(strings.TrimSpace(parts[1]))
			if err != nil {
				return err
			}
			end, ok := incrementIPBytes(endIP)
			if !ok {
				return fmt.Errorf("range element %q overflows the address space", entry)
			}
			s.Elements = append(s.Elements, NftSetElement{Key: start, End: end})
			continue
		}
		if strings.Contains(entry, "/") {
			_, ipNet, err := net.ParseCIDR(entry)
			if err != nil {
				return fmt.Errorf("invalid CIDR element %q: %w", entry, err)
			}
			if !s.Interval {
				return fmt.Errorf("CIDR element %q requires an interval set", entry)
			}
			start := []byte(ipNet.IP)
			if len(start) != keyLen {
				// net.ParseCIDR returns a 4-byte IP for v4 CIDRs and
				// 16-byte for v6; normalize to the set's key length.
				if ip4 := ipNet.IP.To4(); ip4 != nil && keyLen == 4 {
					start = []byte(ip4)
				} else if keyLen == 16 {
					start = []byte(ipNet.IP.To16())
				} else {
					return fmt.Errorf("CIDR element %q does not match set key length %d", entry, keyLen)
				}
			}
			mask := []byte(ipNet.Mask)
			if len(mask) != keyLen {
				return fmt.Errorf("CIDR element %q does not match set key length %d", entry, keyLen)
			}
			last := make([]byte, keyLen)
			for i := range start {
				last[i] = start[i] | ^mask[i]
			}
			end, ok := incrementIPBytes(last)
			if !ok {
				return fmt.Errorf("CIDR element %q covers the whole address space", entry)
			}
			s.Elements = append(s.Elements, NftSetElement{Key: start, End: end})
			continue
		}
		key, err := parseKey(entry)
		if err != nil {
			return err
		}
		if len(key) != keyLen {
			return fmt.Errorf("set element %q does not match set key length %d", entry, keyLen)
		}
		el := NftSetElement{Key: key}
		if s.Interval {
			end, ok := incrementIPBytes(key)
			if !ok {
				return fmt.Errorf("set element %q overflows the address space", entry)
			}
			el.End = end
		}
		s.Elements = append(s.Elements, el)
	}
	return nil
}

// CompileNftScriptToNetlinkBatch parses an Axonwall nftables script (emergency lockdown or
// satellite/edge-ngfw policy) into an atomic sequence of NETLINK_NETFILTER messages.
// It requires zero userland binaries (/usr/sbin/nft) or C libraries.
func CompileNftScriptToNetlinkBatch(script string) (*NftCompiledBatch, error) {
	batch := &NftCompiledBatch{
		TableName: "axonwall",
	}

	lines := strings.Split(script, "\n")
	inTable := false
	inSet := ""
	var curSet NftSetSpec
	inFlowtable := ""
	var curFt NftFlowtableSpec
	inChain := ""
	var curChain NftChainSpec
	nextSetID := uint32(1)
	inElements := false
	var elemBuf strings.Builder

	for _, rawLine := range lines {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") || line == "flush ruleset" {
			continue
		}

		// Strip inline comments if outside quotes
		if strings.HasPrefix(line, "table inet ") {
			fields := strings.Fields(line)
			if len(fields) >= 3 {
				batch.TableName = strings.TrimSuffix(fields[2], "{")
			}
			inTable = true
			continue
		}

		if !inTable {
			continue
		}

		if inSet != "" {
			// A-H7 (round 2): `elements = { ... }` inside a set block
			// used to be discarded, so the set was created empty and
			// blocklists failed open. Accumulate the element list
			// (which may span lines) and resolve it when the set closes.
			if inElements {
				if idx := strings.Index(line, "}"); idx >= 0 {
					elemBuf.WriteString(line[:idx])
					curSet.ElementSpecs = append(curSet.ElementSpecs, splitSetElementEntries(elemBuf.String())...)
					elemBuf.Reset()
					inElements = false
					// A trailing "}" on the same line closes the set itself.
					if strings.TrimSpace(line[idx+1:]) == "}" {
						if err := resolveSetElements(&curSet); err != nil {
							return nil, fmt.Errorf("set %s: %w", curSet.Name, err)
						}
						batch.Sets = append(batch.Sets, curSet)
						inSet = ""
					}
				} else {
					elemBuf.WriteString(line)
					elemBuf.WriteString(",")
				}
				continue
			}
			if line == "}" {
				if err := resolveSetElements(&curSet); err != nil {
					return nil, fmt.Errorf("set %s: %w", curSet.Name, err)
				}
				batch.Sets = append(batch.Sets, curSet)
				inSet = ""
				continue
			}
			if strings.HasPrefix(line, "type ") {
				t := strings.TrimSuffix(strings.TrimPrefix(line, "type "), ";")
				t = strings.TrimSpace(t)
				curSet.KeyType = t
				switch t {
				case "ipv4_addr":
					curSet.KeyLen = 4
				case "ipv6_addr":
					curSet.KeyLen = 16
				case "ether_addr":
					curSet.KeyLen = 6
				default:
					curSet.KeyLen = 4
				}
			} else if strings.Contains(line, "interval") {
				curSet.Interval = true
			} else if strings.HasPrefix(line, "elements") {
				rest := strings.TrimSpace(strings.TrimPrefix(line, "elements"))
				rest = strings.TrimSpace(strings.TrimPrefix(rest, "="))
				openIdx := strings.Index(rest, "{")
				if openIdx < 0 {
					return nil, fmt.Errorf("set %s: malformed elements line %q", curSet.Name, line)
				}
				rest = rest[openIdx+1:]
				if closeIdx := strings.Index(rest, "}"); closeIdx >= 0 {
					curSet.ElementSpecs = append(curSet.ElementSpecs, splitSetElementEntries(rest[:closeIdx])...)
					// A trailing "}" on the same line closes the set itself.
					if strings.TrimSpace(rest[closeIdx+1:]) == "}" {
						if err := resolveSetElements(&curSet); err != nil {
							return nil, fmt.Errorf("set %s: %w", curSet.Name, err)
						}
						batch.Sets = append(batch.Sets, curSet)
						inSet = ""
					}
				} else {
					elemBuf.WriteString(rest)
					elemBuf.WriteString(",")
					inElements = true
				}
			}
			continue
		}

		if inFlowtable != "" {
			if line == "}" {
				batch.Flowtables = append(batch.Flowtables, curFt)
				inFlowtable = ""
				continue
			}
			if strings.HasPrefix(line, "hook ") {
				curFt.HookNum = nfNetdevIngress
				curFt.Priority = 0
			} else if strings.HasPrefix(line, "flags ") && strings.Contains(line, "offload") {
				curFt.HwOffload = true
			} else if strings.HasPrefix(line, "devices") {
				idxOpen := strings.Index(line, "{")
				idxClose := strings.Index(line, "}")
				if idxOpen >= 0 && idxClose > idxOpen {
					devList := line[idxOpen+1 : idxClose]
					for _, d := range strings.Split(devList, ",") {
						clean := strings.Trim(strings.TrimSpace(d), `"`)
						if clean != "" {
							curFt.Devices = append(curFt.Devices, clean)
						}
					}
				}
			}
			continue
		}

		if inChain != "" {
			if line == "}" {
				batch.Chains = append(batch.Chains, curChain)
				inChain = ""
				continue
			}
			if strings.HasPrefix(line, "type ") && strings.Contains(line, "hook ") {
				parseChainHeader(line, &curChain)
				continue
			}
			ruleSpecs, err := compileRuleLines(curChain.Name, line)
			if err != nil {
				return nil, fmt.Errorf("chain %s rule %q: %w", curChain.Name, line, err)
			}
			batch.Rules = append(batch.Rules, ruleSpecs...)
			continue
		}

		if strings.HasPrefix(line, "set ") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				inSet = strings.TrimSuffix(fields[1], "{")
				curSet = NftSetSpec{
					Name:  inSet,
					SetID: nextSetID,
				}
				nextSetID++
			}
			continue
		}

		if strings.HasPrefix(line, "flowtable ") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				inFlowtable = strings.TrimSuffix(fields[1], "{")
				curFt = NftFlowtableSpec{
					Name: inFlowtable,
				}
			}
			continue
		}

		if strings.HasPrefix(line, "chain ") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				inChain = strings.TrimSuffix(fields[1], "{")
				curChain = NftChainSpec{
					Name:   inChain,
					Type:   "filter",
					Policy: nfAccept,
				}
			}
			continue
		}
	}

	if len(batch.Chains) == 0 {
		return nil, fmt.Errorf("nftables script contained no valid chains")
	}

	batch.RawMsgs = serializeNftBatch(batch)
	return batch, nil
}

func parseChainHeader(line string, ch *NftChainSpec) {
	// e.g. "type filter hook input priority filter; policy drop;"
	semiParts := strings.Split(line, ";")
	for _, part := range semiParts {
		part = strings.TrimSpace(part)
		fields := strings.Fields(part)
		for i := 0; i < len(fields); i++ {
			switch fields[i] {
			case "type":
				if i+1 < len(fields) {
					ch.Type = fields[i+1]
				}
			case "hook":
				if i+1 < len(fields) {
					ch.Hook = fields[i+1]
					switch ch.Hook {
					case "prerouting":
						ch.HookNum = nfInetPreRouting
					case "input":
						ch.HookNum = nfInetLocalIn
					case "forward":
						ch.HookNum = nfInetForward
					case "output":
						ch.HookNum = nfInetLocalOut
					case "postrouting":
						ch.HookNum = nfInetPostRouting
					}
				}
			case "priority":
				if i+1 < len(fields) {
					switch fields[i+1] {
					case "srcnat":
						ch.Priority = 100
					case "dstnat":
						ch.Priority = -100
					default:
						ch.Priority = 0
					}
				}
			case "policy":
				if i+1 < len(fields) {
					if fields[i+1] == "drop" {
						ch.Policy = nfDrop
					} else {
						ch.Policy = nfAccept
					}
				}
			}
		}
	}
}

// compileRuleLines translates a single nftables rule line into kernel nf_tables expression TLVs.
// A line containing a set literal over ports or protocols (e.g. `tcp dport { 80, 443 }`
// or `meta l4proto { tcp, udp }`) expands to one rule per value: the rules are
// sequential with the same verdict, so the expansion enforces exactly the written match.
func compileRuleLines(chainName, line string) ([]NftRuleSpec, error) {
	spec := NftRuleSpec{
		Chain:   chainName,
		RawLine: line,
	}

	// Extract optional comment "..."
	work := line
	if idx := strings.Index(work, `comment "`); idx >= 0 {
		rest := work[idx+len(`comment "`):]
		if endQuote := strings.Index(rest, `"`); endQuote >= 0 {
			spec.Comment = rest[:endQuote]
			work = strings.TrimSpace(work[:idx] + " " + rest[endQuote+1:])
		}
	}

	var baseExprs [][]byte

	// Extract optional log prefix "..."
	if idx := strings.Index(work, `log prefix "`); idx >= 0 {
		rest := work[idx+len(`log prefix "`):]
		if endQuote := strings.Index(rest, `"`); endQuote >= 0 {
			prefix := rest[:endQuote]
			baseExprs = append(baseExprs, buildExprLog(prefix))
			work = strings.TrimSpace(work[:idx] + " " + rest[endQuote+1:])
		}
	}

	variants, err := expandRuleTokenSets(tokenizeNftLine(work))
	if err != nil {
		return nil, err
	}
	specs := make([]NftRuleSpec, 0, len(variants))
	for _, variant := range variants {
		s, err := compileRuleTokens(chainName, strings.Join(variant, " "), spec, baseExprs, variant)
		if err != nil {
			return nil, err
		}
		specs = append(specs, s)
	}
	return specs, nil
}

// expandRuleTokenSets expands set literals over ports/protocols in a rule's
// token list into one token list per value (cartesian across groups, capped
// at 16 variants). Groups the compiler handles in a single rule — `ct
// state { ... }` and `icmpv6 type { ... }` — are left untouched, as are
// groups in any other position, so their existing handling still applies.
func expandRuleTokenSets(tokens []string) ([][]string, error) {
	variants := [][]string{append([]string(nil), tokens...)}
	offset := 0 // shift of indices in variants relative to tokens
	i := 0
	for i < len(tokens) {
		if tokens[i] != "{" {
			i++
			continue
		}
		j := i + 1
		for j < len(tokens) && tokens[j] != "}" {
			j++
		}
		if j >= len(tokens) {
			return nil, fmt.Errorf("unterminated set in rule")
		}
		values, ok := expandableSetGroup(tokens, i, j)
		if !ok {
			i = j + 1
			continue
		}
		var next [][]string
		for _, v := range variants {
			for _, val := range values {
				nv := make([]string, 0, len(v)-(j-i))
				nv = append(nv, v[:i+offset]...)
				nv = append(nv, val)
				nv = append(nv, v[j+offset+1:]...)
				next = append(next, nv)
			}
		}
		if len(next) > 16 {
			return nil, fmt.Errorf("rule expands to %d variants (requires nft binary fallback)", len(next))
		}
		variants = next
		offset -= j - i
		i = j + 1
	}
	return variants, nil
}

// expandableSetGroup reports whether the `{ ... }` group opening at openIdx
// (closing at closeIdx) is a port or protocol set the compiler can expand,
// and returns its values with trailing commas stripped.
func expandableSetGroup(tokens []string, openIdx, closeIdx int) ([]string, bool) {
	if openIdx < 1 {
		return nil, false
	}
	prev := tokens[openIdx-1]
	switch prev {
	case "dport", "sport":
		if openIdx < 2 || (tokens[openIdx-2] != "tcp" && tokens[openIdx-2] != "udp") {
			return nil, false
		}
	case "l4proto":
		if openIdx < 2 || tokens[openIdx-2] != "meta" {
			return nil, false
		}
	default:
		return nil, false
	}
	var values []string
	for _, v := range tokens[openIdx+1 : closeIdx] {
		v = strings.TrimSuffix(v, ",")
		if v != "" {
			values = append(values, v)
		}
	}
	if len(values) == 0 {
		return nil, false
	}
	return values, true
}

// compileRuleTokens translates one (already set-expanded) rule line into a
// rule spec. `line` is the expanded line; `spec` carries the chain and
// comment from the original line, and `baseExprs` the log expression
// extracted before expansion.
func compileRuleTokens(chainName, line string, spec NftRuleSpec, baseExprs [][]byte, tokens []string) (NftRuleSpec, error) {
	spec.RawLine = line
	exprs := append([][]byte(nil), baseExprs...)
	i := 0
	for i < len(tokens) {
		tok := tokens[i]
		switch tok {
		case "iif", "iifname":
			if i+1 >= len(tokens) {
				return spec, fmt.Errorf("missing interface name after %s", tok)
			}
			dev := strings.Trim(tokens[i+1], `"`)
			exprs = append(exprs,
				buildExprMetaLoad(nftMetaIIfName, nftReg1),
				buildExprCmpEq(nftReg1, encodeIfnameBytes(dev)),
			)
			i += 2

		case "oif", "oifname":
			if i+1 >= len(tokens) {
				return spec, fmt.Errorf("missing interface name after %s", tok)
			}
			dev := strings.Trim(tokens[i+1], `"`)
			exprs = append(exprs,
				buildExprMetaLoad(nftMetaOIfName, nftReg1),
				buildExprCmpEq(nftReg1, encodeIfnameBytes(dev)),
			)
			i += 2

		case "ip":
			if i+2 >= len(tokens) {
				return spec, fmt.Errorf("incomplete ip match")
			}
			field := tokens[i+1]
			target := tokens[i+2]
			offset := uint32(12) // IPv4 saddr offset
			if field == "daddr" {
				offset = 16 // IPv4 daddr offset
			}
			exprs = append(exprs,
				buildExprMetaLoad(nftMetaNFProto, nftReg1),
				buildExprCmpEq(nftReg1, []byte{nfprotoIPv4}),
				buildExprPayloadLoad(nftPayloadNetworkHeader, offset, 4, nftReg1),
			)
			if strings.HasPrefix(target, "@") {
				exprs = append(exprs, buildExprLookup(strings.TrimPrefix(target, "@"), nftReg1))
			} else if strings.Contains(target, "/") {
				// A-M36 (round 2): a CIDR match used to fail the whole
				// ruleset ("invalid IPv4 address"). Compile it as a
				// masked compare: payload & mask == network.
				_, ipNet, err := net.ParseCIDR(target)
				if err != nil {
					return spec, fmt.Errorf("invalid IPv4 address or prefix %q", target)
				}
				network := ipNet.IP.To4()
				if network == nil {
					return spec, fmt.Errorf("invalid IPv4 prefix %q", target)
				}
				exprs = append(exprs,
					buildExprBitwiseMaskBytes(nftReg1, nftReg1, []byte(ipNet.Mask)),
					buildExprCmpEq(nftReg1, network),
				)
			} else {
				ip := net.ParseIP(target).To4()
				if ip == nil {
					return spec, fmt.Errorf("invalid IPv4 address %q", target)
				}
				exprs = append(exprs, buildExprCmpEq(nftReg1, ip))
			}
			i += 3

		case "ip6":
			if i+2 >= len(tokens) {
				return spec, fmt.Errorf("incomplete ip6 match")
			}
			field := tokens[i+1]
			target := tokens[i+2]
			offset := uint32(8) // IPv6 saddr offset
			if field == "daddr" {
				offset = 24 // IPv6 daddr offset
			}
			exprs = append(exprs,
				buildExprMetaLoad(nftMetaNFProto, nftReg1),
				buildExprCmpEq(nftReg1, []byte{nfprotoIPv6}),
				buildExprPayloadLoad(nftPayloadNetworkHeader, offset, 16, nftReg1),
			)
			if strings.HasPrefix(target, "@") {
				exprs = append(exprs, buildExprLookup(strings.TrimPrefix(target, "@"), nftReg1))
			} else if strings.Contains(target, "/") {
				// A-M36 (round 2): see the `ip` case above.
				_, ipNet, err := net.ParseCIDR(target)
				if err != nil {
					return spec, fmt.Errorf("invalid IPv6 address or prefix %q", target)
				}
				network := ipNet.IP.To16()
				if network == nil || len(ipNet.Mask) != 16 {
					return spec, fmt.Errorf("invalid IPv6 prefix %q", target)
				}
				exprs = append(exprs,
					buildExprBitwiseMaskBytes(nftReg1, nftReg1, []byte(ipNet.Mask)),
					buildExprCmpEq(nftReg1, network),
				)
			} else {
				ip := net.ParseIP(target).To16()
				if ip == nil {
					return spec, fmt.Errorf("invalid IPv6 address %q", target)
				}
				exprs = append(exprs, buildExprCmpEq(nftReg1, ip))
			}
			i += 3

		case "ether":
			if i+2 >= len(tokens) {
				return spec, fmt.Errorf("incomplete ether match")
			}
			target := tokens[i+2]
			exprs = append(exprs,
				buildExprPayloadLoad(nftPayloadLLHeader, 6, 6, nftReg1),
			)
			if strings.HasPrefix(target, "@") {
				exprs = append(exprs, buildExprLookup(strings.TrimPrefix(target, "@"), nftReg1))
			} else {
				hw, err := net.ParseMAC(target)
				if err != nil {
					return spec, fmt.Errorf("invalid MAC %q: %w", target, err)
				}
				exprs = append(exprs, buildExprCmpEq(nftReg1, hw))
			}
			i += 3

		case "meta":
			if i+2 >= len(tokens) {
				return spec, fmt.Errorf("incomplete meta expression")
			}
			metaKey := tokens[i+1]
			if metaKey == "nfproto" {
				nfTok := tokens[i+2]
				var nfNum byte = nfprotoIPv6
				if nfTok == "ipv4" || nfTok == "ip" {
					nfNum = nfprotoIPv4
				}
				exprs = append(exprs,
					buildExprMetaLoad(nftMetaNFProto, nftReg1),
					buildExprCmpEq(nftReg1, []byte{nfNum}),
				)
				i += 3
				continue
			}
			if metaKey != "l4proto" {
				return spec, fmt.Errorf("unsupported meta expression %q", metaKey)
			}
			protoTok := tokens[i+2]
			if protoTok == "{" {
				if !strings.Contains(line, "flow add ") && !strings.Contains(line, "flow offload ") {
					return spec, fmt.Errorf("unsupported meta l4proto set in native netlink compiler (requires nft binary fallback)")
				}
				// Skip until closing "}" for flowtable offload rules
				for i < len(tokens) && tokens[i] != "}" {
					i++
				}
				if i < len(tokens) {
					i++
				}
				continue
			}
			var protoNum byte = 58 // ipv6-icmp default
			switch protoTok {
			case "tcp":
				protoNum = syscall.IPPROTO_TCP
			case "udp":
				protoNum = syscall.IPPROTO_UDP
			case "icmp":
				protoNum = syscall.IPPROTO_ICMP
			case "ipv6-icmp":
				protoNum = syscall.IPPROTO_ICMPV6
			default:
				return spec, fmt.Errorf("unsupported meta l4proto %q", protoTok)
			}
			exprs = append(exprs,
				buildExprMetaLoad(nftMetaL4Proto, nftReg1),
				buildExprCmpEq(nftReg1, []byte{protoNum}),
			)
			i += 3

		case "icmpv6":
			exprs = append(exprs,
				buildExprMetaLoad(nftMetaL4Proto, nftReg1),
				buildExprCmpEq(nftReg1, []byte{syscall.IPPROTO_ICMPV6}),
			)
			i++
			if i < len(tokens) && tokens[i] == "type" {
				i++
				if i < len(tokens) && tokens[i] == "{" {
					if strings.Contains(line, " drop") || strings.Contains(line, " reject") {
						return spec, fmt.Errorf("icmpv6 type set with drop/reject requires nft binary fallback")
					}
					for i < len(tokens) && tokens[i] != "}" {
						i++
					}
					if i < len(tokens) {
						i++
					}
				} else if i < len(tokens) {
					icmpv6TypeByte, ok := parseICMPv6TypeByte(tokens[i])
					if !ok {
						return spec, fmt.Errorf("unsupported icmpv6 type %q (requires nft binary fallback)", tokens[i])
					}
					exprs = append(exprs,
						buildExprPayloadLoad(nftPayloadTransportHeader, 0, 1, nftReg1),
						buildExprCmpEq(nftReg1, []byte{icmpv6TypeByte}),
					)
					i++
				}
			}

		case "tcp", "udp":
			if i+2 >= len(tokens) {
				return spec, fmt.Errorf("incomplete %s port match", tok)
			}
			protoNum := byte(syscall.IPPROTO_TCP)
			if tok == "udp" {
				protoNum = byte(syscall.IPPROTO_UDP)
			}
			portField := tokens[i+1]
			portVal, err := strconv.Atoi(tokens[i+2])
			if err != nil || portVal < 1 || portVal > 65535 {
				return spec, fmt.Errorf("invalid port %q", tokens[i+2])
			}
			offset := uint32(2) // dport offset in TCP/UDP header
			if portField == "sport" {
				offset = 0
			}
			var portBytes [2]byte
			binary.BigEndian.PutUint16(portBytes[:], uint16(portVal))
			exprs = append(exprs,
				buildExprMetaLoad(nftMetaL4Proto, nftReg1),
				buildExprCmpEq(nftReg1, []byte{protoNum}),
				buildExprPayloadLoad(nftPayloadTransportHeader, offset, 2, nftReg1),
				buildExprCmpEq(nftReg1, portBytes[:]),
			)
			i += 3

		case "ct":
			if i+2 >= len(tokens) || tokens[i+1] != "state" {
				return spec, fmt.Errorf("unsupported ct expression")
			}
			// A-H8 (round 2): the mask used to be built by starting from
			// ESTABLISHED|RELATED and only switching to INVALID, so
			// `ct state new` compiled to established|related — the
			// exact inverse of the written rule. Build the mask from
			// the named states instead, and fail on an unknown name
			// rather than silently defaulting.
			var mask uint32
			consumed := 3
			if tokens[i+2] == "{" {
				// `ct state { established, new }`
				j := i + 3
				for j < len(tokens) && tokens[j] != "}" {
					bit, ok := ctStateBit(strings.TrimSuffix(tokens[j], ","))
					if !ok {
						return spec, fmt.Errorf("unsupported ct state %q", tokens[j])
					}
					mask |= bit
					j++
				}
				if j >= len(tokens) {
					return spec, fmt.Errorf("unterminated ct state set")
				}
				consumed = j - i + 1
			} else {
				// `ct state new` or `ct state established,related,new`
				for _, name := range strings.Split(tokens[i+2], ",") {
					bit, ok := ctStateBit(name)
					if !ok {
						return spec, fmt.Errorf("unsupported ct state %q", name)
					}
					mask |= bit
				}
			}
			if mask == 0 {
				return spec, fmt.Errorf("empty ct state match")
			}
			exprs = append(exprs,
				buildExprCtLoad(nftCtState, nftReg1),
				buildExprBitwiseMask(nftReg1, nftReg1, mask),
				buildExprCmpNeqZero(nftReg1),
			)
			i += consumed

		case "limit":
			// e.g. limit rate 10/second
			if i+2 < len(tokens) && tokens[i+1] == "rate" {
				rateStr := tokens[i+2]
				rateParts := strings.SplitN(rateStr, "/", 2)
				rateVal, _ := strconv.ParseUint(rateParts[0], 10, 64)
				if rateVal == 0 {
					rateVal = 10
				}
				exprs = append(exprs, buildExprLimit(rateVal, 1))
				i += 3
				continue
			}
			i++

		case "flow":
			// e.g. flow add @fastpath
			if i+2 < len(tokens) && (tokens[i+1] == "add" || tokens[i+1] == "offload") {
				ftName := strings.TrimPrefix(tokens[i+2], "@")
				exprs = append(exprs, buildExprFlowOffload(ftName))
				i += 3
				continue
			}
			i++

		case "masquerade":
			exprs = append(exprs, buildExprMasq())
			i++

		case "dnat":
			// e.g. dnat ip to 10.0.0.2:443 or dnat to 10.0.0.2:443
			i++
			if i < len(tokens) && (tokens[i] == "ip" || tokens[i] == "ip6") {
				i++
			}
			if i < len(tokens) && tokens[i] == "to" {
				i++
			}
			if i >= len(tokens) {
				return spec, fmt.Errorf("missing target after dnat")
			}
			dnatTarget := tokens[i]
			hostStr, portStr, err := net.SplitHostPort(dnatTarget)
			if err != nil {
				hostStr = dnatTarget
			}
			ip := net.ParseIP(hostStr)
			if ip == nil || ip.To4() == nil {
				return spec, fmt.Errorf("invalid dnat IPv4 target %q", dnatTarget)
			}
			exprs = append(exprs, buildExprImmediateData(nftReg1, ip.To4()))
			hasPort := false
			if portStr != "" {
				if pVal, err := strconv.Atoi(portStr); err == nil && pVal >= 1 && pVal <= 65535 {
					var pb [2]byte
					binary.BigEndian.PutUint16(pb[:], uint16(pVal))
					exprs = append(exprs, buildExprImmediateData(nftReg2, pb[:]))
					hasPort = true
				}
			}
			exprs = append(exprs, buildExprDnatIPv4(nftReg1, nftReg2, hasPort))
			i++

		case "accept":
			exprs = append(exprs, buildExprVerdict(nfAccept))
			i++

		case "drop":
			exprs = append(exprs, buildExprVerdict(nfDrop))
			i++

		case "reject":
			// A-M36 (round 2): a bare `reject` used to fail the whole
			// ruleset. Emit a real reject expression (ICMP port
			// unreachable by default); `reject with tcp reset` sends a
			// TCP RST instead. Any other `reject with ...` form still
			// fails loudly so the nft binary fallback applies.
			rejectType := uint32(nftRejectIcmpUnreach)
			withCode := true
			if i+3 < len(tokens) && tokens[i+1] == "with" && tokens[i+2] == "tcp" && tokens[i+3] == "reset" {
				rejectType = nftRejectTcpReset
				withCode = false
				i += 4
			} else if i+1 < len(tokens) && tokens[i+1] == "with" {
				return spec, fmt.Errorf("unsupported reject form %q (requires nft binary fallback)", strings.Join(tokens[i:], " "))
			} else {
				i++
			}
			exprs = append(exprs, buildExprReject(rejectType, 3, withCode))

		case "return":
			exprs = append(exprs, buildExprVerdict(nftReturn))
			i++

		case "jump", "goto":
			if i+1 >= len(tokens) {
				return spec, fmt.Errorf("missing chain name after %s", tok)
			}
			code := uint32(nftJump)
			if tok == "goto" {
				code = nftGoto
			}
			exprs = append(exprs, buildExprVerdictChain(code, tokens[i+1]))
			i += 2

		case "log":
			// A-M36 (round 2): a bare `log` (or `log level ...`) used
			// to fail the whole ruleset. Logging is non-load-bearing:
			// skip the statement (with a warning) instead of changing
			// enforcement. The quoted `log prefix "..."` form was
			// already extracted into a log expression above.
			slog.Warn("Native nft compiler drops non-load-bearing log statement", "rule", line)
			i++
			if i < len(tokens) && (tokens[i] == "level" || tokens[i] == "prefix") {
				i += 2 // skip the keyword and its value
			}

		case "counter":
			i++

		default:
			return spec, fmt.Errorf("unsupported nftables token %q in native netlink compiler", tok)
		}
	}

	if len(exprs) == 0 {
		return spec, fmt.Errorf("rule produced zero expressions")
	}
	spec.Expressions = exprs
	return spec, nil
}

func tokenizeNftLine(s string) []string {
	// Normalize braces so "{ tcp, udp }" tokenizes cleanly
	s = strings.ReplaceAll(s, "{", " { ")
	s = strings.ReplaceAll(s, "}", " } ")
	return strings.Fields(s)
}

// ctStateBit maps one conntrack state name to its bit in the
// NFT_CT_STATE bitmask (see the nfCtState*Bit constants above).
func ctStateBit(name string) (uint32, bool) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "invalid":
		return nfCtStateInvalidBit, true
	case "established":
		return 1 << 1, true
	case "related":
		return 1 << 2, true
	case "new":
		return nfCtStateNewBit, true
	default:
		return 0, false
	}
}

func encodeIfnameBytes(dev string) []byte {
	b := make([]byte, len(dev)+1)
	copy(b, dev)
	return b
}

func parseICMPv6TypeByte(name string) (byte, bool) {
	name = strings.TrimSuffix(strings.TrimSpace(name), ",")
	if n, err := strconv.Atoi(name); err == nil && n >= 0 && n <= 255 {
		return byte(n), true
	}
	switch name {
	case "destination-unreachable":
		return 1, true
	case "packet-too-big":
		return 2, true
	case "time-exceeded":
		return 3, true
	case "parameter-problem":
		return 4, true
	case "echo-request":
		return 128, true
	case "echo-reply":
		return 129, true
	case "mld-listener-query":
		return 130, true
	case "mld-listener-report":
		return 131, true
	case "mld-listener-done":
		return 132, true
	case "nd-router-solicit", "router-solicitation":
		return 133, true
	case "nd-router-advert", "router-advertisement":
		return 134, true
	case "nd-neighbor-solicit", "neighbour-solicitation":
		return 135, true
	case "nd-neighbor-advert", "neighbour-advertisement":
		return 136, true
	case "nd-redirect":
		return 137, true
	case "mld2-listener-report":
		return 143, true
	default:
		return 0, false
	}
}

// =============================================================================
// Netlink Attribute & Expression Builders
// =============================================================================

func nlAttr(typ uint16, payload []byte) []byte {
	rawLen := 4 + len(payload)
	alignedLen := (rawLen + 3) & ^3
	buf := make([]byte, alignedLen)
	binary.LittleEndian.PutUint16(buf[0:2], uint16(rawLen))
	binary.LittleEndian.PutUint16(buf[2:4], typ)
	copy(buf[4:], payload)
	return buf
}

func nlAttrStr(typ uint16, s string) []byte {
	b := append([]byte(s), 0)
	return nlAttr(typ, b)
}

func nlAttrU32BE(typ uint16, v uint32) []byte {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return nlAttr(typ|nlaFNetByteorder, b[:])
}

func nlAttrU64BE(typ uint16, v uint64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	return nlAttr(typ|nlaFNetByteorder, b[:])
}

func nlAttrNested(typ uint16, children ...[]byte) []byte {
	var payload bytes.Buffer
	for _, c := range children {
		payload.Write(c)
	}
	return nlAttr(typ|nlaFNested, payload.Bytes())
}

func wrapExpr(name string, dataAttrs ...[]byte) []byte {
	return nlAttrNested(nftaListElem,
		nlAttrStr(nftaExprName, name),
		nlAttrNested(nftaExprData, dataAttrs...),
	)
}

func buildExprMetaLoad(key uint32, dreg uint32) []byte {
	return wrapExpr("meta",
		nlAttrU32BE(nftaMetaKey, key),
		nlAttrU32BE(nftaMetaDreg, dreg),
	)
}

func buildExprPayloadLoad(base, offset, length, dreg uint32) []byte {
	return wrapExpr("payload",
		nlAttrU32BE(nftaPayloadDreg, dreg),
		nlAttrU32BE(nftaPayloadBase, base),
		nlAttrU32BE(nftaPayloadOffset, offset),
		nlAttrU32BE(nftaPayloadLen, length),
	)
}

func buildExprCmpEq(sreg uint32, val []byte) []byte {
	return wrapExpr("cmp",
		nlAttrU32BE(nftaCmpSreg, sreg),
		nlAttrU32BE(nftaCmpOp, nftCmpEq),
		nlAttrNested(nftaCmpData, nlAttr(nftaDataValue, val)),
	)
}

func buildExprCmpNeqZero(sreg uint32) []byte {
	var zero [4]byte
	return wrapExpr("cmp",
		nlAttrU32BE(nftaCmpSreg, sreg),
		nlAttrU32BE(nftaCmpOp, 1), // NFT_CMP_NEQ
		nlAttrNested(nftaCmpData, nlAttr(nftaDataValue, zero[:])),
	)
}

func buildExprLookup(setName string, sreg uint32) []byte {
	return wrapExpr("lookup",
		nlAttrStr(nftaLookupSet, setName),
		nlAttrU32BE(nftaLookupSreg, sreg),
	)
}

func buildExprCtLoad(key, dreg uint32) []byte {
	return wrapExpr("ct",
		nlAttrU32BE(nftaCtDreg, dreg),
		nlAttrU32BE(nftaCtKey, key),
	)
}

func buildExprBitwiseMask(sreg, dreg, mask uint32) []byte {
	var maskBytes [4]byte
	var xorBytes [4]byte
	binary.NativeEndian.PutUint32(maskBytes[:], mask)
	return wrapExpr("bitwise",
		nlAttrU32BE(nftaBitwiseSreg, sreg),
		nlAttrU32BE(nftaBitwiseDreg, dreg),
		nlAttrU32BE(nftaBitwiseLen, 4),
		nlAttrNested(nftaBitwiseMask, nlAttr(nftaDataValue, maskBytes[:])),
		nlAttrNested(nftaBitwiseXor, nlAttr(nftaDataValue, xorBytes[:])),
	)
}

// buildExprBitwiseMaskBytes is buildExprBitwiseMask for a mask given as raw
// bytes (e.g. a CIDR netmask in network byte order): the mask bytes are
// emitted verbatim, so the expression matches payload bytes masked with
// exactly those bytes. Used for CIDR prefix matches (A-M36).
func buildExprBitwiseMaskBytes(sreg, dreg uint32, maskBytes []byte) []byte {
	xorBytes := make([]byte, len(maskBytes))
	return wrapExpr("bitwise",
		nlAttrU32BE(nftaBitwiseSreg, sreg),
		nlAttrU32BE(nftaBitwiseDreg, dreg),
		nlAttrU32BE(nftaBitwiseLen, uint32(len(maskBytes))),
		nlAttrNested(nftaBitwiseMask, nlAttr(nftaDataValue, maskBytes)),
		nlAttrNested(nftaBitwiseXor, nlAttr(nftaDataValue, xorBytes)),
	)
}

func buildExprLimit(rate, unitSec uint64) []byte {
	return wrapExpr("limit",
		nlAttrU64BE(nftaLimitRate, rate),
		nlAttrU64BE(nftaLimitUnit, unitSec),
		nlAttrU32BE(nftaLimitBurst, 5),
		nlAttrU32BE(nftaLimitType, 0),
	)
}

func buildExprLog(prefix string) []byte {
	return wrapExpr("log",
		nlAttrStr(nftaLogPrefix, prefix),
		nlAttrU32BE(nftaLogLevel, 4), // NFT_LOGLEVEL_WARNING
	)
}

func buildExprMasq() []byte {
	return wrapExpr("masq")
}

func buildExprImmediateData(dreg uint32, val []byte) []byte {
	return wrapExpr("immediate",
		nlAttrU32BE(nftaImmediateDreg, dreg),
		nlAttrNested(nftaImmediateData, nlAttr(nftaDataValue, val)),
	)
}

func buildExprDnatIPv4(addrReg, protoReg uint32, hasPort bool) []byte {
	attrs := [][]byte{
		nlAttrU32BE(1, 1),           // NFTA_NAT_TYPE = NFT_NAT_DNAT (1)
		nlAttrU32BE(2, nfprotoIPv4), // NFTA_NAT_FAMILY = NFPROTO_IPV4 (2)
		nlAttrU32BE(3, addrReg),     // NFTA_NAT_REG_ADDR_MIN
	}
	if hasPort {
		attrs = append(attrs, nlAttrU32BE(5, protoReg)) // NFTA_NAT_REG_PROTO_MIN
	}
	return wrapExpr("nat", attrs...)
}

func buildExprFlowOffload(ftName string) []byte {
	return wrapExpr("flow_offload",
		nlAttrStr(nftaFlowTableName, ftName),
	)
}

func buildExprVerdict(code uint32) []byte {
	return wrapExpr("immediate",
		nlAttrU32BE(nftaImmediateDreg, nftRegVerdict),
		nlAttrNested(nftaImmediateData,
			nlAttrNested(nftaDataVerdict,
				nlAttrU32BE(nftaVerdictCode, code),
			),
		),
	)
}

// buildExprVerdictChain emits an immediate jump/goto verdict naming the
// target chain (A-M36).
func buildExprVerdictChain(code uint32, chain string) []byte {
	return wrapExpr("immediate",
		nlAttrU32BE(nftaImmediateDreg, nftRegVerdict),
		nlAttrNested(nftaImmediateData,
			nlAttrNested(nftaDataVerdict,
				nlAttrU32BE(nftaVerdictCode, code),
				nlAttrStr(nftaVerdictChain, chain),
			),
		),
	)
}

// buildExprReject emits an nft reject expression (A-M36). icmpCode is the
// ICMP code (3 = port unreachable) and is only sent for ICMP rejects;
// a TCP RST reject carries no code.
func buildExprReject(rejectType uint32, icmpCode byte, withCode bool) []byte {
	attrs := [][]byte{
		nlAttrU32BE(nftaRejectType, rejectType),
	}
	if withCode {
		attrs = append(attrs, nlAttr(nftaRejectIcmpCode, []byte{icmpCode}))
	}
	return wrapExpr("reject", attrs...)
}

// buildNfgenMsg builds a complete Netlink message with struct nlmsghdr + struct nfgenmsg + attributes.
func buildNfgenMsg(msgType uint16, flags uint16, seq uint32, family uint8, resID uint16, attrs ...[]byte) []byte {
	var attrBuf bytes.Buffer
	for _, a := range attrs {
		attrBuf.Write(a)
	}
	totalLen := syscall.NLMSG_HDRLEN + 4 + attrBuf.Len()
	alignedLen := (totalLen + 3) & ^3
	msg := make([]byte, alignedLen)

	binary.NativeEndian.PutUint32(msg[0:4], uint32(alignedLen))
	binary.NativeEndian.PutUint16(msg[4:6], msgType)
	binary.NativeEndian.PutUint16(msg[6:8], flags)
	binary.NativeEndian.PutUint32(msg[8:12], seq)
	binary.NativeEndian.PutUint32(msg[12:16], 0)

	// struct nfgenmsg { u8 nfgen_family; u8 version; __be16 res_id; }
	msg[16] = family
	msg[17] = nfnetlinkV0
	binary.BigEndian.PutUint16(msg[18:20], resID)

	copy(msg[20:], attrBuf.Bytes())
	return msg
}

func nftMsgType(op uint16) uint16 {
	return (uint16(nfnlSubsysNftables) << 8) | op
}

// buildSetElemMsg builds one NFT_MSG_NEW_SET_ELEM message carrying all of a
// set's initial elements, using the same element encoding as
// AddSetElementNetlink / AddIntervalSetElementNetlink: a singleton is a
// single key element, an interval is a start element plus an end element
// flagged NFT_SET_ELEM_INTERVAL_END.
func buildSetElemMsg(tableName, setName string, elems []NftSetElement, seq uint32) []byte {
	var elemBuf bytes.Buffer
	for _, e := range elems {
		elemBuf.Write(nlAttrNested(nftaListElem,
			nlAttrNested(nftaSetElemKey, nlAttr(nftaDataValue, e.Key)),
		))
		if e.End != nil {
			elemBuf.Write(nlAttrNested(nftaListElem,
				nlAttrU32BE(nftaSetElemFlags, 1), // NFT_SET_ELEM_INTERVAL_END
				nlAttrNested(nftaSetElemKey, nlAttr(nftaDataValue, e.End)),
			))
		}
	}
	return buildNfgenMsg(
		nftMsgType(nftMsgNewSetElem),
		syscall.NLM_F_REQUEST|syscall.NLM_F_CREATE,
		seq,
		nfprotoInet,
		0,
		nlAttrStr(nftaSetElemListTable, tableName),
		nlAttrStr(nftaSetElemListSet, setName),
		nlAttrNested(nftaSetElemListElements, elemBuf.Bytes()),
	)
}

func serializeNftBatch(b *NftCompiledBatch) [][]byte {
	var msgs [][]byte
	seq := uint32(1)

	// 1. NFNL_MSG_BATCH_BEGIN (res_id = NFNL_SUBSYS_NFTABLES)
	msgs = append(msgs, buildNfgenMsg(nfnlMsgBatchBegin, syscall.NLM_F_REQUEST, seq, nfprotoUnspec, nfnlSubsysNftables))
	seq++

	// 2. Create table inet <TableName>
	msgs = append(msgs, buildNfgenMsg(
		nftMsgType(nftMsgNewTable),
		syscall.NLM_F_REQUEST|syscall.NLM_F_CREATE,
		seq,
		nfprotoInet,
		0,
		nlAttrStr(nftaTableName, b.TableName),
		nlAttrU32BE(nftaTableFlags, 0),
	))
	seq++

	// 3. Create sets (blocked_ips, blocked_ips6, blocked_macs)
	for _, s := range b.Sets {
		var flags uint32
		if s.Interval {
			flags |= 0x4 // NFT_SET_INTERVAL
		}
		keyType := uint32(7) // ipv4_addr
		switch s.KeyType {
		case "ipv6_addr":
			keyType = 8
		case "ether_addr":
			keyType = 9
		}
		msgs = append(msgs, buildNfgenMsg(
			nftMsgType(nftMsgNewSet),
			syscall.NLM_F_REQUEST|syscall.NLM_F_CREATE,
			seq,
			nfprotoInet,
			0,
			nlAttrStr(nftaSetTable, b.TableName),
			nlAttrStr(nftaSetName, s.Name),
			nlAttrU32BE(nftaSetFlags, flags),
			nlAttrU32BE(nftaSetKeyType, keyType),
			nlAttrU32BE(nftaSetKeyLen, s.KeyLen),
			nlAttrU32BE(nftaSetID, s.SetID),
		))
		seq++

		// 3a. Populate initial `elements = { ... }` (A-H7, round 2):
		// a set created without them silently enforces nothing.
		if len(s.Elements) > 0 {
			msgs = append(msgs, buildSetElemMsg(b.TableName, s.Name, s.Elements, seq))
			seq++
		}
	}

	// 3b. Create flowtables (e.g. fastpath)
	for _, ft := range b.Flowtables {
		var devAttrs [][]byte
		for _, d := range ft.Devices {
			devAttrs = append(devAttrs, nlAttrStr(nftaDeviceName, d))
		}
		msgs = append(msgs, buildNfgenMsg(
			nftMsgType(nftMsgNewFlowtable),
			syscall.NLM_F_REQUEST|syscall.NLM_F_CREATE,
			seq,
			nfprotoInet,
			0,
			nlAttrStr(nftaFlowtableTable, b.TableName),
			nlAttrStr(nftaFlowtableName, ft.Name),
			nlAttrNested(nftaFlowtableHook,
				nlAttrU32BE(nftaFlowtableHookNum, ft.HookNum),
				nlAttrU32BE(nftaFlowtableHookPriority, uint32(ft.Priority)),
				nlAttrNested(nftaFlowtableHookDevs, devAttrs...),
			),
		))
		seq++
	}

	// 4. Create base chains (input, forward, output, postrouting)
	for _, ch := range b.Chains {
		msgs = append(msgs, buildNfgenMsg(
			nftMsgType(nftMsgNewChain),
			syscall.NLM_F_REQUEST|syscall.NLM_F_CREATE,
			seq,
			nfprotoInet,
			0,
			nlAttrStr(nftaChainTable, b.TableName),
			nlAttrStr(nftaChainName, ch.Name),
			nlAttrStr(nftaChainType, ch.Type),
			nlAttrNested(nftaChainHook,
				nlAttrU32BE(nftaHookHooknum, ch.HookNum),
				nlAttrU32BE(nftaHookPriority, uint32(ch.Priority)),
			),
			nlAttrU32BE(nftaChainPolicy, ch.Policy),
		))
		seq++
	}

	// 5. Append rules to chains
	for _, r := range b.Rules {
		// Skip flow_offload rules if flowtable wasn't created in the kernel transaction
		hasFlowOffload := strings.Contains(r.RawLine, "flow add @")
		if hasFlowOffload && len(b.Flowtables) == 0 {
			continue
		}
		msgs = append(msgs, buildNfgenMsg(
			nftMsgType(nftMsgNewRule),
			syscall.NLM_F_REQUEST|syscall.NLM_F_CREATE|syscall.NLM_F_APPEND,
			seq,
			nfprotoInet,
			0,
			nlAttrStr(nftaRuleTable, b.TableName),
			nlAttrStr(nftaRuleChain, r.Chain),
			nlAttrNested(nftaRuleExpressions, r.Expressions...),
		))
		seq++
	}

	// 6. NFNL_MSG_BATCH_END. A-L1: request an ack on the batch end so
	// the kernel positively confirms the whole transaction. None of
	// the messages above requests one, so without this the sender
	// could never tell an accepted batch from one the kernel had not
	// finished (or had rejected) yet.
	msgs = append(msgs, buildNfgenMsg(nfnlMsgBatchEnd, syscall.NLM_F_REQUEST|syscall.NLM_F_ACK, seq, nfprotoUnspec, nfnlSubsysNftables))
	return msgs
}

// ApplyNftBatchNetlink sends the compiled nf_tables batch directly to the Linux kernel
// via AF_NETLINK (NETLINK_NETFILTER = 12).
func ApplyNftBatchNetlink(batch *NftCompiledBatch) error {
	if batch == nil || len(batch.RawMsgs) == 0 {
		return fmt.Errorf("empty nftables netlink batch")
	}

	// Best-effort delete existing table first so rules are replaced cleanly
	_ = DeleteTableNetlink(batch.TableName)

	var wire bytes.Buffer
	for _, m := range batch.RawMsgs {
		wire.Write(m)
	}

	return sendNetfilterNetlinkBatch(wire.Bytes())
}

// DeleteTableNetlink deletes `table inet <tableName>` via a NETLINK_NETFILTER batch.
func DeleteTableNetlink(tableName string) error {
	if tableName == "" {
		tableName = "axonwall"
	}
	var wire bytes.Buffer
	wire.Write(buildNfgenMsg(nfnlMsgBatchBegin, syscall.NLM_F_REQUEST, 1, nfprotoUnspec, nfnlSubsysNftables))
	wire.Write(buildNfgenMsg(
		nftMsgType(nftMsgDelTable),
		syscall.NLM_F_REQUEST|syscall.NLM_F_ACK,
		2,
		nfprotoInet,
		0,
		nlAttrStr(nftaTableName, tableName),
	))
	wire.Write(buildNfgenMsg(nfnlMsgBatchEnd, syscall.NLM_F_REQUEST, 3, nfprotoUnspec, nfnlSubsysNftables))
	return sendNetfilterNetlinkBatch(wire.Bytes())
}

func incrementIPBytes(ip []byte) ([]byte, bool) {
	out := bytes.Clone(ip)
	for i := len(out) - 1; i >= 0; i-- {
		out[i]++
		if out[i] != 0 {
			return out, true
		}
	}
	return nil, false
}

// AddSetElementNetlink adds an IPv4, IPv6, or MAC address to `table inet <tableName> <setName>` via Netlink.
func AddSetElementNetlink(tableName, setName string, keyBytes []byte) error {
	if setName == "blocked_ips" || setName == "blocked_ips6" {
		endBytes, ok := incrementIPBytes(keyBytes)
		if !ok {
			return fmt.Errorf("cannot encode interval end for max address in %s", setName)
		}
		return AddIntervalSetElementNetlink(tableName, setName, keyBytes, endBytes)
	}
	if tableName == "" {
		tableName = "axonwall"
	}
	elem := nlAttrNested(nftaListElem,
		nlAttrNested(nftaSetElemKey, nlAttr(nftaDataValue, keyBytes)),
	)
	var wire bytes.Buffer
	wire.Write(buildNfgenMsg(nfnlMsgBatchBegin, syscall.NLM_F_REQUEST, 1, nfprotoUnspec, nfnlSubsysNftables))
	wire.Write(buildNfgenMsg(
		nftMsgType(nftMsgNewSetElem),
		syscall.NLM_F_REQUEST|syscall.NLM_F_CREATE|syscall.NLM_F_ACK,
		2,
		nfprotoInet,
		0,
		nlAttrStr(nftaSetElemListTable, tableName),
		nlAttrStr(nftaSetElemListSet, setName),
		nlAttrNested(nftaSetElemListElements, elem),
	))
	wire.Write(buildNfgenMsg(nfnlMsgBatchEnd, syscall.NLM_F_REQUEST, 3, nfprotoUnspec, nfnlSubsysNftables))
	return sendNetfilterNetlinkBatch(wire.Bytes())
}

// AddIntervalSetElementNetlink adds a half-open [startBytes, endBytes) interval to an NFT_SET_INTERVAL set via Netlink.
func AddIntervalSetElementNetlink(tableName, setName string, startBytes, endBytes []byte) error {
	if tableName == "" {
		tableName = "axonwall"
	}
	startElem := nlAttrNested(nftaListElem,
		nlAttrNested(nftaSetElemKey, nlAttr(nftaDataValue, startBytes)),
	)
	endElem := nlAttrNested(nftaListElem,
		nlAttrU32BE(nftaSetElemFlags, 1), // NFT_SET_ELEM_INTERVAL_END = 1
		nlAttrNested(nftaSetElemKey, nlAttr(nftaDataValue, endBytes)),
	)
	var elems bytes.Buffer
	elems.Write(startElem)
	elems.Write(endElem)

	var wire bytes.Buffer
	wire.Write(buildNfgenMsg(nfnlMsgBatchBegin, syscall.NLM_F_REQUEST, 1, nfprotoUnspec, nfnlSubsysNftables))
	wire.Write(buildNfgenMsg(
		nftMsgType(nftMsgNewSetElem),
		syscall.NLM_F_REQUEST|syscall.NLM_F_CREATE|syscall.NLM_F_ACK,
		2,
		nfprotoInet,
		0,
		nlAttrStr(nftaSetElemListTable, tableName),
		nlAttrStr(nftaSetElemListSet, setName),
		nlAttrNested(nftaSetElemListElements, elems.Bytes()),
	))
	wire.Write(buildNfgenMsg(nfnlMsgBatchEnd, syscall.NLM_F_REQUEST, 3, nfprotoUnspec, nfnlSubsysNftables))
	return sendNetfilterNetlinkBatch(wire.Bytes())
}

func sendNetfilterNetlinkBatch(payload []byte) error {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, syscall.NETLINK_NETFILTER)
	if err != nil {
		return fmt.Errorf("NETLINK_NETFILTER socket failed: %w", err)
	}
	defer syscall.Close(fd)

	sa := &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}
	if err := syscall.Bind(fd, sa); err != nil {
		return fmt.Errorf("NETLINK_NETFILTER bind failed: %w", err)
	}

	tv := syscall.NsecToTimeval((2 * 1000 * 1000 * 1000))
	_ = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)

	if err := syscall.Sendto(fd, payload, 0, sa); err != nil {
		return fmt.Errorf("NETLINK_NETFILTER sendto failed: %w", err)
	}

	// A-L1: wait for the kernel's verdict with a blocking read instead
	// of a single non-blocking recv racing kernel processing. The old
	// code returned success whenever the error had not landed yet, so
	// a rejected batch (bad rule, missing set/table) was recorded as
	// applied and could later be confirmed into last-known-good. The
	// socket's 2s SO_RCVTIMEO bounds this read: a kernel that never
	// answers is a failure, not a success. The kernel sends exactly
	// one NLMSG_ERROR verdict per batch — errno 0 for an acked batch,
	// negative errno for a rejected one.
	buf := make([]byte, 8192)
	for {
		n, _, recvErr := syscall.Recvfrom(fd, buf, 0)
		if recvErr != nil {
			return fmt.Errorf("timed out waiting for kernel acknowledgement of nftables batch: %w", recvErr)
		}
		if n < syscall.NLMSG_HDRLEN {
			continue
		}
		msgs, parseErr := syscall.ParseNetlinkMessage(buf[:n])
		if parseErr != nil {
			continue
		}
		for _, m := range msgs {
			if m.Header.Type == syscall.NLMSG_ERROR && len(m.Data) >= 4 {
				errno := int32(binary.NativeEndian.Uint32(m.Data[0:4]))
				if errno < 0 {
					return syscall.Errno(-errno)
				}
				return nil
			}
		}
	}
}
