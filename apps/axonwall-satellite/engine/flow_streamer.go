package engine

import (
	"errors"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// EdgeFlowRecord represents an active 5-tuple connection tracked in kernel conntrack / flowtable.
type EdgeFlowRecord struct {
	Protocol  string `json:"protocol"`
	SrcIP     string `json:"srcIp"`
	DstIP     string `json:"dstIp"`
	SrcPort   int    `json:"srcPort"`
	DstPort   int    `json:"dstPort"`
	Packets   int64  `json:"packets"`
	Bytes     int64  `json:"bytes"`
	State     string `json:"state,omitempty"`
	Offloaded bool   `json:"offloaded"`
}

// EdgeFirewallLog represents a matched nftables log event harvested from the kernel ring buffer (/dev/kmsg).
type EdgeFirewallLog struct {
	Timestamp int64  `json:"timestamp"`
	RuleID    string `json:"ruleId"`
	InIface   string `json:"inIface,omitempty"`
	OutIface  string `json:"outIface,omitempty"`
	SrcIP     string `json:"srcIp"`
	DstIP     string `json:"dstIp"`
	Protocol  string `json:"protocol"`
	SrcPort   int    `json:"srcPort,omitempty"`
	DstPort   int    `json:"dstPort,omitempty"`
}

// EdgeFlowBatchPayload is streamed from the stateless edge NGFW to the internal Full Axonwall Hub.
type EdgeFlowBatchPayload struct {
	SatelliteID  string            `json:"satelliteId"`
	Timestamp    int64             `json:"timestamp"`
	Flows        []EdgeFlowRecord  `json:"flows"`
	FirewallLogs []EdgeFirewallLog `json:"firewallLogs,omitempty"`
}

// EdgeFlowStreamer collects kernel conntrack flows and nftables log events in memory.
type EdgeFlowStreamer struct {
	mu          sync.Mutex
	pendingLogs []EdgeFirewallLog
	maxLogs     int
}

func NewEdgeFlowStreamer() *EdgeFlowStreamer {
	return &EdgeFlowStreamer{
		maxLogs: 256,
	}
}

// StartKmsgReader tails /dev/kmsg for "axonwall-rule:" firewall packet logs.
// /dev/kmsg returns exactly one log record per read(2). A blocking fd is used
// deliberately: a bufio.Scanner over a non-blocking fd stops permanently on the
// first EAGAIN, which would silently end log collection after the initial drain.
func (s *EdgeFlowStreamer) StartKmsgReader(stop <-chan struct{}) {
	f, err := os.OpenFile("/dev/kmsg", os.O_RDONLY, 0)
	if err != nil {
		return
	}

	go func() {
		<-stop
		_ = f.Close() // unblocks the pending Read below
	}()

	go func() {
		buf := make([]byte, 8192)
		for {
			n, err := f.Read(buf)
			if err != nil {
				if errors.Is(err, syscall.EPIPE) {
					// Ring buffer overwrote unread records; continue from next record.
					continue
				}
				return // fd closed via stop, or unrecoverable error
			}
			if entry, ok := ParseKmsgFirewallLog(string(buf[:n])); ok {
				s.RecordLog(entry)
			}
		}
	}()
}

// RecordLog buffers a firewall log event in memory until the next telemetry flush to the Hub.
func (s *EdgeFlowStreamer) RecordLog(entry EdgeFirewallLog) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.pendingLogs) >= s.maxLogs {
		s.pendingLogs = s.pendingLogs[1:]
	}
	s.pendingLogs = append(s.pendingLogs, entry)
}

// DrainBatch harvests the current top conntrack flows and drains buffered firewall logs.
func (s *EdgeFlowStreamer) DrainBatch(satelliteID string, maxFlows int) EdgeFlowBatchPayload {
	if maxFlows <= 0 {
		maxFlows = 50
	}

	var flows []EdgeFlowRecord
	if data, err := os.ReadFile("/proc/net/nf_conntrack"); err == nil && len(data) > 0 {
		flows = ParseConntrackFlows(string(data), maxFlows)
	}

	s.mu.Lock()
	logs := s.pendingLogs
	s.pendingLogs = nil
	s.mu.Unlock()

	return EdgeFlowBatchPayload{
		SatelliteID:  satelliteID,
		Timestamp:    time.Now().Unix(),
		Flows:        flows,
		FirewallLogs: logs,
	}
}

// ParseConntrackFlows parses /proc/net/nf_conntrack lines into structured EdgeFlowRecord entries,
// ordered by total bytes descending so the Hub receives the highest-volume active flows.
func ParseConntrackFlows(raw string, maxFlows int) []EdgeFlowRecord {
	var records []EdgeFlowRecord
	lines := strings.Split(raw, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}

		proto := strings.ToLower(fields[2])
		var rec EdgeFlowRecord
		rec.Protocol = proto

		seenSrc := false
		seenDst := false
		seenSport := false
		seenDport := false

		for _, tok := range fields[3:] {
			if tok == "[OFFLOAD]" || tok == "[HW_OFFLOAD]" {
				rec.Offloaded = true
				continue
			}
			if !strings.Contains(tok, "=") && !strings.HasPrefix(tok, "[") {
				// TCP state token e.g. ESTABLISHED, SYN_SENT, TIME_WAIT
				if rec.State == "" && isConntrackState(tok) {
					rec.State = tok
				}
				continue
			}
			kv := strings.SplitN(tok, "=", 2)
			if len(kv) != 2 {
				continue
			}
			k, v := kv[0], kv[1]
			switch k {
			case "src":
				if !seenSrc {
					rec.SrcIP = v
					seenSrc = true
				}
			case "dst":
				if !seenDst {
					rec.DstIP = v
					seenDst = true
				}
			case "sport":
				if !seenSport {
					rec.SrcPort, _ = strconv.Atoi(v)
					seenSport = true
				}
			case "dport":
				if !seenDport {
					rec.DstPort, _ = strconv.Atoi(v)
					seenDport = true
				}
			case "packets":
				if p, err := strconv.ParseInt(v, 10, 64); err == nil {
					rec.Packets += p
				}
			case "bytes":
				if b, err := strconv.ParseInt(v, 10, 64); err == nil {
					rec.Bytes += b
				}
			}
		}

		// Skip localhost/loopback internal noise
		if rec.SrcIP == "" || rec.DstIP == "" || rec.SrcIP == "127.0.0.1" || rec.DstIP == "127.0.0.1" {
			continue
		}

		records = append(records, rec)
	}

	sort.Slice(records, func(i, j int) bool {
		return records[i].Bytes > records[j].Bytes
	})

	if maxFlows > 0 && len(records) > maxFlows {
		records = records[:maxFlows]
	}
	return records
}

func isConntrackState(s string) bool {
	switch s {
	case "ESTABLISHED", "SYN_SENT", "SYN_RECV", "FIN_WAIT", "CLOSE_WAIT", "LAST_ACK", "TIME_WAIT", "CLOSE", "LISTEN":
		return true
	}
	return false
}

// ParseKmsgFirewallLog parses a kernel log line containing "axonwall-rule:<id>:"
// into an EdgeFirewallLog entry.
func ParseKmsgFirewallLog(line string) (EdgeFirewallLog, bool) {
	const marker = "axonwall-rule:"
	idx := strings.Index(line, marker)
	if idx < 0 {
		return EdgeFirewallLog{}, false
	}

	rest := line[idx+len(marker):]
	colonIdx := strings.Index(rest, ":")
	if colonIdx <= 0 {
		return EdgeFirewallLog{}, false
	}

	ruleID := strings.TrimSpace(rest[:colonIdx])
	kvPart := strings.TrimSpace(rest[colonIdx+1:])

	entry := EdgeFirewallLog{
		Timestamp: time.Now().Unix(),
		RuleID:    ruleID,
	}

	for _, tok := range strings.Fields(kvPart) {
		kv := strings.SplitN(tok, "=", 2)
		if len(kv) != 2 {
			continue
		}
		k, v := kv[0], kv[1]
		switch k {
		case "IN":
			entry.InIface = v
		case "OUT":
			entry.OutIface = v
		case "SRC":
			entry.SrcIP = v
		case "DST":
			entry.DstIP = v
		case "PROTO":
			entry.Protocol = strings.ToLower(v)
		case "SPT":
			entry.SrcPort, _ = strconv.Atoi(v)
		case "DPT":
			entry.DstPort, _ = strconv.Atoi(v)
		}
	}

	if entry.SrcIP == "" || entry.DstIP == "" {
		return EdgeFirewallLog{}, false
	}
	return entry, true
}
