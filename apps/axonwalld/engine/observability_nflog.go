package engine

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
)

const (
	nfnlSubsysUlog    = 4
	nfulnlMsgPacket   = 0
	nfulnlMsgConfig   = 1
	nfulnlCfgCmd      = 1
	nfulnlCfgMode     = 2
	nfulnlCmdBind     = 1
	nfulnlCmdUnbind   = 2
	nfulnlCmdPfBind   = 3
	nfulnlCmdPfUnbind = 4
	nfulnlCopyPacket  = 2

	nfulaTimestamp     = 3
	nfulaIfindexIndev  = 4
	nfulaIfindexOutdev = 5
	nfulaPayload       = 9
	nfulaPrefix        = 10
)

type StructuredLogEntry struct {
	Time        string         `json:"_time"`
	Msg         string         `json:"_msg"`
	NodeID      string         `json:"node_id"`
	Hostname    string         `json:"hostname"`
	Source      string         `json:"source"`
	Level       string         `json:"level"`
	RuleID      string         `json:"rule_id,omitempty"`
	Action      string         `json:"action,omitempty"`
	Interface   string         `json:"interface,omitempty"`
	OutIface    string         `json:"out_interface,omitempty"`
	SrcIP       string         `json:"src_ip,omitempty"`
	DstIP       string         `json:"dst_ip,omitempty"`
	SrcPort     uint16         `json:"src_port,omitempty"`
	DstPort     uint16         `json:"dst_port,omitempty"`
	Protocol    string         `json:"protocol,omitempty"`
	Fields      map[string]any `json:"fields,omitempty"`
}

type tokenBucketLimiter struct {
	mu       sync.Mutex
	rate     float64
	tokens   float64
	lastTime time.Time
}

func newTokenBucketLimiter(ratePerSec int) *tokenBucketLimiter {
	if ratePerSec <= 0 {
		return &tokenBucketLimiter{rate: 0}
	}
	r := float64(ratePerSec)
	return &tokenBucketLimiter{
		rate:     r,
		tokens:   r,
		lastTime: time.Now(),
	}
}

func (l *tokenBucketLimiter) SetRate(ratePerSec int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if ratePerSec <= 0 {
		l.rate = 0
		l.tokens = 0
		return
	}
	l.rate = float64(ratePerSec)
	if l.tokens > l.rate {
		l.tokens = l.rate
	}
	if l.lastTime.IsZero() {
		l.lastTime = time.Now()
	}
}

func (l *tokenBucketLimiter) Allow() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.rate <= 0 {
		return true
	}
	now := time.Now()
	elapsed := now.Sub(l.lastTime).Seconds()
	l.lastTime = now
	l.tokens += elapsed * l.rate
	if l.tokens > l.rate {
		l.tokens = l.rate
	}
	if l.tokens >= 1.0 {
		l.tokens -= 1.0
		return true
	}
	return false
}

// NflogReader consumes Linux netfilter NFLOG group events over AF_NETLINK (NETLINK_NETFILTER)
// and emits enriched structured firewall log entries.
type NflogReader struct {
	mu      sync.Mutex
	running bool
	fd      int
	stopCh  chan struct{}
	wg      sync.WaitGroup
	limiter *tokenBucketLimiter
	onLog   func(StructuredLogEntry)

	received atomic.Uint64
	dropped  atomic.Uint64
}

func NewNflogReader(onLog func(StructuredLogEntry)) *NflogReader {
	return &NflogReader{
		fd:      -1,
		limiter: newTokenBucketLimiter(50),
		onLog:   onLog,
	}
}

func (n *NflogReader) Start(group uint16, rateLimitPerSec int, nodeID, hostname string, rules map[string]ObservabilityRuleMeta) {
	n.Stop()
	n.limiter.SetRate(rateLimitPerSec)

	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW, unix.NETLINK_NETFILTER)
	if err != nil {
		if err == unix.EPERM || err == unix.EACCES {
			log.Printf("[Observability] NFLOG group %d disabled (unprivileged socket)", group)
		} else {
			log.Printf("[Observability] NFLOG socket warning: %v", err)
		}
		return
	}
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		_ = unix.Close(fd)
		log.Printf("[Observability] NFLOG bind warning: %v", err)
		return
	}
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 1, Usec: 0})

	// Configure NFLOG group binding for IPv4 & IPv6 with NLM_F_ACK verification
	cfgSeqs := []struct {
		pf        uint8
		cmd       uint8
		seq       uint32
		copyBytes uint32
		allowEnoent bool
	}{
		{unix.AF_INET, nfulnlCmdPfUnbind, 1, 0, true},
		{unix.AF_INET6, nfulnlCmdPfUnbind, 2, 0, true},
		{unix.AF_INET, nfulnlCmdPfBind, 3, 0, false},
		{unix.AF_INET6, nfulnlCmdPfBind, 4, 0, false},
		{0, nfulnlCmdBind, 5, 128, false},
	}
	for _, c := range cfgSeqs {
		msg := buildNflogConfigMsg(group, c.pf, c.cmd, c.seq, c.copyBytes)
		if err := unix.Sendto(fd, msg, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
			_ = unix.Close(fd)
			log.Printf("[Observability] NFLOG config sendto failed (group=%d cmd=%d): %v", group, c.cmd, err)
			return
		}
		if err := waitNetlinkAck(fd, c.seq, c.allowEnoent); err != nil {
			_ = unix.Close(fd)
			log.Printf("[Observability] NFLOG config ACK failed (group=%d cmd=%d): %v", group, c.cmd, err)
			return
		}
	}

	ifMap := snapshotLocalIfIndexMap()

	n.mu.Lock()
	n.fd = fd
	n.running = true
	stopCh := make(chan struct{})
	n.stopCh = stopCh
	n.mu.Unlock()

	n.wg.Add(1)
	go func() {
		defer n.wg.Done()
		buf := make([]byte, 65536)
		lastIfRefresh := time.Now()
		for {
			select {
			case <-stopCh:
				return
			default:
			}
			rn, _, rerr := unix.Recvfrom(fd, buf, 0)
			if rerr != nil {
				if rerr == unix.EAGAIN || rerr == unix.EWOULDBLOCK || rerr == unix.EINTR {
					if time.Since(lastIfRefresh) > 30*time.Second {
						ifMap = snapshotLocalIfIndexMap()
						lastIfRefresh = time.Now()
					}
					continue
				}
				return
			}
			if rn <= 0 {
				continue
			}
			entries := ParseNflogNetlinkMessages(buf[:rn], nodeID, hostname, rules, ifMap)
			for _, ent := range entries {
				n.received.Add(1)
				if !n.limiter.Allow() {
					n.dropped.Add(1)
					continue
				}
				if n.onLog != nil {
					n.onLog(ent)
				}
			}
		}
	}()
}

func (n *NflogReader) Stop() {
	n.mu.Lock()
	if !n.running {
		n.mu.Unlock()
		return
	}
	n.running = false
	close(n.stopCh)
	if n.fd >= 0 {
		_ = unix.Close(n.fd)
		n.fd = -1
	}
	n.mu.Unlock()
	n.wg.Wait()
}

func snapshotLocalIfIndexMap() map[uint32]string {
	out := make(map[uint32]string)
	if ifaces, err := net.Interfaces(); err == nil {
		for _, ifc := range ifaces {
			if ifc.Index > 0 {
				out[uint32(ifc.Index)] = ifc.Name
			}
		}
	}
	return out
}

func waitNetlinkAck(fd int, expectedSeq uint32, allowEnoent bool) error {
	buf := make([]byte, 4096)
	for {
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			return err
		}
		if n < 16 {
			return fmt.Errorf("short netlink ACK response (%d bytes)", n)
		}
		off := 0
		for off+16 <= n {
			nlLen := int(binary.LittleEndian.Uint32(buf[off : off+4]))
			nlType := binary.LittleEndian.Uint16(buf[off+4 : off+6])
			nlSeq := binary.LittleEndian.Uint32(buf[off+8 : off+12])
			if nlLen < 16 || off+nlLen > n {
				break
			}
			if nlType == unix.NLMSG_ERROR && nlSeq == expectedSeq {
				if nlLen < 20 {
					return fmt.Errorf("truncated NLMSG_ERROR (%d bytes)", nlLen)
				}
				errno := int32(binary.LittleEndian.Uint32(buf[off+16 : off+20]))
				if errno == 0 {
					return nil
				}
				if allowEnoent && errno == -int32(unix.ENOENT) {
					return nil
				}
				return fmt.Errorf("netlink error %d (%s)", errno, unix.Errno(-errno).Error())
			}
			aligned := (nlLen + 3) &^ 3
			if aligned <= 0 {
				break
			}
			off += aligned
		}
	}
}

func buildNflogConfigMsg(group uint16, pf uint8, cmd uint8, seq uint32, copyBytes uint32) []byte {
	var attrs []byte
	// NFULA_CFG_CMD: nla_len=5 (4 hdr + 1 u8 command), padded to 8
	cmdAttr := make([]byte, 8)
	binary.LittleEndian.PutUint16(cmdAttr[0:2], 5)
	binary.LittleEndian.PutUint16(cmdAttr[2:4], nfulnlCfgCmd)
	cmdAttr[4] = cmd
	attrs = append(attrs, cmdAttr...)

	if copyBytes > 0 {
		// NFULA_CFG_MODE: nla_len=10 (4 hdr + 4 copy_range BE + 1 copy_mode + 1 _pad), padded to 12
		modeAttr := make([]byte, 12)
		binary.LittleEndian.PutUint16(modeAttr[0:2], 10)
		binary.LittleEndian.PutUint16(modeAttr[2:4], nfulnlCfgMode)
		binary.BigEndian.PutUint32(modeAttr[4:8], copyBytes)
		modeAttr[8] = nfulnlCopyPacket
		modeAttr[9] = 0
		attrs = append(attrs, modeAttr...)
	}

	totalLen := 16 + 4 + len(attrs)
	msg := make([]byte, totalLen)
	binary.LittleEndian.PutUint32(msg[0:4], uint32(totalLen))
	binary.LittleEndian.PutUint16(msg[4:6], uint16((nfnlSubsysUlog<<8)|nfulnlMsgConfig))
	binary.LittleEndian.PutUint16(msg[6:8], unix.NLM_F_REQUEST|unix.NLM_F_ACK)
	binary.LittleEndian.PutUint32(msg[8:12], seq)
	msg[16] = pf
	msg[17] = 0 // NFNETLINK_V0
	binary.BigEndian.PutUint16(msg[18:20], group)
	copy(msg[20:], attrs)
	return msg
}

// ParseNflogNetlinkMessages decodes raw NETLINK_NETFILTER NFLOG messages into structured logs.
func ParseNflogNetlinkMessages(
	data []byte,
	nodeID, hostname string,
	rules map[string]ObservabilityRuleMeta,
	ifNames map[uint32]string,
) []StructuredLogEntry {
	var out []StructuredLogEntry
	off := 0
	for off+16 <= len(data) {
		nlLen := int(binary.LittleEndian.Uint32(data[off : off+4]))
		nlType := binary.LittleEndian.Uint16(data[off+4 : off+6])
		if nlLen < 16 || off+nlLen > len(data) {
			break
		}
		alignedLen := (nlLen + 3) &^ 3
		msg := data[off : off+nlLen]
		if off+alignedLen <= len(data) {
			off += alignedLen
		} else {
			off += nlLen
		}

		subsys := nlType >> 8
		msgKind := nlType & 0xFF
		if subsys != nfnlSubsysUlog || msgKind != nfulnlMsgPacket || len(msg) < 20 {
			continue
		}

		groupID := binary.BigEndian.Uint16(msg[18:20])
		entry := StructuredLogEntry{
			Time:     time.Now().UTC().Format(time.RFC3339Nano),
			NodeID:   nodeID,
			Hostname: hostname,
			Source:   "nflog",
			Level:    "warn",
		}

		var prefix string
		attrOff := 20
		for attrOff+4 <= len(msg) {
			aLen := int(binary.LittleEndian.Uint16(msg[attrOff : attrOff+2]))
			aType := binary.LittleEndian.Uint16(msg[attrOff+2 : attrOff+4]) & 0x7FFF
			if aLen < 4 || attrOff+aLen > len(msg) {
				break
			}
			val := msg[attrOff+4 : attrOff+aLen]
			step := (aLen + 3) &^ 3
			if step == 0 {
				break
			}
			attrOff += step

			switch aType {
			case nfulaPrefix:
				prefix = strings.TrimRight(string(val), "\x00 ")
			case nfulaIfindexIndev:
				if len(val) >= 4 {
					idx := binary.BigEndian.Uint32(val[:4])
					if n, ok := ifNames[idx]; ok {
						entry.Interface = n
					} else if idx > 0 {
						entry.Interface = fmt.Sprintf("if%d", idx)
					}
				}
			case nfulaIfindexOutdev:
				if len(val) >= 4 {
					idx := binary.BigEndian.Uint32(val[:4])
					if n, ok := ifNames[idx]; ok {
						entry.OutIface = n
					} else if idx > 0 {
						entry.OutIface = fmt.Sprintf("if%d", idx)
					}
				}
			case nfulaTimestamp:
				if len(val) >= 16 {
					sec := int64(binary.BigEndian.Uint64(val[0:8]))
					usec := int64(binary.BigEndian.Uint64(val[8:16]))
					if sec > 0 {
						entry.Time = time.Unix(sec, usec*1000).UTC().Format(time.RFC3339Nano)
					}
				}
			case nfulaPayload:
				parseIPPacketSummary(val, &entry)
			}
		}

		// Enrich prefix: "axonwall-rule:<8char>:"
		ruleKey := ""
		if strings.HasPrefix(prefix, "axonwall-rule:") {
			rest := strings.TrimPrefix(prefix, "axonwall-rule:")
			if idx := strings.IndexByte(rest, ':'); idx >= 0 {
				ruleKey = rest[:idx]
			} else {
				ruleKey = strings.TrimSpace(rest)
			}
		}
		if ruleKey != "" {
			if rm, ok := rules[ruleKey]; ok {
				entry.RuleID = rm.ID
				entry.Action = rm.Action
				if entry.Interface == "" {
					entry.Interface = rm.Interface
				}
				if rm.Action == "pass" {
					entry.Level = "info"
				}
				entry.Msg = fmt.Sprintf("Firewall %s [%s] %s %s:%d -> %s:%d (%s)",
					strings.ToUpper(rm.Action), rm.Description, entry.Protocol, entry.SrcIP, entry.SrcPort, entry.DstIP, entry.DstPort, prefix)
			} else {
				entry.RuleID = ruleKey
			}
		}
		if entry.Msg == "" {
			entry.Msg = fmt.Sprintf("NFLOG[%d] %s %s %s:%d -> %s:%d",
				groupID, prefix, entry.Protocol, entry.SrcIP, entry.SrcPort, entry.DstIP, entry.DstPort)
		}
		out = append(out, entry)
	}
	return out
}

func parseIPPacketSummary(pkt []byte, entry *StructuredLogEntry) {
	if len(pkt) < 1 {
		return
	}
	ver := pkt[0] >> 4
	if ver == 4 && len(pkt) >= 20 {
		ihl := int(pkt[0]&0x0F) * 4
		if ihl < 20 || ihl > len(pkt) {
			return
		}
		proto := pkt[9]
		entry.Protocol = netflowProtocolName(proto)
		entry.SrcIP = net.IP(pkt[12:16]).String()
		entry.DstIP = net.IP(pkt[16:20]).String()
		parseL4Ports(pkt[ihl:], proto, entry)
	} else if ver == 6 && len(pkt) >= 40 {
		proto := pkt[6]
		entry.Protocol = netflowProtocolName(proto)
		entry.SrcIP = net.IP(pkt[8:24]).String()
		entry.DstIP = net.IP(pkt[24:40]).String()
		parseL4Ports(pkt[40:], proto, entry)
	}
}

func parseL4Ports(l4 []byte, proto uint8, entry *StructuredLogEntry) {
	if (proto == 6 || proto == 17) && len(l4) >= 4 {
		entry.SrcPort = binary.BigEndian.Uint16(l4[0:2])
		entry.DstPort = binary.BigEndian.Uint16(l4[2:4])
	}
}
