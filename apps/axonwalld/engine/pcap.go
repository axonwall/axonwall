package engine

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type CapturedPacket struct {
	Index     int    `json:"index"`
	Timestamp string `json:"timestamp"`
	SrcIP     string `json:"srcIp"`
	SrcPort   string `json:"srcPort"`
	DstIP     string `json:"dstIp"`
	DstPort   string `json:"dstPort"`
	Protocol  string `json:"protocol"`
	Length    int    `json:"length"`
	Info      string `json:"info"`
}

type CaptureResult struct {
	ID          string           `json:"id"`
	Interface   string           `json:"interface"`
	Filter      string           `json:"filter"`
	PacketCount int              `json:"packetCount"`
	Packets     []CapturedPacket `json:"packets"`
	PcapPath    string           `json:"pcapPath"`
	StartedAt   string           `json:"startedAt"`
	CompletedAt string           `json:"completedAt"`
}

type PacketCaptureManager struct {
	captureDir string
}

func NewPacketCaptureManager() *PacketCaptureManager {
	dir := "/var/lib/axonwall/captures"
	if err := os.MkdirAll(dir, 0775); err != nil {
		dir = "/var/log/axonwall/captures"
		if err2 := os.MkdirAll(dir, 0775); err2 != nil {
			dir = filepath.Join(os.TempDir(), "axonwall-captures")
			_ = os.MkdirAll(dir, 0775)
		}
	}
	_ = os.Chmod(dir, 0775)
	return &PacketCaptureManager{captureDir: dir}
}

func (m *PacketCaptureManager) GetCaptureDir() string {
	return m.captureDir
}

var validIfaceRegex = regexp.MustCompile(`^[a-zA-Z0-9_.-]+$`)

// RunCapture captures up to `count` packets matching `filter` on `iface`
func (m *PacketCaptureManager) RunCapture(ctx context.Context, iface string, filter string, count int) (*CaptureResult, error) {
	if count <= 0 || count > 1000 {
		count = 50
	}
	if iface == "" {
		iface = "any"
	}
	if !validIfaceRegex.MatchString(iface) || strings.Contains(iface, "..") || strings.Contains(iface, "/") || strings.HasPrefix(iface, "-") {
		return nil, fmt.Errorf("invalid interface name: %s", iface)
	}

	var filterTokens []string
	if filter != "" {
		for _, tok := range strings.Fields(filter) {
			if strings.HasPrefix(tok, "-") {
				return nil, fmt.Errorf("invalid filter token starting with '-': %s", tok)
			}
			filterTokens = append(filterTokens, tok)
		}
	}

	safeIface := strings.ReplaceAll(iface, ".", "_")
	// A-M15: the ID must be unique per capture, not per second. Two
	// captures on one interface within the same second previously
	// shared a filename, so the second tcpdump truncated the file
	// while the first caller was still parsing it.
	captureID := fmt.Sprintf("pcap-%d-%d-%s", os.Getpid(), time.Now().UnixNano(), safeIface)
	pcapFile := filepath.Join(m.captureDir, fmt.Sprintf("%s.pcap", captureID))
	startedAt := time.Now().UTC().Format(time.RFC3339)

	// Verify if tcpdump exists on the system. There is deliberately
	// no mock fallback here: serving fabricated flows in the shape
	// of a live capture (the old generateMockCapture) presented
	// invented traffic as observed traffic — the same defect class
	// as the UI-side C5 fix. A box without tcpdump gets an error,
	// not a plausible-looking lie.
	tcpdumpPath, err := exec.LookPath("tcpdump")
	if err != nil {
		return nil, fmt.Errorf("packet capture unavailable: tcpdump is not installed on this system")
	}

	args := []string{"-i", iface, "-c", strconv.Itoa(count), "-nn", "-s", "0", "-w", pcapFile}
	if len(filterTokens) > 0 {
		args = append(args, filterTokens...)
	}

	// Safety: limit capture to max 30 seconds
	execCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(execCtx, tcpdumpPath, args...)
	// Capture stderr so a failed run can be reported, not swallowed.
	var tcpdumpStderr strings.Builder
	cmd.Stderr = &tcpdumpStderr
	runErr := cmd.Run() // tcpdump exits when count packets captured or timeout occurs
	_ = os.Chmod(pcapFile, 0664)

	completedAt := time.Now().UTC().Format(time.RFC3339)

	// Parse captured packets from the pcap file using tcpdump -nn -tt -r
	packets, _ := m.parsePcap(pcapFile)
	if len(packets) == 0 {
		// A-M15: a failed tcpdump run (down/nonexistent interface,
		// permission, bad filter) used to return "success, 0
		// packets". Return tcpdump's error instead. A run that was
		// cut short by the 30s cap but still captured packets keeps
		// returning those packets below.
		if runErr != nil {
			return nil, fmt.Errorf("tcpdump failed on interface %s: %w (stderr: %s)", iface, runErr, strings.TrimSpace(tcpdumpStderr.String()))
		}
		// If 0 packets captured on live interface, provide clean result
		packets = []CapturedPacket{}
	}

	return &CaptureResult{
		ID:          captureID,
		Interface:   iface,
		Filter:      filter,
		PacketCount: len(packets),
		Packets:     packets,
		PcapPath:    pcapFile,
		StartedAt:   startedAt,
		CompletedAt: completedAt,
	}, nil
}

func (m *PacketCaptureManager) parsePcap(pcapFile string) ([]CapturedPacket, error) {
	var packets []CapturedPacket
	if _, err := os.Stat(pcapFile); os.IsNotExist(err) {
		return packets, err
	}

	cmd := exec.Command("tcpdump", "-nn", "-tt", "-r", pcapFile)
	out, err := cmd.StdoutPipe()
	if err != nil {
		return packets, err
	}
	if err := cmd.Start(); err != nil {
		return packets, err
	}

	scanner := bufio.NewScanner(out)
	idx := 1

	for scanner.Scan() {
		if pkt, ok := parseTcpdumpLine(scanner.Text(), idx); ok {
			packets = append(packets, pkt)
			idx++
		}
	}
	_ = cmd.Wait()

	return packets, nil
}

var (
	pcapIPPortRegex     = regexp.MustCompile(`^(\d+\.\d+)\s+IP\s+([0-9a-fA-F.:]+)\.([0-9]+)\s+>\s+([0-9a-fA-F.:]+)\.([0-9]+):\s+(.*)$`)
	pcapGenericIPRegex  = regexp.MustCompile(`^(\d+\.\d+)\s+IP\s+([0-9a-fA-F.:]+)\s+>\s+([0-9a-fA-F.:]+):\s+(.*)$`)
	pcapIP6PortRegex    = regexp.MustCompile(`^(\d+\.\d+)\s+IP6\s+([0-9a-fA-F:]+)\.([0-9]+)\s+>\s+([0-9a-fA-F:]+)\.([0-9]+):\s+(.*)$`)
	pcapIP6GenericRegex = regexp.MustCompile(`^(\d+\.\d+)\s+IP6\s+(\S+)\s+>\s+(\S+):\s+(.*)$`)
	pcapARPRegex        = regexp.MustCompile(`^(\d+\.\d+)\s+ARP,\s+(.*)$`)
)

func pcapTimestamp(tsSec float64) string {
	return time.Unix(int64(tsSec), int64((tsSec-float64(int64(tsSec)))*1e9)).Format("15:04:05.000000")
}

// parseTcpdumpLine parses one tcpdump -tt line into a packet. L13:
// IPv6 (IP6) and ARP lines used to fall through both regexes and be
// dropped without a trace, so PacketCount reported only the parsed
// IPv4 subset as if it were the whole capture.
func parseTcpdumpLine(line string, idx int) (CapturedPacket, bool) {
	var pkt CapturedPacket
	pkt.Index = idx

	if matches := pcapIPPortRegex.FindStringSubmatch(line); len(matches) >= 7 {
		tsSec, _ := strconv.ParseFloat(matches[1], 64)
		pkt.Timestamp = pcapTimestamp(tsSec)
		pkt.SrcIP = matches[2]
		pkt.SrcPort = matches[3]
		pkt.DstIP = matches[4]
		pkt.DstPort = matches[5]
		pkt.Info = matches[6]

		// Protocol inference
		if pkt.SrcPort == "53" || pkt.DstPort == "53" {
			pkt.Protocol = "DNS"
		} else if pkt.SrcPort == "443" || pkt.DstPort == "443" {
			pkt.Protocol = "TLS/HTTPS"
		} else if pkt.SrcPort == "80" || pkt.DstPort == "80" {
			pkt.Protocol = "HTTP"
		} else if pkt.SrcPort == "22" || pkt.DstPort == "22" {
			pkt.Protocol = "SSH"
		} else if pkt.SrcPort == "51820" || pkt.DstPort == "51820" {
			pkt.Protocol = "WireGuard"
		} else if strings.Contains(pkt.Info, "Flags") {
			pkt.Protocol = "TCP"
		} else {
			pkt.Protocol = "UDP"
		}
		pkt.Length = len(line)
		return pkt, true
	}
	if matches := pcapGenericIPRegex.FindStringSubmatch(line); len(matches) >= 5 {
		tsSec, _ := strconv.ParseFloat(matches[1], 64)
		pkt.Timestamp = pcapTimestamp(tsSec)
		pkt.SrcIP = matches[2]
		pkt.DstIP = matches[3]
		pkt.Info = matches[4]
		if strings.Contains(pkt.Info, "ICMP") {
			pkt.Protocol = "ICMP"
		} else {
			pkt.Protocol = "IP"
		}
		pkt.Length = len(line)
		return pkt, true
	}
	if matches := pcapIP6PortRegex.FindStringSubmatch(line); len(matches) >= 7 {
		tsSec, _ := strconv.ParseFloat(matches[1], 64)
		pkt.Timestamp = pcapTimestamp(tsSec)
		pkt.SrcIP = matches[2]
		pkt.SrcPort = matches[3]
		pkt.DstIP = matches[4]
		pkt.DstPort = matches[5]
		pkt.Info = matches[6]
		if pkt.SrcPort == "53" || pkt.DstPort == "53" {
			pkt.Protocol = "DNS"
		} else if pkt.SrcPort == "443" || pkt.DstPort == "443" {
			pkt.Protocol = "TLS/HTTPS"
		} else if strings.Contains(pkt.Info, "Flags") {
			pkt.Protocol = "TCP"
		} else {
			pkt.Protocol = "UDP"
		}
		pkt.Length = len(line)
		return pkt, true
	}
	if matches := pcapIP6GenericRegex.FindStringSubmatch(line); len(matches) >= 5 {
		tsSec, _ := strconv.ParseFloat(matches[1], 64)
		pkt.Timestamp = pcapTimestamp(tsSec)
		pkt.SrcIP = matches[2]
		pkt.DstIP = matches[3]
		pkt.Info = matches[4]
		if strings.Contains(pkt.Info, "ICMP6") {
			pkt.Protocol = "ICMPv6"
		} else {
			pkt.Protocol = "IPv6"
		}
		pkt.Length = len(line)
		return pkt, true
	}
	if matches := pcapARPRegex.FindStringSubmatch(line); len(matches) >= 3 {
		tsSec, _ := strconv.ParseFloat(matches[1], 64)
		pkt.Timestamp = pcapTimestamp(tsSec)
		pkt.Info = matches[2]
		pkt.Protocol = "ARP"
		pkt.Length = len(line)
		return pkt, true
	}
	return pkt, false
}
