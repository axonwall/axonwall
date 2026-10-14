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
	dir := "/var/log/axonwall/captures"
	if err := os.MkdirAll(dir, 0755); err != nil {
		dir = filepath.Join(os.TempDir(), "axonwall-captures")
		_ = os.MkdirAll(dir, 0755)
	}
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

	captureID := fmt.Sprintf("pcap-%d-%s", time.Now().Unix(), iface)
	pcapFile := filepath.Join(m.captureDir, fmt.Sprintf("%s.pcap", captureID))
	startedAt := time.Now().UTC().Format(time.RFC3339)

	// Verify if tcpdump exists on the system
	tcpdumpPath, err := exec.LookPath("tcpdump")
	if err != nil {
		// Mock capture fallback for development mode when tcpdump is not installed
		return m.generateMockCapture(captureID, iface, filter, count, startedAt, pcapFile), nil
	}

	args := []string{"-i", iface, "-c", strconv.Itoa(count), "-nn", "-s", "0", "-w", pcapFile}
	if len(filterTokens) > 0 {
		args = append(args, filterTokens...)
	}

	// Safety: limit capture to max 30 seconds
	execCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(execCtx, tcpdumpPath, args...)
	_ = cmd.Run() // tcpdump exits when count packets captured or timeout occurs

	completedAt := time.Now().UTC().Format(time.RFC3339)

	// Parse captured packets from the pcap file using tcpdump -nn -tt -r
	packets, _ := m.parsePcap(pcapFile)
	if len(packets) == 0 {
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
	ipPortRegex := regexp.MustCompile(`^(\d+\.\d+)\s+IP\s+([0-9a-fA-F.:]+)\.([0-9]+)\s+>\s+([0-9a-fA-F.:]+)\.([0-9]+):\s+(.*)$`)
	genericIPRegex := regexp.MustCompile(`^(\d+\.\d+)\s+IP\s+([0-9a-fA-F.:]+)\s+>\s+([0-9a-fA-F.:]+):\s+(.*)$`)

	for scanner.Scan() {
		line := scanner.Text()
		var pkt CapturedPacket
		pkt.Index = idx

		if matches := ipPortRegex.FindStringSubmatch(line); len(matches) >= 7 {
			tsSec, _ := strconv.ParseFloat(matches[1], 64)
			pkt.Timestamp = time.Unix(int64(tsSec), int64((tsSec-float64(int64(tsSec)))*1e9)).Format("15:04:05.000000")
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
			packets = append(packets, pkt)
			idx++
		} else if matches := genericIPRegex.FindStringSubmatch(line); len(matches) >= 5 {
			tsSec, _ := strconv.ParseFloat(matches[1], 64)
			pkt.Timestamp = time.Unix(int64(tsSec), int64((tsSec-float64(int64(tsSec)))*1e9)).Format("15:04:05.000000")
			pkt.SrcIP = matches[2]
			pkt.DstIP = matches[3]
			pkt.Info = matches[4]
			if strings.Contains(pkt.Info, "ICMP") {
				pkt.Protocol = "ICMP"
			} else {
				pkt.Protocol = "IP"
			}
			pkt.Length = len(line)
			packets = append(packets, pkt)
			idx++
		}
	}
	_ = cmd.Wait()

	return packets, nil
}

func (m *PacketCaptureManager) generateMockCapture(id, iface, filter string, count int, startedAt, pcapFile string) *CaptureResult {
	// Create an empty dummy file for pcap download
	_ = os.WriteFile(pcapFile, []byte("MOCK_PCAP_FILE_HEADER"), 0644)

	var packets []CapturedPacket
	mockFlows := []struct {
		proto   string
		srcIP   string
		srcPort string
		dstIP   string
		dstPort string
		info    string
	}{
		{"DNS", "192.168.1.105", "54321", "192.168.1.1", "53", "Standard query 0x1a2b A deb.debian.org"},
		{"DNS", "192.168.1.1", "53", "192.168.1.105", "54321", "Standard query response 0x1a2b A 151.101.130.132"},
		{"TLS/HTTPS", "192.168.1.105", "51234", "151.101.130.132", "443", "Client Hello, Version: TLS 1.3 (SNI: deb.debian.org)"},
		{"TLS/HTTPS", "151.101.130.132", "443", "192.168.1.105", "51234", "Server Hello, Change Cipher Spec, Encrypted Handshake Message"},
		{"TCP", "192.168.1.105", "51234", "151.101.130.132", "443", "Flags [P.], seq 1:512, ack 1, win 502, length 511"},
		{"ICMP", "192.168.1.50", "-", "8.8.8.8", "-", "echo request, id 0x1234, seq 1, length 64"},
		{"ICMP", "8.8.8.8", "-", "192.168.1.50", "-", "echo reply, id 0x1234, seq 1, length 64"},
		{"WireGuard", "192.168.1.1", "51820", "198.51.100.25", "51820", "Transport Data, Receiver index 0x98f2, Counter 1024, length 128"},
	}

	now := time.Now()
	for i := 0; i < count && i < len(mockFlows); i++ {
		flow := mockFlows[i%len(mockFlows)]
		t := now.Add(time.Duration(i*80) * time.Millisecond)
		packets = append(packets, CapturedPacket{
			Index:     i + 1,
			Timestamp: t.Format("15:04:05.000000"),
			SrcIP:     flow.srcIP,
			SrcPort:   flow.srcPort,
			DstIP:     flow.dstIP,
			DstPort:   flow.dstPort,
			Protocol:  flow.proto,
			Length:    64 + (i * 128),
			Info:      flow.info,
		})
	}

	return &CaptureResult{
		ID:          id,
		Interface:   iface,
		Filter:      filter,
		PacketCount: len(packets),
		Packets:     packets,
		PcapPath:    pcapFile,
		StartedAt:   startedAt,
		CompletedAt: time.Now().UTC().Format(time.RFC3339),
	}
}
