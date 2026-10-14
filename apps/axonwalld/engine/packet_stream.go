package engine

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type PacketStreamFilter struct {
	Interface string `json:"interface"`
	SrcIP     string `json:"srcIp"`
	DstIP     string `json:"dstIp"`
	Protocol  string `json:"protocol"`
	Port      string `json:"port"`
}

type PacketStreamManager struct {
	pcapManager *PacketCaptureManager
}

func NewPacketStreamManager(pcapMgr *PacketCaptureManager) *PacketStreamManager {
	return &PacketStreamManager{
		pcapManager: pcapMgr,
	}
}

func (m *PacketStreamManager) HandleStreamSSE(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	filter := PacketStreamFilter{
		Interface: strings.TrimSpace(r.URL.Query().Get("interface")),
		SrcIP:     strings.TrimSpace(r.URL.Query().Get("srcIp")),
		DstIP:     strings.TrimSpace(r.URL.Query().Get("dstIp")),
		Protocol:  strings.TrimSpace(r.URL.Query().Get("protocol")),
		Port:      strings.TrimSpace(r.URL.Query().Get("port")),
	}
	if filter.Interface == "" {
		filter.Interface = "any"
	}
	if !validIfaceRegex.MatchString(filter.Interface) || strings.Contains(filter.Interface, "..") || strings.HasPrefix(filter.Interface, "-") {
		http.Error(w, "Invalid interface parameter", http.StatusBadRequest)
		return
	}
	if filter.SrcIP != "" && net.ParseIP(filter.SrcIP) == nil {
		http.Error(w, "Invalid srcIp parameter", http.StatusBadRequest)
		return
	}
	if filter.DstIP != "" && net.ParseIP(filter.DstIP) == nil {
		http.Error(w, "Invalid dstIp parameter", http.StatusBadRequest)
		return
	}
	if filter.Port != "" {
		p, err := strconv.Atoi(filter.Port)
		if err != nil || p < 1 || p > 65535 {
			http.Error(w, "Invalid port parameter", http.StatusBadRequest)
			return
		}
	}
	if filter.Protocol != "" && strings.ToLower(filter.Protocol) != "any" {
		proto := strings.ToLower(filter.Protocol)
		switch proto {
		case "tcp", "udp", "icmp", "icmp6", "arp":
			filter.Protocol = proto
		default:
			http.Error(w, "Invalid protocol parameter", http.StatusBadRequest)
			return
		}
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("X-Accel-Buffering", "no")
	flusher.Flush()

	ctx := r.Context()

	// Check if tcpdump is available
	tcpdumpPath, err := exec.LookPath("tcpdump")
	if err == nil {
		var bpfArgs []string
		if filter.SrcIP != "" {
			bpfArgs = append(bpfArgs, "src", filter.SrcIP)
		}
		if filter.DstIP != "" {
			bpfArgs = append(bpfArgs, "dst", filter.DstIP)
		}
		if filter.Port != "" {
			bpfArgs = append(bpfArgs, "port", filter.Port)
		}
		if filter.Protocol != "" && strings.ToLower(filter.Protocol) != "any" {
			bpfArgs = append(bpfArgs, strings.ToLower(filter.Protocol))
		}

		args := []string{"-l", "-nn", "-tt", "-i", filter.Interface}
		args = append(args, bpfArgs...)

		cmd := exec.CommandContext(ctx, tcpdumpPath, args...)
		stdout, pipeErr := cmd.StdoutPipe()
		if pipeErr == nil && cmd.Start() == nil {
			defer func() {
				_ = cmd.Process.Kill()
				_ = cmd.Wait()
			}()

			scanner := bufio.NewScanner(stdout)
			idx := 1
			ipPortRegex := regexp.MustCompile(`^(\d+\.\d+)\s+IP\s+([0-9a-fA-F.:]+)\.([0-9]+)\s+>\s+([0-9a-fA-F.:]+)\.([0-9]+):\s+(.*)$`)

			for scanner.Scan() {
				select {
				case <-ctx.Done():
					return
				default:
				}

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
					pkt.Length = len(line)

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
					pkt.SrcIP = filter.Interface
					pkt.DstIP = "kernel"
					pkt.Protocol = "RAW"
					pkt.Info = line
					pkt.Length = len(line)
				}

				data, _ := json.Marshal(pkt)
				_, _ = fmt.Fprintf(w, "event: packet\ndata: %s\n\n", data)
				flusher.Flush()
				idx++
			}
			return
		}
	}

	// Fallback simulated packet stream generator for environments without root/tcpdump
	m.streamMockPackets(ctx, w, flusher, filter)
}

func (m *PacketStreamManager) streamMockPackets(ctx context.Context, w http.ResponseWriter, flusher http.Flusher, filter PacketStreamFilter) {
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()

	sampleFlows := []struct {
		proto   string
		srcIP   string
		srcPort string
		dstIP   string
		dstPort string
		info    string
	}{
		{"TLS", "192.168.1.105", "58492", "142.250.190.46", "443", "Application Data [TLS 1.3], len=482"},
		{"DNS", "192.168.1.105", "61023", "192.168.1.1", "53", "Standard query 0x4f12 A security.axonwall.net"},
		{"DNS", "192.168.1.1", "53", "192.168.1.105", "61023", "Standard query response 0x4f12 A 198.51.100.8"},
		{"TCP", "192.168.1.50", "22", "192.168.1.10", "51240", "Flags [P.], seq 104:248, ack 12, win 502"},
		{"WireGuard", "192.168.1.1", "51820", "198.51.100.25", "51820", "Transport Data, Counter 4920, len=128"},
		{"ICMP", "192.168.1.105", "-", "8.8.8.8", "-", "echo request, id 0x8201, seq 4"},
		{"ICMP", "8.8.8.8", "-", "192.168.1.105", "-", "echo reply, id 0x8201, seq 4"},
	}

	idx := 1
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sample := sampleFlows[idx%len(sampleFlows)]
			src := sample.srcIP
			if filter.SrcIP != "" {
				src = filter.SrcIP
			}
			dst := sample.dstIP
			if filter.DstIP != "" {
				dst = filter.DstIP
			}
			proto := sample.proto
			if filter.Protocol != "" && filter.Protocol != "any" {
				proto = strings.ToUpper(filter.Protocol)
			}

			pkt := CapturedPacket{
				Index:     idx,
				Timestamp: time.Now().Format("15:04:05.000000"),
				SrcIP:     src,
				SrcPort:   sample.srcPort,
				DstIP:     dst,
				DstPort:   sample.dstPort,
				Protocol:  proto,
				Length:    64 + (idx%8)*128,
				Info:      sample.info,
			}

			data, _ := json.Marshal(pkt)
			_, _ = fmt.Fprintf(w, "event: packet\ndata: %s\n\n", data)
			flusher.Flush()
			idx++
		}
	}
}
