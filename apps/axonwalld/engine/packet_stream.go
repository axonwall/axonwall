package engine

import (
	"bufio"
	"bytes"
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

	// There is deliberately no mock fallback here: the old code
	// streamed fabricated flows (hardcoded 192.168.1.x sample
	// traffic) in exactly the same `event: packet` shape as live
	// traffic whenever tcpdump was missing — invented traffic
	// presented as observed traffic, the same defect class as the
	// UI-side C5 fix. A box without tcpdump gets a 503, not a
	// plausible-looking lie. The availability check runs before any
	// SSE headers are written so the error is a real HTTP error.
	ctx := r.Context()

	tcpdumpPath, err := exec.LookPath("tcpdump")
	if err != nil {
		http.Error(w, "packet capture unavailable: tcpdump is not installed on this system", http.StatusServiceUnavailable)
		return
	}

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
	if pipeErr != nil {
		http.Error(w, fmt.Sprintf("packet capture failed to start: %v", pipeErr), http.StatusInternalServerError)
		return
	}
	// A-M19: capture stderr so a failed tcpdump run can be reported
	// instead of ending the stream silently.
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		http.Error(w, fmt.Sprintf("packet capture failed to start: %v", err), http.StatusInternalServerError)
		return
	}
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("X-Accel-Buffering", "no")
	flusher.Flush()
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
		if _, err := fmt.Fprintf(w, "event: packet\ndata: %s\n\n", data); err != nil {
			return
		}
		flusher.Flush()
		idx++
	}

	// A-M19: tcpdump's exit status used to be discarded (the deferred
	// Wait swallowed it) and its stderr was never wired up, so a failed
	// run — down/nonexistent interface, bad BPF — ended the stream
	// silently and looked exactly like a live, idle interface. Surface
	// the failure as an SSE error event instead. A client disconnect
	// (ctx done) is not an error.
	waitErr := cmd.Wait()
	if ctx.Err() == nil {
		errMsg := ""
		if serr := scanner.Err(); serr != nil {
			errMsg = fmt.Sprintf("packet capture stream failed: %v", serr)
		} else if waitErr != nil {
			errMsg = fmt.Sprintf("packet capture failed: %v", waitErr)
			if detail := strings.TrimSpace(stderr.String()); detail != "" {
				errMsg = fmt.Sprintf("%s: %s", errMsg, detail)
			}
		}
		if errMsg != "" {
			_, _ = fmt.Fprintf(w, "event: error\ndata: %s\n\n", errMsg)
			flusher.Flush()
		}
	}
}
