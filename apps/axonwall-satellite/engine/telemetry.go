package engine

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"time"
)

// SatelliteMetrics holds live runtime performance telemetry from the edge
type SatelliteMetrics struct {
	Timestamp       int64   `json:"timestamp"`
	UptimeSeconds   int64   `json:"uptimeSeconds"`
	CpuUsagePercent float64 `json:"cpuUsagePercent"`
	MemUsagePercent float64 `json:"memUsagePercent"`
	ActiveConns     int64   `json:"activeConns"`
	RxBytesTotal    int64   `json:"rxBytesTotal"`
	TxBytesTotal    int64   `json:"txBytesTotal"`
}

// CollectMetrics gathers metrics from the Linux kernel (/proc)
func CollectMetrics() SatelliteMetrics {
	metrics := SatelliteMetrics{
		Timestamp: time.Now().Unix(),
	}

	// 1. Read Uptime
	if data, err := os.ReadFile("/proc/uptime"); err == nil {
		parts := strings.Fields(string(data))
		if len(parts) > 0 {
			if sec, err := strconv.ParseFloat(parts[0], 64); err == nil {
				metrics.UptimeSeconds = int64(sec)
			}
		}
	}

	// 2. Read Meminfo
	if file, err := os.Open("/proc/meminfo"); err == nil {
		defer file.Close()
		scanner := bufio.NewScanner(file)
		var totalMem, availMem float64
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "MemTotal:") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					totalMem, _ = strconv.ParseFloat(fields[1], 64)
				}
			} else if strings.HasPrefix(line, "MemAvailable:") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					availMem, _ = strconv.ParseFloat(fields[1], 64)
				}
			}
		}
		if totalMem > 0 {
			metrics.MemUsagePercent = ((totalMem - availMem) / totalMem) * 100.0
		}
	}

	// 3. Read Active Conntrack entries
	if data, err := os.ReadFile("/proc/sys/net/netfilter/nf_conntrack_count"); err == nil {
		if val, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64); err == nil {
			metrics.ActiveConns = val
		}
	}

	// 4. Read Network Device I/O (/proc/net/dev)
	if file, err := os.Open("/proc/net/dev"); err == nil {
		defer file.Close()
		scanner := bufio.NewScanner(file)
		var totalRx, totalTx int64
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if strings.Contains(line, ":") {
				parts := strings.Split(line, ":")
				fields := strings.Fields(parts[1])
				if len(fields) >= 9 {
					rx, _ := strconv.ParseInt(fields[0], 10, 64)
					tx, _ := strconv.ParseInt(fields[8], 10, 64)
					// Exclude loopback
					if !strings.HasPrefix(parts[0], "lo") {
						totalRx += rx
						totalTx += tx
					}
				}
			}
		}
		metrics.RxBytesTotal = totalRx
		metrics.TxBytesTotal = totalTx
	}

	return metrics
}
