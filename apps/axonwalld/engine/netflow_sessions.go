package engine

import (
	"fmt"
	"math"
	"sort"
	"strings"
)

// StitchBidirectionalSessions pairs unidirectional flow records into bidirectional
// 5-tuple sessions, computing asymmetry ratios, unanswered SYN detection, and RTT summaries.
func StitchBidirectionalSessions(flows []FlowRecord, gapMs int64) []FlowSessionRecord {
	if len(flows) == 0 {
		return nil
	}
	if gapMs <= 0 {
		gapMs = 120_000
	}

	// Sort chronologically so earliest initiator packet determines forward direction.
	sorted := make([]FlowRecord, len(flows))
	copy(sorted, flows)
	sort.Slice(sorted, func(i, j int) bool {
		si := sorted[i].FlowStartMs
		if si <= 0 {
			si = sorted[i].TimestampMs
		}
		sj := sorted[j].FlowStartMs
		if sj <= 0 {
			sj = sorted[j].TimestampMs
		}
		return si < sj
	})

	type sessState struct {
		rec      FlowSessionRecord
		rttSum   float64
		rttCount int
		synSeen  bool
	}

	byKey := make(map[string][]*sessState)
	var all []*sessState

	for _, f := range sorted {
		epA := fmt.Sprintf("%s:%d", f.SrcIP, f.SrcPort)
		epB := fmt.Sprintf("%s:%d", f.DstIP, f.DstPort)
		canon := fmt.Sprintf("%d|%s|%s", f.Protocol, epA, epB)
		if epB < epA {
			canon = fmt.Sprintf("%d|%s|%s", f.Protocol, epB, epA)
		}

		fStart := f.FlowStartMs
		if fStart <= 0 {
			fStart = f.TimestampMs
		}
		fEnd := f.TimestampMs
		if fEnd < fStart {
			fEnd = fStart
		}

		var st *sessState
		for _, cand := range byKey[canon] {
			if fStart-cand.rec.LastSeenMs <= gapMs {
				st = cand
				break
			}
		}

		synOnly := f.Protocol == 6 && (f.TCPFlags&0x02 != 0) && (f.TCPFlags&0x10 == 0)
		if st == nil {
			st = &sessState{
				rec: FlowSessionRecord{
					ID:            fmt.Sprintf("sess-%d-%s-%d-%s-%d", fStart, f.SrcIP, f.SrcPort, f.DstIP, f.DstPort),
					InitiatorIP:   f.SrcIP,
					InitiatorHost: f.SrcHost,
					ResponderIP:   f.DstIP,
					ResponderHost: f.DstHost,
					InitiatorPort: f.SrcPort,
					ResponderPort: f.DstPort,
					Protocol:      f.Protocol,
					ProtocolName:  f.ProtocolName,
					AppName:       firstNonEmpty(f.AppName, f.ProtocolName),
					Direction:     f.Direction,
					FirstSeenMs:   fStart,
					LastSeenMs:    fEnd,
					ThreatMatch:   f.ThreatMatch,
				},
			}
			byKey[canon] = append(byKey[canon], st)
			all = append(all, st)
		} else if synOnly && st.rec.PacketsRev == 0 && (f.SrcIP != st.rec.InitiatorIP || f.SrcPort != st.rec.InitiatorPort) {
			// Flip roles if true TCP SYN initiator appears slightly out-of-order and reverse had no packets.
			st.rec.InitiatorIP, st.rec.ResponderIP = st.rec.ResponderIP, st.rec.InitiatorIP
			st.rec.InitiatorHost, st.rec.ResponderHost = st.rec.ResponderHost, st.rec.InitiatorHost
			st.rec.InitiatorPort, st.rec.ResponderPort = st.rec.ResponderPort, st.rec.InitiatorPort
			st.rec.BytesFwd, st.rec.BytesRev = st.rec.BytesRev, st.rec.BytesFwd
			st.rec.PacketsFwd, st.rec.PacketsRev = st.rec.PacketsRev, st.rec.PacketsFwd
		}

		isFwd := f.SrcIP == st.rec.InitiatorIP && f.SrcPort == st.rec.InitiatorPort
		if isFwd {
			st.rec.BytesFwd += f.Bytes
			st.rec.PacketsFwd += f.Packets
			if f.TCPFlags&0x02 != 0 {
				st.synSeen = true
			}
		} else {
			st.rec.BytesRev += f.Bytes
			st.rec.PacketsRev += f.Packets
		}
		st.rec.FlowsCount++
		if fEnd > st.rec.LastSeenMs {
			st.rec.LastSeenMs = fEnd
		}
		if fStart < st.rec.FirstSeenMs {
			st.rec.FirstSeenMs = fStart
		}
		if f.ThreatMatch != "" && st.rec.ThreatMatch == "" {
			st.rec.ThreatMatch = f.ThreatMatch
		}
		if f.RttMs > 0 {
			st.rttSum += f.RttMs
			st.rttCount++
		}
		st.rec.TotalRetransmits += f.Retransmits
	}

	out := make([]FlowSessionRecord, 0, len(all))
	for _, st := range all {
		r := st.rec
		r.DurationMs = r.LastSeenMs - r.FirstSeenMs
		totalB := r.BytesFwd + r.BytesRev
		if totalB > 0 {
			hi := r.BytesFwd
			if r.BytesRev > hi {
				hi = r.BytesRev
			}
			r.AsymmetryRatio = math.Round((float64(hi)/float64(totalB))*1000) / 1000
		}
		r.UnansweredSyn = r.Protocol == 6 && st.synSeen && r.PacketsRev == 0
		if st.rttCount > 0 {
			r.AvgRttMs = math.Round((st.rttSum/float64(st.rttCount))*100) / 100
		}
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool {
		return (out[i].BytesFwd + out[i].BytesRev) > (out[j].BytesFwd + out[j].BytesRev)
	})
	if len(out) > 250 {
		out = out[:250]
	}
	return out
}

// BuildHostHeatmap constructs a top-N source x destination byte intensity matrix.
func BuildHostHeatmap(flows []FlowRecord, topSources, topDests []FlowTopEntry) *FlowHeatmapMatrix {
	if len(topSources) == 0 || len(topDests) == 0 {
		return nil
	}
	maxN := 12
	rows := make([]string, 0, minInt(maxN, len(topSources)))
	rowIdx := make(map[string]int, maxN)
	for i := 0; i < len(topSources) && i < maxN; i++ {
		rows = append(rows, topSources[i].Key)
		rowIdx[topSources[i].Key] = i
	}
	cols := make([]string, 0, minInt(maxN, len(topDests)))
	colIdx := make(map[string]int, maxN)
	for i := 0; i < len(topDests) && i < maxN; i++ {
		cols = append(cols, topDests[i].Key)
		colIdx[topDests[i].Key] = i
	}
	vals := make([][]uint64, len(rows))
	for i := range vals {
		vals[i] = make([]uint64, len(cols))
	}
	var maxVal uint64
	for _, f := range flows {
		r, okR := rowIdx[f.SrcIP]
		c, okC := colIdx[f.DstIP]
		if !okR || !okC {
			continue
		}
		vals[r][c] += f.Bytes
		if vals[r][c] > maxVal {
			maxVal = vals[r][c]
		}
	}
	return &FlowHeatmapMatrix{RowLabels: rows, ColLabels: cols, Values: vals, MaxValue: maxVal}
}

// BuildPortTimeHeatmap constructs a top-12 destination ports x time buckets matrix.
func BuildPortTimeHeatmap(flows []FlowRecord, timeseries []FlowTimeseriesPoint, startMs, bucketMs int64) *FlowHeatmapMatrix {
	if len(flows) == 0 || len(timeseries) == 0 || bucketMs <= 0 {
		return nil
	}
	portTotals := make(map[string]uint64)
	for _, f := range flows {
		if f.DstPort > 0 {
			portTotals[fmt.Sprintf("%d", f.DstPort)] += f.Bytes
		}
	}
	if len(portTotals) == 0 {
		return nil
	}
	type pk struct {
		p string
		b uint64
	}
	var ranked []pk
	for p, b := range portTotals {
		ranked = append(ranked, pk{p: p, b: b})
	}
	sort.Slice(ranked, func(i, j int) bool { return ranked[i].b > ranked[j].b })
	maxRows := 12
	if len(ranked) > maxRows {
		ranked = ranked[:maxRows]
	}
	rows := make([]string, len(ranked))
	rowIdx := make(map[string]int, len(ranked))
	for i, item := range ranked {
		rows[i] = item.p
		rowIdx[item.p] = i
	}

	cols := make([]string, len(timeseries))
	colIdx := make(map[int64]int, len(timeseries))
	for i, pt := range timeseries {
		cols[i] = pt.TimeLabel
		colIdx[pt.TimestampMs] = i
	}
	vals := make([][]uint64, len(rows))
	for i := range vals {
		vals[i] = make([]uint64, len(cols))
	}
	var maxVal uint64
	for _, f := range flows {
		r, okR := rowIdx[fmt.Sprintf("%d", f.DstPort)]
		if !okR {
			continue
		}
		bTs := (f.TimestampMs / bucketMs) * bucketMs
		c, okC := colIdx[bTs]
		if !okC {
			// Fallback nearest column when offset-based bucketing varies
			continue
		}
		vals[r][c] += f.Bytes
		if vals[r][c] > maxVal {
			maxVal = vals[r][c]
		}
	}
	_ = startMs
	return &FlowHeatmapMatrix{RowLabels: rows, ColLabels: cols, Values: vals, MaxValue: maxVal}
}

// BuildGeoArcs aggregates lat/lon flow arcs from MMDB-enriched coordinates or country centroids.
func BuildGeoArcs(flows []FlowRecord) []FlowGeoArc {
	type arcKey struct {
		sc, dc string
	}
	agg := make(map[arcKey]*FlowGeoArc)
	for _, f := range flows {
		if f.SrcCountry == "" || f.DstCountry == "" {
			continue
		}
		if f.SrcCountry == "LAN" && f.DstCountry == "LAN" {
			continue
		}
		sLat, sLon := f.SrcLat, f.SrcLon
		dLat, dLon := f.DstLat, f.DstLon
		if sLat == 0 && sLon == 0 {
			sLat, sLon = countryFallbackCoords(f.SrcCountry)
		}
		if dLat == 0 && dLon == 0 {
			dLat, dLon = countryFallbackCoords(f.DstCountry)
		}
		if (sLat == 0 && sLon == 0) || (dLat == 0 && dLon == 0) {
			continue
		}
		k := arcKey{sc: f.SrcCountry, dc: f.DstCountry}
		a := agg[k]
		if a == nil {
			a = &FlowGeoArc{
				SrcCountry: f.SrcCountry,
				DstCountry: f.DstCountry,
				SrcCity:    f.SrcCity,
				DstCity:    f.DstCity,
				SrcLat:     sLat,
				SrcLon:     sLon,
				DstLat:     dLat,
				DstLon:     dLon,
			}
			agg[k] = a
		}
		a.Bytes += f.Bytes
		a.Flows++
		if f.ThreatMatch != "" {
			a.Threat = true
		}
	}
	out := make([]FlowGeoArc, 0, len(agg))
	for _, a := range agg {
		out = append(out, *a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Bytes > out[j].Bytes })
	if len(out) > 40 {
		out = out[:40]
	}
	return out
}

func countryFallbackCoords(iso string) (float64, float64) {
	switch strings.ToUpper(iso) {
	case "LAN":
		return 39.8, -98.5
	case "US":
		return 37.75, -97.82
	case "CA":
		return 56.13, -106.34
	case "GB":
		return 55.37, -3.43
	case "DE":
		return 51.16, 10.45
	case "FR":
		return 46.22, 2.21
	case "NL":
		return 52.13, 5.29
	case "CH":
		return 46.81, 8.22
	case "JP":
		return 36.20, 138.25
	case "SG":
		return 1.35, 103.81
	case "AU":
		return -25.27, 133.77
	case "BR":
		return -14.23, -51.92
	case "IN":
		return 20.59, 78.96
	case "CN":
		return 35.86, 104.19
	case "KR":
		return 35.90, 127.76
	case "EXT":
		return 50.11, 8.68
	default:
		return 0, 0
	}
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
