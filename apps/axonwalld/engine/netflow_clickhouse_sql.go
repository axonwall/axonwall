package engine

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
)

func joinCompositeCH(op, a, b string) string {
	if op == "!=" {
		return fmt.Sprintf("(%s AND %s)", a, b)
	}
	return fmt.Sprintf("(%s OR %s)", a, b)
}

// CompileFQLToClickHouseSQL translates an FQL AST into a strictly parameterized ClickHouse WHERE predicate.
// Column names are strictly allow-listed; user values are always passed via positional ? parameters.
func CompileFQLToClickHouseSQL(node fqlNode) (string, []any, error) {
	if node == nil {
		return "1=1", nil, nil
	}
	var args []any
	sqlExpr, err := compileFqlNodeCH(node, &args)
	if err != nil {
		return "", nil, err
	}
	return sqlExpr, args, nil
}

func compileFqlNodeCH(node fqlNode, args *[]any) (string, error) {
	switch n := node.(type) {
	case fqlAnd:
		l, err := compileFqlNodeCH(n.left, args)
		if err != nil {
			return "", err
		}
		r, err := compileFqlNodeCH(n.right, args)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("(%s AND %s)", l, r), nil
	case fqlOr:
		l, err := compileFqlNodeCH(n.left, args)
		if err != nil {
			return "", err
		}
		r, err := compileFqlNodeCH(n.right, args)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("(%s OR %s)", l, r), nil
	case fqlNot:
		inner, err := compileFqlNodeCH(n.inner, args)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("(NOT %s)", inner), nil
	case fqlPred:
		return compileFqlPredCH(n, args)
	default:
		return "", fmt.Errorf("unsupported FQL AST node type %T", node)
	}
}

func chCompareOp(op string) (string, error) {
	switch op {
	case "=":
		return "=", nil
	case "!=":
		return "!=", nil
	case ">":
		return ">", nil
	case ">=":
		return ">=", nil
	case "<":
		return "<", nil
	case "<=":
		return "<=", nil
	default:
		return "", fmt.Errorf("unsupported numeric/equality operator %q", op)
	}
}

func chStringPred(col string, p fqlPred, args *[]any) (string, error) {
	if p.op == "~" {
		*args = append(*args, p.raw)
		return fmt.Sprintf("positionCaseInsensitive(%s, ?) > 0", col), nil
	}
	op, err := chCompareOp(p.op)
	if err != nil {
		op = "="
	}
	*args = append(*args, strings.ToLower(p.raw))
	return fmt.Sprintf("lower(%s) %s ?", col, op), nil
}

func chIPPred(col string, p fqlPred, args *[]any) (string, error) {
	if p.isNet {
		*args = append(*args, p.cidr.String())
		fn := "isIPv4String"
		if p.cidr.Addr().Is6() {
			fn = "isIPv6String"
		}
		if p.op == "!=" {
			return fmt.Sprintf("(NOT (%s(%s) AND isIPAddressInRange(%s, ?)))", fn, col, col), nil
		}
		return fmt.Sprintf("(%s(%s) AND isIPAddressInRange(%s, ?))", fn, col, col), nil
	}
	return chStringPred(col, p, args)
}

func chNumPred(col string, p fqlPred, args *[]any) (string, error) {
	if !p.isNum {
		return "0=1", nil
	}
	op, err := chCompareOp(p.op)
	if err != nil {
		return "", err
	}
	*args = append(*args, p.num)
	return fmt.Sprintf("%s %s ?", col, op), nil
}

func compileFqlPredCH(p fqlPred, args *[]any) (string, error) {
	if p.field == "_any" {
		q := p.raw
		*args = append(*args, q, q, q, q, q)
		return "(positionCaseInsensitive(src_ip, ?) > 0 OR positionCaseInsensitive(dst_ip, ?) > 0 OR positionCaseInsensitive(app_name, ?) > 0 OR positionCaseInsensitive(threat_match, ?) > 0 OR positionCaseInsensitive(src_city, ?) > 0)", nil
	}

	switch p.field {
	case "ip":
		a, err := chIPPred("src_ip", p, args)
		if err != nil {
			return "", err
		}
		b, err := chIPPred("dst_ip", p, args)
		if err != nil {
			return "", err
		}
		return joinCompositeCH(p.op, a, b), nil
	case "src", "src_ip":
		return chIPPred("src_ip", p, args)
	case "dst", "dst_ip":
		return chIPPred("dst_ip", p, args)
	case "exporter", "exporter_ip":
		return chIPPred("exporter_ip", p, args)
	case "post_nat_src":
		return chIPPred("post_nat_src_ip", p, args)
	case "post_nat_dst":
		return chIPPred("post_nat_dst_ip", p, args)
	case "src_port":
		return chNumPred("src_port", p, args)
	case "dst_port":
		return chNumPred("dst_port", p, args)
	case "post_nat_sport":
		return chNumPred("post_nat_src_port", p, args)
	case "post_nat_dport":
		return chNumPred("post_nat_dst_port", p, args)
	case "port":
		a, err := chNumPred("src_port", p, args)
		if err != nil {
			return "", err
		}
		b, err := chNumPred("dst_port", p, args)
		if err != nil {
			return "", err
		}
		return joinCompositeCH(p.op, a, b), nil
	case "proto", "protocol":
		if p.isNum {
			return chNumPred("protocol", p, args)
		}
		switch strings.ToUpper(strings.TrimSpace(p.raw)) {
		case "TCP":
			*args = append(*args, 6)
		case "UDP":
			*args = append(*args, 17)
		case "ICMP":
			*args = append(*args, 1)
		case "ICMPV6":
			*args = append(*args, 58)
		default:
			*args = append(*args, 0)
		}
		op, err := chCompareOp(p.op)
		if err != nil {
			op = "="
		}
		return fmt.Sprintf("protocol %s ?", op), nil
	case "app":
		return chStringPred("app_name", p, args)
	case "in_if":
		return chStringPred("in_if_name", p, args)
	case "out_if":
		return chStringPred("out_if_name", p, args)
	case "if":
		a, err := chStringPred("in_if_name", p, args)
		if err != nil {
			return "", err
		}
		b, err := chStringPred("out_if_name", p, args)
		if err != nil {
			return "", err
		}
		return joinCompositeCH(p.op, a, b), nil
	case "vlan":
		return chNumPred("vlan_id", p, args)
	case "bytes":
		return chNumPred("bytes", p, args)
	case "packets", "pkts":
		return chNumPred("packets", p, args)
	case "bps":
		return chNumPred("bps", p, args)
	case "asn":
		a, err := chNumPred("src_asn", p, args)
		if err != nil {
			return "", err
		}
		b, err := chNumPred("dst_asn", p, args)
		if err != nil {
			return "", err
		}
		return joinCompositeCH(p.op, a, b), nil
	case "peer_as":
		return chNumPred("peer_as", p, args)
	case "country":
		a, err := chStringPred("src_country", p, args)
		if err != nil {
			return "", err
		}
		b, err := chStringPred("dst_country", p, args)
		if err != nil {
			return "", err
		}
		return joinCompositeCH(p.op, a, b), nil
	case "city":
		a, err := chStringPred("src_city", p, args)
		if err != nil {
			return "", err
		}
		b, err := chStringPred("dst_city", p, args)
		if err != nil {
			return "", err
		}
		return joinCompositeCH(p.op, a, b), nil
	case "direction", "dir":
		return chStringPred("direction", p, args)
	case "threat":
		return chStringPred("threat_match", p, args)
	case "k3s_ns":
		return chStringPred("k3s_namespace", p, args)
	case "k3s_workload", "k3s_pod":
		return chStringPred("k3s_workload", p, args)
	case "rtt_ms":
		return chNumPred("rtt_ms", p, args)
	case "retransmits":
		return chNumPred("retransmits", p, args)
	case "version":
		return chStringPred("version", p, args)
	case "node", "node_id", "host_id":
		return chStringPred("node_id", p, args)
	case "host":
		a, err := chStringPred("node_id", p, args)
		if err != nil {
			return "", err
		}
		b, err := chStringPred("node_name", p, args)
		if err != nil {
			return "", err
		}
		return joinCompositeCH(p.op, a, b), nil
	default:
		return "", fmt.Errorf("field %q requires local evaluation fallback", p.field)
	}
}

func queryCHTopEntries(
	ctx context.Context,
	conn driver.Conn,
	tableFQN, whereSQL string,
	baseArgs []any,
	durSec float64,
	keyExpr, labelExpr, metaExpr string,
	limit int,
	mapKey func(string) string,
) []FlowTopEntry {
	q := fmt.Sprintf(`
		SELECT %s AS k, any(%s) AS lbl, any(%s) AS m, sum(bytes) AS b, sum(packets) AS p, toInt32(count()) AS c
		FROM %s
		WHERE timestamp >= ? AND timestamp <= ? AND %s
		GROUP BY k
		HAVING k != ''
		ORDER BY b DESC
		LIMIT %d
	`, keyExpr, labelExpr, metaExpr, tableFQN, whereSQL, limit)
	rows, err := conn.Query(ctx, q, baseArgs...)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var out []FlowTopEntry
	for rows.Next() {
		var k, lbl, meta string
		var b, p uint64
		var c int32
		if err := rows.Scan(&k, &lbl, &meta, &b, &p, &c); err != nil {
			continue
		}
		if mapKey != nil {
			k = mapKey(k)
			lbl = k
		}
		if lbl == "" {
			lbl = k
		}
		out = append(out, FlowTopEntry{
			Key:     k,
			Label:   lbl,
			Meta:    meta,
			Bytes:   b,
			Packets: p,
			Flows:   int(c),
			Bps:     float64(b*8) / durSec,
		})
	}
	return out
}

func chGroupColExpr(groupBy string) string {
	switch strings.ToLower(strings.TrimSpace(groupBy)) {
	case "app":
		return "if(app_name='', toString(protocol), app_name)"
	case "exporter":
		return "exporter_ip"
	case "country":
		return "if(dst_country='' OR dst_country='LAN', src_country, dst_country)"
	case "interface":
		return "if(in_if_name='', out_if_name, in_if_name)"
	case "direction":
		return "direction"
	case "src":
		return "src_ip"
	case "dst":
		return "dst_ip"
	default:
		return "toString(protocol)"
	}
}

func normalizeCHGroupKey(groupBy, k string) string {
	g := strings.ToLower(strings.TrimSpace(groupBy))
	if g == "" || g == "protocol" || g == "app" {
		if n, err := strconv.Atoi(k); err == nil && n >= 0 && n <= 255 {
			return netflowProtocolName(uint8(n))
		}
	}
	if k == "" {
		return "Other"
	}
	return k
}

func (s *FlowStore) queryClickHouse(req FlowQueryRequest, fqlAst fqlNode, startMs, endMs int64) (FlowQueryResponse, bool) {
	s.mu.RLock()
	conn := s.chConn
	connected := s.chConnected
	tableFQN := s.chTableFQN
	s.mu.RUnlock()

	if !connected || conn == nil || tableFQN == "" {
		return FlowQueryResponse{}, false
	}

	whereSQL, fqlArgs, err := CompileFQLToClickHouseSQL(fqlAst)
	if err != nil {
		return FlowQueryResponse{}, false
	}

	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()

	startTime := time.UnixMilli(startMs).UTC()
	endTime := time.UnixMilli(endMs).UTC()
	baseArgs := append([]any{startTime, endTime}, fqlArgs...)

	// 1. Exact SQL summary aggregation across full time window
	sumQ := fmt.Sprintf(`
		SELECT count(), coalesce(sum(bytes), 0), coalesce(sum(packets), 0), uniqExact(src_ip), uniqExact(dst_ip)
		FROM %s
		WHERE timestamp >= ? AND timestamp <= ? AND %s
	`, tableFQN, whereSQL)
	var totalFlows, uniqSrc, uniqDst uint64
	var totalBytes, totalPackets uint64
	if err := conn.QueryRow(ctx, sumQ, baseArgs...).Scan(&totalFlows, &totalBytes, &totalPackets, &uniqSrc, &uniqDst); err != nil {
		return FlowQueryResponse{}, false
	}

	spanMs := endMs - startMs
	if spanMs <= 0 {
		spanMs = 60_000
	}
	durSec := float64(spanMs) / 1000.0
	if durSec < 1 {
		durSec = 1
	}
	bucketMs := spanMs / 40
	if bucketMs < 10_000 {
		bucketMs = 10_000
	}
	bSec := float64(bucketMs) / 1000.0

	limit := req.Limit
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	offset := req.Offset
	if offset < 0 {
		offset = 0
	}
	orderCol := "timestamp"
	switch strings.ToLower(req.SortBy) {
	case "bytes":
		orderCol = "bytes"
	case "packets":
		orderCol = "packets"
	case "bps":
		orderCol = "bps"
	}

	// 2. Paginated flow rows
	q := fmt.Sprintf(`
		SELECT
			timestamp, version, exporter_ip, node_id, node_name, src_ip, dst_ip, src_port, dst_port,
			protocol, app_name, direction, in_if_name, out_if_name, vlan_id,
			bytes, packets, bps, src_country, dst_country, threat_match,
			src_asn, dst_asn, src_city, dst_city, peer_as,
			post_nat_src_ip, post_nat_dst_ip, post_nat_src_port, post_nat_dst_port,
			tcp_flags, k3s_namespace, k3s_workload, rtt_ms, retransmits
		FROM %s
		WHERE timestamp >= ? AND timestamp <= ? AND %s
		ORDER BY %s DESC
		LIMIT ? OFFSET ?
	`, tableFQN, whereSQL, orderCol)
	flowArgs := append(append([]any{}, baseArgs...), limit, offset)
	rows, err := conn.Query(ctx, q, flowArgs...)
	if err != nil {
		return FlowQueryResponse{}, false
	}
	defer rows.Close()

	matched := make([]FlowRecord, 0, limit)
	for rows.Next() {
		var ts time.Time
		var r FlowRecord
		if scanErr := rows.Scan(
			&ts, &r.Version, &r.ExporterIP, &r.HostID, &r.HostName, &r.SrcIP, &r.DstIP, &r.SrcPort, &r.DstPort,
			&r.Protocol, &r.AppName, &r.Direction, &r.InIfName, &r.OutIfName, &r.VlanID,
			&r.Bytes, &r.Packets, &r.Bps, &r.SrcCountry, &r.DstCountry, &r.ThreatMatch,
			&r.SrcAsn, &r.DstAsn, &r.SrcCity, &r.DstCity, &r.PeerAs,
			&r.PostNatSrcIP, &r.PostNatDstIP, &r.PostNatSrcPort, &r.PostNatDstPort,
			&r.TCPFlags, &r.K3sNamespace, &r.K3sWorkload, &r.RttMs, &r.Retransmits,
		); scanErr != nil {
			continue
		}
		r.TimestampMs = ts.UnixMilli()
		r.Timestamp = ts.UTC().Format(time.RFC3339Nano)
		r.ProtocolName = netflowProtocolName(r.Protocol)
		r.TCPFlagsStr = formatTCPFlags(r.TCPFlags)
		r.ID = fmt.Sprintf("ch-%d-%s-%d-%s-%d", r.TimestampMs, r.SrcIP, r.SrcPort, r.DstIP, r.DstPort)
		matched = append(matched, r)
	}
	if rows.Err() != nil {
		return FlowQueryResponse{}, false
	}

	resp := FlowQueryResponse{
		Timestamp:         time.Now().UTC().Format(time.RFC3339),
		Engine:            "clickhouse",
		TotalMatchedFlows: int(totalFlows),
		TotalBytes:        totalBytes,
		TotalPackets:      totalPackets,
		AvgBps:            float64(totalBytes*8) / durSec,
		UniqueSources:     int(uniqSrc),
		UniqueDests:       int(uniqDst),
		Flows:             matched,
	}

	// 3. Exact SQL Timeseries aggregation
	groupExpr := chGroupColExpr(req.GroupBy)
	tsQ := fmt.Sprintf(`
		SELECT intDiv(toUnixTimestamp64Milli(timestamp), ?) * ? AS bts, %s AS gk, sum(bytes) AS b, sum(packets) AS p, toInt32(count()) AS c
		FROM %s
		WHERE timestamp >= ? AND timestamp <= ? AND %s
		GROUP BY bts, gk
		ORDER BY bts ASC
	`, groupExpr, tableFQN, whereSQL)
	tsArgs := append([]any{bucketMs, bucketMs}, baseArgs...)
	bucketMap := make(map[int64]*FlowTimeseriesPoint)
	groupTotals := make(map[string]uint64)
	if tsRows, tsErr := conn.Query(ctx, tsQ, tsArgs...); tsErr == nil {
		for tsRows.Next() {
			var bts int64
			var gk string
			var b, p uint64
			var c int32
			if err := tsRows.Scan(&bts, &gk, &b, &p, &c); err != nil {
				continue
			}
			pt := bucketMap[bts]
			if pt == nil {
				pt = &FlowTimeseriesPoint{
					TimestampMs: bts,
					TimeLabel:   time.UnixMilli(bts).Local().Format("15:04:05"),
					Series:      make(map[string]float64),
				}
				bucketMap[bts] = pt
			}
			pt.TotalBytes += b
			pt.TotalPkts += p
			pt.FlowsCount += int(c)
			normKey := normalizeCHGroupKey(req.GroupBy, gk)
			pt.Series[normKey] += float64(b*8) / bSec
			groupTotals[normKey] += b
		}
		_ = tsRows.Close()
	}

	bKeys := make([]int64, 0, len(bucketMap))
	for k := range bucketMap {
		bKeys = append(bKeys, k)
	}
	sort.Slice(bKeys, func(i, j int) bool { return bKeys[i] < bKeys[j] })
	resp.Timeseries = make([]FlowTimeseriesPoint, 0, len(bKeys))
	for _, k := range bKeys {
		pt := bucketMap[k]
		pt.Bps = float64(pt.TotalBytes*8) / bSec
		pt.Pps = float64(pt.TotalPkts) / bSec
		resp.Timeseries = append(resp.Timeseries, *pt)
	}
	seriesRank := make([]struct {
		k string
		b uint64
	}, 0, len(groupTotals))
	for k, b := range groupTotals {
		seriesRank = append(seriesRank, struct {
			k string
			b uint64
		}{k: k, b: b})
	}
	sort.Slice(seriesRank, func(i, j int) bool { return seriesRank[i].b > seriesRank[j].b })
	for i := 0; i < len(seriesRank) && i < 6; i++ {
		resp.SeriesKeys = append(resp.SeriesKeys, seriesRank[i].k)
	}

	// 4. Exact SQL Top-N aggregations
	protoMapFn := func(k string) string {
		if n, err := strconv.Atoi(k); err == nil && n >= 0 && n <= 255 {
			return netflowProtocolName(uint8(n))
		}
		return k
	}
	resp.TopSources = queryCHTopEntries(ctx, conn, tableFQN, whereSQL, baseArgs, durSec, "src_ip", "src_ip", "src_country", 15, nil)
	resp.TopDestinations = queryCHTopEntries(ctx, conn, tableFQN, whereSQL, baseArgs, durSec, "dst_ip", "dst_ip", "dst_country", 15, nil)
	resp.TopApps = queryCHTopEntries(ctx, conn, tableFQN, whereSQL, baseArgs, durSec, "if(app_name='', toString(protocol), app_name)", "if(app_name='', toString(protocol), app_name)", "toString(protocol)", 15, func(k string) string {
		return normalizeCHGroupKey("app", k)
	})
	resp.TopProtocols = queryCHTopEntries(ctx, conn, tableFQN, whereSQL, baseArgs, durSec, "toString(protocol)", "toString(protocol)", "''", 10, protoMapFn)
	resp.TopCountries = queryCHTopEntries(ctx, conn, tableFQN, whereSQL, baseArgs, durSec, "if(dst_country='' OR dst_country='LAN', src_country, dst_country)", "if(dst_country='' OR dst_country='LAN', src_country, dst_country)", "''", 10, nil)
	resp.TopASNs = queryCHTopEntries(ctx, conn, tableFQN, whereSQL, baseArgs, durSec, "if(dst_asn > 0, concat('AS', toString(dst_asn)), if(src_asn > 0, concat('AS', toString(src_asn)), ''))", "if(dst_asn > 0, concat('AS', toString(dst_asn)), if(src_asn > 0, concat('AS', toString(src_asn)), ''))", "''", 10, nil)
	resp.TopExporters = queryCHTopEntries(ctx, conn, tableFQN, whereSQL, baseArgs, durSec, "exporter_ip", "node_name", "version", 10, nil)
	resp.TopInterfaces = queryCHTopEntries(ctx, conn, tableFQN, whereSQL, baseArgs, durSec, "if(in_if_name='', out_if_name, in_if_name)", "if(in_if_name='', out_if_name, in_if_name)", "exporter_ip", 12, nil)
	resp.TopVLANs = queryCHTopEntries(ctx, conn, tableFQN, whereSQL, baseArgs, durSec, "if(vlan_id > 0, concat('VLAN ', toString(vlan_id)), '')", "if(vlan_id > 0, concat('VLAN ', toString(vlan_id)), '')", "''", 10, nil)

	// 5. Top Conversations via SQL GROUP BY
	convQ := fmt.Sprintf(`
		SELECT src_ip, dst_ip, dst_port, protocol, any(app_name), any(direction), max(threat_match), sum(bytes) AS b, sum(packets) AS p, toInt32(count()) AS c
		FROM %s
		WHERE timestamp >= ? AND timestamp <= ? AND %s
		GROUP BY src_ip, dst_ip, dst_port, protocol
		ORDER BY b DESC
		LIMIT 25
	`, tableFQN, whereSQL)
	if cRows, cErr := conn.Query(ctx, convQ, baseArgs...); cErr == nil {
		sankeySrcApp := make(map[string]uint64)
		sankeyAppDst := make(map[string]uint64)
		for cRows.Next() {
			var ce FlowConversationEntry
			var proto uint8
			var cnt int32
			if err := cRows.Scan(&ce.SrcIP, &ce.DstIP, &ce.DstPort, &proto, &ce.AppName, &ce.Direction, &ce.ThreatMatch, &ce.Bytes, &ce.Packets, &cnt); err != nil {
				continue
			}
			ce.ProtocolName = netflowProtocolName(proto)
			if ce.AppName == "" {
				ce.AppName = ce.ProtocolName
			}
			ce.Flows = int(cnt)
			ce.Bps = float64(ce.Bytes*8) / durSec
			resp.TopConversations = append(resp.TopConversations, ce)
			sankeySrcApp[ce.SrcIP+"→"+ce.AppName] += ce.Bytes
			sankeyAppDst[ce.AppName+"→"+ce.DstIP] += ce.Bytes
		}
		_ = cRows.Close()
		resp.SankeyLinks = buildSankeyLinks(sankeySrcApp, sankeyAppDst)
	}

	resp.HostHeatmap = BuildHostHeatmap(matched, resp.TopSources, resp.TopDestinations)
	resp.PortTimeHeatmap = BuildPortTimeHeatmap(matched, resp.Timeseries, startMs, bucketMs)
	resp.GeoArcs = BuildGeoArcs(matched)
	if req.Biflow {
		resp.Sessions = StitchBidirectionalSessions(matched, 120_000)
	}
	return resp, true
}
