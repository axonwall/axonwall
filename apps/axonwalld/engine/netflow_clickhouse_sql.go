package engine

import (
	"context"
	"fmt"
	"strings"
	"time"
)

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
		return fmt.Sprintf("(%s OR %s)", a, b), nil
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
		if p.op == "!=" {
			return fmt.Sprintf("(%s AND %s)", a, b), nil
		}
		return fmt.Sprintf("(%s OR %s)", a, b), nil
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
		a, _ := chStringPred("in_if_name", p, args)
		b, _ := chStringPred("out_if_name", p, args)
		return fmt.Sprintf("(%s OR %s)", a, b), nil
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
		return fmt.Sprintf("(%s OR %s)", a, b), nil
	case "peer_as":
		return chNumPred("peer_as", p, args)
	case "country":
		a, _ := chStringPred("src_country", p, args)
		b, _ := chStringPred("dst_country", p, args)
		return fmt.Sprintf("(%s OR %s)", a, b), nil
	case "city":
		a, _ := chStringPred("src_city", p, args)
		b, _ := chStringPred("dst_city", p, args)
		return fmt.Sprintf("(%s OR %s)", a, b), nil
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
		a, _ := chStringPred("node_id", p, args)
		b, _ := chStringPred("node_name", p, args)
		return fmt.Sprintf("(%s OR %s)", a, b), nil
	default:
		return "", fmt.Errorf("field %q requires local evaluation fallback", p.field)
	}
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

	limit := req.Limit
	if limit <= 0 || limit > 1000 {
		limit = 200
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
		LIMIT 5000
	`, tableFQN, whereSQL, orderCol)

	rows, err := conn.Query(ctx, q, baseArgs...)
	if err != nil {
		return FlowQueryResponse{}, false
	}
	defer rows.Close()

	var matched []FlowRecord
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

	resp := buildFlowQueryResponse(matched, startMs, endMs, req)
	resp.Engine = "clickhouse"
	return resp, true
}
