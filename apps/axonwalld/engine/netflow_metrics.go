package engine

import (
	"fmt"
	"io"
	"sort"
	"strings"
)

// WritePrometheusMetrics writes dependency-free OpenMetrics / Prometheus v0.0.4 text output.
func (m *NetFlowManager) WritePrometheusMetrics(w io.Writer) {
	st := m.GetStatus()
	exps := m.GetExporters()
	alerts := m.ListAlerts()

	fmt.Fprintf(w, "# HELP axonwall_netflow_collector_up Whether the NetFlow collector pipeline is running (1=up, 0=down).\n")
	fmt.Fprintf(w, "# TYPE axonwall_netflow_collector_up gauge\n")
	if st.Running {
		fmt.Fprintf(w, "axonwall_netflow_collector_up 1\n")
	} else {
		fmt.Fprintf(w, "axonwall_netflow_collector_up 0\n")
	}

	fmt.Fprintf(w, "# HELP axonwall_netflow_packets_received_total Total NetFlow/IPFIX/sFlow packets received per listener.\n")
	fmt.Fprintf(w, "# TYPE axonwall_netflow_packets_received_total counter\n")
	for _, l := range st.Listeners {
		fmt.Fprintf(w, "axonwall_netflow_packets_received_total{listener=%q,protocol=%q,transport=%q} %d\n",
			promEsc(l.ID), promEsc(l.Protocol), promEsc(l.Transport), l.PacketsReceived)
	}

	fmt.Fprintf(w, "# HELP axonwall_netflow_decode_errors_total Total decode errors per listener.\n")
	fmt.Fprintf(w, "# TYPE axonwall_netflow_decode_errors_total counter\n")
	for _, l := range st.Listeners {
		fmt.Fprintf(w, "axonwall_netflow_decode_errors_total{listener=%q} %d\n", promEsc(l.ID), l.DecodeErrors)
	}

	fmt.Fprintf(w, "# HELP axonwall_netflow_flows_ingested_total Total decoded and enriched flow records ingested.\n")
	fmt.Fprintf(w, "# TYPE axonwall_netflow_flows_ingested_total counter\n")
	fmt.Fprintf(w, "axonwall_netflow_flows_ingested_total %d\n", st.FlowsIngested)

	fmt.Fprintf(w, "# HELP axonwall_netflow_bytes_ingested_total Total accounted bytes across all ingested flows.\n")
	fmt.Fprintf(w, "# TYPE axonwall_netflow_bytes_ingested_total counter\n")
	fmt.Fprintf(w, "axonwall_netflow_bytes_ingested_total %d\n", st.BytesIngested)

	fmt.Fprintf(w, "# HELP axonwall_netflow_replicated_packets_total Total datagrams replicated via UDP fan-out.\n")
	fmt.Fprintf(w, "# TYPE axonwall_netflow_replicated_packets_total counter\n")
	fmt.Fprintf(w, "axonwall_netflow_replicated_packets_total %d\n", st.ReplicatedPackets)

	fmt.Fprintf(w, "# HELP axonwall_netflow_self_exported_flows_total Total local flows exported via eBPF/conntrack exporter.\n")
	fmt.Fprintf(w, "# TYPE axonwall_netflow_self_exported_flows_total counter\n")
	fmt.Fprintf(w, "axonwall_netflow_self_exported_flows_total %d\n", st.SelfExportedFlows)

	fmt.Fprintf(w, "# HELP axonwall_netflow_store_hot_ring_entries Current number of flow records in the in-memory ring.\n")
	fmt.Fprintf(w, "# TYPE axonwall_netflow_store_hot_ring_entries gauge\n")
	fmt.Fprintf(w, "axonwall_netflow_store_hot_ring_entries %d\n", st.HotRingCount)

	fmt.Fprintf(w, "# HELP axonwall_netflow_store_disk_bytes Total bytes occupied by compressed on-disk flow chunks.\n")
	fmt.Fprintf(w, "# TYPE axonwall_netflow_store_disk_bytes gauge\n")
	fmt.Fprintf(w, "axonwall_netflow_store_disk_bytes %.0f\n", st.DiskUsageMB*1024*1024)

	fmt.Fprintf(w, "# HELP axonwall_netflow_baseline_entities Total entities tracked by adaptive EWMA baselines.\n")
	fmt.Fprintf(w, "# TYPE axonwall_netflow_baseline_entities gauge\n")
	fmt.Fprintf(w, "axonwall_netflow_baseline_entities %d\n", st.BaselineEntities)

	fmt.Fprintf(w, "# HELP axonwall_netflow_exporter_flows_total Total flows received per exporter.\n")
	fmt.Fprintf(w, "# TYPE axonwall_netflow_exporter_flows_total counter\n")
	for _, ex := range exps {
		ver := strings.Join(ex.Versions, ",")
		fmt.Fprintf(w, "axonwall_netflow_exporter_flows_total{exporter=%q,name=%q,version=%q} %d\n",
			promEsc(ex.ExporterIP), promEsc(ex.Name), promEsc(ver), ex.FlowsReceived)
	}

	fmt.Fprintf(w, "# HELP axonwall_netflow_exporter_bytes_total Total bytes reported per exporter.\n")
	fmt.Fprintf(w, "# TYPE axonwall_netflow_exporter_bytes_total counter\n")
	for _, ex := range exps {
		fmt.Fprintf(w, "axonwall_netflow_exporter_bytes_total{exporter=%q,name=%q} %d\n",
			promEsc(ex.ExporterIP), promEsc(ex.Name), ex.BytesAccounted)
	}

	fmt.Fprintf(w, "# HELP axonwall_netflow_exporter_fps Estimated flows per second per exporter.\n")
	fmt.Fprintf(w, "# TYPE axonwall_netflow_exporter_fps gauge\n")
	for _, ex := range exps {
		fmt.Fprintf(w, "axonwall_netflow_exporter_fps{exporter=%q,name=%q} %.2f\n",
			promEsc(ex.ExporterIP), promEsc(ex.Name), ex.FpsEstimate)
	}

	fmt.Fprintf(w, "# HELP axonwall_netflow_exporter_up Exporter health status (1=green, 0.5=yellow, 0=red).\n")
	fmt.Fprintf(w, "# TYPE axonwall_netflow_exporter_up gauge\n")
	for _, ex := range exps {
		v := 0.0
		switch ex.Status {
		case "green":
			v = 1.0
		case "yellow":
			v = 0.5
		}
		fmt.Fprintf(w, "axonwall_netflow_exporter_up{exporter=%q,name=%q} %.1f\n",
			promEsc(ex.ExporterIP), promEsc(ex.Name), v)
	}

	type ak struct{ sev, kind string }
	aCounts := make(map[ak]int)
	for _, a := range alerts {
		aCounts[ak{sev: a.Severity, kind: a.Kind}]++
	}
	var aKeys []ak
	for k := range aCounts {
		aKeys = append(aKeys, k)
	}
	sort.Slice(aKeys, func(i, j int) bool {
		if aKeys[i].sev != aKeys[j].sev {
			return aKeys[i].sev < aKeys[j].sev
		}
		return aKeys[i].kind < aKeys[j].kind
	})
	fmt.Fprintf(w, "# HELP axonwall_netflow_alerts_total Total recorded anomaly alerts by severity and kind.\n")
	fmt.Fprintf(w, "# TYPE axonwall_netflow_alerts_total gauge\n")
	for _, k := range aKeys {
		fmt.Fprintf(w, "axonwall_netflow_alerts_total{severity=%q,kind=%q} %d\n",
			promEsc(k.sev), promEsc(k.kind), aCounts[k])
	}
}

func promEsc(s string) string {
	return strings.ReplaceAll(s, "\"", "'")
}
