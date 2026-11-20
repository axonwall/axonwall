package engine

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestBuildNodeSchedulingMergePatch_EdgePresetAndSystemTaintPreserved(t *testing.T) {
	existingLabels := map[string]string{
		"kubernetes.io/hostname":             "klaxon",
		"node-role.kubernetes.io/control-plane": "true",
		"node-role.kubernetes.io/worker":     "worker",
		"axonwall.io/role":                   "k3s-storage",
	}
	existingTaints := []K3sNodeTaint{
		{Key: "node.kubernetes.io/unreachable", Effect: "NoSchedule"},
		{Key: "custom/old", Value: "1", Effect: "NoSchedule"},
	}
	unschedulable := false
	req := K3sNodeUpdateRequest{
		NodeName: "klaxon",
		Roles:    []string{"edge"},
		Taints: []K3sNodeTaint{
			{Key: "CriticalAddonsOnly", Value: "true", Effect: "NoExecute"},
			{Key: "CriticalAddonsOnly", Value: "true", Effect: "NoExecute"}, // duplicate should dedupe
		},
		Unschedulable: &unschedulable,
	}

	patchBytes, err := buildNodeSchedulingMergePatch(existingLabels, existingTaints, req)
	if err != nil {
		t.Fatalf("buildNodeSchedulingMergePatch returned error: %v", err)
	}

	var parsed struct {
		Metadata struct {
			Labels map[string]any `json:"labels"`
		} `json:"metadata"`
		Spec struct {
			Unschedulable *bool          `json:"unschedulable"`
			Taints        []K3sNodeTaint `json:"taints"`
		} `json:"spec"`
	}
	if err := json.Unmarshal(patchBytes, &parsed); err != nil {
		t.Fatalf("unmarshal patch failed: %v", err)
	}

	if parsed.Metadata.Labels["node-role.kubernetes.io/edge"] != "true" {
		t.Errorf("expected edge role label=true, got %#v", parsed.Metadata.Labels["node-role.kubernetes.io/edge"])
	}
	if parsed.Metadata.Labels["axonwall.io/role"] != "edge" {
		t.Errorf("expected axonwall.io/role=edge, got %#v", parsed.Metadata.Labels["axonwall.io/role"])
	}
	if val, exists := parsed.Metadata.Labels["node-role.kubernetes.io/worker"]; !exists || val != nil {
		t.Errorf("expected worker label nulled out, got exists=%v val=%#v", exists, val)
	}
	if val, exists := parsed.Metadata.Labels["node-role.kubernetes.io/storage"]; !exists || val != nil {
		t.Errorf("expected storage label nulled out, got exists=%v val=%#v", exists, val)
	}
	// R4-A-L2: the merge preserves existing custom taints — the old
	// replace semantics dropped `custom/old` here, so the patch
	// carried only 2 taints (1 system + 1 CriticalAddonsOnly).
	if len(parsed.Spec.Taints) != 3 {
		t.Fatalf("expected 3 taints (1 system + 1 preserved custom/old + 1 CriticalAddonsOnly), got %#v", parsed.Spec.Taints)
	}
	if parsed.Spec.Taints[0].Key != "node.kubernetes.io/unreachable" || parsed.Spec.Taints[1].Key != "custom/old" || parsed.Spec.Taints[2].Key != "CriticalAddonsOnly" || parsed.Spec.Taints[2].Effect != "NoExecute" {
		t.Errorf("unexpected taints slice: %#v", parsed.Spec.Taints)
	}
	if parsed.Spec.Unschedulable == nil || *parsed.Spec.Unschedulable != false {
		t.Errorf("expected unschedulable=false, got %#v", parsed.Spec.Unschedulable)
	}
}

func TestBuildNodeSchedulingMergePatch_ClearTaintsEmitsEmptySlice(t *testing.T) {
	req := K3sNodeUpdateRequest{
		NodeName: "suburban-hello",
		Roles:    []string{"worker", "storage"},
		Taints:   []K3sNodeTaint{},
	}
	patchBytes, err := buildNodeSchedulingMergePatch(nil, nil, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(string(patchBytes), `"taints":[]`) {
		t.Fatalf("expected explicit empty \"taints\":[] in merge patch, got %s", string(patchBytes))
	}
}

func TestBuildNodeSchedulingMergePatch_ValidationErrors(t *testing.T) {
	cases := []struct {
		name string
		req  K3sNodeUpdateRequest
	}{
		{
			name: "invalid node name leading dash",
			req:  K3sNodeUpdateRequest{NodeName: "-bad"},
		},
		{
			name: "invalid node name slash",
			req:  K3sNodeUpdateRequest{NodeName: "foo/bar"},
		},
		{
			name: "invalid taint effect",
			req: K3sNodeUpdateRequest{
				NodeName: "klaxon",
				Taints:   []K3sNodeTaint{{Key: "CriticalAddonsOnly", Value: "true", Effect: "DropPod"}},
			},
		},
		{
			name: "protected kubernetes.io label",
			req: K3sNodeUpdateRequest{
				NodeName:     "klaxon",
				CustomLabels: map[string]string{"kubernetes.io/hostname": "spoof"},
			},
		},
		{
			name: "protected control-plane role label",
			req: K3sNodeUpdateRequest{
				NodeName:     "klaxon",
				RemoveLabels: []string{"node-role.kubernetes.io/control-plane"},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := buildNodeSchedulingMergePatch(nil, nil, tc.req); err == nil {
				t.Fatalf("expected validation error for %s, got nil", tc.name)
			}
		})
	}
}

func TestMergePeerReplicaPreservingLocalIdentity(t *testing.T) {
	localJSON := []byte(`{
  "system": {"hostname": "saxon", "domain": "home.arpa"},
  "interfaces": [
    {"name": "wan", "device": "eth1", "ipv4Address": "148.135.193.203/27", "gateway": "148.135.193.193"},
    {"name": "lan", "device": "eth0", "ipv4Address": "10.80.0.203/24"},
    {"name": "keepalivenet", "device": "eth2", "ipv4Address": "10.0.99.203/24"}
  ],
  "ha": {
    "enabled": true,
    "role": "backup",
    "nodeRole": "backup",
    "peerIp": "10.0.99.202",
    "peerAddress": "10.0.99.202",
    "syncInterface": "eth2",
    "vrrpInstances": [
      {"name": "VI_WAN", "vrid": 51, "interface": "eth1", "priority": 50},
      {"name": "VI_LAN", "vrid": 52, "interface": "eth0", "priority": 50}
    ]
  },
  "firewall": {"rules": ["old"]}
}`)

	replicaJSON := []byte(`{
  "system": {"hostname": "klaxon", "domain": "home.arpa", "webGuiPort": 2966},
  "interfaces": [
    {"name": "wan", "device": "eth1", "ipv4Address": "148.135.193.202/27", "gateway": "148.135.193.193", "ipv6Address": "2001:db8::2/64"},
    {"name": "lan", "device": "eth0", "ipv4Address": "10.80.0.202/24"},
    {"name": "keepalivenet", "device": "eth2", "ipv4Address": "10.0.99.202/24"}
  ],
  "ha": {
    "enabled": true,
    "role": "master",
    "nodeRole": "master",
    "peerIp": "10.0.99.203",
    "peerAddress": "10.0.99.203",
    "syncInterface": "eth2",
    "vrrpInstances": [
      {"name": "VI_WAN", "vrid": 51, "interface": "eth1", "priority": 150, "virtualIps": ["148.135.193.200/27"]},
      {"name": "VI_LAN", "vrid": 52, "interface": "eth0", "priority": 150, "virtualIps": ["10.80.0.200/24"]}
    ]
  },
  "firewall": {"rules": ["updated-from-master"]}
}`)

	mergedBytes, err := mergePeerReplicaPreservingLocalIdentity(localJSON, replicaJSON)
	if err != nil {
		t.Fatalf("mergePeerReplicaPreservingLocalIdentity failed: %v", err)
	}

	var merged map[string]any
	if err := json.Unmarshal(mergedBytes, &merged); err != nil {
		t.Fatalf("unmarshal merged failed: %v", err)
	}

	sys := merged["system"].(map[string]any)
	if sys["hostname"] != "saxon" {
		t.Errorf("expected preserved hostname saxon, got %v", sys["hostname"])
	}
	if sys["webGuiPort"] != float64(2966) {
		t.Errorf("expected adopted shared webGuiPort=2966, got %v", sys["webGuiPort"])
	}

	ifaces := merged["interfaces"].([]any)
	wan := ifaces[0].(map[string]any)
	lan := ifaces[1].(map[string]any)
	ka := ifaces[2].(map[string]any)
	if wan["ipv4Address"] != "148.135.193.203/27" {
		t.Errorf("expected wan ipv4 148.135.193.203/27, got %v", wan["ipv4Address"])
	}
	// R4-A-L4: a preserved key the local interface lacks is KEPT
	// from the replica (the peer's gateway/ipv6), not deleted — the
	// old code deleted it, which could drop the shared gateway.
	if wan["ipv6Address"] != "2001:db8::2/64" {
		t.Errorf("expected replica ipv6Address kept when absent locally, got %v", wan["ipv6Address"])
	}
	if lan["ipv4Address"] != "10.80.0.203/24" || ka["ipv4Address"] != "10.0.99.203/24" {
		t.Errorf("expected local lan/keepalivenet IPs, got lan=%v ka=%v", lan["ipv4Address"], ka["ipv4Address"])
	}

	ha := merged["ha"].(map[string]any)
	if ha["role"] != "backup" || ha["peerIp"] != "10.0.99.202" {
		t.Errorf("expected preserved backup role & peer 10.0.99.202, got role=%v peerIp=%v", ha["role"], ha["peerIp"])
	}
	vrrps := ha["vrrpInstances"].([]any)
	if vrrps[0].(map[string]any)["priority"] != float64(50) {
		t.Errorf("expected preserved VI_WAN priority 50, got %v", vrrps[0].(map[string]any)["priority"])
	}
	if merged["firewall"].(map[string]any)["rules"].([]any)[0] != "updated-from-master" {
		t.Errorf("expected shared firewall section from replica")
	}
}

// R4-A-L2: removeTaints deletes by exact key+effect+value, req.Taints
// upserts by key+effect (request wins on a value change), and custom
// taints not mentioned anywhere are preserved.
func TestBuildNodeSchedulingMergePatch_RemoveAndUpsertTaints(t *testing.T) {
	existing := []K3sNodeTaint{
		{Key: "custom/keep", Value: "1", Effect: "NoSchedule"},
		{Key: "custom/drop", Value: "x", Effect: "NoSchedule"},
		{Key: "custom/change", Value: "old", Effect: "NoExecute"},
		{Key: "custom/same-key-diff-effect", Value: "v", Effect: "NoSchedule"},
	}
	req := K3sNodeUpdateRequest{
		NodeName: "klaxon",
		Roles:    []string{"worker"},
		Taints: []K3sNodeTaint{
			{Key: "custom/change", Value: "new", Effect: "NoExecute"},
			{Key: "custom/added", Value: "y", Effect: "PreferNoSchedule"},
		},
		RemoveTaints: []K3sNodeTaint{
			{Key: "custom/drop", Value: "x", Effect: "NoSchedule"},
			// Wrong value: must NOT delete custom/keep.
			{Key: "custom/keep", Value: "not-1", Effect: "NoSchedule"},
		},
	}
	patchBytes, err := buildNodeSchedulingMergePatch(nil, existing, req)
	if err != nil {
		t.Fatalf("buildNodeSchedulingMergePatch returned error: %v", err)
	}
	var parsed struct {
		Spec struct {
			Taints []K3sNodeTaint `json:"taints"`
		} `json:"spec"`
	}
	if err := json.Unmarshal(patchBytes, &parsed); err != nil {
		t.Fatalf("unmarshal patch failed: %v", err)
	}
	want := map[string]string{
		"custom/keep|NoSchedule":                 "1",
		"custom/change|NoExecute":                "new",
		"custom/same-key-diff-effect|NoSchedule": "v",
		"custom/added|PreferNoSchedule":          "y",
	}
	if len(parsed.Spec.Taints) != len(want) {
		t.Fatalf("expected %d taints, got %#v", len(want), parsed.Spec.Taints)
	}
	for _, tc := range parsed.Spec.Taints {
		key := tc.Key + "|" + tc.Effect
		v, ok := want[key]
		if !ok {
			t.Errorf("unexpected taint in patch: %#v", tc)
			continue
		}
		if tc.Value != v {
			t.Errorf("taint %s: expected value %q, got %q", key, v, tc.Value)
		}
	}
}

// R4-A-L4: a replica interface with no local match (renamed NIC /
// extra interface) is dropped when the local node has interfaces of
// its own, and kept only as a bootstrap config when it has none.
func TestMergePeerReplicaUnmatchedInterfaceDropped(t *testing.T) {
	localJSON := []byte(`{
  "system": {"hostname": "saxon"},
  "interfaces": [
    {"name": "wan", "device": "eth1", "ipv4Address": "148.135.193.203/27", "gateway": "148.135.193.193"}
  ]
}`)
	replicaJSON := []byte(`{
  "system": {"hostname": "klaxon"},
  "interfaces": [
    {"name": "wan", "device": "eth1", "ipv4Address": "148.135.193.202/27", "gateway": "148.135.193.193"},
    {"name": "lan", "device": "enp3s0", "ipv4Address": "10.80.0.202/24", "macAddress": "aa:bb:cc:dd:ee:ff"},
    {"name": "ghost", "device": "eth9", "ipv4Address": "192.0.2.1/24"}
  ]
}`)

	mergedBytes, err := mergePeerReplicaPreservingLocalIdentity(localJSON, replicaJSON)
	if err != nil {
		t.Fatalf("merge failed: %v", err)
	}
	var merged map[string]any
	if err := json.Unmarshal(mergedBytes, &merged); err != nil {
		t.Fatalf("unmarshal merged failed: %v", err)
	}
	ifaces := merged["interfaces"].([]any)
	if len(ifaces) != 1 {
		t.Fatalf("expected only the matched wan interface to survive, got %d: %v", len(ifaces), ifaces)
	}
	wan := ifaces[0].(map[string]any)
	if wan["ipv4Address"] != "148.135.193.203/27" {
		t.Errorf("expected local wan IP preserved, got %v", wan["ipv4Address"])
	}

	// Bootstrap case: no local interfaces at all — the replica
	// stands as the initial config.
	mergedBytes, err = mergePeerReplicaPreservingLocalIdentity([]byte(`{"system": {"hostname": "fresh"}}`), replicaJSON)
	if err != nil {
		t.Fatalf("bootstrap merge failed: %v", err)
	}
	if err := json.Unmarshal(mergedBytes, &merged); err != nil {
		t.Fatalf("unmarshal bootstrap merged failed: %v", err)
	}
	if len(merged["interfaces"].([]any)) != 3 {
		t.Fatalf("bootstrap merge should keep all 3 replica interfaces, got %v", merged["interfaces"])
	}
}
