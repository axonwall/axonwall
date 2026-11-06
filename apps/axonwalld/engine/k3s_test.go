package engine

import (
	"os"
	"path/filepath"
	"testing"
)

func TestK3sGetStatusReportsDownWhenProbesFail(t *testing.T) {
	// A-H2 (round 2): GetStatus fabricated a healthy 2-node cluster with
	// bound volumes out of constants, even with k3s stopped or never
	// installed — and a peer IP alone reported a joined cluster.
	mgr := NewK3sManager()
	mgr.cfg = K3sRuntimeBundle{Enabled: true, PeerIp: "10.0.0.2"}

	st := mgr.GetStatus()
	if st.Enabled != true {
		t.Errorf("expected Enabled=true from config, got false")
	}
	if st.ServiceActive {
		t.Errorf("expected ServiceActive=false with no k3s service, got true")
	}
	if st.Running {
		t.Errorf("expected Running=false with no k3s service, got true")
	}
	if st.ClusterJoined || st.HaAutoJoined {
		t.Errorf("expected ClusterJoined/HaAutoJoined=false for a peer IP with no join, got %v/%v", st.ClusterJoined, st.HaAutoJoined)
	}
	if st.Role != "primary-server" {
		t.Errorf("expected role primary-server, got %q", st.Role)
	}
	if len(st.Nodes) != 0 {
		t.Errorf("expected no nodes without a probe, got %+v", st.Nodes)
	}
	if len(st.Volumes) != 0 {
		t.Errorf("expected no volumes without a probe, got %+v", st.Volumes)
	}
	if st.OpenEbsReady || st.OpenEbsHealthy {
		t.Errorf("expected OpenEBS not ready/healthy without a probe, got %v/%v", st.OpenEbsReady, st.OpenEbsHealthy)
	}
}

func TestK3sGetStatusProbesRealNodes(t *testing.T) {
	dir := t.TempDir()
	fixtures := filepath.Join(dir, "fixtures")
	if err := os.MkdirAll(fixtures, 0755); err != nil {
		t.Fatal(err)
	}
	writeFixture := func(name, content string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(fixtures, name), []byte(content), 0644); err != nil {
			t.Fatalf("Failed to write fixture %s: %v", name, err)
		}
	}
	writeFixture("nodes.json", `{"items": [
		{"metadata": {"name": "node-a", "labels": {"node-role.kubernetes.io/control-plane": "true"}},
		 "status": {"conditions": [{"type": "Ready", "status": "True"}],
		 "nodeInfo": {"kubeletVersion": "v1.31.2+k3s1"},
		 "addresses": [{"type": "InternalIP", "address": "10.0.0.1"}]}},
		{"metadata": {"name": "node-b", "labels": {}},
		 "status": {"conditions": [{"type": "Ready", "status": "False"}],
		 "nodeInfo": {"kubeletVersion": "v1.31.2+k3s1"},
		 "addresses": [{"type": "InternalIP", "address": "10.0.0.2"}]}}
	]}`)
	writeFixture("pvc.json", `{"items": [
		{"metadata": {"name": "pvc-data", "namespace": "default"},
		 "spec": {"storageClassName": "axonwall-zfs-local"},
		 "status": {"phase": "Bound", "capacity": {"storage": "20Gi"}}}
	]}`)
	writeFixture("pods.json", `{"items": [
		{"status": {"phase": "Running", "containerStatuses": [{"ready": true}]}}
	]}`)

	// Fake systemctl reporting the k3s unit active, and a fake kubectl
	// answering from the fixtures above.
	binDir := filepath.Join(dir, "bin")
	if err := os.MkdirAll(binDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(binDir, "systemctl"), []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		t.Fatal(err)
	}
	kubectlScript := "#!/bin/sh\n" +
		"case \"$2\" in\n" +
		"  nodes) cat \"$KUBECTL_FIXTURES/nodes.json\";;\n" +
		"  pvc) cat \"$KUBECTL_FIXTURES/pvc.json\";;\n" +
		"  pods) cat \"$KUBECTL_FIXTURES/pods.json\";;\n" +
		"esac\n" +
		"exit 0\n"
	if err := os.WriteFile(filepath.Join(binDir, "kubectl"), []byte(kubectlScript), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir+":"+os.Getenv("PATH"))
	t.Setenv("KUBECTL_FIXTURES", fixtures)

	mgr := NewK3sManager()
	mgr.cfg = K3sRuntimeBundle{Enabled: true, PeerIp: "10.0.0.2"}

	st := mgr.GetStatus()
	if !st.ServiceActive {
		t.Errorf("expected ServiceActive=true with the fake systemctl, got false")
	}
	if !st.Running {
		t.Errorf("expected Running=true with kubectl answering, got false")
	}
	if len(st.Nodes) != 2 {
		t.Fatalf("expected 2 probed nodes, got %+v", st.Nodes)
	}
	if st.Nodes[0].Name != "node-a" || st.Nodes[0].Status != "Ready" || st.Nodes[0].Version != "v1.31.2+k3s1" || st.Nodes[0].InternalIp != "10.0.0.1" {
		t.Errorf("unexpected first node: %+v", st.Nodes[0])
	}
	if st.Nodes[1].Name != "node-b" || st.Nodes[1].Status != "NotReady" {
		t.Errorf("unexpected second node: %+v", st.Nodes[1])
	}
	if st.ClusterJoined || st.HaAutoJoined {
		t.Errorf("a peer IP must not report a joined cluster, got %v/%v", st.ClusterJoined, st.HaAutoJoined)
	}
	if st.Role != "primary-server" {
		t.Errorf("expected role primary-server without a join, got %q", st.Role)
	}
	if len(st.Volumes) != 1 || st.Volumes[0].Name != "pvc-data" || st.Volumes[0].Status != "Bound" || st.Volumes[0].Capacity != "20Gi" {
		t.Errorf("unexpected volumes: %+v", st.Volumes)
	}
	if !st.OpenEbsReady || !st.OpenEbsHealthy {
		t.Errorf("expected OpenEBS ready/healthy with all pods running, got %v/%v", st.OpenEbsReady, st.OpenEbsHealthy)
	}

	// A latched join is still reported — but only the latch, never the peer IP.
	mgr.haAutoJoined = true
	st = mgr.GetStatus()
	if !st.ClusterJoined || !st.HaAutoJoined || st.Role != "secondary-ha-server" {
		t.Errorf("expected joined=true/role secondary-ha-server after a join, got %+v", st)
	}
}
