package engine

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestXdpLpmCidrAndSynFloodProtection(t *testing.T) {
	mgr := NewEBPFManager()

	// Valid public IPv4 /24 CIDR block
	if err := mgr.AddXdpBlock("198.51.100.0/24", 600, 1, "Threat feed ASN prefix"); err != nil {
		t.Fatalf("expected valid IPv4 CIDR block to succeed, got: %v", err)
	}
	// Valid public IPv6 /48 CIDR block
	if err := mgr.AddXdpBlock("2001:db8:c0de::/48", 600, 2, "IPv6 botnet prefix"); err != nil {
		t.Fatalf("expected valid IPv6 CIDR block to succeed, got: %v", err)
	}

	// Overly broad IPv4 CIDR (/4 < /8) must be rejected
	if err := mgr.AddXdpBlock("198.0.0.0/4", 600, 1, "too broad"); err == nil {
		t.Fatalf("expected /4 CIDR block to be rejected by blast-radius guard")
	}
	// Loopback CIDR must be rejected by blast-radius / anti-lockout guard
	if err := mgr.AddXdpBlock("127.0.0.0/8", 600, 1, "loopback"); err == nil {
		t.Fatalf("expected loopback CIDR block to be rejected by blast-radius guard")
	}

	if err := mgr.SetSynFloodLimitPps(5000); err != nil {
		t.Fatalf("SetSynFloodLimitPps failed: %v", err)
	}
	if err := mgr.SetSynFloodLimitPps(5); err == nil {
		t.Fatalf("expected dangerously low SYN limit (5 pps) to be rejected")
	}

	snap := mgr.GetDataplaneSnapshot(10)
	if snap.SynFloodLimitPps != 5000 {
		t.Fatalf("expected SynFloodLimitPps=5000, got %d", snap.SynFloodLimitPps)
	}
	if len(snap.ActiveBlocks) != 2 {
		t.Fatalf("expected 2 active CIDR blocks, got %d", len(snap.ActiveBlocks))
	}

	if err := mgr.RemoveXdpBlock("198.51.100.0/24"); err != nil {
		t.Fatalf("RemoveXdpBlock CIDR failed: %v", err)
	}
	if len(mgr.GetDataplaneSnapshot(10).ActiveBlocks) != 1 {
		t.Fatalf("expected 1 active block remaining")
	}
}

func TestZfsSpecialVdevsAndNativeEncryption(t *testing.T) {
	pool := ZfsPoolSpec{
		Name:               "tank",
		Topology:           "raidz2",
		DataDisks:          []string{"/dev/sda", "/dev/sdb", "/dev/sdc", "/dev/sdd"},
		SpecialDisks:       []string{"/dev/nvme0n1", "/dev/nvme1n1"},
		DedupDisks:         []string{"/dev/nvme2n1", "/dev/nvme3n1"},
		SpecialSmallBlocks: "32K",
		Ashift:             12,
		Autotrim:           true,
	}
	if err := ValidateZfsPoolSpec(pool); err != nil {
		t.Fatalf("expected valid pool with special & dedup VDEVs, got: %v", err)
	}

	args := BuildZfsPoolCreateArgs(pool)
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "special mirror /dev/nvme0n1 /dev/nvme1n1") {
		t.Fatalf("expected special mirror VDEV in zpool args, got: %s", joined)
	}
	if !strings.Contains(joined, "dedup mirror /dev/nvme2n1 /dev/nvme3n1") {
		t.Fatalf("expected dedup mirror VDEV in zpool args, got: %s", joined)
	}
	if !strings.Contains(joined, "special_small_blocks=32K") {
		t.Fatalf("expected special_small_blocks=32K in zpool args, got: %s", joined)
	}

	// Reject partition on SpecialDisks
	badPool := pool
	badPool.SpecialDisks = []string{"/dev/nvme0n1p1"}
	if err := ValidateZfsPoolSpec(badPool); err == nil {
		t.Fatalf("expected partition path in SpecialDisks to be rejected")
	}

	ds := ZfsDatasetSpec{
		Pool:             "tank",
		Name:             "vault",
		Compression:      "zstd",
		RecordSize:       "128K",
		Encryption:       "aes-256-gcm",
		KeyFormat:        "passphrase",
		KeyLocation:      "/etc/axonwall/keys/vault.key",
		RefQuotaGb:       500,
		RefReservationGb: 50,
		Atime:            "off",
		Sync:             "always",
	}
	if err := ValidateZfsDatasetSpec(ds); err != nil {
		t.Fatalf("expected valid encrypted dataset, got: %v", err)
	}
	var flat []string
	for _, cmd := range BuildZfsDatasetCreateArgs(ds) {
		flat = append(flat, strings.Join(cmd, " "))
	}
	dsArgs := strings.Join(flat, " ; ")
	for _, want := range []string{
		"encryption=aes-256-gcm",
		"keyformat=passphrase",
		"refquota=500G",
		"refreservation=50G",
		"sync=always",
	} {
		if !strings.Contains(dsArgs, want) {
			t.Fatalf("expected %q in zfs create args, got: %s", want, dsArgs)
		}
	}
}

func TestBundleValidatorsParityPlusSecurityInvariants(t *testing.T) {
	// SMB VFS recycle & full_audit allowed
	smbGood := "[global]\nworkgroup = WORKGROUP\n[finance]\npath = /mnt/tank/finance\nvfs objects = shadow_copy2 recycle full_audit\n"
	if err := validateSmbConf(smbGood); err != nil {
		t.Fatalf("expected shadow_copy2 + recycle + full_audit to pass validateSmbConf, got: %v", err)
	}

	// NFSv4 Kerberos sec=krb5p allowed, disallowed sec flavor or option blocked
	nfsGood := "/mnt/tank/secure 10.0.10.0/24(rw,sync,no_subtree_check,sec=krb5p)\n"
	if err := validateNfsExports(nfsGood); err != nil {
		t.Fatalf("expected sec=krb5p NFS export to pass, got: %v", err)
	}
	nfsBad := "/mnt/tank/secure 10.0.10.0/24(rw,sec=evil_plugin)\n"
	if err := validateNfsExports(nfsBad); err == nil {
		t.Fatalf("expected sec=evil_plugin to be blocked")
	}

	// K3s config: Cilium flags + UserNamespacesSupport kubelet-arg allowed, arbitrary kubelet-arg blocked
	k3sGood := "flannel-backend: \"none\"\ndisable-network-policy: true\nkubelet-arg:\n  - \"feature-gates=UserNamespacesSupport=true\"\n"
	if err := validateK3sConfig(k3sGood); err != nil {
		t.Fatalf("expected Cilium + UserNS k3s config to pass, got: %v", err)
	}
	k3sBad := "kubelet-arg:\n  - \"root-dir=/etc\"\n"
	if err := validateK3sConfig(k3sBad); err == nil {
		t.Fatalf("expected arbitrary kubelet-arg to be rejected")
	}

	// K3s manifest: Cilium HelmChart allowed, arbitrary HelmChart repo rejected
	ciliumHelm := "apiVersion: helm.cattle.io/v1\nkind: HelmChart\nmetadata:\n  name: cilium\n  namespace: kube-system\nspec:\n  repo: https://helm.cilium.io/\n  chart: cilium\n"
	if err := validateK3sManifest(ciliumHelm); err != nil {
		t.Fatalf("expected official Cilium HelmChart to pass, got: %v", err)
	}
	evilHelm := "apiVersion: helm.cattle.io/v1\nkind: HelmChart\nmetadata:\n  name: backdoor\n  namespace: kube-system\nspec:\n  repo: https://evil.example.com/\n  chart: pwn\n"
	if err := validateK3sManifest(evilHelm); err == nil {
		t.Fatalf("expected untrusted HelmChart repo to be rejected")
	}
}

func TestVirtManagerCloneLibvirtXmlAndGfsPrune(t *testing.T) {
	tm := NewTaskManager()
	nm := NewNasManager()
	vm := NewVirtManager(tm, nm)

	rawBundle := []byte(`{
		"defaultPool": "tank",
		"vms": [{
			"vmid": 100,
			"name": "win11-ws",
			"autostart": false,
			"cores": 4,
			"memoryMb": 8192,
			"tpm2": true,
			"qemuBinary": "/usr/bin/qemu-system-x86_64",
			"args": ["-name", "win11-ws", "-m", "8192", "-pidfile", "/run/axonwall/pids/vm-100.pid", "-fw_cfg", "name=opt/com.coreos/config,file=/var/lib/axonwall/cloudinit/vm-100/ignition.json"],
			"disks": [{"id": "root", "pool": "tank", "sizeGb": 64, "resolvedZvol": "tank/vms/vm-100-disk-0"}],
			"nics": [{"bridge": "br0", "vlanTag": 20, "tapName": "tap100i0"}]
		}],
		"containers": []
	}`)

	if err := vm.ApplyVirtBundleJSON(rawBundle); err != nil {
		t.Fatalf("ApplyVirtBundleJSON failed: %v", err)
	}

	cloned, err := vm.CloneVM(100, 200, "win11-clone", true)
	if err != nil {
		t.Fatalf("CloneVM failed: %v", err)
	}
	if cloned.VMID != 200 || cloned.Name != "win11-clone" {
		t.Fatalf("unexpected cloned VM spec: %+v", cloned)
	}
	if cloned.Disks[0].Zvol != "tank/vms/vm-200-disk-0" {
		t.Fatalf("expected rewritten zvol path, got %s", cloned.Disks[0].Zvol)
	}

	xmlStr, err := vm.ExportLibvirtXML(200)
	if err != nil {
		t.Fatalf("ExportLibvirtXML failed: %v", err)
	}
	if !strings.Contains(xmlStr, "<domain type='kvm'>") || !strings.Contains(xmlStr, "<name>win11-clone</name>") {
		t.Fatalf("unexpected Libvirt XML: %s", xmlStr)
	}

	// Test GFS backup pruning logic via temp directory under /mnt if writable or verify input guard
	if _, err := vm.PruneBackupsGFS("tank", 0); err == nil {
		t.Fatalf("expected keepLast=0 to be rejected")
	}

	// Ensure backup archive validation rejects path traversal
	if _, err := vm.RestoreBackup("../../etc/passwd", "vm", 100, "tank", "admin"); err == nil {
		t.Fatalf("expected RestoreBackup to reject invalid archive name")
	}

	// Ensure unused imports compile cleanly in test helper check
	_ = os.TempDir()
	_ = filepath.Clean("/tmp")
	_ = time.Second
}

func TestDdnsManagerValidationAndReconcile(t *testing.T) {
	dm := NewDdnsManager()
	good := []byte(`{"enabled":true,"entries":[{"provider":"cloudflare","hostname":"edge.axonwall.io","interface":"wan","ipVersion":"dual","enabled":true}]}`)
	if err := dm.ApplyConfigJSON(good); err != nil {
		t.Fatalf("expected valid DDNS config to succeed, got: %v", err)
	}
	st := dm.GetStatus()
	if !st.Enabled || len(st.Entries) != 1 || st.Entries[0].Hostname != "edge.axonwall.io" {
		t.Fatalf("unexpected DDNS status: %+v", st)
	}
	bad := []byte(`{"enabled":true,"entries":[{"provider":"evil_exec","hostname":"edge.axonwall.io","enabled":true}]}`)
	if err := dm.ApplyConfigJSON(bad); err == nil {
		t.Fatalf("expected unknown DDNS provider to be rejected")
	}
}
