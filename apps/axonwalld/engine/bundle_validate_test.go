package engine

import (
	"os"
	"path/filepath"
	"testing"
)

// Shapes mirror packages/axonwall_lib compile/nas and compile/k3s
// output: the validators must accept everything the compiler emits.

const validSmbConf = `# Axonwall Auto-Generated Samba (SMB3) Configuration
[global]
  workgroup = WORKGROUP
  server string = Axonwall Enterprise ZFS NAS
  security = user
  map to guest = Bad User
  server min protocol = SMB2_10
  ea support = yes
  vfs objects = acl_xattr
  map acl inherit = yes
  store dos attributes = yes
  load printers = no
  printing = bsd
  printcap name = /dev/null
  disable spoolss = yes

[media]
  path = /mnt/tank/media
  comment = Family media
  browseable = yes
  read only = no
  guest ok = no
  vfs objects = acl_xattr shadow_copy2 catia fruit streams_xattr
  shadow:snapdir = .zfs/snapshot
  shadow:sort = desc
  fruit:aapl = yes
  fruit:time machine = yes
  valid users = admin
  hosts allow = 192.168.1.
`

const validExports = `# Axonwall Auto-Generated NFSv4 Exports
/mnt/tank/media 192.168.1.0/24(rw,sync,no_subtree_check,no_root_squash)
/mnt/tank/backups *(ro,sync,no_subtree_check,root_squash)
`

const validK3sConfig = `# Axonwall Auto-Generated K3s Control Plane Configuration
write-kubeconfig-mode: "0640"
cluster-cidr: "10.42.0.0/16"
service-cidr: "10.43.0.0/16"
flannel-backend: "vxlan"
cluster-init: true
disable:
  - traefik
tls-san:
  - "127.0.0.1"
  - "localhost"
`

const validManifest = `apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: axonwall-zfs
provisioner: zfs.csi.openebs.io
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: app
spec:
  template:
    spec:
      containers:
        - name: app
          image: example/app:1.0
          volumeMounts:
            - name: data
              mountPath: /data
      volumes:
        - name: data
          persistentVolumeClaim:
            claimName: data
`

func TestValidateSmbConfAcceptsCompilerOutput(t *testing.T) {
	if err := validateSmbConf(validSmbConf); err != nil {
		t.Fatalf("compiler-shaped smb.conf rejected: %v", err)
	}
}

func TestValidateSmbConfRejectsEscapes(t *testing.T) {
	for name, conf := range map[string]string{
		"root preexec":    "[share]\n  path = /mnt/tank/x\n  root preexec = /tmp/evil.sh\n",
		"include":         "[global]\n  include = /tmp/evil.conf\n",
		"passwd prog":     "[global]\n  passwd program = /tmp/evil\n",
		"evil vfs":        "[share]\n  path = /mnt/tank/x\n  vfs objects = /tmp/evil.so\n",
		"path escape":     "[share]\n  path = /etc\n",
		"path dotdot":     "[share]\n  path = /mnt/../etc\n",
		"newline smuggle": "[global]\n  server string = x\nroot preexec = /tmp/evil\n",
	} {
		if err := validateSmbConf(conf); err == nil {
			t.Errorf("%s: accepted, want rejection", name)
		}
	}
}

func TestValidateNfsExportsAcceptsCompilerOutput(t *testing.T) {
	if err := validateNfsExports(validExports); err != nil {
		t.Fatalf("compiler-shaped exports rejected: %v", err)
	}
}

func TestValidateNfsExportsRejectsEscapes(t *testing.T) {
	for name, exp := range map[string]string{
		"root export":   "/ *(rw,sync,no_root_squash)\n",
		"etc export":    "/etc 192.168.1.0/24(rw,sync)\n",
		"unknown opt":   "/mnt/tank/x *(rw,sync,evil_option)\n",
		"valued opt":    "/mnt/tank/x *(rw,fsid=0,map=/tmp/x)\n",
		"no client":     "/mnt/tank/x\n",
		"relative path": "tank/x *(rw)\n",
	} {
		if err := validateNfsExports(exp); err == nil {
			t.Errorf("%s: accepted, want rejection", name)
		}
	}
}

func TestValidateK3sConfigAcceptsCompilerOutput(t *testing.T) {
	if err := validateK3sConfig(validK3sConfig); err != nil {
		t.Fatalf("compiler-shaped k3s config rejected: %v", err)
	}
}

func TestValidateK3sConfigAcceptsSafeKubeletArgs(t *testing.T) {
	sliceCfg := `write-kubeconfig-mode: "0640"
cluster-cidr: "10.42.0.0/16"
kubelet-arg:
  - "eviction-hard=memory.available<256Mi,nodefs.available<10%"
  - "eviction-soft=memory.available<512Mi"
  - "eviction-soft-grace-period=memory.available=1m30s"
  - "system-reserved=cpu=100m,memory=256Mi"
  - "kube-reserved=cpu=100m,memory=256Mi"
  - "max-pods=64"
  - "image-gc-high-threshold=85"
  - "image-gc-low-threshold=80"
  - "feature-gates=UserNamespacesSupport=true"
`
	if err := validateK3sConfig(sliceCfg); err != nil {
		t.Fatalf("expected safe kubelet-arg slice to pass validation, got: %v", err)
	}

	scalarCfg := "node-name: storage-01\nkubelet-arg: \"max-pods=48\"\n"
	if err := validateK3sConfig(scalarCfg); err != nil {
		t.Fatalf("expected safe scalar kubelet-arg to pass validation, got: %v", err)
	}
}

func TestValidateK3sConfigRejectsArgInjection(t *testing.T) {
	for name, cfg := range map[string]string{
		"apiserver arg":       "kube-apiserver-arg:\n  - authorization-mode=AlwaysAllow\n",
		"kubelet arg":         "kubelet-arg:\n  - serialize-image-pulls=false\n",
		"root-dir bare":       "kubelet-arg:\n  - root-dir=/\n",
		"root-dir dashed":     "kubelet-arg:\n  - --root-dir=/\n",
		"cred provider bin":   "kubelet-arg:\n  - image-credential-provider-bin-dir=/tmp\n",
		"cred provider cfg":   "kubelet-arg:\n  - image-credential-provider-config=/etc/shadow\n",
		"scalar dangerous":    "kubelet-arg: \"root-dir=/\"\n",
		"empty value":         "kubelet-arg:\n  - max-pods=\n",
		"metachar semicolon":  "kubelet-arg:\n  - \"eviction-hard=memory.available<256Mi;id\"\n",
		"metachar dollar":     "kubelet-arg:\n  - \"system-reserved=memory=$(id)\"\n",
		"newline injection":   "kubelet-arg:\n  - \"max-pods=64\\nroot-dir=/\"\n",
		"whitespace smuggle":  "kubelet-arg:\n  - \"max-pods=64 --root-dir=/\"\n",
		"empty kubelet slice": "kubelet-arg: []\n",
		"etcd arg":            "etcd-arg:\n  - unsafe\n",
		"unknown key":         "some-random-key: true\n",
	} {
		if err := validateK3sConfig(cfg); err == nil {
			t.Errorf("%s: accepted, want rejection", name)
		}
	}
}

func TestValidateK3sManifestAcceptsCompilerOutput(t *testing.T) {
	if err := validateK3sManifest(validManifest); err != nil {
		t.Fatalf("compiler-shaped manifest rejected: %v", err)
	}
}

func TestValidateK3sManifestRejectsEscapes(t *testing.T) {
	pod := func(extra string) string {
		return "apiVersion: v1\nkind: Pod\nmetadata:\n  name: x\nspec:\n" + extra
	}
	for name, doc := range map[string]string{
		"privileged":            pod("  containers:\n    - name: c\n      image: i\n      securityContext:\n        privileged: true\n"),
		"hostPath":              pod("  containers:\n    - name: c\n      image: i\n  volumes:\n    - name: v\n      hostPath:\n        path: /etc\n"),
		"hostNetwork":           pod("  hostNetwork: true\n  containers:\n    - name: c\n      image: i\n"),
		"cluster-admin binding": "apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRoleBinding\nmetadata:\n  name: x\nroleRef:\n  apiGroup: rbac.authorization.k8s.io\n  kind: ClusterRole\n  name: cluster-admin\nsubjects: []\n",
	} {
		if err := validateK3sManifest(doc); err == nil {
			t.Errorf("%s: accepted, want rejection", name)
		}
	}
}

func TestValidateSmbConfAllowlistAndDangerousRejections(t *testing.T) {
	fullCompilerSmb := `# Axonwall Auto-Generated Samba (SMB3) Configuration
[global]
  workgroup = WORKGROUP
  server string = Axonwall Enterprise ZFS NAS
  security = user
  map to guest = Bad User
  server min protocol = SMB2_10
  server multi channel support = yes
  ea support = yes
  vfs objects = acl_xattr
  map acl inherit = yes
  store dos attributes = yes
  load printers = no
  printing = bsd
  printcap name = /dev/null
  disable spoolss = yes

[media]
  path = /mnt/tank/media
  comment = Family media
  browseable = yes
  read only = no
  guest ok = no
  vfs objects = acl_xattr shadow_copy2 catia fruit streams_xattr recycle full_audit
  shadow:snapdir = .zfs/snapshot
  shadow:sort = desc
  shadow:format = @auto-%Y%m%d-%H%M
  shadow:localtime = yes
  fruit:aapl = yes
  fruit:time machine = yes
  recycle:repository = .recycle/%U
  recycle:keeptree = yes
  recycle:versions = yes
  recycle:touch = yes
  full_audit:prefix = %u|%I|%S
  full_audit:success = open write unlink rename mkdir rmdir
  full_audit:failure = connect
  valid users = admin
  hosts allow = 192.168.1.
`
	if err := validateSmbConf(fullCompilerSmb); err != nil {
		t.Fatalf("full compiler smb.conf rejected: %v", err)
	}

	rejected := map[string]string{
		"wide links":                "[share]\n  path = /mnt/tank/x\n  wide links = yes\n",
		"allow insecure wide links": "[global]\n  allow insecure wide links = yes\n",
		"usershare path":            "[global]\n  usershare path = /etc\n",
		"usershare allow guests":    "[global]\n  usershare allow guests = yes\n",
		"enumports command":         "[global]\n  enumports command = /tmp/evil.sh\n",
		"arbitrary script":          "[global]\n  custom magic script = /tmp/evil.sh\n",
		"arbitrary module":          "[global]\n  custom auth module = /tmp/evil.so\n",
		"arbitrary directive":       "[global]\n  unix extensions = yes\n",
		"follow symlinks":           "[share]\n  path = /mnt/tank/x\n  follow symlinks = yes\n",
		"bad printcap":              "[global]\n  printcap name = /etc/shadow\n",
		"bad recycle repo":          "[share]\n  path = /mnt/tank/x\n  recycle:repository = /etc/evil\n",
		"reserved section":          "[homes]\n  path = /mnt/tank/x\n",
		"directory alias":           "[share]\n  directory = /etc\n",
	}
	for name, conf := range rejected {
		if err := validateSmbConf(conf); err == nil {
			t.Errorf("smb.conf %s: accepted, want rejection", name)
		}
	}
}

func TestValidateK3sConfigStrictValuesAndYAML(t *testing.T) {
	validConfigs := map[string]string{
		"agent join":         "server: \"https://192.168.1.2:6443\"\ntoken-file: \"/var/lib/axonwall/k3s-join.token\"\n",
		"ipv6 server":        "server: \"https://[fd00::1]:6443\"\ntoken-file: \"/var/lib/axonwall/k3s-join.token\"\n",
		"mode 0600":          "write-kubeconfig-mode: \"0600\"\n",
		"mode 0640":          "write-kubeconfig-mode: \"0640\"\nwrite-kubeconfig-group: \"axonwall-api\"\n",
		"datastore postgres": "datastore-endpoint: \"postgres://k3s:secret@10.0.0.5:5432/k3s?sslmode=require\"\n",
		"datastore mysql":    "datastore-endpoint: \"mysql://k3s:secret@tcp(10.0.0.5:3306)/k3s\"\n",
		"datastore etcd":     "datastore-endpoint: \"https://10.0.0.1:2379,https://10.0.0.2:2379\"\n",
		"snapshot backups":   "etcd-snapshot-dir: \"/var/lib/axonwall/backups/etcd\"\n",
		"snapshot mnt":       "etcd-snapshot-dir: \"/mnt/tank/k3s-snapshots\"\n",
		"snapshot default":   "etcd-snapshot-dir: \"/var/lib/rancher/k3s/server/db/snapshots\"\n",
		"snapshot cron":      "etcd-snapshot-schedule-cron: \"0 */6 * * *\"\netcd-snapshot-retention: 14\n",
	}
	for name, cfg := range validConfigs {
		if err := validateK3sConfig(cfg); err != nil {
			t.Errorf("valid config %s rejected: %v", name, err)
		}
	}

	// Symlink ancestor rejection for etcd-snapshot-dir if testable under temp dir?
	// Also test bad values for every strictly validated key + YAML bypass primitives.
	badConfigs := map[string]string{
		"server http":            "server: \"http://10.0.0.1:6443\"\n",
		"server space":           "server: \"https://10.0.0.1:6443 --evil\"\n",
		"server ctrl":            "server: \"https://10.0.0.1:6443\\nfoo\"\n",
		"server userinfo":        "server: \"https://user@10.0.0.1:6443\"\n",
		"server path":            "server: \"https://10.0.0.1:6443/evil\"\n",
		"server query":           "server: \"https://10.0.0.1:6443?a=1\"\n",
		"server bad port":        "server: \"https://10.0.0.1:99999\"\n",
		"token-file shadow":      "token-file: \"/etc/shadow\"\n",
		"token-file traversal":   "token-file: \"/var/lib/axonwall/../etc/passwd\"\n",
		"token-file subdir":      "token-file: \"/var/lib/axonwall/k3s-join.token.bak\"\n",
		"datastore sqlite":       "datastore-endpoint: \"sqlite:///etc/passwd\"\n",
		"datastore file":         "datastore-endpoint: \"file:///tmp/evil.db\"\n",
		"datastore ctrl":         "datastore-endpoint: \"postgres://u:p@10.0.0.1:5432/db\\nevil\"\n",
		"datastore space":        "datastore-endpoint: \"postgres://u:p@10.0.0.1:5432/db --flag\"\n",
		"snapshot etc":           "etcd-snapshot-dir: \"/etc/cron.d\"\n",
		"snapshot dotdot":        "etcd-snapshot-dir: \"/var/lib/axonwall/backups/../../etc\"\n",
		"snapshot prefix escape": "etcd-snapshot-dir: \"/var/lib/axonwall/backups-evil/x\"\n",
		"snapshot bare mnt":      "etcd-snapshot-dir: \"/mnt\"\n",
		"snapshot mnt escape":    "etcd-snapshot-dir: \"/mnt/../etc\"\n",
		"kubeconfig mode 0644":   "write-kubeconfig-mode: \"0644\"\n",
		"kubeconfig mode 0777":   "write-kubeconfig-mode: \"0777\"\n",
		"kubeconfig mode int":    "write-kubeconfig-mode: 640\n",
		"kubeconfig group bad":   "write-kubeconfig-group: \"root;id\"\n",
		"yaml duplicate key":     "node-name: a\nnode-name: b\n",
		"yaml anchor alias":      "node-name: &n a\nnode-ip: *n\n",
		"yaml integer key":       "123: bad\n",
		"yaml multi doc":         "node-name: a\n---\nnode-name: b\n",
	}
	for name, cfg := range badConfigs {
		if err := validateK3sConfig(cfg); err == nil {
			t.Errorf("bad config %s: accepted, want rejection", name)
		}
	}

	// Verify symlink check helper directly for etcd-snapshot-dir ancestor
	tmpDir := t.TempDir()
	realDir := filepath.Join(tmpDir, "real")
	symDir := filepath.Join(tmpDir, "sym")
	if err := os.MkdirAll(realDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realDir, symDir); err != nil {
		t.Fatal(err)
	}
	if err := checkExistingAncestorsNoSymlink(filepath.Join(symDir, "snapshots")); err == nil {
		t.Errorf("expected symlink ancestor to be rejected")
	}
}

func TestValidateK3sManifestYAMLNodeAndBypassRejections(t *testing.T) {
	// 1. YAML structural bypasses (SEC-C02)
	yamlBypasses := map[string]string{
		"integer key map[any]any": "apiVersion: v1\nkind: Pod\nmetadata:\n  name: x\n1:\n  hostNetwork: true\n  privileged: true\n",
		"boolean key map[any]any": "apiVersion: v1\nkind: Pod\nmetadata:\n  name: x\ntrue:\n  hostPath:\n    path: /etc\n",
		"null key":                "apiVersion: v1\nkind: ConfigMap\nnull:\n  privileged: true\n",
		"duplicate keys top":      "apiVersion: v1\nkind: ConfigMap\nkind: ClusterRole\nmetadata:\n  name: x\n",
		"duplicate keys nested":   "apiVersion: v1\nkind: Pod\nmetadata:\n  name: x\nspec:\n  hostNetwork: false\n  hostNetwork: true\n",
		"yaml anchor and alias":   "apiVersion: v1\nkind: Pod\nmetadata:\n  name: x\n  annotations:\n    a: &ref\n      privileged: true\n    b: *ref\n",
		"yaml merge key":          "apiVersion: v1\nkind: Pod\nmetadata:\n  name: x\nspec:\n  <<: { hostNetwork: true }\n  containers:\n    - name: c\n      image: nginx\n",
		"unknown tag binary":      "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: x\ndata:\n  bin: !!binary SGVsbG8=\n",
		"custom tag":              "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: x\ndata:\n  x: !evil foo\n",
		"timestamp tag":           "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: x\ndata:\n  d: 2026-11-27\n",
		"top level sequence":      "- kind: Pod\n",
	}
	for name, doc := range yamlBypasses {
		if err := validateK3sManifest(doc); err == nil {
			t.Errorf("YAML bypass %s: accepted, want rejection", name)
		}
	}

	// 2. HelmChart bypasses (SEC-C02)
	ciliumFull := `# Axonwall Auto-Generated Cilium eBPF CNI
apiVersion: helm.cattle.io/v1
kind: HelmChart
metadata:
  name: cilium
  namespace: kube-system
spec:
  repo: https://helm.cilium.io/
  chart: cilium
  targetNamespace: kube-system
  valuesContent: |-
    kubeProxyReplacement: "true"
    k8sServiceHost: "192.168.1.1"
    k8sServicePort: 6443
    bpf:
      masquerade: true
    ipam:
      operator:
        clusterPoolIPv4PodCIDRList: ["10.42.0.0/16"]
    l2announcements:
      enabled: true
    bgpControlPlane:
      enabled: false
    hubble:
      enabled: true
      relay:
        enabled: true
`
	if err := validateK3sManifest(ciliumFull); err != nil {
		t.Fatalf("full compiler Cilium HelmChart rejected: %v", err)
	}

	vigilanteValid := `apiVersion: helm.cattle.io/v1
kind: HelmChart
metadata:
  name: vigilante-opensearch
  namespace: kube-system
spec:
  repo: https://charts.vigilante.local
  chart: opensearch
  targetNamespace: vigilante-soc
  valuesContent: "clusterName: opensearch-soc\n"
`
	if err := validateK3sManifest(vigilanteValid); err != nil {
		t.Fatalf("valid Vigilante HelmChart rejected: %v", err)
	}

	helmBypasses := map[string]string{
		"untrusted vigilante chart": "apiVersion: helm.cattle.io/v1\nkind: HelmChart\nmetadata:\n  name: x\n  namespace: kube-system\nspec:\n  repo: https://charts.vigilante.local\n  chart: arbitrary-backdoor\n",
		"cilium wrong chart":        "apiVersion: helm.cattle.io/v1\nkind: HelmChart\nmetadata:\n  name: x\n  namespace: kube-system\nspec:\n  repo: https://helm.cilium.io/\n  chart: hubble-evil\n",
		"spec.repoCA":               "apiVersion: helm.cattle.io/v1\nkind: HelmChart\nmetadata:\n  name: cilium\n  namespace: kube-system\nspec:\n  repo: https://helm.cilium.io/\n  chart: cilium\n  repoCA: LS0tLS1CRUdJTi...\n",
		"vigilante target kube-sys": "apiVersion: helm.cattle.io/v1\nkind: HelmChart\nmetadata:\n  name: x\n  namespace: kube-system\nspec:\n  repo: https://charts.vigilante.local\n  chart: opensearch\n  targetNamespace: kube-system\n",
		"values image override":     "apiVersion: helm.cattle.io/v1\nkind: HelmChart\nmetadata:\n  name: cilium\n  namespace: kube-system\nspec:\n  repo: https://helm.cilium.io/\n  chart: cilium\n  values:\n    image:\n      repository: evil/pwn\n",
		"values command override":   "apiVersion: helm.cattle.io/v1\nkind: HelmChart\nmetadata:\n  name: cilium\n  namespace: kube-system\nspec:\n  repo: https://helm.cilium.io/\n  chart: cilium\n  values:\n    command: [\"/bin/sh\"]\n",
		"values args override":      "apiVersion: helm.cattle.io/v1\nkind: HelmChart\nmetadata:\n  name: cilium\n  namespace: kube-system\nspec:\n  repo: https://helm.cilium.io/\n  chart: cilium\n  values:\n    args: [\"-c\", \"id\"]\n",
		"valuesContent priv string": "apiVersion: helm.cattle.io/v1\nkind: HelmChart\nmetadata:\n  name: cilium\n  namespace: kube-system\nspec:\n  repo: https://helm.cilium.io/\n  chart: cilium\n  valuesContent: |\n    securityContext:\n      privileged: \"true\"\n",
		"valuesContent roleRef":     "apiVersion: helm.cattle.io/v1\nkind: HelmChart\nmetadata:\n  name: cilium\n  namespace: kube-system\nspec:\n  repo: https://helm.cilium.io/\n  chart: cilium\n  valuesContent: |\n    rbac:\n      roleRef:\n        name: cluster-admin\n",
		"valuesContent userns hp":   "apiVersion: helm.cattle.io/v1\nkind: HelmChart\nmetadata:\n  name: cilium\n  namespace: kube-system\nspec:\n  repo: https://helm.cilium.io/\n  chart: cilium\n  valuesContent: |\n    hostUsers: false\n    extraVolumes:\n      - hostPath:\n          path: /run/axonwall/bpffs-tokens/evil\n",
		"valuesContent anchor":      "apiVersion: helm.cattle.io/v1\nkind: HelmChart\nmetadata:\n  name: cilium\n  namespace: kube-system\nspec:\n  repo: https://helm.cilium.io/\n  chart: cilium\n  valuesContent: |\n    a: &x 1\n    b: *x\n",
		"valuesContent SA":          "apiVersion: helm.cattle.io/v1\nkind: HelmChart\nmetadata:\n  name: cilium\n  namespace: kube-system\nspec:\n  repo: https://helm.cilium.io/\n  chart: cilium\n  valuesContent: |\n    serviceAccountName: helm-controller\n",
		"set dotted image":          "apiVersion: helm.cattle.io/v1\nkind: HelmChart\nmetadata:\n  name: cilium\n  namespace: kube-system\nspec:\n  repo: https://helm.cilium.io/\n  chart: cilium\n  set:\n    agent.image.repository: evil/pwn\n",
		"set dotted privileged":     "apiVersion: helm.cattle.io/v1\nkind: HelmChart\nmetadata:\n  name: cilium\n  namespace: kube-system\nspec:\n  repo: https://helm.cilium.io/\n  chart: cilium\n  set:\n    securityContext.privileged: \"true\"\n",
		"set dotted hostPath":       "apiVersion: helm.cattle.io/v1\nkind: HelmChart\nmetadata:\n  name: cilium\n  namespace: kube-system\nspec:\n  repo: https://helm.cilium.io/\n  chart: cilium\n  set:\n    extraVolumes[0].hostPath.path: /etc\n",
		"set dotted capabilities":   "apiVersion: helm.cattle.io/v1\nkind: HelmChart\nmetadata:\n  name: cilium\n  namespace: kube-system\nspec:\n  repo: https://helm.cilium.io/\n  chart: cilium\n  set:\n    securityContext.capabilities.add[0]: SYS_ADMIN\n",
		"set dotted hostNetwork":    "apiVersion: helm.cattle.io/v1\nkind: HelmChart\nmetadata:\n  name: cilium\n  namespace: kube-system\nspec:\n  repo: https://helm.cilium.io/\n  chart: cilium\n  set:\n    hostNetwork: \"true\"\n",
		"set comma smuggle":         "apiVersion: helm.cattle.io/v1\nkind: HelmChart\nmetadata:\n  name: cilium\n  namespace: kube-system\nspec:\n  repo: https://helm.cilium.io/\n  chart: cilium\n  set:\n    k8sServiceHost: \"10.0.0.1,image.repository=evil/pwn\"\n",
	}
	for name, doc := range helmBypasses {
		if err := validateK3sManifest(doc); err == nil {
			t.Errorf("HelmChart bypass %s: accepted, want rejection", name)
		}
	}

	// 3. System namespaces & privileged ServiceAccounts (SEC-C02)
	nsAndSaRejects := map[string]string{
		"pod in kube-system":              "apiVersion: v1\nkind: Pod\nmetadata:\n  name: x\n  namespace: kube-system\nspec:\n  automountServiceAccountToken: false\n  containers:\n    - name: c\n      image: nginx\n",
		"deploy in kube-public":           "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: x\n  namespace: kube-public\nspec:\n  template:\n    spec:\n      containers:\n        - name: c\n          image: nginx\n",
		"sa in kube-node-lease":           "apiVersion: v1\nkind: ServiceAccount\nmetadata:\n  name: evil\n  namespace: kube-node-lease\n",
		"create kube-system ns":           "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: kube-system\n",
		"sa helm-controller":              "apiVersion: v1\nkind: Pod\nmetadata:\n  name: x\nspec:\n  serviceAccountName: helm-controller\n  containers:\n    - name: c\n      image: nginx\n",
		"sa openebs-zfs-controller-sa":    "apiVersion: v1\nkind: Pod\nmetadata:\n  name: x\nspec:\n  serviceAccountName: openebs-zfs-controller-sa\n  automountServiceAccountToken: false\n  containers:\n    - name: c\n      image: nginx\n",
		"deprecated serviceAccount":       "apiVersion: v1\nkind: Pod\nmetadata:\n  name: x\nspec:\n  serviceAccount: helm-controller\n  containers:\n    - name: c\n      image: nginx\n",
		"system colon SA":                 "apiVersion: v1\nkind: Pod\nmetadata:\n  name: x\nspec:\n  serviceAccountName: system:serviceaccount:kube-system:default\n  containers:\n    - name: c\n      image: nginx\n",
		"explicit default SA w/o false":   "apiVersion: v1\nkind: Pod\nmetadata:\n  name: x\nspec:\n  serviceAccountName: default\n  containers:\n    - name: c\n      image: nginx\n",
		"automount true no SA":            "apiVersion: v1\nkind: Pod\nmetadata:\n  name: x\nspec:\n  automountServiceAccountToken: true\n  containers:\n    - name: c\n      image: nginx\n",
		"case bypass HostNetwork":         "apiVersion: v1\nkind: Pod\nmetadata:\n  name: x\nspec:\n  HostNetwork: true\n  containers:\n    - name: c\n      image: nginx\n",
		"privileged string true":          "apiVersion: v1\nkind: Pod\nmetadata:\n  name: x\nspec:\n  containers:\n    - name: c\n      image: nginx\n      securityContext:\n        privileged: \"true\"\n",
		"null kind no panic":              "apiVersion: v1\nkind: null\nmetadata:\n  name: x\n",
		"empty kind no panic":             "apiVersion: v1\nkind:\nmetadata:\n  name: x\n",
		"non-string kind":                 "apiVersion: v1\nkind: 123\nmetadata:\n  name: x\n",
		"helmrelease values kube-system":  "apiVersion: helm.toolkit.fluxcd.io/v2\nkind: HelmRelease\nmetadata:\n  name: evil\n  namespace: apps\nspec:\n  values:\n    metadata:\n      namespace: kube-system\n",
		"helmrelease values clusterrole":  "apiVersion: helm.toolkit.fluxcd.io/v2\nkind: HelmRelease\nmetadata:\n  name: evil\n  namespace: apps\nspec:\n  values:\n    kind: ClusterRoleBinding\n",
		"configmap valuesObject SA":       "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: evil\nvaluesObject:\n  serviceAccountName: helm-controller\n",
		"configmap values automount true": "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: evil\nvalues:\n  automountServiceAccountToken: true\n",
	}
	for name, doc := range nsAndSaRejects {
		if err := validateK3sManifest(doc); err == nil {
			t.Errorf("namespace/SA bypass %s: accepted, want rejection", name)
		}
	}

	// Safe ServiceAccount + automountServiceAccountToken: false cases must pass
	validSaDocs := map[string]string{
		"safe non-system SA":              "apiVersion: v1\nkind: Pod\nmetadata:\n  name: x\n  namespace: apps\nspec:\n  serviceAccountName: web-sa\n  containers:\n    - name: c\n      image: nginx\n",
		"default SA with automount false": "apiVersion: v1\nkind: Pod\nmetadata:\n  name: x\n  namespace: apps\nspec:\n  serviceAccountName: default\n  automountServiceAccountToken: false\n  containers:\n    - name: c\n      image: nginx\n",
		"vigilante canary SA":             "apiVersion: v1\nkind: ServiceAccount\nmetadata:\n  name: cluster-admin-backup\n  namespace: vigilante-soc\n",
	}
	for name, doc := range validSaDocs {
		if err := validateK3sManifest(doc); err != nil {
			t.Errorf("valid SA manifest %s rejected: %v", name, err)
		}
	}
}

func TestValidateMinioEnvConfAllowlistAndOpts(t *testing.T) {
	validEnvs := map[string]string{
		"full compiler output": `# Axonwall Auto-Generated S3 Object Storage (MinIO) Configuration
MINIO_VOLUMES="/mnt/tank/s3"
MINIO_OPTS="--address :9000 --console-address :9001"
MINIO_ROOT_USER="axonwall-admin"
MINIO_ROOT_PASSWORD="superSecret\$Pass\` + "`" + `123"
`,
		"host:port and ipv6 opts": `MINIO_VOLUMES="/mnt/tank/s3"
MINIO_OPTS="--address 127.0.0.1:9000 --console-address [::1]:9001"
MINIO_BROWSER=off
MINIO_DOMAIN=s3.axonwall.local
MINIO_REGION_NAME=us-east-1
`,
		"equals opt form": `MINIO_VOLUMES="/mnt/tank/s3"
MINIO_OPTS="--address=:9000 --console-address=:9001"
`,
	}
	for name, env := range validEnvs {
		if err := validateMinioEnvConf(env); err != nil {
			t.Errorf("valid MinIO env %s rejected: %v", name, err)
		}
	}

	badEnvs := map[string]string{
		"unknown MINIO webhook":          "MINIO_NOTIFY_WEBHOOK_ENDPOINT=https://evil.example/hook\n",
		"unknown MINIO certs dir":        "MINIO_CERTS_DIR=/tmp/evil-certs\n",
		"unknown MINIO config env":       "MINIO_CONFIG_ENV_FILE=/etc/shadow\n",
		"non-MINIO env var":              "LD_PRELOAD=/tmp/evil.so\n",
		"MINIO_OPTS certs-dir":           "MINIO_OPTS=\"--address :9000 --certs-dir /tmp/evil\"\n",
		"MINIO_OPTS config-dir":          "MINIO_OPTS=\"--config-dir=/tmp/evil\"\n",
		"MINIO_OPTS unknown flag":        "MINIO_OPTS=\"--anonymous\"\n",
		"MINIO_OPTS shell semi":          "MINIO_OPTS=\"--address :9000;id\"\n",
		"MINIO_OPTS cmd subst":           "MINIO_OPTS=\"--address $(id):9000\"\n",
		"MINIO_OPTS backtick":            "MINIO_OPTS=\"--address `id`:9000\"\n",
		"MINIO_OPTS path in addr":        "MINIO_OPTS=\"--address 127.0.0.1:9000/evil\"\n",
		"MINIO_OPTS bad port":            "MINIO_OPTS=\"--address :99999\"\n",
		"MINIO_OPTS missing val":         "MINIO_OPTS=\"--address\"\n",
		"MINIO_OPTS dup flag":            "MINIO_OPTS=\"--address :9000 --address :9001\"\n",
		"MINIO_VOLUMES bare mnt":         "MINIO_VOLUMES=\"/mnt\"\n",
		"MINIO_VOLUMES outside":          "MINIO_VOLUMES=\"/etc\"\n",
		"MINIO_VOLUMES dotdot":           "MINIO_VOLUMES=\"/mnt/../etc\"\n",
		"MINIO_ROOT_PASSWORD cmd":        "MINIO_ROOT_PASSWORD=\"$(id)\"\n",
		"MINIO_ROOT_PASSWORD mixed $":    "MINIO_ROOT_PASSWORD=\"$(id)\\$\"\n",
		"MINIO_ROOT_PASSWORD mixed tick": "MINIO_ROOT_PASSWORD=\"`id`\\`\"\n",
		"MINIO_ROOT_PASSWORD dbl slash":  "MINIO_ROOT_PASSWORD=\"foo\\\\$bar\"\n",
		"MINIO_ROOT_PASSWORD single q":   "MINIO_ROOT_PASSWORD='$(id)'\n",
		"MINIO_BROWSER invalid":          "MINIO_BROWSER=maybe\n",
		"MINIO_DOMAIN invalid":           "MINIO_DOMAIN=\"evil.com;id\"\n",
		"line continuation":              "MINIO_ROOT_USER=axw\\\n",
	}
	for name, env := range badEnvs {
		if err := validateMinioEnvConf(env); err == nil {
			t.Errorf("bad MinIO env %s: accepted, want rejection", name)
		}
	}
}
