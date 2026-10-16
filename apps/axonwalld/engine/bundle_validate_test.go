package engine

import "testing"

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
		"root preexec":  "[share]\n  path = /mnt/tank/x\n  root preexec = /tmp/evil.sh\n",
		"include":       "[global]\n  include = /tmp/evil.conf\n",
		"passwd prog":   "[global]\n  passwd program = /tmp/evil\n",
		"evil vfs":      "[share]\n  path = /mnt/tank/x\n  vfs objects = /tmp/evil.so\n",
		"path escape":   "[share]\n  path = /etc\n",
		"path dotdot":   "[share]\n  path = /mnt/../etc\n",
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

func TestValidateK3sConfigRejectsArgInjection(t *testing.T) {
	for name, cfg := range map[string]string{
		"apiserver arg": "kube-apiserver-arg:\n  - authorization-mode=AlwaysAllow\n",
		"kubelet arg":   "kubelet-arg:\n  - serialize-image-pulls=false\n",
		"etcd arg":      "etcd-arg:\n  - unsafe\n",
		"unknown key":   "some-random-key: true\n",
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
		"privileged":  pod("  containers:\n    - name: c\n      image: i\n      securityContext:\n        privileged: true\n"),
		"hostPath":    pod("  containers:\n    - name: c\n      image: i\n  volumes:\n    - name: v\n      hostPath:\n        path: /etc\n"),
		"hostNetwork": pod("  hostNetwork: true\n  containers:\n    - name: c\n      image: i\n"),
		"cluster-admin binding": "apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRoleBinding\nmetadata:\n  name: x\nroleRef:\n  apiGroup: rbac.authorization.k8s.io\n  kind: ClusterRole\n  name: cluster-admin\nsubjects: []\n",
	} {
		if err := validateK3sManifest(doc); err == nil {
			t.Errorf("%s: accepted, want rejection", name)
		}
	}
}
