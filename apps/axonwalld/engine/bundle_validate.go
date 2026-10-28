package engine

// Content validation for the free-text fields of NAS / K3s bundles
// (audit finding D-05). The daemon used to write bundle-supplied
// smb.conf, /etc/exports, the k3s config.yaml and k3s auto-apply
// manifests to disk verbatim as root: Samba command directives,
// world-writable exports of system directories, privileged/hostPath
// pods and kube-apiserver flags all convert straight into root code
// execution. The agent token (Tier 2) authenticates the channel; this
// layer bounds what an accepted bundle may contain, using the shapes
// the desired-state compiler in packages/axonwall_lib actually emits:
//
//   - Samba: shares live under /mnt (pools mount at /mnt/<pool>); the
//     compiler emits a fixed directive set. Command-execution and
//     include directives are rejected, share paths must stay under
//     /mnt, and `vfs objects` is limited to the modules the compiler
//     uses (an arbitrary VFS module is a shared library smbd loads).
//   - NFS exports: export paths must stay under /mnt; every option
//     must be on the allowlist the compiler draws from (no_root_squash
//     included -- it is a designed feature for /mnt exports when the
//     desired state maps the root user).
//   - K3s manifests: parsed as YAML; host namespaces, privileged
//     containers, hostPath volumes and cluster-admin bindings are
//     rejected anywhere in any document.
//   - K3s config.yaml: parsed as YAML; keys are limited to the set the
//     compiler emits plus basic node addressing. *-arg keys (the
//     kube-apiserver/kubelet flag injection vector) are not in it.

import (
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// --- Samba ---------------------------------------------------------------

var smbDeniedDirectives = map[string]bool{
	"rootpreexec": true, "rootpostexec": true, "rootexec": true,
	"preexec": true, "postexec": true, "preexecclose": true, "exec": true,
	"addsharecommand": true, "changesharecommand": true,
	"deletesharecommand": true,
	"addprintercommand": true, "deleteprintercommand": true,
	"printcommand": true, "lpqcommand": true, "lprmcommand": true,
	"lppausecommand": true, "lpresumecommand": true,
	"queuepausecommand": true, "queueresumecommand": true,
	"dfreecommand": true, "getquotacommand": true, "setquotacommand": true,
	"messagecommand": true, "panicaction": true,
	"include": true, "configfile": true, "copy": true,
	"smbpasswdfile": true, "passwdprogram": true, "passwdchat": true,
	"adduserscript": true, "deleteuserscript": true,
	"addgroupscript": true, "deletegroupscript": true,
	"addusertogroupscript": true, "setprimarygroupscript": true,
	"addmachinescript": true, "checkpasswordscript": true,
	"usernamemapscript": true,
	"shutdownscript": true, "abortshutdownscript": true,
	"logonscript": true, "magicscript": true,
}

func normalizeSmbKey(raw string) string {
	return strings.NewReplacer(" ", "", "\t", "", "_", "").Replace(strings.ToLower(strings.TrimSpace(raw)))
}

var smbAllowedVfsObjects = map[string]bool{
	"acl_xattr": true, "shadow_copy2": true, "catia": true,
	"fruit": true, "streams_xattr": true,
}

// underMnt reports whether a cleaned absolute path is /mnt or below it.
func underMnt(p string) bool {
	clean := filepath.Clean(p)
	return clean == "/mnt" || strings.HasPrefix(clean, "/mnt/")
}

func validateSmbConf(content string) error {
	for lineNo, raw := range strings.Split(content, "\n") {
		trimmedRight := strings.TrimRight(raw, " \t\r")
		if strings.HasSuffix(trimmedRight, "\\") {
			return fmt.Errorf("smb.conf line %d: backslash line continuations are not permitted in a bundle", lineNo+1)
		}
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			continue // section header
		}
		eq := strings.Index(line, "=")
		if eq < 0 {
			return fmt.Errorf("smb.conf line %d: not a key = value directive", lineNo+1)
		}
		key := strings.Join(strings.Fields(strings.ToLower(line[:eq])), " ")
		normKey := normalizeSmbKey(line[:eq])
		value := strings.TrimSpace(line[eq+1:])
		if smbDeniedDirectives[normKey] {
			return fmt.Errorf("smb.conf line %d: directive %q is not permitted in a bundle", lineNo+1, key)
		}
		switch normKey {
		case "path", "directory":
			if !underMnt(value) {
				return fmt.Errorf("smb.conf line %d: share path %q is outside /mnt", lineNo+1, value)
			}
		case "vfsobject", "vfsobjects":
			for _, mod := range strings.Fields(value) {
				if !smbAllowedVfsObjects[mod] {
					return fmt.Errorf("smb.conf line %d: vfs object %q is not permitted in a bundle", lineNo+1, mod)
				}
			}
		}
	}
	return nil
}

// --- NFS exports -----------------------------------------------------------

var nfsAllowedOptions = map[string]bool{
	"ro": true, "rw": true, "sync": true, "async": true,
	"root_squash": true, "no_root_squash": true, "all_squash": true,
	"subtree_check": true, "no_subtree_check": true,
	"secure": true, "insecure": true, "nohide": true, "crossmnt": true,
	"mp": true, "wdelay": true, "no_wdelay": true, "hide": true,
}

func validateNfsExports(content string) error {
	for lineNo, raw := range strings.Split(content, "\n") {
		trimmedRight := strings.TrimRight(raw, " \t\r")
		if strings.HasSuffix(trimmedRight, "\\") {
			return fmt.Errorf("exports line %d: backslash line continuations are not permitted in a bundle", lineNo+1)
		}
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return fmt.Errorf("exports line %d: expected a path and at least one client spec", lineNo+1)
		}
		if !underMnt(fields[0]) {
			return fmt.Errorf("exports line %d: export path %q is outside /mnt", lineNo+1, fields[0])
		}
		for _, spec := range fields[1:] {
			open := strings.Index(spec, "(")
			if open < 0 {
				continue // bare host with default options
			}
			if !strings.HasSuffix(spec, ")") {
				return fmt.Errorf("exports line %d: malformed client spec %q", lineNo+1, spec)
			}
			for _, opt := range strings.Split(spec[open+1:len(spec)-1], ",") {
				opt = strings.TrimSpace(opt)
				if opt == "" {
					continue
				}
				name := opt
				if eq := strings.Index(opt, "="); eq >= 0 {
					name = opt[:eq]
					// Only numeric id-mapping options may carry a value.
					if name != "fsid" && name != "anonuid" && name != "anongid" {
						return fmt.Errorf("exports line %d: option %q is not permitted in a bundle", lineNo+1, opt)
					}
					continue
				}
				if !nfsAllowedOptions[name] {
					return fmt.Errorf("exports line %d: option %q is not permitted in a bundle", lineNo+1, opt)
				}
			}
		}
	}
	return nil
}

// --- K3s -------------------------------------------------------------------

var k3sConfigAllowedKeys = map[string]bool{
	// Emitted by packages/axonwall_lib compile/k3s:
	"write-kubeconfig-mode": true, "cluster-cidr": true,
	"service-cidr": true, "flannel-backend": true, "flannel-iface": true,
	"server": true, "token": true, "token-file": true,
	"cluster-init": true, "disable": true, "tls-san": true,
	// Basic node addressing an operator may set through the same flow:
	"node-name": true, "node-ip": true, "advertise-address": true,
	"cluster-dns": true, "cluster-domain": true,
}

func validateK3sConfig(content string) error {
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(content), &doc); err != nil {
		return fmt.Errorf("k3s config.yaml does not parse: %w", err)
	}
	for key := range doc {
		if !k3sConfigAllowedKeys[key] {
			return fmt.Errorf("k3s config.yaml: key %q is not permitted in a bundle", key)
		}
	}
	return nil
}

func validateK3sManifest(content string) error {
	dec := yaml.NewDecoder(strings.NewReader(content))
	for {
		var doc any
		err := dec.Decode(&doc)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("k3s manifest does not parse: %w", err)
		}
		if doc == nil {
			continue
		}
		if err := walkManifest(doc); err != nil {
			return err
		}
	}
}

var k3sDeniedManifestKinds = map[string]bool{
	"helmchart":          true,
	"helmchartconfig":    true,
	"persistentvolume":   true,
	"clusterrole":        true,
	"clusterrolebinding": true,
	"role":               true,
	"rolebinding":        true,
}

// walkManifest rejects the primitives that turn a manifest into host
// control, anywhere in the document tree.
func walkManifest(node any) error {
	switch v := node.(type) {
	case map[string]any:
		for key, val := range v {
			switch key {
			case "kind":
				if kStr, ok := val.(string); ok {
					if k3sDeniedManifestKinds[strings.ToLower(strings.TrimSpace(kStr))] {
						return fmt.Errorf("k3s manifest: resource kind %q is not permitted in a bundle", kStr)
					}
				}
			case "hostPath":
				return fmt.Errorf("k3s manifest: hostPath volumes are not permitted in a bundle")
			case "hostPID", "hostNetwork", "hostIPC":
				if b, ok := val.(bool); ok && b {
					return fmt.Errorf("k3s manifest: %s is not permitted in a bundle", key)
				}
			case "privileged":
				if b, ok := val.(bool); ok && b {
					return fmt.Errorf("k3s manifest: privileged containers are not permitted in a bundle")
				}
			case "capabilities":
				if capMap, ok := val.(map[string]any); ok {
					if addVal, hasAdd := capMap["add"]; hasAdd && addVal != nil {
						if list, isSlice := addVal.([]any); !isSlice || len(list) > 0 {
							return fmt.Errorf("k3s manifest: capabilities.add is not permitted in a bundle")
						}
					}
				}
			case "roleRef":
				if ref, ok := val.(map[string]any); ok {
					if name, ok := ref["name"].(string); ok && name == "cluster-admin" {
						return fmt.Errorf("k3s manifest: binding to cluster-admin is not permitted in a bundle")
					}
				}
			}
			if err := walkManifest(val); err != nil {
				return err
			}
		}
	case []any:
		for _, item := range v {
			if err := walkManifest(item); err != nil {
				return err
			}
		}
	}
	return nil
}
