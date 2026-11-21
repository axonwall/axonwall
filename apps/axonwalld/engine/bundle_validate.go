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
	"regexp"
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
	"preloadmodules": true, "winshook": true,
	"renameuserscript": true, "deleteuserfromgroupscript": true,
	"logfile": true, "privatedir": true, "statedirectory": true,
	"cachedirectory": true, "lockdirectory": true, "piddirectory": true,
	"configbackend": true, "usernamemap": true,
}

func normalizeSmbKey(raw string) string {
	return strings.NewReplacer(" ", "", "\t", "", "_", "").Replace(strings.ToLower(strings.TrimSpace(raw)))
}

var smbAllowedVfsObjects = map[string]bool{
	"acl_xattr": true, "shadow_copy2": true, "catia": true,
	"fruit": true, "streams_xattr": true, "recycle": true, "full_audit": true,
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
					val := opt[eq+1:]
					if name == "sec" {
						for _, flavor := range strings.Split(val, ":") {
							if flavor != "sys" && flavor != "krb5" && flavor != "krb5i" && flavor != "krb5p" {
								return fmt.Errorf("exports line %d: sec flavor %q is not permitted in a bundle", lineNo+1, flavor)
							}
						}
						continue
					}
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
	"write-kubeconfig-mode": true, "write-kubeconfig-group": true, "cluster-cidr": true,
	"service-cidr": true, "flannel-backend": true, "flannel-iface": true,
	"server": true, "token": true, "token-file": true,
	"cluster-init": true, "disable": true, "tls-san": true,
	"disable-kube-proxy": true, "disable-network-policy": true,
	"datastore-endpoint": true,
	"etcd-snapshot-schedule-cron": true, "etcd-snapshot-retention": true,
	"etcd-snapshot-dir": true, "etcd-s3": true, "etcd-s3-endpoint": true,
	"etcd-s3-bucket": true, "etcd-s3-region": true,
	"kubelet-arg": true,
	// Basic node addressing an operator may set through the same flow:
	"node-name": true, "node-ip": true, "advertise-address": true,
	"cluster-dns": true, "cluster-domain": true,
}

var k3sAllowedExactKubeletArgs = map[string]bool{
	"feature-gates=UserNamespacesSupport=true": true,
}

var k3sAllowedKubeletArgPrefixes = []string{
	"eviction-hard=",
	"eviction-soft=",
	"eviction-soft-grace-period=",
	"system-reserved=",
	"kube-reserved=",
	"max-pods=",
	"image-gc-high-threshold=",
	"image-gc-low-threshold=",
}

func validateSingleKubeletArg(raw string) error {
	if raw == "" {
		return fmt.Errorf("k3s config.yaml: kubelet-arg entry cannot be empty")
	}
	if strings.ContainsAny(raw, "\n\r\x00;&|`$()\\\"'") {
		return fmt.Errorf("k3s config.yaml: kubelet-arg %q contains disallowed control or shell metacharacters", raw)
	}
	for _, r := range raw {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("k3s config.yaml: kubelet-arg %q contains disallowed control characters", raw)
		}
	}
	if strings.TrimSpace(raw) != raw {
		return fmt.Errorf("k3s config.yaml: kubelet-arg %q must not contain leading or trailing whitespace", raw)
	}
	if k3sAllowedExactKubeletArgs[raw] {
		return nil
	}
	for _, prefix := range k3sAllowedKubeletArgPrefixes {
		if strings.HasPrefix(raw, prefix) {
			val := raw[len(prefix):]
			if val == "" {
				return fmt.Errorf("k3s config.yaml: kubelet-arg %q requires a non-empty value", raw)
			}
			// Reject whitespace inside flag values so additional flags cannot be smuggled
			if strings.ContainsAny(val, " \t") {
				return fmt.Errorf("k3s config.yaml: kubelet-arg %q contains disallowed whitespace", raw)
			}
			return nil
		}
	}
	return fmt.Errorf("k3s config.yaml: kubelet-arg %q is not permitted in a bundle (only safe resource/eviction flags are allowed)", raw)
}

func validateK3sConfig(content string) error {
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(content), &doc); err != nil {
		return fmt.Errorf("k3s config.yaml does not parse: %w", err)
	}
	for key, rawVal := range doc {
		if !k3sConfigAllowedKeys[key] {
			return fmt.Errorf("k3s config.yaml: key %q is not permitted in a bundle", key)
		}
		if key == "kubelet-arg" {
			switch v := rawVal.(type) {
			case string:
				if err := validateSingleKubeletArg(v); err != nil {
					return err
				}
			case []any:
				if len(v) == 0 {
					return fmt.Errorf("k3s config.yaml: kubelet-arg must be a non-empty string or array of strings")
				}
				for _, item := range v {
					s, isStr := item.(string)
					if !isStr {
						return fmt.Errorf("k3s config.yaml: kubelet-arg entry %v must be a string", item)
					}
					if err := validateSingleKubeletArg(s); err != nil {
						return err
					}
				}
			default:
				return fmt.Errorf("k3s config.yaml: kubelet-arg must be a string or array of strings")
			}
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

var bpffsTokenHostPathRe = regexp.MustCompile(`^/run/axonwall/bpffs-tokens/[a-z0-9][a-z0-9._-]{1,62}$`)

type manifestWalkCtx struct {
	inHelmValues     bool
	isolatedUserNs   bool
}

func isIsolatedUserNsPodSpec(spec map[string]any) bool {
	if spec == nil {
		return false
	}
	hostUsers, ok := spec["hostUsers"].(bool)
	if !ok || hostUsers {
		return false
	}
	for _, hostFlag := range []string{"hostPID", "hostNetwork", "hostIPC"} {
		if b, ok := spec[hostFlag].(bool); ok && b {
			return false
		}
	}
	for _, listKey := range []string{"containers", "initContainers", "ephemeralContainers"} {
		rawList, ok := spec[listKey].([]any)
		if !ok {
			continue
		}
		for _, item := range rawList {
			cMap, ok := item.(map[string]any)
			if !ok {
				continue
			}
			if sc, ok := cMap["securityContext"].(map[string]any); ok {
				if priv, ok := sc["privileged"].(bool); ok && priv {
					return false
				}
			}
		}
	}
	return true
}

func isAllowedUserNsBpffsHostPath(val any) bool {
	hpMap, ok := val.(map[string]any)
	if !ok {
		return false
	}
	rawPath, ok := hpMap["path"].(string)
	if !ok {
		return false
	}
	return bpffsTokenHostPathRe.MatchString(strings.TrimSpace(rawPath))
}

func isAllowedUserNsCapabilities(capMap map[string]any) bool {
	addVal, hasAdd := capMap["add"]
	if !hasAdd || addVal == nil {
		return true
	}
	addList, isSlice := addVal.([]any)
	if !isSlice {
		return false
	}
	if len(addList) == 0 {
		return true
	}
	hasDropAll := false
	if dropList, ok := capMap["drop"].([]any); ok {
		for _, d := range dropList {
			if ds, ok := d.(string); ok && strings.EqualFold(strings.TrimSpace(ds), "ALL") {
				hasDropAll = true
				break
			}
		}
	}
	if !hasDropAll {
		return false
	}
	for _, item := range addList {
		cStr, ok := item.(string)
		if !ok {
			return false
		}
		upper := strings.ToUpper(strings.TrimSpace(cStr))
		if upper != "BPF" && upper != "NET_ADMIN" {
			return false
		}
	}
	return true
}

// walkManifest rejects the primitives that turn a manifest into host
// control, anywhere in the document tree.
func walkManifest(node any) error {
	return walkManifestWithCtx(node, manifestWalkCtx{})
}

func walkManifestWithCtx(node any, ctx manifestWalkCtx) error {
	switch v := node.(type) {
	case map[string]any:
		nextBaseCtx := ctx
		// Detect isolated UserNS PodSpecs (`hostUsers: false`, no host namespaces, no privileged containers)
		if isIsolatedUserNsPodSpec(v) {
			nextBaseCtx.isolatedUserNs = true
		} else if _, hasContainers := v["containers"]; hasContainers {
			// Entering another PodSpec resets UserNS inheritance unless itself sets hostUsers: false
			nextBaseCtx.isolatedUserNs = false
		}

		for key, val := range v {
			childCtx := nextBaseCtx
			switch key {
			case "valuesObject":
				childCtx.inHelmValues = true
			case "values":
				// Flux HelmRelease spec.values or HelmChart spec.values
				childCtx.inHelmValues = true
			case "kind":
				if !ctx.inHelmValues {
					if kStr, ok := val.(string); ok {
						kLower := strings.ToLower(strings.TrimSpace(kStr))
						if kLower == "helmchart" {
							// Permit ONLY Axonwall-compiled HelmCharts:
							// 1. Cilium eBPF CNI HelmChart from https://helm.cilium.io/
							// 2. In-house Vigilante modular SOC HelmCharts from https://charts.vigilante.local
							specMap, _ := v["spec"].(map[string]any)
							if err := validateAllowedHelmChartSpec(specMap); err != nil {
								return err
							}
						} else if k3sDeniedManifestKinds[kLower] {
							return fmt.Errorf("k3s manifest: resource kind %q is not permitted in a bundle", kStr)
						}
					}
				}
			case "hostPath":
				if !(nextBaseCtx.isolatedUserNs && isAllowedUserNsBpffsHostPath(val)) {
					return fmt.Errorf("k3s manifest: hostPath volumes are not permitted in a bundle")
				}
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
						if nextBaseCtx.isolatedUserNs && isAllowedUserNsCapabilities(capMap) {
							// Permitted strictly under hostUsers: false with drop: ["ALL"] and BPF/NET_ADMIN only
						} else if list, isSlice := addVal.([]any); !isSlice || len(list) > 0 {
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
			if err := walkManifestWithCtx(val, childCtx); err != nil {
				return err
			}
		}
	case []any:
		for _, item := range v {
			if err := walkManifestWithCtx(item, ctx); err != nil {
				return err
			}
		}
	}
	return nil
}

var helmChartAllowedSpecKeys = map[string]bool{
	"chart":           true,
	"repo":            true,
	"version":         true,
	"targetNamespace": true,
	"createNamespace": true,
	"set":             true,
	"valuesContent":   true,
	"values":          true,
	"repoCA":          true,
	"helmVersion":     true,
	"timeout":         true,
	"failurePolicy":   true,
	"backOffLimit":    true,
}

func validateAllowedHelmChartSpec(specMap map[string]any) error {
	if specMap == nil {
		return fmt.Errorf("k3s manifest: HelmChart missing spec")
	}
	for k := range specMap {
		if !helmChartAllowedSpecKeys[k] {
			return fmt.Errorf("k3s manifest: HelmChart spec.%s is not permitted in a bundle", k)
		}
	}
	repo, _ := specMap["repo"].(string)
	chart, _ := specMap["chart"].(string)
	repo = strings.TrimSpace(repo)
	chart = strings.TrimSpace(chart)

	isCilium := repo == "https://helm.cilium.io/" && chart == "cilium"
	isVigilante := repo == "https://charts.vigilante.local" && chart != ""
	if !isCilium && !isVigilante {
		return fmt.Errorf("k3s manifest: untrusted HelmChart (%s / %s) is not permitted in a bundle", repo, chart)
	}
	if vcRaw, ok := specMap["valuesContent"]; ok && vcRaw != nil {
		vcStr, ok := vcRaw.(string)
		if !ok {
			return fmt.Errorf("k3s manifest: HelmChart spec.valuesContent must be a string")
		}
		dec := yaml.NewDecoder(strings.NewReader(vcStr))
		for {
			var doc any
			err := dec.Decode(&doc)
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				return fmt.Errorf("k3s manifest: HelmChart spec.valuesContent does not parse: %w", err)
			}
			if doc != nil {
				if err := walkManifestWithCtx(doc, manifestWalkCtx{inHelmValues: true}); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
