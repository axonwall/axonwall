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
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// --- Samba ---------------------------------------------------------------

var smbAllowedDirectives = map[string]bool{
	// [global] directives emitted by packages/axonwall_lib/src/compile/nas:
	"workgroup":                 true,
	"serverstring":              true,
	"security":                  true,
	"maptoguest":                true,
	"serverminprotocol":         true,
	"servermultichannelsupport": true,
	"easupport":                 true,
	"vfsobjects":                true,
	"mapaclinherit":             true,
	"storedosattributes":        true,
	"loadprinters":              true,
	"printing":                  true,
	"printcapname":              true,
	"disablespoolss":            true,
	// Share directives emitted by packages/axonwall_lib/src/compile/nas:
	"path":               true,
	"comment":            true,
	"browseable":         true,
	"readonly":           true,
	"guestok":            true,
	"shadow:snapdir":     true,
	"shadow:sort":        true,
	"shadow:format":      true,
	"shadow:localtime":   true,
	"fruit:aapl":         true,
	"fruit:timemachine":  true,
	"recycle:repository": true,
	"recycle:keeptree":   true,
	"recycle:versions":   true,
	"recycle:touch":      true,
	"fullaudit:prefix":   true,
	"fullaudit:success":  true,
	"fullaudit:failure":  true,
	"validusers":         true,
	"hostsallow":         true,
}

var smbReservedSections = map[string]bool{
	"homes":    true,
	"printers": true,
	"ipc$":     true,
}

func isDeniedSmbDirective(normKey string) bool {
	if normKey == "widelinks" || normKey == "allowinsecurewidelinks" {
		return true
	}
	if strings.HasPrefix(normKey, "usershare") {
		return true
	}
	if strings.HasSuffix(normKey, "command") ||
		strings.HasSuffix(normKey, "script") ||
		strings.HasSuffix(normKey, "module") ||
		strings.HasSuffix(normKey, "modules") {
		return true
	}
	return false
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
	if strings.ContainsRune(content, '\x00') {
		return fmt.Errorf("smb.conf contains NUL byte")
	}
	for lineNo, raw := range strings.Split(content, "\n") {
		trimmedRight := strings.TrimRight(raw, " \t\r")
		if strings.HasSuffix(trimmedRight, "\\") {
			return fmt.Errorf("smb.conf line %d: backslash line continuations are not permitted in a bundle", lineNo+1)
		}
		if strings.ContainsRune(trimmedRight, '\r') {
			return fmt.Errorf("smb.conf line %d: carriage return is not permitted", lineNo+1)
		}
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			if !strings.HasSuffix(line, "]") {
				return fmt.Errorf("smb.conf line %d: malformed section header", lineNo+1)
			}
			secName := strings.TrimSpace(line[1 : len(line)-1])
			if secName == "" || strings.ContainsAny(secName, "[]#\r\n") {
				return fmt.Errorf("smb.conf line %d: invalid section header %q", lineNo+1, line)
			}
			if smbReservedSections[strings.ToLower(secName)] {
				return fmt.Errorf("smb.conf line %d: reserved section %q is not permitted in a bundle", lineNo+1, secName)
			}
			continue
		}
		eq := strings.Index(line, "=")
		if eq < 0 {
			return fmt.Errorf("smb.conf line %d: not a key = value directive", lineNo+1)
		}
		key := strings.Join(strings.Fields(strings.ToLower(line[:eq])), " ")
		normKey := normalizeSmbKey(line[:eq])
		value := strings.TrimSpace(line[eq+1:])
		if isDeniedSmbDirective(normKey) || !smbAllowedDirectives[normKey] {
			return fmt.Errorf("smb.conf line %d: directive %q is not permitted in a bundle", lineNo+1, key)
		}
		switch normKey {
		case "path":
			if strings.Contains(value, "..") || !underMnt(value) {
				return fmt.Errorf("smb.conf line %d: share path %q is outside /mnt", lineNo+1, value)
			}
		case "vfsobjects":
			for _, mod := range strings.Fields(value) {
				if !smbAllowedVfsObjects[mod] {
					return fmt.Errorf("smb.conf line %d: vfs object %q is not permitted in a bundle", lineNo+1, mod)
				}
			}
		case "printcapname":
			if value != "/dev/null" {
				return fmt.Errorf("smb.conf line %d: printcap name must be /dev/null", lineNo+1)
			}
		case "recycle:repository", "shadow:snapdir":
			if strings.HasPrefix(value, "/") || strings.Contains(value, "..") {
				return fmt.Errorf("smb.conf line %d: %s path %q must be relative without '..'", lineNo+1, key, value)
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
	"datastore-endpoint":          true,
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

const (
	maxYAMLNestingDepth = 64
	maxYAMLDocs         = 1024
)

func hasControlChars(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

func yamlNodeToStrictValue(n *yaml.Node, depth int) (any, error) {
	if n == nil {
		return nil, fmt.Errorf("unexpected nil YAML node")
	}
	if depth > maxYAMLNestingDepth {
		return nil, fmt.Errorf("YAML nesting exceeds maximum depth (%d)", maxYAMLNestingDepth)
	}
	if n.Anchor != "" {
		return nil, fmt.Errorf("YAML anchors (&%s) are not permitted", n.Anchor)
	}
	switch n.Kind {
	case yaml.AliasNode:
		return nil, fmt.Errorf("YAML aliases (*) are not permitted")
	case yaml.MappingNode:
		if n.Tag != "" && n.Tag != "!!map" {
			return nil, fmt.Errorf("unsupported YAML mapping tag %q is not permitted", n.Tag)
		}
		if len(n.Content)%2 != 0 {
			return nil, fmt.Errorf("malformed YAML mapping node")
		}
		m := make(map[string]any, len(n.Content)/2)
		seen := make(map[string]bool, len(n.Content)/2)
		for i := 0; i < len(n.Content); i += 2 {
			kNode, vNode := n.Content[i], n.Content[i+1]
			if kNode.Anchor != "" {
				return nil, fmt.Errorf("YAML anchors (&%s) on mapping keys are not permitted", kNode.Anchor)
			}
			if kNode.Kind != yaml.ScalarNode {
				return nil, fmt.Errorf("non-scalar YAML mapping key is not permitted")
			}
			if kNode.Tag == "!!merge" || kNode.Value == "<<" {
				return nil, fmt.Errorf("YAML merge keys (<<) are not permitted")
			}
			if kNode.Tag != "!!str" {
				return nil, fmt.Errorf("non-string YAML mapping key %q (tag %s) is not permitted", kNode.Value, kNode.Tag)
			}
			if strings.ContainsRune(kNode.Value, '\x00') {
				return nil, fmt.Errorf("YAML mapping key contains NUL byte")
			}
			if seen[kNode.Value] {
				return nil, fmt.Errorf("duplicate YAML mapping key %q is not permitted", kNode.Value)
			}
			seen[kNode.Value] = true
			val, err := yamlNodeToStrictValue(vNode, depth+1)
			if err != nil {
				return nil, err
			}
			m[kNode.Value] = val
		}
		return m, nil
	case yaml.SequenceNode:
		if n.Tag != "" && n.Tag != "!!seq" {
			return nil, fmt.Errorf("unsupported YAML sequence tag %q is not permitted", n.Tag)
		}
		s := make([]any, 0, len(n.Content))
		for _, item := range n.Content {
			val, err := yamlNodeToStrictValue(item, depth+1)
			if err != nil {
				return nil, err
			}
			s = append(s, val)
		}
		return s, nil
	case yaml.ScalarNode:
		switch n.Tag {
		case "!!str":
			if strings.ContainsRune(n.Value, '\x00') {
				return nil, fmt.Errorf("YAML string contains NUL byte")
			}
			return n.Value, nil
		case "!!null":
			return nil, nil
		case "!!bool":
			var b bool
			if err := n.Decode(&b); err != nil {
				return nil, fmt.Errorf("invalid YAML bool %q: %w", n.Value, err)
			}
			return b, nil
		case "!!int":
			var iv int64
			if err := n.Decode(&iv); err == nil {
				return iv, nil
			}
			var uv uint64
			if err := n.Decode(&uv); err == nil {
				return uv, nil
			}
			var fv float64
			if err := n.Decode(&fv); err == nil {
				return fv, nil
			}
			return nil, fmt.Errorf("invalid YAML integer %q", n.Value)
		case "!!float":
			var fv float64
			if err := n.Decode(&fv); err != nil {
				return nil, fmt.Errorf("invalid YAML float %q: %w", n.Value, err)
			}
			return fv, nil
		default:
			return nil, fmt.Errorf("unsupported YAML scalar tag %q is not permitted", n.Tag)
		}
	default:
		return nil, fmt.Errorf("unsupported YAML node kind %d is not permitted", n.Kind)
	}
}

func parseStrictYAMLDocuments(content string, maxDocs int, label string) ([]map[string]any, error) {
	if strings.ContainsRune(content, '\x00') {
		return nil, fmt.Errorf("%s contains NUL byte", label)
	}
	dec := yaml.NewDecoder(strings.NewReader(content))
	var docs []map[string]any
	for {
		var docNode yaml.Node
		err := dec.Decode(&docNode)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("%s does not parse: %w", label, err)
		}
		if docNode.Anchor != "" {
			return nil, fmt.Errorf("%s: YAML anchors are not permitted", label)
		}
		if docNode.Kind != yaml.DocumentNode {
			return nil, fmt.Errorf("%s: unexpected YAML document node kind %d", label, docNode.Kind)
		}
		if len(docNode.Content) == 0 {
			continue
		}
		if len(docNode.Content) > 1 {
			return nil, fmt.Errorf("%s: unexpected multiple root nodes in YAML document", label)
		}
		root := docNode.Content[0]
		if root.Anchor != "" {
			return nil, fmt.Errorf("%s: YAML anchors are not permitted", label)
		}
		if root.Kind == yaml.ScalarNode && root.Tag == "!!null" {
			continue
		}
		if root.Kind != yaml.MappingNode {
			return nil, fmt.Errorf("%s: YAML document root must be a mapping", label)
		}
		val, err := yamlNodeToStrictValue(root, 0)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", label, err)
		}
		m, ok := val.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("%s: YAML document root must be a string-keyed mapping", label)
		}
		docs = append(docs, m)
		if len(docs) > maxYAMLDocs {
			return nil, fmt.Errorf("%s: exceeds maximum document count (%d)", label, maxYAMLDocs)
		}
		if maxDocs > 0 && len(docs) > maxDocs {
			return nil, fmt.Errorf("%s: expected at most %d YAML document(s)", label, maxDocs)
		}
	}
	return docs, nil
}

func validateSingleKubeletArg(raw string) error {
	if raw == "" {
		return fmt.Errorf("k3s config.yaml: kubelet-arg entry cannot be empty")
	}
	if strings.ContainsAny(raw, "\n\r\x00;&|`$()\\\"'") {
		return fmt.Errorf("k3s config.yaml: kubelet-arg %q contains disallowed control or shell metacharacters", raw)
	}
	if hasControlChars(raw) {
		return fmt.Errorf("k3s config.yaml: kubelet-arg %q contains disallowed control characters", raw)
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

const k3sPinnedJoinTokenFile = "/var/lib/axonwall/k3s-join.token"
const k3sDefaultEtcdSnapshotDir = "/var/lib/rancher/k3s/server/db/snapshots"

var k3sConfigGroupRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$`)
var k3sHostnameRe = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?$`)

func validateHostAndPort(host, portStr, field, raw string) error {
	if host == "" {
		return fmt.Errorf("k3s config.yaml: %s %q missing host", field, raw)
	}
	if net.ParseIP(host) == nil && (!k3sHostnameRe.MatchString(host) || strings.Contains(host, "..")) {
		return fmt.Errorf("k3s config.yaml: %s %q has invalid host %q", field, raw, host)
	}
	if portStr != "" {
		p, pErr := strconv.Atoi(portStr)
		if pErr != nil || p < 1 || p > 65535 || strconv.Itoa(p) != portStr {
			return fmt.Errorf("k3s config.yaml: %s %q has invalid port %q", field, raw, portStr)
		}
	}
	return nil
}

func validateStrictHTTPSServerURL(raw string) error {
	if raw == "" || strings.TrimSpace(raw) != raw || strings.ContainsAny(raw, " \t\r\n\x00\\?#@;&|$`'\"()") || hasControlChars(raw) {
		return fmt.Errorf("k3s config.yaml: server %q must be a strict https URL without whitespace or control characters", raw)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("k3s config.yaml: server URL %q is invalid: %w", raw, err)
	}
	if u.Scheme != "https" || u.User != nil || u.Host == "" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("k3s config.yaml: server %q must be a strict https://host[:port] URL", raw)
	}
	return validateHostAndPort(u.Hostname(), u.Port(), "server", raw)
}

func validateSingleDatastoreHTTPURI(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("k3s config.yaml: datastore-endpoint %q is invalid: %w", raw, err)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return fmt.Errorf("k3s config.yaml: datastore-endpoint scheme %q is not permitted", u.Scheme)
	}
	return validateHostAndPort(u.Hostname(), u.Port(), "datastore-endpoint", raw)
}

func validateMysqlDatastoreURI(raw string) error {
	rest := strings.TrimPrefix(raw, "mysql://")
	slash := strings.IndexByte(rest, '/')
	auth := rest
	suffix := ""
	if slash >= 0 {
		auth = rest[:slash]
		suffix = rest[slash:]
	}
	userPrefix := ""
	hostPart := auth
	if at := strings.LastIndexByte(auth, '@'); at >= 0 {
		userPrefix = auth[:at+1]
		hostPart = auth[at+1:]
	}
	if strings.HasPrefix(hostPart, "tcp(") && strings.HasSuffix(hostPart, ")") {
		inner := hostPart[len("tcp(") : len(hostPart)-1]
		if strings.ContainsAny(inner, "()") || strings.ContainsAny(userPrefix+suffix, "()") {
			return fmt.Errorf("k3s config.yaml: datastore-endpoint %q has malformed tcp() syntax", raw)
		}
		h, pStr, splitErr := net.SplitHostPort(inner)
		if splitErr != nil || pStr == "" {
			return fmt.Errorf("k3s config.yaml: datastore-endpoint %q has invalid tcp(host:port)", raw)
		}
		if err := validateHostAndPort(h, pStr, "datastore-endpoint", raw); err != nil {
			return err
		}
		if _, err := url.Parse("mysql://" + userPrefix + inner + suffix); err != nil {
			return fmt.Errorf("k3s config.yaml: datastore-endpoint %q is invalid: %w", raw, err)
		}
		return nil
	}
	if strings.ContainsAny(raw, "()") {
		return fmt.Errorf("k3s config.yaml: datastore-endpoint %q contains disallowed parentheses", raw)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("k3s config.yaml: datastore-endpoint %q is invalid: %w", raw, err)
	}
	return validateHostAndPort(u.Hostname(), u.Port(), "datastore-endpoint", raw)
}

func validateK3sDatastoreEndpoint(raw string) error {
	if raw == "" || strings.TrimSpace(raw) != raw || strings.ContainsAny(raw, " \t\r\n\x00;&|`$\\'\"") || hasControlChars(raw) || strings.Contains(raw, "..") {
		return fmt.Errorf("k3s config.yaml: datastore-endpoint %q contains disallowed whitespace, control, or shell characters", raw)
	}
	if strings.Contains(raw, ",") {
		for _, part := range strings.Split(raw, ",") {
			if part == "" {
				return fmt.Errorf("k3s config.yaml: datastore-endpoint %q contains empty endpoint", raw)
			}
			if strings.ContainsAny(part, "()") {
				return fmt.Errorf("k3s config.yaml: datastore-endpoint %q contains disallowed parentheses", raw)
			}
			if err := validateSingleDatastoreHTTPURI(part); err != nil {
				return err
			}
		}
		return nil
	}
	if strings.HasPrefix(raw, "mysql://") {
		return validateMysqlDatastoreURI(raw)
	}
	if strings.ContainsAny(raw, "()") {
		return fmt.Errorf("k3s config.yaml: datastore-endpoint %q contains disallowed parentheses", raw)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("k3s config.yaml: datastore-endpoint %q is invalid: %w", raw, err)
	}
	switch u.Scheme {
	case "https", "http":
		return validateSingleDatastoreHTTPURI(raw)
	case "postgres", "postgresql":
		return validateHostAndPort(u.Hostname(), u.Port(), "datastore-endpoint", raw)
	default:
		return fmt.Errorf("k3s config.yaml: datastore-endpoint scheme %q is not permitted (allowed: postgres, postgresql, mysql, https, http)", u.Scheme)
	}
}

func checkExistingAncestorsNoSymlink(absPath string) error {
	cur := filepath.Clean(absPath)
	for cur != "/" && cur != "." {
		info, err := os.Lstat(cur)
		if err == nil {
			if info.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("path component %q is a symlink", cur)
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("cannot inspect path component %q: %w", cur, err)
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			break
		}
		cur = parent
	}
	return nil
}

func validateK3sEtcdSnapshotDir(raw string) error {
	if raw == "" || strings.TrimSpace(raw) != raw || strings.ContainsAny(raw, " \t\r\n\x00") || hasControlChars(raw) {
		return fmt.Errorf("k3s config.yaml: etcd-snapshot-dir %q contains disallowed whitespace or control characters", raw)
	}
	if !strings.HasPrefix(raw, "/") || strings.Contains(raw, "..") {
		return fmt.Errorf("k3s config.yaml: etcd-snapshot-dir %q must be an absolute path without '..'", raw)
	}
	clean := filepath.Clean(raw)
	allowed := clean == k3sDefaultEtcdSnapshotDir ||
		(strings.HasPrefix(clean, "/var/lib/axonwall/backups/") && len(clean) > len("/var/lib/axonwall/backups/")) ||
		(strings.HasPrefix(clean, "/mnt/") && len(clean) > len("/mnt/"))
	if !allowed {
		return fmt.Errorf("k3s config.yaml: etcd-snapshot-dir %q must be under /var/lib/axonwall/backups/, /mnt/, or %s", raw, k3sDefaultEtcdSnapshotDir)
	}
	if err := checkExistingAncestorsNoSymlink(clean); err != nil {
		return fmt.Errorf("k3s config.yaml: etcd-snapshot-dir %q rejected: %w", raw, err)
	}
	return nil
}

func validateK3sConfig(content string) error {
	docs, err := parseStrictYAMLDocuments(content, 1, "k3s config.yaml")
	if err != nil {
		return err
	}
	if len(docs) == 0 {
		return nil
	}
	doc := docs[0]
	for key, rawVal := range doc {
		if !k3sConfigAllowedKeys[key] {
			return fmt.Errorf("k3s config.yaml: key %q is not permitted in a bundle", key)
		}
		if rawVal == nil {
			return fmt.Errorf("k3s config.yaml: key %q cannot be null", key)
		}
		switch key {
		case "write-kubeconfig-mode":
			s, ok := rawVal.(string)
			if !ok || (s != "0600" && s != "0640") {
				return fmt.Errorf("k3s config.yaml: write-kubeconfig-mode must be strictly \"0600\" or \"0640\"")
			}
		case "write-kubeconfig-group":
			s, ok := rawVal.(string)
			if !ok || !k3sConfigGroupRe.MatchString(s) {
				return fmt.Errorf("k3s config.yaml: write-kubeconfig-group %v is invalid", rawVal)
			}
		case "server":
			s, ok := rawVal.(string)
			if !ok {
				return fmt.Errorf("k3s config.yaml: server must be a string")
			}
			if err := validateStrictHTTPSServerURL(s); err != nil {
				return err
			}
		case "token-file":
			s, ok := rawVal.(string)
			if !ok || s != k3sPinnedJoinTokenFile {
				return fmt.Errorf("k3s config.yaml: token-file must be strictly %q", k3sPinnedJoinTokenFile)
			}
		case "datastore-endpoint":
			s, ok := rawVal.(string)
			if !ok {
				return fmt.Errorf("k3s config.yaml: datastore-endpoint must be a string")
			}
			if err := validateK3sDatastoreEndpoint(s); err != nil {
				return err
			}
		case "etcd-snapshot-dir":
			s, ok := rawVal.(string)
			if !ok {
				return fmt.Errorf("k3s config.yaml: etcd-snapshot-dir must be a string")
			}
			if err := validateK3sEtcdSnapshotDir(s); err != nil {
				return err
			}
		case "kubelet-arg":
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
		case "cluster-init", "disable-kube-proxy", "disable-network-policy", "etcd-s3":
			if _, ok := rawVal.(bool); !ok {
				return fmt.Errorf("k3s config.yaml: %s must be a boolean", key)
			}
		case "etcd-snapshot-retention":
			switch n := rawVal.(type) {
			case int64:
				if n <= 0 {
					return fmt.Errorf("k3s config.yaml: etcd-snapshot-retention must be positive")
				}
			case uint64:
				if n == 0 {
					return fmt.Errorf("k3s config.yaml: etcd-snapshot-retention must be positive")
				}
			default:
				return fmt.Errorf("k3s config.yaml: etcd-snapshot-retention must be an integer")
			}
		case "disable", "tls-san":
			list, ok := rawVal.([]any)
			if !ok {
				return fmt.Errorf("k3s config.yaml: %s must be an array of strings", key)
			}
			for _, item := range list {
				s, isStr := item.(string)
				if !isStr || s == "" || strings.ContainsAny(s, " \t\r\n\x00") || hasControlChars(s) {
					return fmt.Errorf("k3s config.yaml: %s entry %v is invalid", key, item)
				}
			}
		default:
			s, ok := rawVal.(string)
			if !ok || s == "" || hasControlChars(s) {
				return fmt.Errorf("k3s config.yaml: %s must be a non-empty string without control characters", key)
			}
		}
	}
	return nil
}

func validateK3sManifest(content string) error {
	docs, err := parseStrictYAMLDocuments(content, 0, "k3s manifest")
	if err != nil {
		return err
	}
	for _, doc := range docs {
		if err := walkManifest(doc); err != nil {
			return err
		}
	}
	return nil
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

var k3sSystemNamespaces = map[string]bool{
	"kube-system":     true,
	"kube-public":     true,
	"kube-node-lease": true,
}

func isSystemK8sNamespace(ns string) bool {
	return k3sSystemNamespaces[strings.ToLower(strings.TrimSpace(ns))]
}

var validK8sNameRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$`)
var validK8sNamespaceRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

var privilegedSystemSANames = map[string]bool{
	"helm-controller":                        true,
	"openebs-zfs-controller-sa":              true,
	"openebs-zfs-node-sa":                    true,
	"openebs-zfs-csi-controller":             true,
	"openebs-zfs-csi-node":                   true,
	"openebs-mayastor-sa":                    true,
	"local-path-provisioner-service-account": true,
	"coredns":                                true,
	"traefik":                                true,
	"metrics-server":                         true,
	"cilium":                                 true,
	"cilium-operator":                        true,
	"cilium-envoy":                           true,
	"hubble-relay":                           true,
	"hubble-ui":                              true,
	"cluster-admin":                          true,
	"tiller":                                 true,
	"service-lb":                             true,
}

var privilegedSystemSAPrefixes = []string{
	"system:",
	"kube-",
	"helm-",
	"openebs-",
	"cilium-",
	"klipper-",
	"svclb-",
	"rancher-",
	"cattle-",
	"k3s-",
	"local-path-provisioner",
	"traefik-",
	"argocd-",
	"flux-",
	"cert-manager",
}

func isPrivilegedSystemServiceAccount(raw string) bool {
	sa := strings.ToLower(strings.TrimSpace(raw))
	if privilegedSystemSANames[sa] {
		return true
	}
	for _, pfx := range privilegedSystemSAPrefixes {
		if strings.HasPrefix(sa, pfx) {
			return true
		}
	}
	return false
}

func validateManifestServiceAccountName(raw string) (string, error) {
	sa := strings.TrimSpace(raw)
	if sa == "" || sa != raw || hasControlChars(sa) {
		return "", fmt.Errorf("k3s manifest: invalid serviceAccountName %q", raw)
	}
	if isPrivilegedSystemServiceAccount(sa) {
		return "", fmt.Errorf("k3s manifest: privileged/system serviceAccountName %q is not permitted in a bundle", sa)
	}
	if !validK8sNameRe.MatchString(sa) {
		return "", fmt.Errorf("k3s manifest: invalid serviceAccountName %q", sa)
	}
	return sa, nil
}

var bpffsTokenHostPathRe = regexp.MustCompile(`^/run/axonwall/bpffs-tokens/[a-z0-9][a-z0-9._-]{1,62}$`)

type manifestWalkCtx struct {
	inHelmValues           bool
	inAllowedHelmChartSpec bool
	isolatedUserNs         bool
}

func isIsolatedUserNsPodSpec(spec map[string]any) bool {
	if spec == nil {
		return false
	}
	hostUsers, ok := spec["hostUsers"].(bool)
	if !ok || hostUsers {
		return false
	}
	containers, hasContainers := spec["containers"].([]any)
	if !hasContainers || len(containers) == 0 {
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
	if !ok || strings.Contains(rawPath, "..") {
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

func mapGetCI(m map[string]any, targetLower string) (any, bool) {
	if val, ok := m[targetLower]; ok {
		return val, true
	}
	for k, v := range m {
		if strings.ToLower(k) == targetLower {
			return v, true
		}
	}
	return nil, false
}

func walkManifestWithCtx(node any, ctx manifestWalkCtx) error {
	switch v := node.(type) {
	case map[string]any:
		nextBaseCtx := ctx
		// Detect isolated UserNS PodSpecs (`hostUsers: false`, no host namespaces, no privileged containers)
		if isIsolatedUserNsPodSpec(v) {
			nextBaseCtx.isolatedUserNs = true
		} else if _, hasContainers := mapGetCI(v, "containers"); hasContainers {
			// Entering another PodSpec resets UserNS inheritance unless itself sets hostUsers: false
			nextBaseCtx.isolatedUserNs = false
		} else if _, hasKind := mapGetCI(v, "kind"); hasKind {
			nextBaseCtx.isolatedUserNs = false
		}

		var kindLower string
		if !ctx.inHelmValues {
			if rawKind, hasKind := mapGetCI(v, "kind"); hasKind {
				kStr, ok := rawKind.(string)
				if !ok || strings.TrimSpace(kStr) == "" {
					return fmt.Errorf("k3s manifest: resource kind must be a non-empty string")
				}
				kindLower = strings.ToLower(strings.TrimSpace(kStr))
			}

			// Enforce namespace & ServiceAccount rules on non-HelmValues maps.
			if metaRaw, hasMeta := mapGetCI(v, "metadata"); hasMeta && metaRaw != nil {
				metaMap, ok := metaRaw.(map[string]any)
				if !ok {
					return fmt.Errorf("k3s manifest: metadata must be a mapping")
				}
				if nsRaw, hasNs := mapGetCI(metaMap, "namespace"); hasNs && nsRaw != nil {
					nsStr, ok := nsRaw.(string)
					if !ok || strings.TrimSpace(nsStr) == "" || hasControlChars(nsStr) {
						return fmt.Errorf("k3s manifest: metadata.namespace must be a valid string")
					}
					nsLower := strings.ToLower(strings.TrimSpace(nsStr))
					if isSystemK8sNamespace(nsLower) {
						if !(kindLower == "helmchart" && nsLower == "kube-system") {
							return fmt.Errorf("k3s manifest: metadata.namespace %q is not permitted in a bundle", nsStr)
						}
					}
				}
				if kindLower == "namespace" {
					if nameRaw, hasName := mapGetCI(metaMap, "name"); hasName {
						if nameStr, ok := nameRaw.(string); ok && isSystemK8sNamespace(nameStr) {
							return fmt.Errorf("k3s manifest: system Namespace %q is not permitted in a bundle", nameStr)
						}
					}
				}
				if kindLower == "serviceaccount" {
					if nameRaw, hasName := mapGetCI(metaMap, "name"); hasName {
						if nameStr, ok := nameRaw.(string); ok && isPrivilegedSystemServiceAccount(nameStr) {
							return fmt.Errorf("k3s manifest: privileged/system ServiceAccount %q is not permitted in a bundle", nameStr)
						}
					}
				}
			}

			// Enforce ServiceAccount & automountServiceAccountToken rules on PodSpecs / objects.
			var explicitSA string
			for _, saKey := range []string{"serviceaccountname", "serviceaccount"} {
				if saRaw, hasSA := mapGetCI(v, saKey); hasSA && saRaw != nil {
					saStr, ok := saRaw.(string)
					if !ok {
						return fmt.Errorf("k3s manifest: %s must be a string", saKey)
					}
					cleanSA, err := validateManifestServiceAccountName(saStr)
					if err != nil {
						return err
					}
					explicitSA = cleanSA
				}
			}
			if amRaw, hasAM := mapGetCI(v, "automountserviceaccounttoken"); hasAM && amRaw != nil {
				amBool, ok := amRaw.(bool)
				if !ok {
					return fmt.Errorf("k3s manifest: automountServiceAccountToken must be a boolean")
				}
				if amBool && (explicitSA == "" || explicitSA == "default") {
					return fmt.Errorf("k3s manifest: automountServiceAccountToken: true requires a safe non-system serviceAccountName")
				}
			} else if explicitSA == "default" {
				return fmt.Errorf("k3s manifest: explicit serviceAccountName \"default\" requires automountServiceAccountToken: false")
			}
		}

		for key, val := range v {
			childCtx := nextBaseCtx
			childCtx.inAllowedHelmChartSpec = false
			lowerKey := strings.ToLower(strings.TrimSpace(key))
			switch lowerKey {
			case "spec":
				if !ctx.inHelmValues && kindLower == "helmchart" {
					childCtx.inAllowedHelmChartSpec = true
				}
			case "values":
				if ctx.inAllowedHelmChartSpec {
					childCtx.inHelmValues = true
				}
			case "template":
				childCtx.isolatedUserNs = false
			case "kind":
				if !ctx.inHelmValues {
					kStr, ok := val.(string)
					if !ok || strings.TrimSpace(kStr) == "" {
						return fmt.Errorf("k3s manifest: resource kind must be a non-empty string")
					}
					if kindLower == "helmchart" {
						// Permit ONLY Axonwall-compiled HelmCharts:
						// 1. Cilium eBPF CNI HelmChart from https://helm.cilium.io/
						// 2. In-house Vigilante modular SOC HelmCharts from https://charts.vigilante.local
						rawSpec, _ := mapGetCI(v, "spec")
						specMap, _ := rawSpec.(map[string]any)
						if err := validateAllowedHelmChartSpec(specMap); err != nil {
							return err
						}
					} else if k3sDeniedManifestKinds[kindLower] {
						return fmt.Errorf("k3s manifest: resource kind %q is not permitted in a bundle", kStr)
					}
				}
			case "hostpath":
				if !(nextBaseCtx.isolatedUserNs && isAllowedUserNsBpffsHostPath(val)) {
					return fmt.Errorf("k3s manifest: hostPath volumes are not permitted in a bundle")
				}
			case "hostpid", "hostnetwork", "hostipc":
				switch bv := val.(type) {
				case nil:
				case bool:
					if bv {
						return fmt.Errorf("k3s manifest: %s is not permitted in a bundle", key)
					}
				default:
					return fmt.Errorf("k3s manifest: %s must be a boolean (false)", key)
				}
			case "privileged":
				switch bv := val.(type) {
				case nil:
				case bool:
					if bv {
						return fmt.Errorf("k3s manifest: privileged containers are not permitted in a bundle")
					}
				default:
					return fmt.Errorf("k3s manifest: privileged must be a boolean (false)")
				}
			case "capabilities":
				if val != nil {
					capMap, ok := val.(map[string]any)
					if !ok {
						return fmt.Errorf("k3s manifest: capabilities must be a mapping")
					}
					if addVal, hasAdd := mapGetCI(capMap, "add"); hasAdd && addVal != nil {
						if nextBaseCtx.isolatedUserNs && isAllowedUserNsCapabilities(capMap) {
							// Permitted strictly under hostUsers: false with drop: ["ALL"] and BPF/NET_ADMIN only
						} else if list, isSlice := addVal.([]any); !isSlice || len(list) > 0 {
							return fmt.Errorf("k3s manifest: capabilities.add is not permitted in a bundle")
						}
					}
				}
			case "roleref":
				if ref, ok := val.(map[string]any); ok {
					if nameRaw, hasName := mapGetCI(ref, "name"); hasName {
						if name, ok := nameRaw.(string); ok {
							lowerName := strings.ToLower(strings.TrimSpace(name))
							if lowerName == "cluster-admin" || strings.HasPrefix(lowerName, "system:") {
								return fmt.Errorf("k3s manifest: binding to %q is not permitted in a bundle", name)
							}
						}
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
	case nil, string, bool, int, int64, uint64, float64:
		return nil
	default:
		return fmt.Errorf("k3s manifest: unsupported value type %T is not permitted", node)
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
	"helmVersion":     true,
	"timeout":         true,
	"failurePolicy":   true,
	"backOffLimit":    true,
}

var vigilanteChartNameRe = regexp.MustCompile(`^[a-z0-9-]+$`)

var allowedHelmCharts = map[string]map[string]bool{
	"https://helm.cilium.io/": {
		"cilium": true,
	},
	"https://charts.vigilante.local": {
		"vigilante-soc": true,
		"vigil-soc":     true,
		"vigil-local":   true,
		"opensearch":    true,
		"wazuh":         true,
		"bloodhound":    true,
		"falco":         true,
		"suricata":      true,
		"zeek":          true,
		"zap":           true,
		"flamingo":      true,
		"kctf":          true,
		"openvas":       true,
	},
}

var helmForbiddenValueSegments = map[string]bool{
	"image":              true,
	"command":            true,
	"args":               true,
	"privileged":         true,
	"hostpath":           true,
	"hostnetwork":        true,
	"hostpid":            true,
	"hostipc":            true,
	"roleref":            true,
	"hostusers":          true,
	"repoca":             true,
	"capabilities":       true,
	"serviceaccountname": true,
	"serviceaccount":     true,
	"volumes":            true,
	"volumemounts":       true,
}

func splitHelmKeySegments(key string) ([]string, bool) {
	if key == "" || hasControlChars(key) {
		return nil, false
	}
	cleaned := strings.ReplaceAll(key, `\.`, ".")
	parts := strings.FieldsFunc(cleaned, func(r rune) bool {
		return r == '.' || r == '[' || r == ']'
	})
	if len(parts) == 0 {
		return nil, false
	}
	segs := make([]string, 0, len(parts))
	for _, p := range parts {
		seg := strings.ToLower(strings.TrimSpace(p))
		if seg == "" {
			return nil, false
		}
		segs = append(segs, seg)
	}
	return segs, true
}

func validateHelmKeyAndScalar(segs []string, rawKey string, val any, isCilium bool) error {
	for _, seg := range segs {
		if helmForbiddenValueSegments[seg] {
			return fmt.Errorf("k3s manifest: HelmChart override %q (%s) is not permitted in a bundle", rawKey, seg)
		}
	}
	last := segs[len(segs)-1]
	if last == "kind" {
		if kStr, ok := val.(string); ok {
			if k3sDeniedManifestKinds[strings.ToLower(strings.TrimSpace(kStr))] {
				return fmt.Errorf("k3s manifest: HelmChart value kind %q is not permitted in a bundle", kStr)
			}
		}
	}
	if !isCilium && (last == "namespace" || last == "targetnamespace") {
		if nsStr, ok := val.(string); ok && isSystemK8sNamespace(nsStr) {
			return fmt.Errorf("k3s manifest: HelmChart target namespace %q is not permitted in a bundle", nsStr)
		}
	}
	return nil
}

func validateHelmValues(node any, isCilium bool) error {
	switch v := node.(type) {
	case map[string]any:
		for key, val := range v {
			segs, ok := splitHelmKeySegments(key)
			if !ok {
				return fmt.Errorf("k3s manifest: invalid HelmChart values key %q", key)
			}
			if err := validateHelmKeyAndScalar(segs, key, val, isCilium); err != nil {
				return err
			}
			if err := validateHelmValues(val, isCilium); err != nil {
				return err
			}
		}
		return nil
	case []any:
		for _, item := range v {
			if err := validateHelmValues(item, isCilium); err != nil {
				return err
			}
		}
		return nil
	case string:
		if strings.ContainsRune(v, '\x00') {
			return fmt.Errorf("k3s manifest: HelmChart value string contains NUL byte")
		}
		return nil
	case nil, bool, int, int64, uint64, float64:
		return nil
	default:
		return fmt.Errorf("k3s manifest: unsupported HelmChart value type %T", node)
	}
}

func validateHelmSetEntry(key string, val any, isCilium bool) error {
	if key == "" || strings.TrimSpace(key) != key || strings.ContainsAny(key, " \t\r\n\x00,={}\\") || hasControlChars(key) {
		return fmt.Errorf("k3s manifest: HelmChart spec.set key %q contains disallowed characters", key)
	}
	segs, ok := splitHelmKeySegments(key)
	if !ok {
		return fmt.Errorf("k3s manifest: invalid HelmChart spec.set key %q", key)
	}
	switch sv := val.(type) {
	case string:
		if strings.ContainsAny(sv, "\r\n\x00,={}\\") || hasControlChars(sv) {
			return fmt.Errorf("k3s manifest: HelmChart spec.set[%q] value contains disallowed characters", key)
		}
	case bool, int, int64, uint64, float64:
	default:
		return fmt.Errorf("k3s manifest: HelmChart spec.set[%q] must be a scalar value", key)
	}
	return validateHelmKeyAndScalar(segs, key, val, isCilium)
}

func validateAllowedHelmChartSpec(specMap map[string]any) error {
	if specMap == nil {
		return fmt.Errorf("k3s manifest: HelmChart missing spec")
	}
	if _, hasRepoCA := specMap["repoCA"]; hasRepoCA {
		return fmt.Errorf("k3s manifest: HelmChart spec.repoCA is not permitted in a bundle")
	}
	for k := range specMap {
		if !helmChartAllowedSpecKeys[k] {
			return fmt.Errorf("k3s manifest: HelmChart spec.%s is not permitted in a bundle", k)
		}
	}
	repo, repoIsStr := specMap["repo"].(string)
	chart, chartIsStr := specMap["chart"].(string)
	if !repoIsStr || !chartIsStr {
		return fmt.Errorf("k3s manifest: HelmChart spec.repo and spec.chart must be strings")
	}
	repo = strings.TrimSpace(repo)
	chart = strings.TrimSpace(chart)

	allowedCharts, repoOK := allowedHelmCharts[repo]
	if !repoOK || !allowedCharts[chart] {
		return fmt.Errorf("k3s manifest: untrusted HelmChart (%s / %s) is not permitted in a bundle", repo, chart)
	}
	if repo == "https://charts.vigilante.local" && !vigilanteChartNameRe.MatchString(chart) {
		return fmt.Errorf("k3s manifest: invalid Vigilante HelmChart name %q", chart)
	}
	isCilium := repo == "https://helm.cilium.io/" && chart == "cilium"

	if tnsRaw, hasTns := specMap["targetNamespace"]; hasTns && tnsRaw != nil {
		tns, ok := tnsRaw.(string)
		if !ok || !validK8sNamespaceRe.MatchString(strings.TrimSpace(tns)) {
			return fmt.Errorf("k3s manifest: HelmChart spec.targetNamespace %v is invalid", tnsRaw)
		}
		tnsLower := strings.ToLower(strings.TrimSpace(tns))
		if isSystemK8sNamespace(tnsLower) && !(isCilium && tnsLower == "kube-system") {
			return fmt.Errorf("k3s manifest: HelmChart spec.targetNamespace %q is not permitted for %s/%s", tns, repo, chart)
		}
	}
	if cnRaw, hasCn := specMap["createNamespace"]; hasCn && cnRaw != nil {
		if _, ok := cnRaw.(bool); !ok {
			return fmt.Errorf("k3s manifest: HelmChart spec.createNamespace must be a boolean")
		}
	}
	for _, strKey := range []string{"version", "helmVersion", "timeout", "failurePolicy"} {
		if raw, exists := specMap[strKey]; exists && raw != nil {
			s, ok := raw.(string)
			if !ok || hasControlChars(s) {
				return fmt.Errorf("k3s manifest: HelmChart spec.%s must be a safe string", strKey)
			}
		}
	}
	if bolRaw, exists := specMap["backOffLimit"]; exists && bolRaw != nil {
		switch n := bolRaw.(type) {
		case int:
			if n < 0 {
				return fmt.Errorf("k3s manifest: HelmChart spec.backOffLimit must be non-negative")
			}
		case int64:
			if n < 0 {
				return fmt.Errorf("k3s manifest: HelmChart spec.backOffLimit must be non-negative")
			}
		case uint64:
		default:
			return fmt.Errorf("k3s manifest: HelmChart spec.backOffLimit must be an integer")
		}
	}

	if valRaw, ok := specMap["values"]; ok && valRaw != nil {
		valMap, ok := valRaw.(map[string]any)
		if !ok {
			return fmt.Errorf("k3s manifest: HelmChart spec.values must be a mapping")
		}
		if err := validateHelmValues(valMap, isCilium); err != nil {
			return err
		}
	}
	if vcRaw, ok := specMap["valuesContent"]; ok && vcRaw != nil {
		vcStr, ok := vcRaw.(string)
		if !ok {
			return fmt.Errorf("k3s manifest: HelmChart spec.valuesContent must be a string")
		}
		docs, err := parseStrictYAMLDocuments(vcStr, 1, "HelmChart spec.valuesContent")
		if err != nil {
			return err
		}
		for _, doc := range docs {
			if err := validateHelmValues(doc, isCilium); err != nil {
				return err
			}
		}
	}
	if setRaw, ok := specMap["set"]; ok && setRaw != nil {
		setMap, ok := setRaw.(map[string]any)
		if !ok {
			return fmt.Errorf("k3s manifest: HelmChart spec.set must be a mapping")
		}
		for k, v := range setMap {
			if err := validateHelmSetEntry(k, v, isCilium); err != nil {
				return err
			}
		}
	}
	return nil
}
