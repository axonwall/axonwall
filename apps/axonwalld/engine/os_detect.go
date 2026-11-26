package engine

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// OSFamily identifies the base Linux distribution family managed by axonwalld.
type OSFamily string

const (
	OSFamilyArch   OSFamily = "arch"
	OSFamilyDebian OSFamily = "debian"
	OSFamilyAlpine OSFamily = "alpine"
)

// RuntimeMode controls how aggressively axonwalld takes over host subsystems.
//   - appliance: dedicated Axonwall OS appliance (full firewall/DNS/DHCP/directory takeover)
//   - host: existing Arch/Debian workstation or server (non-destructive host management)
//   - dev: sandboxed local development (never mutates system /etc, boot, or firewall state)
type RuntimeMode string

const (
	ModeAppliance RuntimeMode = "appliance"
	ModeHost      RuntimeMode = "host"
	ModeDev       RuntimeMode = "dev"
	ModeCollector RuntimeMode = "collector"
)

// OSInfo captures normalized identity fields from /etc/os-release.
type OSInfo struct {
	ID           string   `json:"id"`
	IDLike       string   `json:"idLike,omitempty"`
	Name         string   `json:"name,omitempty"`
	PrettyName   string   `json:"prettyName,omitempty"`
	VersionID    string   `json:"versionId,omitempty"`
	Family       OSFamily `json:"family"`
	IsDerivative bool     `json:"isDerivative"`
}

var (
	archDerivatives = map[string]struct{}{
		"omarchy":     {},
		"cachyos":     {},
		"endeavouros": {},
		"manjaro":     {},
		"garuda":      {},
		"artix":       {},
		"arcolinux":   {},
		"archbang":    {},
		"blackarch":   {},
		"parabola":    {},
		"steamos":     {},
	}
	debianDerivatives = map[string]struct{}{
		"axonwall":  {},
		"ubuntu":    {},
		"linuxmint": {},
		"pop":       {},
		"kali":      {},
		"raspbian":  {},
		"devuan":    {},
		"proxmox":   {},
		"pve":       {},
	}
)

// unquoteOSReleaseValue decodes a single KEY=VALUE line value according to
// systemd's os-release escaping rules.
func unquoteOSReleaseValue(raw string) string {
	val := strings.TrimSpace(raw)
	if len(val) >= 2 && val[0] == '"' && val[len(val)-1] == '"' {
		inner := val[1 : len(val)-1]
		var b strings.Builder
		b.Grow(len(inner))
		for i := 0; i < len(inner); i++ {
			if inner[i] == '\\' && i+1 < len(inner) {
				i++
				b.WriteByte(inner[i])
				continue
			}
			b.WriteByte(inner[i])
		}
		return b.String()
	}
	if len(val) >= 2 && val[0] == '\'' && val[len(val)-1] == '\'' {
		return val[1 : len(val)-1]
	}
	return val
}

// ParseOSRelease parses key-value pairs from /etc/os-release content.
func ParseOSRelease(content string) OSInfo {
	var info OSInfo
	for _, rawLine := range strings.Split(content, "\n") {
		line := strings.TrimSpace(strings.TrimSuffix(rawLine, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		idx := strings.IndexByte(line, '=')
		if idx <= 0 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		val := unquoteOSReleaseValue(line[idx+1:])
		switch key {
		case "ID":
			info.ID = strings.ToLower(strings.TrimSpace(val))
		case "ID_LIKE":
			info.IDLike = strings.ToLower(strings.TrimSpace(val))
		case "NAME":
			info.Name = val
		case "PRETTY_NAME":
			info.PrettyName = val
		case "VERSION_ID":
			info.VersionID = val
		}
	}
	return info
}

func containsAnyToken(spaceSeparated string, needles ...string) bool {
	if spaceSeparated == "" {
		return false
	}
	for _, tok := range strings.Fields(strings.ToLower(spaceSeparated)) {
		for _, needle := range needles {
			if tok == needle {
				return true
			}
		}
	}
	return false
}

// ClassifyOSFamily classifies a distro ID / ID_LIKE pair and distro marker files
// into an OSFamily and reports whether the OS is a derivative (e.g. Omarchy on
// Arch, Ubuntu or Axonwall on Debian).
func ClassifyOSFamily(id, idLike string, hasArchRelease, hasDebianVersion, hasAlpineRelease bool) (OSFamily, bool) {
	normID := strings.ToLower(strings.TrimSpace(id))
	normLike := strings.ToLower(strings.TrimSpace(idLike))

	if normID == "arch" || normID == "archlinux" {
		return OSFamilyArch, false
	}
	if _, ok := archDerivatives[normID]; ok {
		return OSFamilyArch, true
	}
	if containsAnyToken(normLike, "arch", "archlinux") {
		return OSFamilyArch, normID != "" && normID != "arch" && normID != "archlinux"
	}

	if normID == "debian" {
		return OSFamilyDebian, false
	}
	if _, ok := debianDerivatives[normID]; ok {
		return OSFamilyDebian, true
	}
	if containsAnyToken(normLike, "debian", "ubuntu") {
		return OSFamilyDebian, normID != "" && normID != "debian"
	}

	if normID == "alpine" {
		return OSFamilyAlpine, false
	}
	if containsAnyToken(normLike, "alpine") {
		return OSFamilyAlpine, normID != "" && normID != "alpine"
	}

	if hasAlpineRelease {
		return OSFamilyAlpine, normID != "" && normID != "alpine"
	}
	if hasArchRelease {
		return OSFamilyArch, normID != "" && normID != "arch" && normID != "archlinux"
	}
	if hasDebianVersion {
		return OSFamilyDebian, normID != "" && normID != "debian"
	}

	return OSFamilyDebian, false
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// DetectOSInfo reads os-release and distro marker files beneath rootDir (default "/").
func DetectOSInfo(rootDir string) OSInfo {
	if strings.TrimSpace(rootDir) == "" {
		rootDir = "/"
	}
	var content string
	for _, rel := range []string{"etc/os-release", "usr/lib/os-release"} {
		p := filepath.Join(rootDir, rel)
		if b, err := os.ReadFile(p); err == nil {
			content = string(b)
			break
		}
	}
	info := ParseOSRelease(content)
	hasArch := fileExists(filepath.Join(rootDir, "etc", "arch-release"))
	hasDebian := fileExists(filepath.Join(rootDir, "etc", "debian_version"))
	hasAlpine := fileExists(filepath.Join(rootDir, "etc", "alpine-release"))
	info.Family, info.IsDerivative = ClassifyOSFamily(info.ID, info.IDLike, hasArch, hasDebian, hasAlpine)
	if info.PrettyName == "" {
		info.PrettyName = info.Name
	}
	return info
}

// DetectOSFamily returns the host's OS family string ("arch", "debian", or "alpine") detected under "/".
func DetectOSFamily() string {
	return string(DetectOSInfo("/").Family)
}

// HasAxonwallMarker returns true when rootDir shows dedicated Axonwall
// appliance identity markers (as opposed to an upstream Arch/Debian host).
func HasAxonwallMarker(rootDir string) bool {
	if strings.TrimSpace(rootDir) == "" {
		rootDir = "/"
	}
	for _, rel := range []string{"etc/os-release", "usr/lib/os-release"} {
		if b, err := os.ReadFile(filepath.Join(rootDir, rel)); err == nil {
			if ParseOSRelease(string(b)).ID == "axonwall" {
				return true
			}
			break
		}
	}
	markers := []string{
		filepath.Join(rootDir, "etc", "axonwall-release"),
		filepath.Join(rootDir, "etc", "axonwall", "version"),
		filepath.Join(rootDir, "etc", "axonwall", "install-mode"),
		filepath.Join(rootDir, "var", "lib", "axonwall", "install-mode"),
		filepath.Join(rootDir, "etc", "axonwall", ".appliance"),
		filepath.Join(rootDir, "etc", "axonwall", ".k3s-edition"),
		filepath.Join(rootDir, "etc", "axonwall", ".vault-edition"),
	}
	for _, m := range markers {
		if fileExists(m) {
			return true
		}
	}
	return false
}

// NormalizeRuntimeMode maps raw ("", "auto", "appliance", "host", "dev", "collector") into a
// concrete RuntimeMode, resolving "auto" or unrecognized empty values via
// AXONWALL_COLLECTOR_ONLY / hasAxonwallMarker.
func NormalizeRuntimeMode(raw string, hasAxonwallMarker bool) RuntimeMode {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case string(ModeAppliance):
		return ModeAppliance
	case string(ModeHost):
		return ModeHost
	case string(ModeDev):
		return ModeDev
	case string(ModeCollector):
		return ModeCollector
	default:
		if strings.TrimSpace(os.Getenv("AXONWALL_COLLECTOR_ONLY")) == "1" {
			return ModeCollector
		}
		if hasAxonwallMarker {
			return ModeAppliance
		}
		return ModeHost
	}
}

// ParseRuntimeMode validates an explicit CLI/env mode string alongside --dev / AXONWALL_DEV_MODE.
func ParseRuntimeMode(raw string, devFlag bool, hasAxonwallMarker bool) (RuntimeMode, error) {
	if devFlag || strings.TrimSpace(os.Getenv("AXONWALL_DEV_MODE")) == "1" {
		return ModeDev, nil
	}
	norm := strings.ToLower(strings.TrimSpace(raw))
	if norm == "" {
		if envMode := strings.ToLower(strings.TrimSpace(os.Getenv("AXONWALL_MODE"))); envMode != "" {
			norm = envMode
		}
	}
	switch norm {
	case "", "auto":
		return NormalizeRuntimeMode(norm, hasAxonwallMarker), nil
	case string(ModeAppliance), string(ModeHost), string(ModeDev), string(ModeCollector):
		return RuntimeMode(norm), nil
	default:
		return "", fmt.Errorf("invalid runtime mode %q (expected auto|appliance|host|dev|collector)", raw)
	}
}

// IsSystemdRunning reports whether systemd appears to be PID 1 on this host.
func IsSystemdRunning() bool {
	return IsSystemdRunningAt("/")
}

// IsSystemdRunningAt reports whether <rootDir>/run/systemd/system exists as a directory.
func IsSystemdRunningAt(rootDir string) bool {
	if strings.TrimSpace(rootDir) == "" {
		rootDir = "/"
	}
	fi, err := os.Stat(filepath.Join(rootDir, "run", "systemd", "system"))
	return err == nil && fi.IsDir()
}
