package engine

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDetectOSInfoOmarchyAndArch(t *testing.T) {
	omarchyRoot := t.TempDir()
	if err := os.MkdirAll(filepath.Join(omarchyRoot, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	osRel := `NAME="Omarchy"
PRETTY_NAME="Omarchy 4.5.0"
ID=omarchy
ID_LIKE=arch
VERSION_ID="4.5.0"
`
	if err := os.WriteFile(filepath.Join(omarchyRoot, "etc", "os-release"), []byte(osRel), 0o644); err != nil {
		t.Fatal(err)
	}
	info := DetectOSInfo(omarchyRoot)
	if info.Family != OSFamilyArch {
		t.Fatalf("expected OSFamilyArch for Omarchy, got %q", info.Family)
	}
	if !info.IsDerivative {
		t.Fatalf("expected IsDerivative=true for Omarchy")
	}
	if info.ID != "omarchy" || info.PrettyName != "Omarchy 4.5.0" || info.VersionID != "4.5.0" {
		t.Fatalf("unexpected parsed fields: %+v", info)
	}

	archRoot := t.TempDir()
	if err := os.MkdirAll(filepath.Join(archRoot, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(archRoot, "etc", "os-release"), []byte("ID=arch\nNAME=\"Arch Linux\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	archInfo := DetectOSInfo(archRoot)
	if archInfo.Family != OSFamilyArch || archInfo.IsDerivative {
		t.Fatalf("expected pure arch without derivative flag, got %+v", archInfo)
	}

	markerOnlyArch := t.TempDir()
	if err := os.MkdirAll(filepath.Join(markerOnlyArch, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(markerOnlyArch, "etc", "arch-release"), []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := DetectOSInfo(markerOnlyArch); got.Family != OSFamilyArch {
		t.Fatalf("expected arch-release fallback to detect Arch, got %+v", got)
	}
}

func TestDetectOSInfoDebianAlpineAndFallback(t *testing.T) {
	debRoot := t.TempDir()
	if err := os.MkdirAll(filepath.Join(debRoot, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(debRoot, "etc", "os-release"), []byte("ID=debian\nPRETTY_NAME=\"Debian GNU/Linux 13 (trixie)\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := DetectOSInfo(debRoot); got.Family != OSFamilyDebian || got.IsDerivative {
		t.Fatalf("unexpected debian info: %+v", got)
	}

	alpRoot := t.TempDir()
	if err := os.MkdirAll(filepath.Join(alpRoot, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(alpRoot, "etc", "os-release"), []byte("ID=alpine\nPRETTY_NAME=\"Alpine Linux v3.21\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := DetectOSInfo(alpRoot); got.Family != OSFamilyAlpine || got.IsDerivative {
		t.Fatalf("unexpected alpine info: %+v", got)
	}
}

func TestDetectOSRuntimeModeAndMarkers(t *testing.T) {
	hostRoot := t.TempDir()
	if HasAxonwallMarker(hostRoot) {
		t.Fatal("empty root must not have axonwall marker")
	}
	if got := NormalizeRuntimeMode("auto", false); got != ModeHost {
		t.Fatalf("expected auto without marker -> host, got %q", got)
	}
	if got := NormalizeRuntimeMode("auto", true); got != ModeAppliance {
		t.Fatalf("expected auto with marker -> appliance, got %q", got)
	}
	if m, err := ParseRuntimeMode("host", true, true); err != nil || m != ModeDev {
		t.Fatalf("expected --dev to force dev mode, got %q, %v", m, err)
	}
	if _, err := ParseRuntimeMode("bogus", false, false); err == nil {
		t.Fatal("expected error for invalid runtime mode")
	}

	applianceRoot := t.TempDir()
	if err := os.MkdirAll(filepath.Join(applianceRoot, "etc", "axonwall"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(applianceRoot, "etc", "axonwall", "version"), []byte("0.11.67\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !HasAxonwallMarker(applianceRoot) {
		t.Fatal("expected /etc/axonwall/version to count as axonwall marker")
	}

	installModeRoot := t.TempDir()
	if err := os.MkdirAll(filepath.Join(installModeRoot, "etc", "axonwall"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(installModeRoot, "etc", "axonwall", "install-mode"), []byte("rolling\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !HasAxonwallMarker(installModeRoot) {
		t.Fatal("expected /etc/axonwall/install-mode to count as axonwall marker")
	}

	t.Setenv("AXONWALL_DEV_MODE", "1")
	if m, err := ParseRuntimeMode("appliance", false, true); err != nil || m != ModeDev {
		t.Fatalf("expected AXONWALL_DEV_MODE=1 to force dev mode, got %q, %v", m, err)
	}
	t.Setenv("AXONWALL_DEV_MODE", "")
	t.Setenv("AXONWALL_MODE", "host")
	if m, err := ParseRuntimeMode("", false, true); err != nil || m != ModeHost {
		t.Fatalf("expected AXONWALL_MODE=host to resolve host mode, got %q, %v", m, err)
	}
	t.Setenv("AXONWALL_MODE", "")

	if fam := DetectOSFamily(); fam != string(OSFamilyArch) && fam != string(OSFamilyDebian) && fam != string(OSFamilyAlpine) {
		t.Fatalf("unexpected DetectOSFamily() value: %q", fam)
	}

	systemdRoot := t.TempDir()
	if IsSystemdRunningAt(systemdRoot) {
		t.Fatal("expected false before /run/systemd/system exists")
	}
	if err := os.MkdirAll(filepath.Join(systemdRoot, "run", "systemd", "system"), 0o755); err != nil {
		t.Fatal(err)
	}
	if !IsSystemdRunningAt(systemdRoot) {
		t.Fatal("expected true when /run/systemd/system exists")
	}
}
