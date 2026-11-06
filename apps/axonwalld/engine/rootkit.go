package engine

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type ScannerBinaryStatus struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Binary    string `json:"binary"`
	Installed bool   `json:"installed"`
	Path      string `json:"path,omitempty"`
	Category  string `json:"category"`
	Layer     string `json:"layer"`
}

type IoUringRingFinding struct {
	PID              int      `json:"pid"`
	Comm             string   `json:"comm"`
	Exe              string   `json:"exe"`
	FD               int      `json:"fd"`
	SqThread         int      `json:"sqThread"`
	SqThreadCPU      int      `json:"sqThreadCpu"`
	SqHead           int      `json:"sqHead"`
	SqTail           int      `json:"sqTail"`
	CqHead           int      `json:"cqHead"`
	CqTail           int      `json:"cqTail"`
	UserFiles        int      `json:"userFiles"`
	SqPollActive     bool     `json:"sqPollActive"`
	FixedFilesActive bool     `json:"fixedFilesActive"`
	Severity         string   `json:"severity"`
	Reasons          []string `json:"reasons"`
}

type KernelPostureStatus struct {
	TaintValue              int      `json:"taintValue"`
	IoUringDisabled         string   `json:"ioUringDisabled"`
	IoUringGroup            string   `json:"ioUringGroup"`
	UnprivilegedBpfDisabled string   `json:"unprivilegedBpfDisabled"`
	BpfJitHarden            string   `json:"bpfJitHarden"`
	LockdownMode            string   `json:"lockdownMode"`
	ActiveLsms              []string `json:"activeLsms"`
	BpfLsmActive            bool     `json:"bpfLsmActive"`
	LdSoPreloadPresent      bool     `json:"ldSoPreloadPresent"`
	LdSoPreloadEntries      string   `json:"ldSoPreloadEntries,omitempty"`
	// UnknownFields lists the posture inputs that could not be read
	// (missing sysctl/sysfs file). Those fields are empty, not
	// substituted with secure-looking defaults (round-2 A-L25: the
	// old code reported unprivileged_bpf_disabled "1",
	// bpf_jit_harden "2", and LSM "lockdown,yama,apparmor" for
	// values it never observed).
	UnknownFields []string `json:"unknownFields,omitempty"`
}

type HostRootkitFinding struct {
	Detector       string `json:"detector"`
	Category       string `json:"category"`
	Severity       string `json:"severity"`
	Target         string `json:"target"`
	Description    string `json:"description"`
	MitreTechnique string `json:"mitreTechnique"`
}

type HostRootkitAuditStatus struct {
	Timestamp           string                 `json:"timestamp"`
	OverallVerdict      string                 `json:"overallVerdict"`
	KernelPosture       KernelPostureStatus    `json:"kernelPosture"`
	Scanners            []ScannerBinaryStatus  `json:"scanners"`
	IoUringRings        []IoUringRingFinding   `json:"ioUringRings"`
	TrampolineHooks     []string               `json:"trampolineHooks"`
	BpfLsmGuardAttached bool                   `json:"bpfLsmGuardAttached"`
	BpfLsmAttachedHooks []string               `json:"bpfLsmAttachedHooks"`
	BpfLsmAllowlist     []BpfLsmAllowlistEntry `json:"bpfLsmAllowlist"`
	BpfLsmDenialEvents  []BpfLsmDenialEvent    `json:"bpfLsmDenialEvents"`
	Findings            []HostRootkitFinding   `json:"findings"`
}

func readSysctlFileTrimmed(path, fallback string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return fallback
	}
	return strings.TrimSpace(string(b))
}

// ParseProcFdInfoIoUring parses the contents of /proc/<pid>/fdinfo/<fd> for an anon_inode:[io_uring] ring.
func ParseProcFdInfoIoUring(pid int, comm, exe string, fd int, fdInfoText string) IoUringRingFinding {
	getInt := func(key string, def int) int {
		re := regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(key) + `:\s*(-?\d+)`)
		m := re.FindStringSubmatch(fdInfoText)
		if len(m) == 2 {
			if v, err := strconv.Atoi(m[1]); err == nil {
				return v
			}
		}
		return def
	}

	sqThread := getInt("SqThread", -1)
	sqThreadCPU := getInt("SqThreadCpu", -1)
	sqHead := getInt("SqHead", 0)
	sqTail := getInt("SqTail", 0)
	cqHead := getInt("CqHead", 0)
	cqTail := getInt("CqTail", 0)
	userFiles := getInt("UserFiles", 0)

	sqPoll := sqThread != -1
	fixedFiles := userFiles > 0

	trusted := map[string]bool{
		"haproxy":         true,
		"nginx":           true,
		"clickhouse":      true,
		"postgres":        true,
		"qemu-system-x86": true,
		"axonwalld":       true,
		"node":            true,
		"k3s":             true,
		"k3s-server":      true,
		"containerd":      true,
		"suricata":        true,
		"unbound":         true,
		"caddy":           true,
		"vector":          true,
		"weed":            true,
		"mariadbd":        true,
	}

	severity := "INFO"
	var reasons []string
	if sqPoll {
		severity = "CRITICAL"
		reasons = append(reasons, "IORING_SETUP_SQPOLL kernel thread active (zero-syscall ring I/O invisible to sys_enter tracepoints)")
	}
	if fixedFiles && !trusted[comm] {
		if severity != "CRITICAL" {
			severity = "HIGH"
		}
		reasons = append(reasons, "IOSQE_FIXED_FILE private file descriptor table registered outside standard fdtable")
	}
	if !trusted[comm] && !sqPoll && !fixedFiles {
		severity = "HIGH"
		reasons = append(reasons, "Untrusted process holding active anon_inode:[io_uring] ring")
	}

	return IoUringRingFinding{
		PID:              pid,
		Comm:             comm,
		Exe:              exe,
		FD:               fd,
		SqThread:         sqThread,
		SqThreadCPU:      sqThreadCPU,
		SqHead:           sqHead,
		SqTail:           sqTail,
		CqHead:           cqHead,
		CqTail:           cqTail,
		UserFiles:        userFiles,
		SqPollActive:     sqPoll,
		FixedFilesActive: fixedFiles,
		Severity:         severity,
		Reasons:          reasons,
	}
}

// InspectKernelPosture reads live /proc/sys and /sys/kernel/security files.
// A posture input that cannot be read is reported as unknown (listed in
// UnknownFields, value left empty) instead of being replaced with a
// secure-looking default (round-2 A-L25).
func InspectKernelPosture() KernelPostureStatus {
	var unknown []string
	readPosture := func(path, field string) string {
		b, err := os.ReadFile(path)
		if err != nil {
			unknown = append(unknown, field)
			return ""
		}
		return strings.TrimSpace(string(b))
	}

	taintStr := readPosture("/proc/sys/kernel/tainted", "kernel.tainted")
	taintVal, _ := strconv.Atoi(taintStr)

	lockdownRaw := readPosture("/sys/kernel/security/lockdown", "kernel.security.lockdown")
	lockdownMode := "none"
	if strings.Contains(lockdownRaw, "[confidentiality]") {
		lockdownMode = "confidentiality"
	} else if strings.Contains(lockdownRaw, "[integrity]") {
		lockdownMode = "integrity"
	}

	lsmRaw := readPosture("/sys/kernel/security/lsm", "kernel.security.lsm")
	var activeLsms []string
	bpfLsm := false
	for _, item := range strings.Split(lsmRaw, ",") {
		trimmed := strings.TrimSpace(item)
		if trimmed != "" {
			activeLsms = append(activeLsms, trimmed)
			if trimmed == "bpf" {
				bpfLsm = true
			}
		}
	}

	// A missing /etc/ld.so.preload is the normal "no entries" state,
	// not an unknown: it is not tracked in UnknownFields.
	preloadEntries := readSysctlFileTrimmed("/etc/ld.so.preload", "")

	return KernelPostureStatus{
		TaintValue:              taintVal,
		IoUringDisabled:         readPosture("/proc/sys/kernel/io_uring_disabled", "kernel.io_uring_disabled"),
		IoUringGroup:            readPosture("/proc/sys/kernel/io_uring_group", "kernel.io_uring_group"),
		UnprivilegedBpfDisabled: readPosture("/proc/sys/kernel/unprivileged_bpf_disabled", "kernel.unprivileged_bpf_disabled"),
		BpfJitHarden:            readPosture("/proc/sys/net/core/bpf_jit_harden", "net.core.bpf_jit_harden"),
		LockdownMode:            lockdownMode,
		ActiveLsms:              activeLsms,
		BpfLsmActive:            bpfLsm,
		LdSoPreloadPresent:      preloadEntries != "",
		LdSoPreloadEntries:      preloadEntries,
		UnknownFields:           unknown,
	}
}

// ScanLiveIoUringRings walks /proc/[0-9]*/fd/* looking for anon_inode:[io_uring].
func ScanLiveIoUringRings(procRoot string) []IoUringRingFinding {
	if procRoot == "" {
		procRoot = "/proc"
	}
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return nil
	}

	var rings []IoUringRingFinding
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 0 {
			continue
		}
		fdDir := filepath.Join(procRoot, entry.Name(), "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}
		for _, fdEntry := range fds {
			fdLink := filepath.Join(fdDir, fdEntry.Name())
			target, err := os.Readlink(fdLink)
			if err != nil || target != "anon_inode:[io_uring]" {
				continue
			}
			fdNum, _ := strconv.Atoi(fdEntry.Name())
			comm := readSysctlFileTrimmed(filepath.Join(procRoot, entry.Name(), "comm"), "unknown")
			exe, _ := os.Readlink(filepath.Join(procRoot, entry.Name(), "exe"))
			fdInfoBytes, _ := os.ReadFile(filepath.Join(procRoot, entry.Name(), "fdinfo", fdEntry.Name()))
			rings = append(rings, ParseProcFdInfoIoUring(pid, comm, exe, fdNum, string(fdInfoBytes)))
		}
	}
	return rings
}

// ListInstalledRootkitScanners checks PATH for all 12 classic and Ghost-in-the-Ring binaries.
func ListInstalledRootkitScanners() []ScannerBinaryStatus {
	specs := []struct {
		id       string
		name     string
		binary   string
		category string
		layer    string
	}{
		{"rkhunter", "Rootkit Hunter (rkhunter)", "rkhunter", "classic_scanner", "userspace"},
		{"chkrootkit", "Check Rootkit (chkrootkit)", "chkrootkit", "classic_scanner", "userspace"},
		{"clamav", "ClamAV Antivirus (clamscan)", "clamscan", "classic_scanner", "userspace"},
		{"aide", "AIDE Cryptographic FIM", "aide", "fim_audit", "userspace"},
		{"lynis", "Lynis CIS & Hardening Auditor", "lynis", "fim_audit", "userspace"},
		{"yara", "YARA Ghost-in-the-Ring Scanner", "yara", "classic_scanner", "userspace"},
		{"unhide", "Unhide Forensic Process Hunter", "unhide", "classic_scanner", "userspace"},
		{"debsums", "Debian Checksum Verifier (debsums)", "debsums", "fim_audit", "userspace"},
		{"io-uring-ring-hunter", "Ghost-in-the-Ring io_uring SQPOLL Hunter", "hunt-io-uring-implants.sh", "ring0_telemetry", "ring0_kcore"},
		{"drgn-kcore-prog-idr", "Ghost-in-the-Ring /proc/kcore prog_idr Auditor", "drgn", "ring0_telemetry", "ring0_kcore"},
		{"pmu-lbr-trampoline-auditor", "Silicon PMU LBR Branch Auditor", "perf", "ring0_telemetry", "silicon_pmu"},
		{"bpf-lsm-lockdown", "Preventive BPF_LSM & bpftool Inspector", "bpftool", "kernel_lockdown", "lsm_enforcement"},
	}

	out := make([]ScannerBinaryStatus, 0, len(specs))
	for _, s := range specs {
		p, err := exec.LookPath(s.binary)
		installed := err == nil && p != ""
		if !installed && strings.HasSuffix(s.binary, ".sh") {
			candidate := filepath.Join("/usr/local/bin", s.binary)
			if _, statErr := os.Stat(candidate); statErr == nil {
				installed = true
				p = candidate
			}
		}
		out = append(out, ScannerBinaryStatus{
			ID:        s.id,
			Name:      s.name,
			Binary:    s.binary,
			Installed: installed,
			Path:      p,
			Category:  s.category,
			Layer:     s.layer,
		})
	}
	return out
}

// RunHostRootkitAudit performs a live non-destructive audit of kernel posture, io_uring rings,
// LD_PRELOAD, and tracing trampolines.
func RunHostRootkitAudit() HostRootkitAuditStatus {
	posture := InspectKernelPosture()
	scanners := ListInstalledRootkitScanners()
	rings := ScanLiveIoUringRings("/proc")

	var findings []HostRootkitFinding
	var trampolines []string

	if posture.LdSoPreloadPresent {
		findings = append(findings, HostRootkitFinding{
			Detector:       "chkrootkit/ld.so.preload",
			Category:       "userspace_rootkit",
			Severity:       "HIGH",
			Target:         "/etc/ld.so.preload",
			Description:    "/etc/ld.so.preload is non-empty (" + posture.LdSoPreloadEntries + ") — verify against Symbiote/Vlany LD_PRELOAD hijacking.",
			MitreTechnique: "T1574.006",
		})
	}

	for _, ring := range rings {
		if ring.Severity == "CRITICAL" || ring.Severity == "HIGH" {
			findings = append(findings, HostRootkitFinding{
				Detector:       "io-uring-ring-hunter",
				Category:       "ring0_io_uring",
				Severity:       ring.Severity,
				Target:         ring.Comm + " (PID " + strconv.Itoa(ring.PID) + ")",
				Description:    strings.Join(ring.Reasons, "; "),
				MitreTechnique: "T1014",
			})
		}
	}

	if enabledBytes, err := os.ReadFile("/sys/kernel/tracing/enabled_functions"); err == nil {
		for _, line := range strings.Split(string(enabledBytes), "\n") {
			if strings.Contains(line, "bpf_trampoline") || strings.Contains(line, "__x64_sys_getdents") || strings.Contains(line, "__x64_sys_bpf") {
				trampolines = append(trampolines, strings.TrimSpace(line))
			}
		}
	}

	lsmAttached, lsmHooks, lsmAllowlist, lsmEvents := GetDefaultLsmGuardManager().Snapshot()
	for _, ev := range lsmEvents {
		action := "Audited"
		if ev.Blocked {
			action = "Blocked"
		}
		findings = append(findings, HostRootkitFinding{
			Detector:       "bpf-lsm-lockdown",
			Category:       "lsm_enforcement",
			Severity:       "CRITICAL",
			Target:         ev.Comm + " (PID " + strconv.FormatUint(uint64(ev.PID), 10) + ")",
			Description:    action + " via " + ev.Hook + " — detail=" + ev.Detail + " (dev=" + strconv.FormatUint(ev.Dev, 10) + " ino=" + strconv.FormatUint(ev.Ino, 10) + ")",
			MitreTechnique: ev.MitreTechnique,
		})
	}

	verdict := "CLEAN"
	for _, f := range findings {
		if f.Severity == "CRITICAL" {
			verdict = "COMPROMISED_CRITICAL"
			break
		}
		if f.Severity == "HIGH" && verdict == "CLEAN" {
			verdict = "SUSPICIOUS_HIGH"
		}
	}

	return HostRootkitAuditStatus{
		Timestamp:           time.Now().UTC().Format(time.RFC3339),
		OverallVerdict:      verdict,
		KernelPosture:       posture,
		Scanners:            scanners,
		IoUringRings:        rings,
		TrampolineHooks:     trampolines,
		BpfLsmGuardAttached: lsmAttached,
		BpfLsmAttachedHooks: lsmHooks,
		BpfLsmAllowlist:     lsmAllowlist,
		BpfLsmDenialEvents:  lsmEvents,
		Findings:            findings,
	}
}
