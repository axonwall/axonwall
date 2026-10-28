package engine

import (
	"testing"
)

func TestParseProcFdInfoIoUring(t *testing.T) {
	fdInfo := "pos:\t0\nflags:\t02000002\nSqMask:\t0x3f\nSqHead:\t512\nSqTail:\t512\nCqHead:\t512\nCqTail:\t512\nSqThread:\t8821\nSqThreadCpu:\t3\nUserFiles:\t6\n"
	finding := ParseProcFdInfoIoUring(8820, "curing_agent", "/dev/shm/.curing", 4, fdInfo)

	if !finding.SqPollActive {
		t.Fatalf("expected SqPollActive=true, got false")
	}
	if !finding.FixedFilesActive {
		t.Fatalf("expected FixedFilesActive=true, got false")
	}
	if finding.SqThread != 8821 {
		t.Fatalf("expected SqThread=8821, got %d", finding.SqThread)
	}
	if finding.UserFiles != 6 {
		t.Fatalf("expected UserFiles=6, got %d", finding.UserFiles)
	}
	if finding.Severity != "CRITICAL" {
		t.Fatalf("expected Severity=CRITICAL, got %s", finding.Severity)
	}
}

func TestListInstalledRootkitScannersAndAudit(t *testing.T) {
	scanners := ListInstalledRootkitScanners()
	if len(scanners) != 12 {
		t.Fatalf("expected 12 scanner entries, got %d", len(scanners))
	}

	audit := RunHostRootkitAudit()
	if audit.Timestamp == "" {
		t.Fatalf("expected non-empty audit timestamp")
	}
	if len(audit.Scanners) != 12 {
		t.Fatalf("expected 12 scanners in audit, got %d", len(audit.Scanners))
	}
}
