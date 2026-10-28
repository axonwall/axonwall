package engine

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"
)

var validGitCommitHashRe = regexp.MustCompile(`^[0-9a-fA-F]{4,64}$`)

// EtckeeperStatus provides health and commit state information for etckeeper.
type EtckeeperStatus struct {
	Installed      bool      `json:"installed"`
	VCS            string    `json:"vcs"`
	Clean          bool      `json:"clean"`
	LastCommitHash string    `json:"lastCommitHash,omitempty"`
	LastCommitMsg  string    `json:"lastCommitMsg,omitempty"`
	LastCommitTime time.Time `json:"lastCommitTime,omitempty"`
	TrackedPath    string    `json:"trackedPath"`
}

// EtckeeperCommitLog represents a historical git log entry from etckeeper.
type EtckeeperCommitLog struct {
	Hash    string    `json:"hash"`
	Author  string    `json:"author"`
	Date    time.Time `json:"date"`
	Subject string    `json:"subject"`
}

// EtckeeperManager manages etckeeper initialization, automated commit tracking on config change,
// diffing, and health verification for /etc.
type EtckeeperManager struct {
	mu           sync.Mutex
	execCmd      func(name string, args ...string) *exec.Cmd
	etcDir       string
	debounceTime time.Duration
	pendingTimer *time.Timer
}

// NewEtckeeperManager creates an EtckeeperManager targeting /etc.
func NewEtckeeperManager(etcDir string) *EtckeeperManager {
	if etcDir == "" {
		etcDir = "/etc"
	}
	return &EtckeeperManager{
		etcDir:       etcDir,
		execCmd:      exec.Command,
		debounceTime: 2 * time.Second,
	}
}

// IsInstalled checks if the etckeeper binary is available in PATH.
func (m *EtckeeperManager) IsInstalled() bool {
	cmd := m.execCmd("which", "etckeeper")
	return cmd.Run() == nil
}

// Init ensures etckeeper is initialized in the target /etc directory.
func (m *EtckeeperManager) Init() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.IsInstalled() {
		return fmt.Errorf("etckeeper binary not found on system")
	}

	gitDir := m.etcDir + "/.git"
	if _, err := os.Stat(gitDir); os.IsNotExist(err) {
		cmd := m.execCmd("etckeeper", "init")
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("etckeeper init failed: %v, output: %s", err, string(out))
		}
	}

	return nil
}

// Commit records changes in /etc with a descriptive commit message.
func (m *EtckeeperManager) Commit(message, author string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.IsInstalled() {
		log.Printf("[Etckeeper] Notice: etckeeper not installed, skipping commit")
		return nil
	}

	cleanMsg := strings.ReplaceAll(message, "\n", " ")
	cleanMsg = strings.TrimSpace(cleanMsg)
	if cleanMsg == "" {
		cleanMsg = "Automated commit of /etc changes via Axonwall"
	}

	// First ensure clean / ignored files pass git status
	cmd := m.execCmd("etckeeper", "commit", cleanMsg)
	if author != "" {
		safeAuthor := strings.ReplaceAll(author, `"`, "")
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME="+safeAuthor,
			"GIT_COMMITTER_NAME="+safeAuthor,
			"GIT_AUTHOR_EMAIL="+safeAuthor+"@axonwall.local",
			"GIT_COMMITTER_EMAIL="+safeAuthor+"@axonwall.local",
		)
	}

	out, err := cmd.CombinedOutput()
	outStr := string(out)
	if err != nil {
		// If nothing to commit, etckeeper might return cleanly or non-zero depending on git version
		if strings.Contains(outStr, "nothing to commit") || strings.Contains(outStr, "working tree clean") {
			return nil
		}
		log.Printf("[Etckeeper] Warning: commit error: %v, out: %s", err, outStr)
		return fmt.Errorf("etckeeper commit failed: %v, output: %s", err, outStr)
	}

	log.Printf("[Etckeeper] Successfully committed changes to /etc: %s", cleanMsg)
	return nil
}

// ScheduleCommit debounces multiple rapid file updates (e.g. multi-domain YAML bundles) into a single commit.
func (m *EtckeeperManager) ScheduleCommit(message, author string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.pendingTimer != nil {
		m.pendingTimer.Stop()
	}

	m.pendingTimer = time.AfterFunc(m.debounceTime, func() {
		_ = m.Commit(message, author)
	})
}

// GetStatus returns the current status of etckeeper repository in /etc.
func (m *EtckeeperManager) GetStatus() EtckeeperStatus {
	m.mu.Lock()
	defer m.mu.Unlock()

	status := EtckeeperStatus{
		Installed:   m.IsInstalled(),
		TrackedPath: m.etcDir,
		VCS:         "git",
		Clean:       true,
	}

	if !status.Installed {
		return status
	}

	// Check if repository exists
	if _, err := os.Stat(m.etcDir + "/.git"); os.IsNotExist(err) {
		return status
	}

	// Check git status
	cmdStatus := m.execCmd("git", "-C", m.etcDir, "status", "--porcelain")
	if out, err := cmdStatus.Output(); err == nil {
		status.Clean = len(strings.TrimSpace(string(out))) == 0
	}

	// Check last commit
	cmdLog := m.execCmd("git", "-C", m.etcDir, "log", "-1", "--format=%H|%s|%aI")
	if out, err := cmdLog.Output(); err == nil {
		parts := strings.Split(strings.TrimSpace(string(out)), "|")
		if len(parts) >= 3 {
			status.LastCommitHash = parts[0]
			status.LastCommitMsg = parts[1]
			if t, err := time.Parse(time.RFC3339, parts[2]); err == nil {
				status.LastCommitTime = t
			}
		}
	}

	return status
}

// GetHistory retrieves the recent commit history from /etc etckeeper.
func (m *EtckeeperManager) GetHistory(limit int) ([]EtckeeperCommitLog, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.IsInstalled() {
		return nil, fmt.Errorf("etckeeper is not installed")
	}

	if limit <= 0 || limit > 100 {
		limit = 20
	}

	cmdLog := m.execCmd("git", "-C", m.etcDir, "log", fmt.Sprintf("-n%d", limit), "--format=%H|%an|%aI|%s")
	out, err := cmdLog.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve etckeeper history: %w", err)
	}

	var results []EtckeeperCommitLog
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		parts := strings.SplitN(line, "|", 4)
		if len(parts) < 4 {
			continue
		}
		item := EtckeeperCommitLog{
			Hash:    parts[0],
			Author:  parts[1],
			Subject: parts[3],
		}
		if t, err := time.Parse(time.RFC3339, parts[2]); err == nil {
			item.Date = t
		}
		results = append(results, item)
	}

	return results, nil
}

// GetDiff returns git diff output for uncommitted changes or a specific commit in /etc.
func (m *EtckeeperManager) GetDiff(commitHash string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.IsInstalled() {
		return "", fmt.Errorf("etckeeper is not installed")
	}

	var cmd *exec.Cmd
	if commitHash != "" {
		cleanHash := strings.TrimSpace(commitHash)
		if !validGitCommitHashRe.MatchString(cleanHash) {
			return "", fmt.Errorf("invalid commit hash %q: must be 4-64 hexadecimal characters", cleanHash)
		}
		cmd = m.execCmd("git", "-C", m.etcDir, "show", cleanHash, "--")
	} else {
		cmd = m.execCmd("git", "-C", m.etcDir, "diff")
	}

	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("failed to get diff: %v, out: %s", err, string(out))
	}
	return string(out), nil
}

// Close stops any pending background debounce timers.
func (m *EtckeeperManager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.pendingTimer != nil {
		m.pendingTimer.Stop()
	}
}
