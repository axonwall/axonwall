package engine

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	validGitCommitHashRe   = regexp.MustCompile(`^[0-9a-fA-F]{4,64}$`)
	safeEtckeeperOptionRe  = regexp.MustCompile(`^[a-zA-Z0-9._\-\s=:/]*$`)
	safeEtckeeperPkgMgrRe  = regexp.MustCompile(`^[a-zA-Z0-9._\-]+$`)
	safeEtckeeperPathFltRe = regexp.MustCompile(`^[a-zA-Z0-9._\-/]+$`)
)

const (
	axonwallIgnoreBeginMarker = "# begin section managed by axonwall"
	axonwallIgnoreEndMarker   = "# end section managed by axonwall"
)

// EtckeeperFileChange represents a modified, added, deleted, or untracked file in /etc.
type EtckeeperFileChange struct {
	Status string `json:"status"`
	Path   string `json:"path"`
}

// EtckeeperConfig represents the parsed configuration from /etc/etckeeper/etckeeper.conf
// and Axonwall's managed ignore list in /etc/.gitignore.
type EtckeeperConfig struct {
	VCS                      string   `json:"vcs"`
	DailyAutocommit          bool     `json:"dailyAutocommit"`
	AvoidSpecialFileWarning  bool     `json:"avoidSpecialFileWarning"`
	AvoidCommitBeforeInstall bool     `json:"avoidCommitBeforeInstall"`
	HighlevelPackageManager  string   `json:"highlevelPackageManager"`
	LowlevelPackageManager   string   `json:"lowlevelPackageManager"`
	PushRemote               string   `json:"pushRemote"`
	GitCommitOptions         string   `json:"gitCommitOptions"`
	AutoCommitOnApply        bool     `json:"autoCommitOnApply"`
	CustomIgnorePatterns     []string `json:"customIgnorePatterns"`
	ConfPath                 string   `json:"confPath"`
	RawConfig                string   `json:"rawConfig,omitempty"`
}

// EtckeeperStatus provides health and commit state information for etckeeper.
type EtckeeperStatus struct {
	Installed        bool                  `json:"installed"`
	VCS              string                `json:"vcs"`
	Clean            bool                  `json:"clean"`
	LastCommitHash   string                `json:"lastCommitHash,omitempty"`
	LastCommitMsg    string                `json:"lastCommitMsg,omitempty"`
	LastCommitAuthor string                `json:"lastCommitAuthor,omitempty"`
	LastCommitTime   time.Time             `json:"lastCommitTime,omitempty"`
	TrackedPath      string                `json:"trackedPath"`
	// Initialized reports whether the tracked path actually holds a
	// git repository. Clean is false (not true) when the repo is
	// absent or git status fails, so a never-initialised /etc is
	// never reported as clean (round-2 A-L26).
	Initialized   bool                  `json:"initialized"`
	TotalCommits  int                   `json:"totalCommits"`
	ModifiedFiles []EtckeeperFileChange `json:"modifiedFiles"`
	TimerActive   bool                  `json:"timerActive"`
	TimerEnabled  bool                  `json:"timerEnabled"`
	NextTimerRun  string                `json:"nextTimerRun,omitempty"`
	LastTimerRun  string                `json:"lastTimerRun,omitempty"`
	Config        EtckeeperConfig       `json:"config"`
}

// EtckeeperCommitLog represents a historical git log entry from etckeeper.
type EtckeeperCommitLog struct {
	Hash      string    `json:"hash"`
	ShortHash string    `json:"shortHash"`
	Author    string    `json:"author"`
	Date      time.Time `json:"date"`
	Subject   string    `json:"subject"`
}

// EtckeeperManager manages etckeeper initialization, automated commit tracking on config change,
// diffing, configuration, and health verification for /etc.
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

func (m *EtckeeperManager) gitCmd(args ...string) *exec.Cmd {
	fullArgs := append([]string{"-c", "safe.directory=" + m.etcDir, "-C", m.etcDir}, args...)
	return m.execCmd("git", fullArgs...)
}

// IsInstalled checks if the etckeeper binary is available in PATH.
func (m *EtckeeperManager) IsInstalled() bool {
	cmd := m.execCmd("which", "etckeeper")
	return cmd.Run() == nil
}

// Init ensures etckeeper is initialized in the target /etc directory and has a valid git identity and baseline commit.
func (m *EtckeeperManager) Init() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.IsInstalled() {
		return fmt.Errorf("etckeeper binary not found on system")
	}

	gitDir := filepath.Join(m.etcDir, ".git")
	if _, err := os.Stat(gitDir); os.IsNotExist(err) {
		cmd := m.execCmd("etckeeper", "init")
		cmd.Dir = m.etcDir
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("etckeeper init failed: %v, output: %s", err, string(out))
		}
	}

	// If the real .git directory exists on disk, ensure git user.name/email and baseline ignore rules are set.
	if info, err := os.Stat(filepath.Join(gitDir, "config")); err == nil && !info.IsDir() {
		_ = m.gitCmd("config", "user.name", "Axonwall Etckeeper").Run()
		_ = m.gitCmd("config", "user.email", "etckeeper@axonwall.local").Run()

		cfg := m.readConfigLocked()
		_ = m.syncCustomIgnoreLocked(cfg.CustomIgnorePatterns)
	}

	return nil
}

// Commit records changes in /etc with a descriptive commit message.
func (m *EtckeeperManager) Commit(message, author string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	return m.commitLocked(message, author)
}

func (m *EtckeeperManager) commitLocked(message, author string) error {
	if !m.IsInstalled() {
		log.Printf("[Etckeeper] Notice: etckeeper not installed, skipping commit")
		return nil
	}

	cleanMsg := strings.ReplaceAll(message, "\n", " ")
	cleanMsg = strings.TrimSpace(cleanMsg)
	if cleanMsg == "" {
		cleanMsg = "Automated commit of /etc changes via Axonwall"
	}

	safeAuthor := strings.TrimSpace(strings.ReplaceAll(author, `"`, ""))
	if safeAuthor == "" {
		safeAuthor = "axonwall"
	}

	cmd := m.execCmd("etckeeper", "commit", cleanMsg)
	cmd.Dir = m.etcDir
	cmd.Env = append(os.Environ(),
		"USER=root",
		"HOME=/root",
		"GIT_AUTHOR_NAME="+safeAuthor,
		"GIT_COMMITTER_NAME="+safeAuthor,
		"GIT_AUTHOR_EMAIL="+safeAuthor+"@axonwall.local",
		"GIT_COMMITTER_EMAIL="+safeAuthor+"@axonwall.local",
	)

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

	cfg := m.readConfigLocked()
	if !cfg.AutoCommitOnApply {
		return
	}

	if m.pendingTimer != nil {
		m.pendingTimer.Stop()
	}

	m.pendingTimer = time.AfterFunc(m.debounceTime, func() {
		_ = m.Commit(message, author)
	})
}

func (m *EtckeeperManager) confFilePath() string {
	return filepath.Join(m.etcDir, "etckeeper", "etckeeper.conf")
}

func (m *EtckeeperManager) gitignoreFilePath() string {
	return filepath.Join(m.etcDir, ".gitignore")
}

func (m *EtckeeperManager) readCustomIgnoreLocked() []string {
	raw, err := os.ReadFile(m.gitignoreFilePath())
	if err != nil {
		return []string{"zfs/zpool.cache"}
	}
	lines := strings.Split(string(raw), "\n")
	inBlock := false
	foundBlock := false
	var patterns []string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == axonwallIgnoreBeginMarker {
			inBlock = true
			foundBlock = true
			continue
		}
		if trimmed == axonwallIgnoreEndMarker {
			inBlock = false
			continue
		}
		if inBlock && trimmed != "" && !strings.HasPrefix(trimmed, "#") {
			patterns = append(patterns, trimmed)
		}
	}
	if !foundBlock {
		return []string{"zfs/zpool.cache"}
	}
	return patterns
}

func (m *EtckeeperManager) syncCustomIgnoreLocked(patterns []string) error {
	gitignorePath := m.gitignoreFilePath()
	raw, err := os.ReadFile(gitignorePath)
	if err != nil && !os.IsNotExist(err) {
		return err
	}

	var cleaned []string
	seen := make(map[string]bool)
	for _, p := range patterns {
		trimmed := strings.TrimSpace(p)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.ContainsAny(trimmed, "\r\n") {
			continue
		}
		if !seen[trimmed] {
			seen[trimmed] = true
			cleaned = append(cleaned, trimmed)
		}
	}

	lines := strings.Split(string(raw), "\n")
	var outLines []string
	inBlock := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == axonwallIgnoreBeginMarker {
			inBlock = true
			continue
		}
		if trimmed == axonwallIgnoreEndMarker {
			inBlock = false
			continue
		}
		if !inBlock {
			outLines = append(outLines, line)
		}
	}

	for len(outLines) > 0 && strings.TrimSpace(outLines[len(outLines)-1]) == "" {
		outLines = outLines[:len(outLines)-1]
	}

	outLines = append(outLines, "")
	outLines = append(outLines, axonwallIgnoreBeginMarker)
	outLines = append(outLines, "# Custom ignore patterns configured via Axonwall Web Console")
	outLines = append(outLines, cleaned...)
	outLines = append(outLines, axonwallIgnoreEndMarker)
	outLines = append(outLines, "")

	newContent := strings.Join(outLines, "\n")
	if string(raw) != newContent {
		if err := os.WriteFile(gitignorePath, []byte(newContent), 0644); err != nil {
			return err
		}
	}

	// Untrack exact relative paths (like zfs/zpool.cache) from the git index while keeping them on disk
	if _, err := os.Stat(filepath.Join(m.etcDir, ".git", "index")); err == nil {
		for _, p := range cleaned {
			if !strings.ContainsAny(p, "*?[]") && !strings.Contains(p, "..") && !strings.HasPrefix(p, "/") {
				_ = m.gitCmd("rm", "--cached", "--ignore-unmatch", "--quiet", "--", p).Run()
			}
		}
	}
	return nil
}

func (m *EtckeeperManager) readConfigLocked() EtckeeperConfig {
	confPath := m.confFilePath()
	cfg := EtckeeperConfig{
		VCS:                      "git",
		DailyAutocommit:          true,
		AvoidSpecialFileWarning:  true,
		AvoidCommitBeforeInstall: false,
		HighlevelPackageManager:  "apt",
		LowlevelPackageManager:   "dpkg",
		PushRemote:               "",
		GitCommitOptions:         "",
		AutoCommitOnApply:        true,
		CustomIgnorePatterns:     m.readCustomIgnoreLocked(),
		ConfPath:                 confPath,
	}

	rawBytes, err := os.ReadFile(confPath)
	if err != nil {
		return cfg
	}
	raw := string(rawBytes)
	cfg.RawConfig = raw

	// Default AvoidSpecialFileWarning to false when reading a real file unless enabled inside it
	cfg.AvoidSpecialFileWarning = false

	for _, line := range strings.Split(raw, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		parts := strings.SplitN(trimmed, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.Trim(strings.TrimSpace(parts[1]), `"'`)
		switch key {
		case "VCS":
			if val != "" {
				cfg.VCS = val
			}
		case "AVOID_DAILY_AUTOCOMMITS":
			cfg.DailyAutocommit = val != "1" && !strings.EqualFold(val, "true")
		case "AVOID_SPECIAL_FILE_WARNING":
			cfg.AvoidSpecialFileWarning = val == "1" || strings.EqualFold(val, "true")
		case "AVOID_COMMIT_BEFORE_INSTALL":
			cfg.AvoidCommitBeforeInstall = val == "1" || strings.EqualFold(val, "true")
		case "HIGHLEVEL_PACKAGE_MANAGER":
			if val != "" {
				cfg.HighlevelPackageManager = val
			}
		case "LOWLEVEL_PACKAGE_MANAGER":
			if val != "" {
				cfg.LowlevelPackageManager = val
			}
		case "PUSH_REMOTE":
			cfg.PushRemote = val
		case "GIT_COMMIT_OPTIONS":
			cfg.GitCommitOptions = val
		case "AXONWALL_AUTOCOMMIT_ON_APPLY":
			cfg.AutoCommitOnApply = val != "0" && !strings.EqualFold(val, "false")
		}
	}

	return cfg
}

// GetConfig returns the current parsed etckeeper configuration.
func (m *EtckeeperManager) GetConfig() EtckeeperConfig {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.readConfigLocked()
}

// UpdateConfig validates and writes /etc/etckeeper/etckeeper.conf, updates /etc/.gitignore custom patterns,
// and reconciles the systemd etckeeper.timer unit.
func (m *EtckeeperManager) UpdateConfig(input EtckeeperConfig) (EtckeeperConfig, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	vcs := strings.TrimSpace(input.VCS)
	if vcs == "" {
		vcs = "git"
	}
	switch vcs {
	case "git", "hg", "bzr", "darcs":
	default:
		return EtckeeperConfig{}, fmt.Errorf("unsupported VCS %q: must be git, hg, bzr, or darcs", vcs)
	}

	highPkg := strings.TrimSpace(input.HighlevelPackageManager)
	if highPkg == "" {
		highPkg = "apt"
	}
	if !safeEtckeeperPkgMgrRe.MatchString(highPkg) {
		return EtckeeperConfig{}, fmt.Errorf("invalid highlevelPackageManager %q", highPkg)
	}

	lowPkg := strings.TrimSpace(input.LowlevelPackageManager)
	if lowPkg == "" {
		lowPkg = "dpkg"
	}
	if !safeEtckeeperPkgMgrRe.MatchString(lowPkg) {
		return EtckeeperConfig{}, fmt.Errorf("invalid lowlevelPackageManager %q", lowPkg)
	}

	pushRemote := strings.TrimSpace(input.PushRemote)
	if !safeEtckeeperOptionRe.MatchString(pushRemote) {
		return EtckeeperConfig{}, fmt.Errorf("invalid pushRemote value")
	}

	gitOpts := strings.TrimSpace(input.GitCommitOptions)
	if !safeEtckeeperOptionRe.MatchString(gitOpts) {
		return EtckeeperConfig{}, fmt.Errorf("invalid gitCommitOptions value")
	}

	var b strings.Builder
	b.WriteString("# /etc/etckeeper/etckeeper.conf -- Managed by Axonwall\n")
	b.WriteString(fmt.Sprintf("VCS=\"%s\"\n\n", vcs))
	b.WriteString("# Options passed to git commit when run by etckeeper.\n")
	b.WriteString(fmt.Sprintf("GIT_COMMIT_OPTIONS=\"%s\"\n\n", gitOpts))
	b.WriteString("HG_COMMIT_OPTIONS=\"\"\n")
	b.WriteString("BZR_COMMIT_OPTIONS=\"--quiet\"\n")
	b.WriteString("DARCS_COMMIT_OPTIONS=\"-a\"\n\n")

	b.WriteString("# Daily autocommit via systemd timer / cron.\n")
	if input.DailyAutocommit {
		b.WriteString("#AVOID_DAILY_AUTOCOMMITS=1\n\n")
	} else {
		b.WriteString("AVOID_DAILY_AUTOCOMMITS=1\n\n")
	}

	b.WriteString("# Avoid special file warning.\n")
	if input.AvoidSpecialFileWarning {
		b.WriteString("AVOID_SPECIAL_FILE_WARNING=1\n\n")
	} else {
		b.WriteString("#AVOID_SPECIAL_FILE_WARNING=1\n\n")
	}

	b.WriteString("# Avoid committing existing changes before package installation.\n")
	if input.AvoidCommitBeforeInstall {
		b.WriteString("AVOID_COMMIT_BEFORE_INSTALL=1\n\n")
	} else {
		b.WriteString("#AVOID_COMMIT_BEFORE_INSTALL=1\n\n")
	}

	b.WriteString(fmt.Sprintf("HIGHLEVEL_PACKAGE_MANAGER=%s\n", highPkg))
	b.WriteString(fmt.Sprintf("LOWLEVEL_PACKAGE_MANAGER=%s\n\n", lowPkg))
	b.WriteString("# Remote repository to push each commit to.\n")
	b.WriteString(fmt.Sprintf("PUSH_REMOTE=\"%s\"\n\n", pushRemote))

	b.WriteString("# Axonwall automatic commit when applying configuration bundles.\n")
	if input.AutoCommitOnApply {
		b.WriteString("AXONWALL_AUTOCOMMIT_ON_APPLY=1\n")
	} else {
		b.WriteString("AXONWALL_AUTOCOMMIT_ON_APPLY=0\n")
	}

	confPath := m.confFilePath()
	if err := os.MkdirAll(filepath.Dir(confPath), 0755); err != nil {
		return EtckeeperConfig{}, fmt.Errorf("failed to create etckeeper config directory: %w", err)
	}
	if err := os.WriteFile(confPath, []byte(b.String()), 0644); err != nil {
		return EtckeeperConfig{}, fmt.Errorf("failed to write %s: %w", confPath, err)
	}

	if err := m.syncCustomIgnoreLocked(input.CustomIgnorePatterns); err != nil {
		return EtckeeperConfig{}, fmt.Errorf("failed to update /etc/.gitignore patterns: %w", err)
	}

	// Reconcile systemd etckeeper.timer when managing host /etc
	if m.etcDir == "/etc" {
		if input.DailyAutocommit {
			_ = m.execCmd("systemctl", "enable", "--now", "etckeeper.timer").Run()
		} else {
			_ = m.execCmd("systemctl", "disable", "--now", "etckeeper.timer").Run()
		}
	}

	// Commit the configuration update itself if repository is initialized
	if _, err := os.Stat(filepath.Join(m.etcDir, ".git")); err == nil {
		_ = m.commitLocked("Updated etckeeper configuration via Axonwall Web Console", "admin")
	}

	return m.readConfigLocked(), nil
}

// GetStatus returns the current status of etckeeper repository in /etc.
func (m *EtckeeperManager) GetStatus() EtckeeperStatus {
	m.mu.Lock()
	defer m.mu.Unlock()

	cfg := m.readConfigLocked()
	status := EtckeeperStatus{
		Installed:     m.IsInstalled(),
		TrackedPath:   m.etcDir,
		VCS:           cfg.VCS,
		Clean:         false,
		Initialized:   false,
		ModifiedFiles: []EtckeeperFileChange{},
		Config:        cfg,
	}

	if !status.Installed {
		return status
	}

	// Check systemd timer state if available
	if m.etcDir == "/etc" {
		cmdTimer := m.execCmd("systemctl", "show", "etckeeper.timer", "--property=ActiveState,UnitFileState,NextElapseUSecRealtime,LastTriggerUSec")
		if out, err := cmdTimer.Output(); err == nil {
			for _, line := range strings.Split(string(out), "\n") {
				parts := strings.SplitN(strings.TrimSpace(line), "=", 2)
				if len(parts) != 2 {
					continue
				}
				k, v := parts[0], strings.TrimSpace(parts[1])
				switch k {
				case "ActiveState":
					status.TimerActive = v == "active"
				case "UnitFileState":
					status.TimerEnabled = v == "enabled" || v == "static"
				case "NextElapseUSecRealtime":
					if v != "" && v != "n/a" && v != "0" {
						status.NextTimerRun = v
					}
				case "LastTriggerUSec":
					if v != "" && v != "n/a" && v != "0" {
						status.LastTimerRun = v
					}
				}
			}
		}
	}

	// Check if repository exists
	if _, err := os.Stat(filepath.Join(m.etcDir, ".git")); os.IsNotExist(err) {
		return status
	}
	status.Initialized = true

	// Check git status
	cmdStatus := m.gitCmd("status", "--porcelain")
	if out, err := cmdStatus.Output(); err == nil {
		rawStatus := strings.TrimSpace(string(out))
		status.Clean = len(rawStatus) == 0
		if rawStatus != "" {
			for _, line := range strings.Split(string(out), "\n") {
				if len(line) < 3 {
					continue
				}
				st := strings.TrimSpace(line[:2])
				filePath := strings.TrimSpace(line[3:])
				if st == "" {
					st = "M"
				}
				if filePath != "" {
					status.ModifiedFiles = append(status.ModifiedFiles, EtckeeperFileChange{
						Status: st,
						Path:   filePath,
					})
				}
			}
		}
	}
	// A-L26: a failed git status leaves Clean false. The old code
	// defaulted Clean to true and never cleared it, so a broken
	// /etc/.git reported "Installed: true, Clean: true".

	// Check last commit
	cmdLog := m.gitCmd("log", "-1", "--format=%H|%s|%aI|%an")
	if out, err := cmdLog.Output(); err == nil {
		parts := strings.Split(strings.TrimSpace(string(out)), "|")
		if len(parts) >= 3 {
			status.LastCommitHash = parts[0]
			status.LastCommitMsg = parts[1]
			if t, err := time.Parse(time.RFC3339, parts[2]); err == nil {
				status.LastCommitTime = t
			}
			if len(parts) >= 4 {
				status.LastCommitAuthor = parts[3]
			}
		}
	}

	// Count total commits
	cmdCount := m.gitCmd("rev-list", "--count", "HEAD")
	if out, err := cmdCount.Output(); err == nil {
		if n, err := strconv.Atoi(strings.TrimSpace(string(out))); err == nil && n > 0 {
			status.TotalCommits = n
		}
	}

	return status
}

// GetHistory retrieves the recent commit history from /etc etckeeper.
func (m *EtckeeperManager) GetHistory(limit int) ([]EtckeeperCommitLog, error) {
	return m.GetHistoryFiltered(limit, "")
}

// GetHistoryFiltered retrieves recent commit history from /etc etckeeper with an optional path filter.
func (m *EtckeeperManager) GetHistoryFiltered(limit int, pathFilter string) ([]EtckeeperCommitLog, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.IsInstalled() {
		return nil, fmt.Errorf("etckeeper is not installed")
	}

	if limit <= 0 || limit > 200 {
		limit = 50
	}

	args := []string{"log", fmt.Sprintf("-n%d", limit), "--format=%H|%an|%aI|%s"}
	cleanPath := strings.TrimSpace(pathFilter)
	if cleanPath != "" {
		cleanPath = strings.TrimPrefix(cleanPath, "/etc/")
		cleanPath = strings.TrimPrefix(cleanPath, "/")
		if !safeEtckeeperPathFltRe.MatchString(cleanPath) || strings.Contains(cleanPath, "..") {
			return nil, fmt.Errorf("invalid path filter %q", pathFilter)
		}
		args = append(args, "--", cleanPath)
	}

	cmdLog := m.gitCmd(args...)
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
		shortHash := parts[0]
		if len(shortHash) > 8 {
			shortHash = shortHash[:8]
		}
		item := EtckeeperCommitLog{
			Hash:      parts[0],
			ShortHash: shortHash,
			Author:    parts[1],
			Subject:   parts[3],
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
		cmd = m.gitCmd("show", "--stat", "--patch", cleanHash, "--")
	} else {
		cmd = m.gitCmd("diff")
	}

	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("failed to get diff: %v, out: %s", err, string(out))
	}

	diffStr := string(out)
	// When inspecting uncommitted changes and git diff (unstaged) is empty, check for staged or untracked files
	if commitHash == "" && strings.TrimSpace(diffStr) == "" {
		statusCmd := m.gitCmd("status", "--porcelain")
		if statusOut, sErr := statusCmd.Output(); sErr == nil && strings.TrimSpace(string(statusOut)) != "" {
			var b strings.Builder
			b.WriteString("# Working tree has staged or untracked files pending commit:\n")
			for _, line := range strings.Split(strings.TrimSpace(string(statusOut)), "\n") {
				b.WriteString(line + "\n")
			}
			return b.String(), nil
		}
	}

	return diffStr, nil
}

// Close stops any pending background debounce timers.
func (m *EtckeeperManager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.pendingTimer != nil {
		m.pendingTimer.Stop()
	}
}
