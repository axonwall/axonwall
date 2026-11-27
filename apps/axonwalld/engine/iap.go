package engine

import (
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// caddyPidFile records the PID of the caddy child so a daemon restart can
// find (and stop) a caddy it did not spawn, and so liveness can be checked
// without trusting the in-memory handle alone (A-M43).
var (
	caddyPidFile     = "/run/axonwall/caddy.pid"
	caddyAdminSocket = "/run/axonwall/caddy-admin.sock"
	iapCaddyfilePath = "/etc/axonwall/Caddyfile"
	iapRunDir        = "/run/axonwall"
)

func enforceCaddyAdminSocketPerms(sockPath string) error {
	return os.Chmod(sockPath, 0600)
}

func validateZeroTrustApp(app ZeroTrustApp) error {
	pubHost := strings.TrimSpace(app.PublicHostname)
	if pubHost == "" || strings.ContainsAny(pubHost, "\n\r{}; \t#\"'\\/?") {
		return fmt.Errorf("invalid characters in zero trust app hostname")
	}
	for _, r := range pubHost {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("invalid characters in zero trust app hostname")
		}
	}

	rawUpstream := app.InternalUpstream
	if strings.TrimSpace(rawUpstream) == "" || rawUpstream != strings.TrimSpace(rawUpstream) {
		return fmt.Errorf("invalid zero trust app upstream")
	}
	if strings.ContainsAny(rawUpstream, "\n\r{}; \t#\"'\\") {
		return fmt.Errorf("invalid characters in zero trust app upstream")
	}
	for _, r := range rawUpstream {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("invalid characters in zero trust app upstream")
		}
	}
	lowerRaw := strings.ToLower(rawUpstream)
	if strings.Contains(lowerRaw, "unix/") || strings.Contains(lowerRaw, ".sock") || strings.Contains(lowerRaw, "/run/axonwall") {
		return fmt.Errorf("disallowed unix socket upstream in zero trust app")
	}
	u, err := url.Parse(rawUpstream)
	if err != nil {
		return fmt.Errorf("invalid zero trust app upstream URL: %w", err)
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return fmt.Errorf("zero trust app upstream scheme %q must be http or https", u.Scheme)
	}
	if u.User != nil {
		return fmt.Errorf("embedded credentials are disallowed in zero trust app upstream")
	}
	host := strings.TrimSpace(u.Hostname())
	if u.Host == "" || host == "" || strings.EqualFold(host, "unix") {
		return fmt.Errorf("zero trust app upstream must specify a valid host")
	}
	if p := u.Port(); p != "" {
		portNum, perr := strconv.Atoi(p)
		if perr != nil || portNum < 1 || portNum > 65535 {
			return fmt.Errorf("invalid port %q in zero trust app upstream", p)
		}
	}
	if (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("zero trust app upstream must not include path, query, or fragment")
	}
	return nil
}

type ZeroTrustApp struct {
	ID               string   `json:"id"`
	Name             string   `json:"name"`
	PublicHostname   string   `json:"publicHostname"`
	InternalUpstream string   `json:"internalUpstream"`
	AllowedRoles     []string `json:"allowedRoles"`
	Enabled          bool     `json:"enabled"`
	Description      string   `json:"description"`
}

type ZeroTrustConfig struct {
	Enabled bool           `json:"enabled"`
	Apps    []ZeroTrustApp `json:"apps"`
}

type IAPManager struct {
	mu  sync.Mutex
	cmd *exec.Cmd
}

func NewIAPManager() *IAPManager {
	return &IAPManager{}
}

func (m *IAPManager) ApplyConfig(configJSON []byte) error {
	var config ZeroTrustConfig
	if err := json.Unmarshal(configJSON, &config); err != nil {
		return fmt.Errorf("failed to unmarshal ZeroTrustConfig: %w", err)
	}

	if !config.Enabled {
		m.Stop()
		return nil
	}

	for _, app := range config.Apps {
		if !app.Enabled {
			continue
		}
		if err := validateZeroTrustApp(app); err != nil {
			return err
		}
	}

	caddyfileContent := m.generateCaddyfile(config)

	caddyfilePath := iapCaddyfilePath
	if err := os.MkdirAll(filepath.Dir(caddyfilePath), 0750); err != nil {
		return fmt.Errorf("failed to create config dir: %w", err)
	}
	_ = os.MkdirAll(iapRunDir, 0750)

	if err := os.WriteFile(caddyfilePath, []byte(caddyfileContent), 0640); err != nil {
		return fmt.Errorf("failed to write Caddyfile: %w", err)
	}

	return m.ReloadCaddy(caddyfilePath)
}

func (m *IAPManager) generateCaddyfile(config ZeroTrustConfig) string {
	var out string

	out += "{\n"
	out += fmt.Sprintf("\tadmin unix/%s\n", caddyAdminSocket)
	out += "}\n\n"

	for _, app := range config.Apps {
		if !app.Enabled {
			continue
		}
		if err := validateZeroTrustApp(app); err != nil {
			continue
		}

		out += fmt.Sprintf("%s {\n", strings.TrimSpace(app.PublicHostname))
		out += fmt.Sprintf("\tforward_auth http://localhost:3000 {\n")
		out += fmt.Sprintf("\t\turi /api/auth/gateway?app_id=%s&roles=%s\n", url.QueryEscape(app.ID), url.QueryEscape(strings.Join(app.AllowedRoles, ",")))
		out += fmt.Sprintf("\t\tcopy_headers X-Remote-User X-Remote-Roles\n")
		out += fmt.Sprintf("\t}\n")
		out += fmt.Sprintf("\treverse_proxy %s\n", app.InternalUpstream)
		out += "}\n\n"
	}

	return out
}

func (m *IAPManager) ReloadCaddy(configPath string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// A-M43 (round 2): the old code decided "running" solely from the
	// in-memory handle (m.cmd != nil), which survives a dead child
	// and is nil after a daemon restart. Liveness is now checked
	// against the actual process (in-memory handle or pidfile), and a
	// start is only reported once the child is alive and listening on
	// its admin socket.
	if m.caddyAliveLocked() {
		// Running: reload via unix admin socket; fallback to process
		// restart if reload fails.
		reloadCmd := exec.Command("caddy", "reload", "--config", configPath, "--adapter", "caddyfile", "--address", "unix/"+caddyAdminSocket)
		if out, err := reloadCmd.CombinedOutput(); err != nil {
			log.Printf("Warning: caddy reload failed (%v: %s), restarting process", err, string(out))
			m.killCaddyLocked()
			return m.startCaddyLocked(configPath)
		}
		if err := enforceCaddyAdminSocketPerms(caddyAdminSocket); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("failed to secure caddy admin socket permissions: %w", err)
		}
		log.Printf("Reloaded Caddy IAP configuration")
		return nil
	}

	// Not running (or the handle is stale): start fresh.
	m.cmd = nil
	return m.startCaddyLocked(configPath)
}

// caddyAliveLocked reports whether a caddy process is actually alive:
// the in-memory child, or a caddy from a previous daemon lifetime
// recorded in the pidfile. Callers must hold m.mu.
func (m *IAPManager) caddyAliveLocked() bool {
	if m.cmd != nil && m.cmd.Process != nil {
		if processAlive(m.cmd.Process.Pid) {
			return true
		}
		// Stale handle: the child is dead. Reap it so it does not
		// linger as a zombie and clear the handle.
		_ = m.cmd.Wait()
		m.cmd = nil
	}
	if pid, err := readCaddyPidFile(); err == nil && processAlive(pid) {
		return true
	}
	return false
}

// killCaddyLocked stops whichever caddy is running (in-memory child or
// pidfile process) and clears the tracking state. Callers must hold m.mu.
func (m *IAPManager) killCaddyLocked() {
	if m.cmd != nil && m.cmd.Process != nil {
		_ = m.cmd.Process.Kill()
		_ = m.cmd.Wait()
		m.cmd = nil
	} else if pid, err := readCaddyPidFile(); err == nil && pid > 0 {
		if proc, err := os.FindProcess(pid); err == nil {
			_ = proc.Kill()
		}
	}
	_ = os.Remove(caddyPidFile)
}

// startCaddyLocked starts caddy and verifies it stays up and exposes its
// admin socket before reporting success. Callers must hold m.mu.
func (m *IAPManager) startCaddyLocked(configPath string) error {
	// A stale admin socket from a crashed caddy would make the
	// liveness check below pass without the new child ever listening,
	// so remove it first (no caddy is alive at this point).
	_ = os.Remove(caddyAdminSocket)
	m.cmd = exec.Command("caddy", "run", "--config", configPath, "--adapter", "caddyfile")
	m.cmd.Stdout = os.Stdout
	m.cmd.Stderr = os.Stderr

	if err := m.cmd.Start(); err != nil {
		m.cmd = nil
		log.Printf("Warning: Failed to start Caddy (IAP): %v", err)
		return err
	}
	_ = os.MkdirAll(filepath.Dir(caddyPidFile), 0750)
	_ = os.WriteFile(caddyPidFile, []byte(strconv.Itoa(m.cmd.Process.Pid)), 0644)

	// A-M43: cmd.Start() succeeding does not mean caddy stays up (a
	// port conflict kills it right after fork). Wait until the child
	// is alive and the admin socket exists; otherwise report the
	// failure instead of claiming the proxy started.
	deadline := time.Now().Add(5 * time.Second)
	for {
		alive := m.cmd != nil && m.cmd.Process != nil && processAlive(m.cmd.Process.Pid)
		if !alive {
			_ = m.cmd.Wait()
			m.cmd = nil
			_ = os.Remove(caddyPidFile)
			return fmt.Errorf("caddy exited during startup (check for a port conflict or bad config)")
		}
		if _, err := os.Stat(caddyAdminSocket); err == nil {
			if err := enforceCaddyAdminSocketPerms(caddyAdminSocket); err != nil {
				m.killCaddyLocked()
				return fmt.Errorf("failed to restrict caddy admin socket permissions: %w", err)
			}
			log.Printf("Started Caddy IAP proxy on port 443")
			return nil
		}
		if time.Now().After(deadline) {
			m.killCaddyLocked()
			return fmt.Errorf("caddy did not expose its admin socket within 5s")
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// processAlive reports whether pid names a living (non-zombie) process.
// Signal(0) alone is not enough: it also succeeds for zombies.
func processAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return false
	}
	// comm is parenthesised and may contain spaces; the state is the
	// first field after the closing paren.
	idx := strings.LastIndexByte(string(data), ')')
	if idx < 0 || idx+2 >= len(data) {
		return false
	}
	return data[idx+2] != 'Z'
}

func readCaddyPidFile() (int, error) {
	data, err := os.ReadFile(caddyPidFile)
	if err != nil {
		return 0, err
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 0, fmt.Errorf("invalid caddy pidfile: %w", err)
	}
	return pid, nil
}

func (m *IAPManager) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()

	// A-M43: the old Stop could only stop a caddy this daemon lifetime
	// spawned; a caddy surviving a daemon restart kept serving the old
	// config after IAP was disabled. Kill by pidfile as well.
	if m.cmd != nil && m.cmd.Process != nil {
		_ = m.cmd.Process.Kill()
		_ = m.cmd.Wait()
		m.cmd = nil
		log.Printf("Stopped Caddy IAP proxy")
	} else if pid, err := readCaddyPidFile(); err == nil && pid > 0 {
		if proc, err := os.FindProcess(pid); err == nil {
			if proc.Signal(syscall.Signal(0)) == nil {
				_ = proc.Kill()
				log.Printf("Stopped Caddy IAP proxy (pid %d from pidfile)", pid)
			}
		}
	}
	_ = os.Remove(caddyPidFile)
}
