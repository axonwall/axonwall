package engine

import (
	"bufio"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math/bits"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

type PasswordPolicyConfig struct {
	MinLength                     int  `json:"minLength"`
	MaxFailures                   int  `json:"maxFailures"`
	LockoutDurationSeconds        int  `json:"lockoutDurationSeconds"`
	HistoryCount                  int  `json:"historyCount"`
	MaxAgeDays                    int  `json:"maxAgeDays"`
	DisableRootSshWhenAdminExists bool `json:"disableRootSshWhenAdminExists"`
}

func DefaultPasswordPolicyConfig() PasswordPolicyConfig {
	return PasswordPolicyConfig{
		MinLength:                     12,
		MaxFailures:                   5,
		LockoutDurationSeconds:        900,
		HistoryCount:                  5,
		MaxAgeDays:                    0,
		DisableRootSshWhenAdminExists: true,
	}
}

type DirectoryStatus struct {
	SlapdRunning        bool                 `json:"slapdRunning"`
	SssdRunning         bool                 `json:"sssdRunning"`
	BaseDN              string               `json:"baseDn"`
	ServerID            int                  `json:"serverId"`
	HaSyncEnabled       bool                 `json:"haSyncEnabled"`
	HaRole              string               `json:"haRole"`
	PeerURI             string               `json:"peerUri,omitempty"`
	ContextCSN          string               `json:"contextCsn,omitempty"`
	PeerContextCSN      string               `json:"peerContextCsn,omitempty"`
	InSync              bool                 `json:"inSync"`
	ClockSkewMs         float64              `json:"clockSkewMs"`
	RootSshDisabled     bool                 `json:"rootSshDisabled"`
	TotalDirectoryUsers int                  `json:"totalDirectoryUsers"`
	AdminUsersCount     int                  `json:"adminUsersCount"`
	UnmigratedLocalCount int                 `json:"unmigratedLocalCount"`
	// AdminSeedError records a break-glass admin seeding failure (A-M32):
	// when set, the box may have no admin account.
	AdminSeedError      string               `json:"adminSeedError,omitempty"`
	PasswordPolicy      PasswordPolicyConfig `json:"passwordPolicy"`
}

type PluginLdapGroupSpec struct {
	CN          string `json:"cn"`
	GIDNumber   int    `json:"gidNumber"`
	Description string `json:"description"`
	Role        string `json:"role"` // "admin", "operator", "readonly"
}

type PluginLDAPSpec struct {
	EnabledByDefault           bool                  `json:"enabledByDefault"`
	ServiceAccountCN           string                `json:"serviceAccountCn"`
	Groups                     []PluginLdapGroupSpec `json:"groups"`
	InheritApplianceRoleGroups bool                  `json:"inheritApplianceRoleGroups"`
	EnvPrefix                  string                `json:"envPrefix"`
}

type PluginLDAPBinding struct {
	PluginID          string              `json:"pluginId"`
	Enabled           bool                `json:"enabled"`
	URL               string              `json:"url"`
	BaseDN            string              `json:"baseDn"`
	BindDN            string              `json:"bindDn"`
	BindPassword      string              `json:"bindPassword"`
	UserSearchBase    string              `json:"userSearchBase"`
	UserSearchFilter  string              `json:"userSearchFilter"`
	GroupSearchBase   string              `json:"groupSearchBase"`
	GroupSearchFilter string              `json:"groupSearchFilter"`
	RoleGroups        map[string][]string `json:"roleGroups"`
	UpdatedAt         string              `json:"updatedAt"`
}

type DirectoryManager struct {
	mu          sync.RWMutex
	baseDN      string
	serverID    int
	haRole      string
	haEnabled   bool
	peerURI     string
	policy      PasswordPolicyConfig
	localUsers  *UserManager
	etckeeper   *EtckeeperManager
	policyFile  string
	// adminSeedError records the last break-glass admin seeding failure
	// (A-M32); surfaced in GetStatus so a box with no admin is visible.
	adminSeedError string
}

func NewDirectoryManager(localUsers *UserManager, etckeeper *EtckeeperManager) *DirectoryManager {
	dm := &DirectoryManager{
		serverID:   1,
		haRole:     "MASTER",
		policy:     DefaultPasswordPolicyConfig(),
		localUsers: localUsers,
		etckeeper:  etckeeper,
		policyFile: "/var/lib/axonwall/ldap/policy.json",
	}
	dm.loadPersistedPolicy()
	baseDN, _, _ := ResolveOrCreateBaseDN("axonwall.local")
	dm.baseDN = baseDN
	return dm
}

func (d *DirectoryManager) loadPersistedPolicy() {
	data, err := os.ReadFile(d.policyFile)
	if err != nil {
		return
	}
	var p PasswordPolicyConfig
	if err := json.Unmarshal(data, &p); err == nil && p.MinLength >= 8 {
		d.policy = p
	}
}

func (d *DirectoryManager) savePersistedPolicy(p PasswordPolicyConfig) {
	_ = os.MkdirAll(filepath.Dir(d.policyFile), 0750)
	if data, err := json.MarshalIndent(p, "", "  "); err == nil {
		_ = os.WriteFile(d.policyFile, data, 0644)
	}
}

// DefaultShellForRole returns the appliance login shell corresponding to the user's role.
func DefaultShellForRole(role string) string {
	switch role {
	case "admin":
		return "/usr/bin/zsh"
	case "operator":
		return "/usr/local/bin/axonwall-opshell"
	case "readonly":
		return "/usr/sbin/nologin"
	default:
		return "/usr/bin/zsh"
	}
}

// seedUserZshrc ensures a user's home directory has a .zshrc that loads /etc/zsh/axonwall.zsh
// so ZSH's first-run wizard (zsh-newuser-install) never blocks interactive logins.
func seedUserZshrc(homeDir string, uid, gid int) {
	if homeDir == "" || !strings.HasPrefix(homeDir, "/") {
		return
	}
	_ = os.MkdirAll(homeDir, 0750)
	_ = os.Chown(homeDir, uid, gid)
	zshrcPath := filepath.Join(homeDir, ".zshrc")
	if _, err := os.Stat(zshrcPath); os.IsNotExist(err) {
		content := "# Axonwall ZSH User Profile\n[ -f /etc/zsh/axonwall.zsh ] && source /etc/zsh/axonwall.zsh\n"
		if skelData, err := os.ReadFile("/etc/skel/.zshrc"); err == nil && len(skelData) > 0 {
			content = string(skelData)
		}
		if err := os.WriteFile(zshrcPath, []byte(content), 0640); err == nil {
			_ = os.Chown(zshrcPath, uid, gid)
		}
	}
	omzLink := filepath.Join(homeDir, ".oh-my-zsh")
	if _, err := os.Lstat(omzLink); os.IsNotExist(err) {
		if info, statErr := os.Stat("/usr/share/oh-my-zsh"); statErr == nil && info.IsDir() {
			_ = os.Symlink("/usr/share/oh-my-zsh", omzLink)
		}
	}
}

// Bootstrap initializes OpenLDAP, SSSD, migrates any existing local human accounts,
// seeds the initial break-glass admin if no admin exists, and enforces root SSH policy.
func (d *DirectoryManager) Bootstrap(domain string, serverID int) error {
	d.mu.Lock()
	if serverID >= 1 {
		d.serverID = serverID
	}
	policy := d.policy
	d.mu.Unlock()

	baseDN, err := EnsureOpenLDAPBootstrapped(domain, serverID, policy)
	if err != nil {
		return err
	}

	d.mu.Lock()
	d.baseDN = baseDN
	d.mu.Unlock()

	if err := EnsureSSSDConfigured(baseDN); err != nil {
		log.Printf("[Directory] Warning configuring SSSD: %v", err)
	}

	// Automatically migrate any existing local human users (UID 1000..59999) into OpenLDAP
	if migrated, err := d.MigrateLocalHumanUsers(); err != nil {
		log.Printf("[Directory] Warning migrating local users: %v", err)
	} else if len(migrated) > 0 {
		log.Printf("[Directory] Migrated local human users into OpenLDAP: %v", migrated)
	}

	// Ensure at least one admin user exists in LDAP; if not, seed initial break-glass 'admin'
	seedErr := d.ensureBreakGlassAdmin()

	d.syncLocalNSSMirrorIfNoSSSD("")
	_ = d.SyncRootSshPolicy()
	d.EnsureAllDefaultPluginLDAPIntegrations()

	// On musl/Alpine systems without SSSD, periodically mirror OpenLDAP users/groups (including HA syncrepl changes)
	if !hasSSSD() {
		go func() {
			ticker := time.NewTicker(15 * time.Second)
			defer ticker.Stop()
			for range ticker.C {
				d.syncLocalNSSMirrorIfNoSSSD("")
			}
		}()
	}
	// A-M32: a failed admin seeding used to be swallowed entirely.
	// Return it so the startup goroutine logs it (and GetStatus
	// already carries it via AdminSeedError).
	if seedErr != nil {
		return seedErr
	}
	return nil
}

// setAdminSeedError records a break-glass admin seeding failure for
// GetStatus; clearAdminSeedError clears it after a successful seed.
func (d *DirectoryManager) setAdminSeedError(msg string) {
	d.mu.Lock()
	d.adminSeedError = msg
	d.mu.Unlock()
}

func (d *DirectoryManager) clearAdminSeedError() {
	d.mu.Lock()
	d.adminSeedError = ""
	d.mu.Unlock()
}

// ensureBreakGlassAdmin verifies at least one unlocked admin exists in
// LDAP and seeds the break-glass "admin" account when none does.
//
// A-M32 (round 2): the old code skipped this whole block silently when
// the user list failed, and discarded the CreateUser error, so a box
// could boot with no admin account and nothing in the log said so.
// Listing and seeding are now retried, failures are logged loudly,
// recorded for GetStatus, and returned.
func (d *DirectoryManager) ensureBreakGlassAdmin() error {
	var users []LocalUser
	var err error
	for attempt := 0; attempt < 4; attempt++ {
		users, err = d.listLDAPUsersInternal()
		if err == nil {
			break
		}
		log.Printf("[Directory] ERROR: cannot list LDAP users to check for an admin account (attempt %d/4): %v", attempt+1, err)
		if attempt < 3 {
			time.Sleep(time.Duration(attempt+1) * 2 * time.Second)
		}
	}
	if err != nil {
		msg := fmt.Sprintf("break-glass admin seeding skipped: cannot list LDAP users: %v", err)
		log.Printf("[Directory] ERROR: %s — the box may have no admin account", msg)
		d.setAdminSeedError(msg)
		return fmt.Errorf("%s", msg)
	}

	hasAdmin := false
	for _, u := range users {
		if u.ApplianceRole == "admin" && !u.PasswordLocked {
			hasAdmin = true
		}
		// Upgrade existing shell users (admin / os_only) from legacy /bin/bash to /usr/bin/zsh
		if (u.ApplianceRole == "admin" || u.ApplianceRole == "os_only") && (u.Shell == "/bin/bash" || u.Shell == "") {
			zshShell := "/usr/bin/zsh"
			_ = d.UpdateUser(u.Username, UpdateUserRequest{Shell: &zshShell})
		}
		if u.HomeDir != "" && u.UID >= 1000 {
			seedUserZshrc(u.HomeDir, u.UID, u.GID)
		}
	}
	if hasAdmin {
		d.clearAdminSeedError()
		return nil
	}

	adminPass, hasExistingScrypt := d.readInitialAdminPasswordWithState()
	log.Printf("[Directory] No active admin user found in LDAP; seeding default 'admin' account...")
	var savedEnv map[string][]byte
	if hasExistingScrypt {
		savedEnv = make(map[string][]byte)
		for _, p := range []string{"/var/lib/axonwall/etc-axonwall/admin.env", "/etc/axonwall/admin.env", "/etc/axonwall/axonwall.env"} {
			if b, err := os.ReadFile(p); err == nil {
				savedEnv[p] = b
			}
		}
	}
	for attempt := 0; attempt < 3; attempt++ {
		err = d.CreateUser(CreateUserRequest{
			Username:      "admin",
			Comment:       "Axonwall Break-Glass Administrator",
			Password:      adminPass,
			ApplianceRole: "admin",
			Shell:         "/usr/bin/zsh",
		})
		if err == nil {
			break
		}
		log.Printf("[Directory] ERROR: failed to seed break-glass 'admin' account (attempt %d/3): %v", attempt+1, err)
		if attempt < 2 {
			time.Sleep(time.Duration(attempt+1) * 2 * time.Second)
		}
	}
	if err != nil {
		msg := fmt.Sprintf("break-glass admin seeding failed: %v", err)
		log.Printf("[Directory] ERROR: %s — the box may have no admin account", msg)
		d.setAdminSeedError(msg)
		return fmt.Errorf("%s", msg)
	}
	for p, b := range savedEnv {
		_ = os.WriteFile(p, b, 0600)
	}
	d.clearAdminSeedError()
	return nil
}

func (d *DirectoryManager) readInitialAdminPassword() string {
	pw, _ := d.readInitialAdminPasswordWithState()
	return pw
}

func (d *DirectoryManager) readInitialAdminPasswordWithState() (string, bool) {
	sawScrypt := false
	for _, path := range []string{"/var/lib/axonwall/etc-axonwall/admin.env", "/etc/axonwall/admin.env", "/etc/axonwall/axonwall.env"} {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "LOCAL_ADMIN_PASSWORD=") {
				pw := strings.TrimSpace(strings.TrimPrefix(line, "LOCAL_ADMIN_PASSWORD="))
				pw = strings.Trim(pw, `"'`)
				if strings.HasPrefix(pw, "scrypt$") {
					sawScrypt = true
					continue
				}
				if pw != "" {
					return pw, false
				}
			}
		}
	}
	randBytes := make([]byte, 16)
	if _, err := rand.Read(randBytes); err == nil {
		return hex.EncodeToString(randBytes), sawScrypt
	}
	return fmt.Sprintf("axonwall-%d", time.Now().UnixNano()), sawScrypt
}

func pbkdf2SHA256(password, salt []byte, iter, keyLen int) []byte {
	prf := hmac.New(sha256.New, password)
	hashLen := prf.Size()
	numBlocks := (keyLen + hashLen - 1) / hashLen
	var buf [4]byte
	dk := make([]byte, 0, numBlocks*hashLen)
	u := make([]byte, hashLen)
	for block := 1; block <= numBlocks; block++ {
		prf.Reset()
		prf.Write(salt)
		binary.BigEndian.PutUint32(buf[:], uint32(block))
		prf.Write(buf[:])
		dk = prf.Sum(dk)
		t := dk[len(dk)-hashLen:]
		copy(u, t)
		for n := 2; n <= iter; n++ {
			prf.Reset()
			prf.Write(u)
			u = prf.Sum(u[:0])
			for x := range u {
				t[x] ^= u[x]
			}
		}
	}
	return dk[:keyLen]
}

func salsaXOR(tmp *[16]uint32, in, out []uint32) {
	w0 := tmp[0] ^ in[0]
	w1 := tmp[1] ^ in[1]
	w2 := tmp[2] ^ in[2]
	w3 := tmp[3] ^ in[3]
	w4 := tmp[4] ^ in[4]
	w5 := tmp[5] ^ in[5]
	w6 := tmp[6] ^ in[6]
	w7 := tmp[7] ^ in[7]
	w8 := tmp[8] ^ in[8]
	w9 := tmp[9] ^ in[9]
	w10 := tmp[10] ^ in[10]
	w11 := tmp[11] ^ in[11]
	w12 := tmp[12] ^ in[12]
	w13 := tmp[13] ^ in[13]
	w14 := tmp[14] ^ in[14]
	w15 := tmp[15] ^ in[15]

	x0, x1, x2, x3, x4, x5, x6, x7 := w0, w1, w2, w3, w4, w5, w6, w7
	x8, x9, x10, x11, x12, x13, x14, x15 := w8, w9, w10, w11, w12, w13, w14, w15

	for i := 0; i < 8; i += 2 {
		x4 ^= bits.RotateLeft32(x0+x12, 7)
		x8 ^= bits.RotateLeft32(x4+x0, 9)
		x12 ^= bits.RotateLeft32(x8+x4, 13)
		x0 ^= bits.RotateLeft32(x12+x8, 18)

		x9 ^= bits.RotateLeft32(x5+x1, 7)
		x13 ^= bits.RotateLeft32(x9+x5, 9)
		x1 ^= bits.RotateLeft32(x13+x9, 13)
		x5 ^= bits.RotateLeft32(x1+x13, 18)

		x14 ^= bits.RotateLeft32(x10+x6, 7)
		x2 ^= bits.RotateLeft32(x14+x10, 9)
		x6 ^= bits.RotateLeft32(x2+x14, 13)
		x10 ^= bits.RotateLeft32(x6+x2, 18)

		x3 ^= bits.RotateLeft32(x15+x11, 7)
		x7 ^= bits.RotateLeft32(x3+x15, 9)
		x11 ^= bits.RotateLeft32(x7+x3, 13)
		x15 ^= bits.RotateLeft32(x11+x7, 18)

		x1 ^= bits.RotateLeft32(x0+x3, 7)
		x2 ^= bits.RotateLeft32(x1+x0, 9)
		x3 ^= bits.RotateLeft32(x2+x1, 13)
		x0 ^= bits.RotateLeft32(x3+x2, 18)

		x6 ^= bits.RotateLeft32(x5+x4, 7)
		x7 ^= bits.RotateLeft32(x6+x5, 9)
		x4 ^= bits.RotateLeft32(x7+x6, 13)
		x5 ^= bits.RotateLeft32(x4+x7, 18)

		x11 ^= bits.RotateLeft32(x10+x9, 7)
		x8 ^= bits.RotateLeft32(x11+x10, 9)
		x9 ^= bits.RotateLeft32(x8+x11, 13)
		x10 ^= bits.RotateLeft32(x9+x8, 18)

		x12 ^= bits.RotateLeft32(x15+x14, 7)
		x13 ^= bits.RotateLeft32(x12+x15, 9)
		x14 ^= bits.RotateLeft32(x13+x12, 13)
		x15 ^= bits.RotateLeft32(x14+x13, 18)
	}
	x0 += w0
	x1 += w1
	x2 += w2
	x3 += w3
	x4 += w4
	x5 += w5
	x6 += w6
	x7 += w7
	x8 += w8
	x9 += w9
	x10 += w10
	x11 += w11
	x12 += w12
	x13 += w13
	x14 += w14
	x15 += w15

	out[0], tmp[0] = x0, x0
	out[1], tmp[1] = x1, x1
	out[2], tmp[2] = x2, x2
	out[3], tmp[3] = x3, x3
	out[4], tmp[4] = x4, x4
	out[5], tmp[5] = x5, x5
	out[6], tmp[6] = x6, x6
	out[7], tmp[7] = x7, x7
	out[8], tmp[8] = x8, x8
	out[9], tmp[9] = x9, x9
	out[10], tmp[10] = x10, x10
	out[11], tmp[11] = x11, x11
	out[12], tmp[12] = x12, x12
	out[13], tmp[13] = x13, x13
	out[14], tmp[14] = x14, x14
	out[15], tmp[15] = x15, x15
}

func scryptBlockMix(tmp *[16]uint32, in, out []uint32, r int) {
	copy(tmp[:], in[(2*r-1)*16:2*r*16])
	for i := 0; i < 2*r; i += 2 {
		salsaXOR(tmp, in[i*16:], out[i*8:])
		salsaXOR(tmp, in[i*16+16:], out[i*8+r*16:])
	}
}

func hashBreakGlassScrypt(pass string) (string, error) {
	if strings.HasPrefix(pass, "scrypt$") {
		return pass, nil
	}
	saltBytes := make([]byte, 16)
	if _, err := rand.Read(saltBytes); err != nil {
		return "", err
	}
	saltHex := hex.EncodeToString(saltBytes)
	const (
		N      = 16384
		r      = 8
		p      = 1
		keyLen = 64
	)
	b := pbkdf2SHA256([]byte(pass), []byte(saltHex), 1, p*128*r)
	xy := make([]uint32, 64*r)
	v := make([]uint32, 32*N*r)
	var tmp [16]uint32
	x := xy[:32*r]
	y := xy[32*r:]
	for i := 0; i < 32*r; i++ {
		x[i] = binary.LittleEndian.Uint32(b[4*i:])
	}
	for i := 0; i < N; i += 2 {
		copy(v[i*(32*r):], x)
		scryptBlockMix(&tmp, x, y, r)
		copy(v[(i+1)*(32*r):], y)
		scryptBlockMix(&tmp, y, x, r)
	}
	for i := 0; i < N; i += 2 {
		j := int(x[(2*r-1)*16] & uint32(N-1))
		for k := range x {
			x[k] ^= v[j*(32*r)+k]
		}
		scryptBlockMix(&tmp, x, y, r)
		j = int(y[(2*r-1)*16] & uint32(N-1))
		for k := range y {
			y[k] ^= v[j*(32*r)+k]
		}
		scryptBlockMix(&tmp, y, x, r)
	}
	for i, v32 := range x {
		binary.LittleEndian.PutUint32(b[4*i:], v32)
	}
	dk := pbkdf2SHA256([]byte(pass), b, 1, keyLen)
	return fmt.Sprintf("scrypt$%s$%s", saltHex, hex.EncodeToString(dk)), nil
}

func (d *DirectoryManager) syncBreakGlassPasswordFile(password string) {
	if strings.ContainsAny(password, "\n\r\x00") || password == "" {
		return
	}
	storedValue := password
	if !strings.HasPrefix(password, "scrypt$") {
		if hashed, err := hashBreakGlassScrypt(password); err == nil {
			storedValue = hashed
		}
	}
	for _, path := range []string{"/var/lib/axonwall/etc-axonwall/admin.env", "/etc/axonwall/admin.env", "/etc/axonwall/axonwall.env"} {
		info, lerr := os.Lstat(path)
		if lerr != nil || (info.Mode()&os.ModeSymlink) != 0 {
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		lines := strings.Split(string(data), "\n")
		updated := false
		for i, line := range lines {
			if strings.HasPrefix(strings.TrimSpace(line), "LOCAL_ADMIN_PASSWORD=") {
				lines[i] = "LOCAL_ADMIN_PASSWORD=" + storedValue
				updated = true
			}
		}
		if updated {
			_ = os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0600)
		}
	}
}

func (d *DirectoryManager) SetHAState(enabled bool, role string, serverID int, peerURI string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.haEnabled = enabled
	if role != "" {
		d.haRole = strings.ToUpper(role)
	}
	if serverID >= 1 {
		d.serverID = serverID
	}
	d.peerURI = peerURI
}

func (d *DirectoryManager) checkWritePermitted() error {
	d.mu.RLock()
	defer d.mu.RUnlock()
	// A-M18: allowlist, not denylist. The old guard blocked only
	// BACKUP, so a node in FAULT — VRRP failed, NAS and SQLite
	// already demoted to backup behaviour — still accepted identity
	// writes while the real master also accepted them, producing
	// divergent directory state for syncrepl to reconcile. When HA
	// is enabled, only MASTER may write.
	// ASSUMPTION (flagged for product confirmation per the hunt
	// report): FAULT must not write. If FAULT nodes are ever meant
	// to accept writes (e.g. during a transitional window), this
	// allowlist is the place to carve out that exception — but the
	// default must stay fail-closed.
	if d.haEnabled && d.haRole != "MASTER" {
		return fmt.Errorf("appliance is currently in HA %s state; identity directory mutations must be performed on the active MASTER node", d.haRole)
	}
	return nil
}

// ParseLDIFEntries parses ldapsearch -LLL output (including line continuations and :: base64 values)
// into a slice of attribute maps.
func ParseLDIFEntries(raw string) []map[string][]string {
	// Unfold LDIF continuation lines (RFC 2849: newline followed by a single space)
	unfolded := strings.ReplaceAll(raw, "\r\n", "\n")
	unfolded = strings.ReplaceAll(unfolded, "\n ", "")

	var entries []map[string][]string
	blocks := strings.Split(unfolded, "\n\n")
	for _, block := range blocks {
		block = strings.TrimSpace(block)
		if block == "" {
			continue
		}
		attrs := make(map[string][]string)
		scanner := bufio.NewScanner(strings.NewReader(block))
		for scanner.Scan() {
			line := scanner.Text()
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			if strings.Contains(line, ":: ") {
				parts := strings.SplitN(line, ":: ", 2)
				key := strings.ToLower(strings.TrimSpace(parts[0]))
				decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(parts[1]))
				if err == nil {
					attrs[key] = append(attrs[key], string(decoded))
				}
			} else if strings.Contains(line, ": ") {
				parts := strings.SplitN(line, ": ", 2)
				key := strings.ToLower(strings.TrimSpace(parts[0]))
				val := strings.TrimSpace(parts[1])
				attrs[key] = append(attrs[key], val)
			}
		}
		if len(attrs["dn"]) > 0 {
			entries = append(entries, attrs)
		}
	}
	return entries
}

func firstAttr(attrs map[string][]string, key string) string {
	vals := attrs[strings.ToLower(key)]
	if len(vals) > 0 {
		return vals[0]
	}
	return ""
}

func (d *DirectoryManager) listLDAPGroupsInternal() ([]LocalGroup, map[int]string, map[string][]string, error) {
	d.mu.RLock()
	baseDN := d.baseDN
	d.mu.RUnlock()

	gidToName := make(map[int]string)
	userGroups := make(map[string][]string)

	cmd := exec.Command("ldapsearch", "-LLL", "-Y", "EXTERNAL", "-H", "ldapi:///", "-b", "ou=groups,"+baseDN, "(objectClass=posixGroup)")
	out, err := cmd.Output()
	if err != nil {
		return nil, gidToName, userGroups, err
	}

	entries := ParseLDIFEntries(string(out))
	var groups []LocalGroup
	for _, e := range entries {
		name := firstAttr(e, "cn")
		gid, _ := strconv.Atoi(firstAttr(e, "gidNumber"))
		if name == "" {
			continue
		}
		gidToName[gid] = name
		members := e["memberuid"]
		if members == nil {
			members = []string{}
		}
		for _, m := range members {
			userGroups[m] = append(userGroups[m], name)
		}
		protected := name == "axonwall-admin" || name == "axonwall-operator" || name == "axonwall-readonly" || name == "sudo" || name == "adm"
		groups = append(groups, LocalGroup{
			Name:      name,
			GID:       gid,
			Members:   members,
			IsSystem:  false,
			Protected: protected,
		})
	}
	return groups, gidToName, userGroups, nil
}

func (d *DirectoryManager) listLDAPUsersInternal() ([]LocalUser, error) {
	d.mu.RLock()
	baseDN := d.baseDN
	d.mu.RUnlock()

	_, gidToName, userGroups, _ := d.listLDAPGroupsInternal()

	cmd := exec.Command("ldapsearch", "-LLL", "-Y", "EXTERNAL", "-H", "ldapi:///", "-b", "ou=users,"+baseDN, "(objectClass=posixAccount)", "*", "+")
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	entries := ParseLDIFEntries(string(out))
	var users []LocalUser
	for _, e := range entries {
		username := firstAttr(e, "uid")
		if username == "" {
			continue
		}
		uid, _ := strconv.Atoi(firstAttr(e, "uidNumber"))
		gid, _ := strconv.Atoi(firstAttr(e, "gidNumber"))
		comment := firstAttr(e, "gecos")
		if comment == "" {
			comment = firstAttr(e, "cn")
		}
		homeDir := firstAttr(e, "homeDirectory")
		shell := firstAttr(e, "loginShell")
		sshKeys := e["sshpublickey"]
		userPass := firstAttr(e, "userPassword")
		pwdLock := firstAttr(e, "pwdAccountLockedTime")

		primaryGroup := gidToName[gid]
		if primaryGroup == "" {
			primaryGroup = username
		}

		groups := userGroups[username]
		role := ResolveApplianceRole(groups, username)

		hasPassword := userPass != "" && userPass != "!" && userPass != "*"
		locked := pwdLock != "" || strings.HasPrefix(userPass, "!") || strings.HasPrefix(userPass, "{CRYPT}!")

		users = append(users, LocalUser{
			Username:       username,
			UID:            uid,
			GID:            gid,
			Comment:        comment,
			HomeDir:        homeDir,
			Shell:          shell,
			Groups:         groups,
			PrimaryGroup:   primaryGroup,
			IsSystem:       false,
			Protected:      false,
			ApplianceRole:  role,
			HasSSHKeys:     len(sshKeys) > 0,
			SSHKeysCount:   len(sshKeys),
			SSHKeys:        sshKeys,
			HasPassword:    hasPassword,
			PasswordLocked: locked,
		})
	}
	return users, nil
}

// ListUsers returns all LDAP human users merged with local OS daemon accounts (and any unmigrated local accounts).
func (d *DirectoryManager) ListUsers() ([]LocalUser, error) {
	ldapUsers, ldapErr := d.listLDAPUsersInternal()
	osUsers, osErr := d.localUsers.ParsePasswd()
	if ldapErr != nil && osErr != nil {
		return nil, fmt.Errorf("failed to list LDAP users (%v) and OS users (%v)", ldapErr, osErr)
	}

	seen := make(map[string]bool)
	var result []LocalUser
	for _, u := range ldapUsers {
		seen[u.Username] = true
		result = append(result, u)
	}

	for _, u := range osUsers {
		if seen[u.Username] {
			continue
		}
		// Keep root and system daemons (or unmigrated local accounts)
		if u.Username == "root" {
			u.IsSystem = true
			u.Protected = true
		}
		result = append(result, u)
	}
	return result, nil
}

// ListGroups returns all LDAP POSIX groups merged with local OS groups.
func (d *DirectoryManager) ListGroups() ([]LocalGroup, error) {
	ldapGroups, _, _, _ := d.listLDAPGroupsInternal()
	osGroups, err := d.localUsers.ParseGroups()
	if err != nil && len(ldapGroups) == 0 {
		return nil, err
	}

	seen := make(map[string]bool)
	var result []LocalGroup
	for _, g := range ldapGroups {
		seen[g.Name] = true
		result = append(result, g)
	}
	for _, g := range osGroups {
		if seen[g.Name] {
			continue
		}
		result = append(result, g)
	}
	return result, nil
}

// AllocateNextUID allocates a collision-free UID striped by serverID (10000 + serverID + 10*k).
func (d *DirectoryManager) AllocateNextUID() int {
	d.mu.RLock()
	sid := d.serverID
	d.mu.RUnlock()
	if sid < 1 || sid > 9 {
		sid = 1
	}

	used := make(map[int]bool)
	if users, err := d.listLDAPUsersInternal(); err == nil {
		for _, u := range users {
			used[u.UID] = true
		}
	}
	for k := 0; k < 10000; k++ {
		candidate := 10000 + sid + (10 * k)
		if !used[candidate] {
			return candidate
		}
	}
	return 10000 + sid
}

// EnsureLDAPGroupExists creates a posixGroup in ou=groups,<baseDN> if not already present.
func (d *DirectoryManager) EnsureLDAPGroupExists(groupName string, preferredGID int) (int, error) {
	if !validGroupNameRegex.MatchString(groupName) {
		return 0, fmt.Errorf("invalid group name: %s", groupName)
	}
	groups, _, _, err := d.listLDAPGroupsInternal()
	usedGIDs := make(map[int]bool)
	if err == nil {
		for _, g := range groups {
			usedGIDs[g.GID] = true
			if g.Name == groupName {
				return g.GID, nil
			}
		}
	}

	gid := preferredGID
	if gid < 1000 || usedGIDs[gid] {
		d.mu.RLock()
		sid := d.serverID
		d.mu.RUnlock()
		if sid < 1 || sid > 9 {
			sid = 1
		}
		for k := 1; k < 10000; k++ {
			candidate := 10000 + sid + (10 * k)
			if !usedGIDs[candidate] {
				gid = candidate
				break
			}
		}
	}

	d.mu.RLock()
	baseDN := d.baseDN
	d.mu.RUnlock()

	ldif := fmt.Sprintf(`dn: cn=%s,ou=groups,%s
objectClass: top
objectClass: posixGroup
cn: %s
gidNumber: %d
`, groupName, baseDN, groupName, gid)

	cmd := exec.Command("ldapadd", "-c", "-Y", "EXTERNAL", "-H", "ldapi:///")
	cmd.Stdin = strings.NewReader(ldif)
	out, addErr := cmd.CombinedOutput()
	if addErr != nil && !strings.Contains(string(out), "Already exists") {
		return 0, fmt.Errorf("failed to create LDAP group %s: %s (%w)", groupName, string(out), addErr)
	}
	return gid, nil
}

func (d *DirectoryManager) setGroupMembership(groupName, username string, member bool) error {
	d.mu.RLock()
	baseDN := d.baseDN
	d.mu.RUnlock()

	op := "add"
	if !member {
		op = "delete"
	}
	ldif := fmt.Sprintf(`dn: cn=%s,ou=groups,%s
changetype: modify
%s: memberUid
memberUid: %s
`, groupName, baseDN, op, username)

	cmd := exec.Command("ldapmodify", "-Y", "EXTERNAL", "-H", "ldapi:///")
	cmd.Stdin = strings.NewReader(ldif)
	out, err := cmd.CombinedOutput()
	if err != nil {
		outStr := string(out)
		if strings.Contains(outStr, "Type or value exists") || strings.Contains(outStr, "No such attribute") || strings.Contains(outStr, "No such object") {
			return nil
		}
		return fmt.Errorf("ldapmodify group %s failed: %s (%w)", groupName, outStr, err)
	}
	return nil
}

// CreateUser creates a new human user in the OpenLDAP directory (ou=users,<baseDN>).
func (d *DirectoryManager) CreateUser(req CreateUserRequest) error {
	if err := d.checkWritePermitted(); err != nil {
		return err
	}

	username := strings.TrimSpace(req.Username)
	if !validUsernameRegex.MatchString(username) {
		return fmt.Errorf("invalid username '%s': must be 1-32 chars, lowercase alphanumeric, starting with a letter", username)
	}
	if username == "root" || username == "axonwall" || username == "axonwall-controller" || username == "openldap" || username == "ldap" || username == "sshd" || username == "nobody" {
		return fmt.Errorf("username '%s' is reserved for OS system daemons", username)
	}

	existing, err := d.listLDAPUsersInternal()
	if err == nil {
		for _, u := range existing {
			if u.Username == username {
				return fmt.Errorf("user '%s' already exists in LDAP directory", username)
			}
		}
	}

	d.mu.RLock()
	minLen := d.policy.MinLength
	baseDN := d.baseDN
	d.mu.RUnlock()

	if req.Password != "" && len(req.Password) < minLen {
		return fmt.Errorf("password must be at least %d characters long (per appliance password policy)", minLen)
	}

	role := req.ApplianceRole
	if role == "" {
		role = "operator"
	}
	shell := strings.TrimSpace(req.Shell)
	if shell == "" {
		shell = DefaultShellForRole(role)
	}
	if strings.ContainsAny(shell, "\n\r\x00") || !allowedLoginShells[shell] {
		return fmt.Errorf("invalid or disallowed login shell '%s'", shell)
	}

	comment := strings.TrimSpace(req.Comment)
	if strings.ContainsAny(comment, "\n\r\x00") {
		return fmt.Errorf("invalid characters in user comment")
	}
	if comment == "" {
		comment = username
	}
	for _, k := range req.SSHKeys {
		if strings.ContainsAny(k, "\n\r\x00") {
			return fmt.Errorf("invalid newline or control character in SSH public key")
		}
	}

	uid := d.AllocateNextUID()
	gid, err := d.EnsureLDAPGroupExists(username, uid)
	if err != nil {
		return err
	}
	homeDir := "/home/" + username

	passAttr := "userPassword: !"
	if req.Password != "" {
		hash, err := HashSSHA(req.Password)
		if err != nil {
			return err
		}
		passAttr = "userPassword: " + hash
	}

	var sshLines strings.Builder
	for _, k := range req.SSHKeys {
		k = strings.TrimSpace(k)
		if k != "" {
			sshLines.WriteString("sshPublicKey: " + k + "\n")
		}
	}

	ldif := fmt.Sprintf(`dn: uid=%s,ou=users,%s
objectClass: top
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
objectClass: ldapPublicKey
uid: %s
cn: %s
sn: %s
gecos: %s
uidNumber: %d
gidNumber: %d
homeDirectory: %s
loginShell: %s
%s
%s`, username, baseDN, username, comment, username, comment, uid, gid, homeDir, shell, passAttr, sshLines.String())

	cmd := exec.Command("ldapadd", "-Y", "EXTERNAL", "-H", "ldapi:///")
	cmd.Stdin = strings.NewReader(ldif)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to create LDAP user %s: %s (%w)", username, string(out), err)
	}

	// Attach POSIX groups
	groupSet := make(map[string]bool)
	for _, g := range req.Groups {
		g = strings.TrimSpace(g)
		if g != "" {
			groupSet[g] = true
		}
	}
	for _, g := range RoleToGroups(role) {
		groupSet[g] = true
	}
	// Attach POSIX groups
	// A-M27: group-attach failures used to be discarded, so a user could
	// be created "successfully" without its role groups (e.g. sudo) and
	// the admin could not sudo. Attempt every group, then report the
	// failures instead of returning success.
	var groupErrs []string
	for g := range groupSet {
		if _, err := d.EnsureLDAPGroupExists(g, 0); err != nil {
			groupErrs = append(groupErrs, fmt.Sprintf("group %s: ensure failed: %v", g, err))
			continue
		}
		if err := d.setGroupMembership(g, username, true); err != nil {
			groupErrs = append(groupErrs, fmt.Sprintf("group %s: attach failed: %v", g, err))
			continue
		}
		// Also mirror membership in /etc/group for local groups like sudo/adm so OS tools work even if nsswitch caches
		if g == "sudo" || g == "adm" {
			if err := exec.Command("usermod", "-a", "-G", g, username).Run(); err != nil {
				groupErrs = append(groupErrs, fmt.Sprintf("group %s: local mirror failed: %v", g, err))
			}
		}
	}
	if len(groupErrs) > 0 {
		return fmt.Errorf("created LDAP user %s, but failed to attach groups: %s", username, strings.Join(groupErrs, "; "))
	}

	// Pre-create home directory on persistent /var/lib/axonwall/home (bind-mounted at /home) and seed .zshrc
	seedUserZshrc(homeDir, uid, gid)

	if username == "admin" && req.Password != "" {
		d.syncBreakGlassPasswordFile(req.Password)
	}

	d.syncLocalNSSMirrorIfNoSSSD("")
	InvalidateSSSDCache(username)
	_ = d.SyncRootSshPolicy()
	return nil
}

// UpdateUser modifies an existing user in the OpenLDAP directory.
func (d *DirectoryManager) UpdateUser(username string, req UpdateUserRequest) error {
	if err := d.checkWritePermitted(); err != nil {
		return err
	}

	username = strings.TrimSpace(username)
	if !validUsernameRegex.MatchString(username) {
		return fmt.Errorf("invalid username: %s", username)
	}

	// If root, delegate to local UserManager for SSH keys / password
	if username == "root" {
		return d.localUsers.UpdateUser(username, req)
	}

	users, err := d.listLDAPUsersInternal()
	if err != nil {
		return err
	}
	var target *LocalUser
	for i := range users {
		if users[i].Username == username {
			target = &users[i]
			break
		}
	}
	if target == nil {
		return fmt.Errorf("user '%s' not found in LDAP directory", username)
	}

	d.mu.RLock()
	minLen := d.policy.MinLength
	baseDN := d.baseDN
	d.mu.RUnlock()

	if req.Password != nil && *req.Password != "" && len(*req.Password) < minLen {
		return fmt.Errorf("password must be at least %d characters long (per appliance password policy)", minLen)
	}

	var mods []string
	if req.Comment != nil {
		if strings.ContainsAny(*req.Comment, "\n\r\x00") {
			return fmt.Errorf("invalid characters in user comment")
		}
		c := strings.TrimSpace(*req.Comment)
		if c == "" {
			c = username
		}
		mods = append(mods, fmt.Sprintf("replace: gecos\ngecos: %s\n-\nreplace: cn\ncn: %s", c, c))
	}

	if req.Shell != nil && strings.TrimSpace(*req.Shell) != "" {
		sh := strings.TrimSpace(*req.Shell)
		if strings.ContainsAny(sh, "\n\r\x00") || !allowedLoginShells[sh] {
			return fmt.Errorf("invalid or disallowed login shell '%s'", sh)
		}
		mods = append(mods, fmt.Sprintf("replace: loginShell\nloginShell: %s", sh))
	} else if req.ApplianceRole != nil && req.Shell == nil {
		mods = append(mods, fmt.Sprintf("replace: loginShell\nloginShell: %s", DefaultShellForRole(*req.ApplianceRole)))
	}

	if req.Password != nil && *req.Password != "" {
		hash, err := HashSSHA(*req.Password)
		if err != nil {
			return err
		}
		mods = append(mods, fmt.Sprintf("replace: userPassword\nuserPassword: %s", hash))
	}

	if req.PasswordLocked != nil {
		if *req.PasswordLocked {
			mods = append(mods, "replace: pwdAccountLockedTime\npwdAccountLockedTime: 000001010000Z")
		} else {
			mods = append(mods, "delete: pwdAccountLockedTime")
		}
	}

	if req.SSHKeys != nil {
		var keyBlock strings.Builder
		keyBlock.WriteString("replace: sshPublicKey\n")
		for _, k := range *req.SSHKeys {
			if strings.ContainsAny(k, "\n\r\x00") {
				return fmt.Errorf("invalid newline or control character in SSH public key")
			}
			k = strings.TrimSpace(k)
			if k != "" {
				keyBlock.WriteString("sshPublicKey: " + k + "\n")
			}
		}
		mods = append(mods, strings.TrimSuffix(keyBlock.String(), "\n"))
	}

	for _, mod := range mods {
		if err := d.runLDAPModify(username, baseDN, mod); err != nil {
			return err
		}
	}

	// Update group memberships if requested
	if req.Groups != nil || req.ApplianceRole != nil {
		desired := make(map[string]bool)
		if req.Groups != nil {
			for _, g := range *req.Groups {
				g = strings.TrimSpace(g)
				if g != "" {
					desired[g] = true
				}
			}
		} else {
			for _, g := range target.Groups {
				if g != "axonwall-admin" && g != "axonwall-operator" && g != "axonwall-readonly" && g != "sudo" {
					desired[g] = true
				}
			}
		}
		if req.ApplianceRole != nil {
			delete(desired, "axonwall-admin")
			delete(desired, "axonwall-operator")
			delete(desired, "axonwall-readonly")
			for _, g := range RoleToGroups(*req.ApplianceRole) {
				desired[g] = true
			}
		}

		// A-M27: a list failure used to be discarded, silently skipping
		// the whole membership sync, and every group add/remove failure
		// was discarded too. Attempt every group, then report failures.
		allGroups, _, _, err := d.listLDAPGroupsInternal()
		if err != nil {
			return fmt.Errorf("failed to list LDAP groups for membership sync of %s: %w", username, err)
		}
		var groupErrs []string
		for _, g := range allGroups {
			if g.Name == username {
				continue
			}
			if err := d.setGroupMembership(g.Name, username, desired[g.Name]); err != nil {
				groupErrs = append(groupErrs, fmt.Sprintf("group %s: sync failed: %v", g.Name, err))
			}
		}
		for g := range desired {
			if _, err := d.EnsureLDAPGroupExists(g, 0); err != nil {
				groupErrs = append(groupErrs, fmt.Sprintf("group %s: ensure failed: %v", g, err))
				continue
			}
			if err := d.setGroupMembership(g, username, true); err != nil {
				groupErrs = append(groupErrs, fmt.Sprintf("group %s: attach failed: %v", g, err))
			}
		}
		if len(groupErrs) > 0 {
			return fmt.Errorf("updated LDAP user %s, but failed to sync groups: %s", username, strings.Join(groupErrs, "; "))
		}
	}

	if username == "admin" && req.Password != nil && *req.Password != "" {
		d.syncBreakGlassPasswordFile(*req.Password)
	}

	d.syncLocalNSSMirrorIfNoSSSD("")
	InvalidateSSSDCache(username)
	_ = d.SyncRootSshPolicy()
	return nil
}

// runLDAPModify applies one LDIF modify block for a user.
//
// A "No such attribute" failure is only benign for delete: operations
// (removing an attribute that was never set, e.g. unlocking a user that
// was never locked). For replace: it means the attribute does not exist
// — which is expected for pwdAccountLockedTime and sshPublicKey, two
// attributes CreateUser never sets — so those retry once as add:.
// Anything else is a real error (A-H6, round 2: the old code swallowed
// "No such attribute" for every modify, silently dropping a first-time
// account lock and a first SSH key).
func (d *DirectoryManager) runLDAPModify(username, baseDN, mod string) error {
	run := func(ldifMod string) (string, error) {
		ldif := fmt.Sprintf("dn: uid=%s,ou=users,%s\nchangetype: modify\n%s\n", username, baseDN, ldifMod)
		cmd := exec.Command("ldapmodify", "-Y", "EXTERNAL", "-H", "ldapi:///")
		cmd.Stdin = strings.NewReader(ldif)
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	out, err := run(mod)
	if err == nil {
		return nil
	}
	if !strings.Contains(out, "No such attribute") {
		return fmt.Errorf("failed to modify LDAP user %s: %s (%w)", username, out, err)
	}
	if strings.HasPrefix(mod, "delete:") {
		return nil
	}
	// replace: on an attribute that does not exist yet — retry as add:
	// when the block targets an add-if-absent attribute and carries
	// values; a bare replace of an absent attribute ("", true) is
	// already in the desired state.
	addMod, ok := replaceToAddForAbsentAttrs(mod)
	if !ok {
		return fmt.Errorf("failed to modify LDAP user %s: %s (%w)", username, out, err)
	}
	if addMod == "" {
		return nil
	}
	if out2, err2 := run(addMod); err2 != nil {
		return fmt.Errorf("failed to modify LDAP user %s: %s (%w)", username, out2, err2)
	}
	return nil
}

// replaceToAddForAbsentAttrs converts a replace: block into an add:
// block when it targets only attributes that may legitimately be absent
// (pwdAccountLockedTime, sshPublicKey — CreateUser never sets them) and
// carries values to add. It reports ok=false when the block targets
// other attributes (a missing attribute there is a real inconsistency,
// not a first-time set) or mixes in other operations. It returns
// ("", true) for a bare replace with no values: deleting an attribute
// that is already absent is the desired end state.
func replaceToAddForAbsentAttrs(mod string) (string, bool) {
	hasAbsentAttr := false
	hasValue := false
	var lines []string
	for _, ln := range strings.Split(mod, "\n") {
		if strings.HasPrefix(ln, "replace: ") {
			attr := strings.TrimSpace(strings.TrimPrefix(ln, "replace: "))
			if attr == "pwdAccountLockedTime" || attr == "sshPublicKey" {
				hasAbsentAttr = true
				lines = append(lines, "add: "+attr)
				continue
			}
			return "", false
		}
		if strings.HasPrefix(ln, "sshPublicKey: ") || strings.HasPrefix(ln, "pwdAccountLockedTime: ") {
			hasValue = true
		}
		lines = append(lines, ln)
	}
	if !hasAbsentAttr {
		return "", false
	}
	if !hasValue {
		return "", true
	}
	return strings.Join(lines, "\n"), true
}

// DeleteUser removes a human user from the OpenLDAP directory (after verifying at least one unlocked admin remains).
func (d *DirectoryManager) DeleteUser(username string, removeHome bool) error {
	if err := d.checkWritePermitted(); err != nil {
		return err
	}

	username = strings.TrimSpace(username)
	if !validUsernameRegex.MatchString(username) {
		return fmt.Errorf("invalid username: %s", username)
	}
	if IsProtectedUser(username, 1000) {
		return fmt.Errorf("cannot delete protected system account '%s'", username)
	}

	users, err := d.listLDAPUsersInternal()
	if err != nil {
		return err
	}

	remainingAdmins := 0
	found := false
	for _, u := range users {
		if u.Username == username {
			found = true
			continue
		}
		if u.ApplianceRole == "admin" && !u.PasswordLocked {
			remainingAdmins++
		}
	}
	if !found {
		return fmt.Errorf("user '%s' not found in LDAP directory", username)
	}
	if remainingAdmins == 0 {
		return fmt.Errorf("cannot delete the last active administrator account '%s'", username)
	}

	d.mu.RLock()
	baseDN := d.baseDN
	d.mu.RUnlock()

	// Remove from all groups. A-H5 (round 2): group-removal failures used
	// to be discarded, so a "deleted" user could keep its roles.
	allGroups, _, _, _ := d.listLDAPGroupsInternal()
	var errs []string
	for _, g := range allGroups {
		if err := d.setGroupMembership(g.Name, username, false); err != nil {
			errs = append(errs, fmt.Sprintf("remove from group %s: %v", g.Name, err))
		}
	}

	// Delete user entry and personal group. A-H5 (round 2): both deletes
	// used to be discarded and the function unconditionally returned nil,
	// so a "deleted" user still existed and could still log in.
	userDN := fmt.Sprintf("uid=%s,ou=users,%s", username, baseDN)
	if err := ldapDeleteEntry(userDN); err != nil {
		errs = append(errs, err.Error())
		// The entry (and its password/SSH keys) is still there: do not
		// remove the home directory or sync the NSS mirror as if the
		// user were gone.
		return fmt.Errorf("failed to delete user '%s': %s", username, strings.Join(errs, "; "))
	}
	groupDN := fmt.Sprintf("cn=%s,ou=groups,%s", username, baseDN)
	if err := ldapDeleteEntry(groupDN); err != nil {
		errs = append(errs, err.Error())
	}

	if removeHome {
		_ = os.RemoveAll(filepath.Join("/home", username))
	}

	d.syncLocalNSSMirrorIfNoSSSD(username)
	InvalidateSSSDCache(username)
	_ = d.SyncRootSshPolicy()
	if len(errs) > 0 {
		return fmt.Errorf("deleted user '%s' but with failures: %s", username, strings.Join(errs, "; "))
	}
	return nil
}

// ldapDeleteEntry deletes one DN with ldapdelete. A missing entry ("No such
// object", e.g. a personal group that was never created) is not an error;
// any other failure is, and must fail the caller's delete (A-H5).
func ldapDeleteEntry(dn string) error {
	out, err := exec.Command("ldapdelete", "-Y", "EXTERNAL", "-H", "ldapi:///", dn).CombinedOutput()
	if err != nil && !strings.Contains(string(out), "No such object") {
		return fmt.Errorf("ldapdelete %s: %s (%w)", dn, strings.TrimSpace(string(out)), err)
	}
	return nil
}

// Authenticate verifies a user's password via OpenLDAP Simple Bind (enforcing ppolicy lockouts),
// with a break-glass fallback to local shadow only for root or when slapd is down.
func (d *DirectoryManager) Authenticate(req AuthUserRequest) AuthUserResponse {
	username := strings.TrimSpace(req.Username)
	password := req.Password
	if username == "" || password == "" {
		return AuthUserResponse{Success: false, Message: "Username and password required"}
	}
	if !validUsernameRegex.MatchString(username) {
		return AuthUserResponse{Success: false, Message: "Invalid username"}
	}

	if username == "root" {
		return d.localUsers.Authenticate(req)
	}

	d.mu.RLock()
	baseDN := d.baseDN
	d.mu.RUnlock()

	users, err := d.listLDAPUsersInternal()
	if err != nil {
		// Emergency fallback if slapd is unreachable
		return d.localUsers.Authenticate(req)
	}

	var target *LocalUser
	for i := range users {
		if users[i].Username == username {
			target = &users[i]
			break
		}
	}
	if target == nil {
		return d.localUsers.Authenticate(req)
	}
	if target.PasswordLocked {
		return AuthUserResponse{Success: false, Message: "Account is locked by administrator or password policy"}
	}

	// Perform LDAP Simple Bind using a transient 0600 secret file in /run/axonwall (never argv!)
	_ = os.MkdirAll("/run/axonwall", 0750)
	tmpFile, err := os.CreateTemp("/run/axonwall", "ldapbind-*")
	if err != nil {
		return AuthUserResponse{Success: false, Message: "Internal authentication error"}
	}
	tmpPath := tmpFile.Name()
	_ = os.Chmod(tmpPath, 0600)
	_, _ = tmpFile.WriteString(password)
	_ = tmpFile.Close()
	defer os.Remove(tmpPath)

	userDN := fmt.Sprintf("uid=%s,ou=users,%s", username, baseDN)
	cmd := exec.Command("ldapwhoami", "-x", "-H", "ldapi:///", "-D", userDN, "-y", tmpPath)
	out, bindErr := cmd.CombinedOutput()
	if bindErr != nil {
		msg := "Invalid credentials"
		if strings.Contains(string(out), "Account locked") {
			msg = "Account locked due to too many failed login attempts"
		}
		return AuthUserResponse{Success: false, Message: msg}
	}

	return AuthUserResponse{
		Success:       true,
		Username:      target.Username,
		ApplianceRole: target.ApplianceRole,
		Groups:        target.Groups,
	}
}

// UpdatePasswordPolicy updates the OpenLDAP cn=default,ou=policies,<baseDN> entry and persists the policy.
func (d *DirectoryManager) UpdatePasswordPolicy(policy PasswordPolicyConfig) error {
	if err := d.checkWritePermitted(); err != nil {
		return err
	}
	if policy.MinLength < 8 {
		policy.MinLength = 8
	}
	if policy.LockoutDurationSeconds < 60 {
		policy.LockoutDurationSeconds = 60
	}

	d.mu.Lock()
	d.policy = policy
	baseDN := d.baseDN
	d.mu.Unlock()

	d.savePersistedPolicy(policy)

	maxAgeSeconds := policy.MaxAgeDays * 86400
	ldif := fmt.Sprintf(`dn: cn=default,ou=policies,%s
changetype: modify
replace: pwdMinLength
pwdMinLength: %d
-
replace: pwdInHistory
pwdInHistory: %d
-
replace: pwdMaxFailure
pwdMaxFailure: %d
-
replace: pwdLockoutDuration
pwdLockoutDuration: %d
-
replace: pwdMaxAge
pwdMaxAge: %d
`, baseDN, policy.MinLength, policy.HistoryCount, policy.MaxFailures, policy.LockoutDurationSeconds, maxAgeSeconds)

	cmd := exec.Command("ldapmodify", "-Y", "EXTERNAL", "-H", "ldapi:///")
	cmd.Stdin = strings.NewReader(ldif)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to update OpenLDAP password policy: %s (%w)", string(out), err)
	}

	_ = d.SyncRootSshPolicy()
	return nil
}

func cleanNSSField(s string) string {
	return strings.Map(func(r rune) rune {
		if r == ':' || r == '\n' || r == '\r' || r == '\x00' {
			return -1
		}
		return r
	}, s)
}

func isValidNSSIdent(s string) bool {
	if s == "" || len(s) > 32 {
		return false
	}
	for i, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' || r == '.' {
			if i == 0 && (r == '-' || r == '.') {
				return false
			}
			continue
		}
		return false
	}
	return true
}

func writeAtomicNSSFile(targetPath string, data []byte, perm os.FileMode) error {
	tmpPath := targetPath + ".axon_tmp"
	if err := os.WriteFile(tmpPath, data, perm); err != nil {
		return err
	}
	return os.Rename(tmpPath, targetPath)
}

// syncLocalNSSMirrorIfNoSSSD mirrors OpenLDAP POSIX users and groups into /etc/passwd, /etc/group, and /etc/shadow
// on musl/Alpine Linux systems where libnss_sss is not available.
func (d *DirectoryManager) syncLocalNSSMirrorIfNoSSSD(deletedUser string) {
	if hasSSSD() {
		return
	}

	ldapUsers, err := d.listLDAPUsersInternal()
	if err != nil {
		return
	}
	ldapGroups, _, _, _ := d.listLDAPGroupsInternal()

	ldapUserByName := make(map[string]LocalUser, len(ldapUsers))
	for _, u := range ldapUsers {
		cleanU := cleanNSSField(u.Username)
		if !isValidNSSIdent(cleanU) {
			continue
		}
		ldapUserByName[cleanU] = u
		if u.HomeDir != "" && u.UID >= 1000 {
			seedUserZshrc(u.HomeDir, u.UID, u.GID)
		}
	}

	// 1. Synchronize /etc/group
	ldapGroupByName := make(map[string]LocalGroup, len(ldapGroups))
	for _, g := range ldapGroups {
		cleanG := cleanNSSField(g.Name)
		if isValidNSSIdent(cleanG) {
			ldapGroupByName[cleanG] = g
		}
	}
	if groupBytes, err := os.ReadFile("/etc/group"); err == nil {
		var newGroupLines []string
		seenGroups := make(map[string]bool)
		for _, line := range strings.Split(string(groupBytes), "\n") {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" || strings.HasPrefix(trimmed, "#") {
				if line != "" {
					newGroupLines = append(newGroupLines, line)
				}
				continue
			}
			parts := strings.Split(trimmed, ":")
			if len(parts) < 4 {
				newGroupLines = append(newGroupLines, line)
				continue
			}
			gName := parts[0]
			gGID, _ := strconv.Atoi(parts[2])
			if deletedUser != "" && gName == deletedUser {
				continue
			}
			if lg, ok := ldapGroupByName[gName]; ok {
				seenGroups[gName] = true
				// Merge existing local system members with LDAP members
				memberMap := make(map[string]bool)
				var mergedMembers []string
				if parts[3] != "" {
					for _, m := range strings.Split(parts[3], ",") {
						m = strings.TrimSpace(m)
						if m == "" || m == deletedUser {
							continue
						}
						// Keep non-LDAP members or still-valid LDAP members
						if _, isLDAP := ldapUserByName[m]; !isLDAP {
							memberMap[m] = true
							mergedMembers = append(mergedMembers, m)
						}
					}
				}
				for _, m := range lg.Members {
					cleanM := cleanNSSField(m)
					if cleanM != "" && cleanM != deletedUser && isValidNSSIdent(cleanM) && !memberMap[cleanM] {
						memberMap[cleanM] = true
						mergedMembers = append(mergedMembers, cleanM)
					}
				}
				newGroupLines = append(newGroupLines, fmt.Sprintf("%s:%s:%s:%s", cleanNSSField(gName), parts[1], parts[2], strings.Join(mergedMembers, ",")))
			} else if gGID >= 10000 && gGID < 60000 {
				// Stale LDAP group that was deleted from directory
				continue
			} else {
				newGroupLines = append(newGroupLines, line)
			}
		}
		for _, lg := range ldapGroups {
			cleanG := cleanNSSField(lg.Name)
			if !isValidNSSIdent(cleanG) || seenGroups[cleanG] || (deletedUser != "" && cleanG == deletedUser) {
				continue
			}
			var cleanMembers []string
			for _, m := range lg.Members {
				cleanM := cleanNSSField(m)
				if cleanM != "" && cleanM != deletedUser && isValidNSSIdent(cleanM) {
					cleanMembers = append(cleanMembers, cleanM)
				}
			}
			newGroupLines = append(newGroupLines, fmt.Sprintf("%s:x:%d:%s", cleanG, lg.GID, strings.Join(cleanMembers, ",")))
		}
		newGroupContent := strings.Join(newGroupLines, "\n") + "\n"
		if newGroupContent != string(groupBytes) {
			_ = writeAtomicNSSFile("/etc/group", []byte(newGroupContent), 0644)
		}
	}

	// 2. Synchronize /etc/passwd
	validUsers := make(map[string]bool)
	if passwdBytes, err := os.ReadFile("/etc/passwd"); err == nil {
		var newPasswdLines []string
		seenUsers := make(map[string]bool)
		for _, line := range strings.Split(string(passwdBytes), "\n") {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" || strings.HasPrefix(trimmed, "#") {
				if line != "" {
					newPasswdLines = append(newPasswdLines, line)
				}
				continue
			}
			parts := strings.Split(trimmed, ":")
			if len(parts) < 7 {
				newPasswdLines = append(newPasswdLines, line)
				continue
			}
			uName := parts[0]
			uUID, _ := strconv.Atoi(parts[2])
			if deletedUser != "" && uName == deletedUser {
				continue
			}
			if lu, ok := ldapUserByName[uName]; ok && uName != "root" {
				seenUsers[uName] = true
				validUsers[uName] = true
				gecos := cleanNSSField(strings.ReplaceAll(lu.Comment, ":", " "))
				home := cleanNSSField(lu.HomeDir)
				if home == "" {
					home = "/home/" + cleanNSSField(lu.Username)
				}
				sh := cleanNSSField(lu.Shell)
				if sh == "" {
					sh = DefaultShellForRole(lu.ApplianceRole)
				}
				newPasswdLines = append(newPasswdLines, fmt.Sprintf("%s:x:%d:%d:%s:%s:%s", cleanNSSField(lu.Username), lu.UID, lu.GID, gecos, home, sh))
			} else if uUID >= 10000 && uUID < 60000 {
				// Stale LDAP user removed from directory
				continue
			} else {
				validUsers[uName] = true
				newPasswdLines = append(newPasswdLines, line)
			}
		}
		for _, lu := range ldapUsers {
			cleanU := cleanNSSField(lu.Username)
			if !isValidNSSIdent(cleanU) || seenUsers[cleanU] || cleanU == "root" || (deletedUser != "" && cleanU == deletedUser) {
				continue
			}
			validUsers[cleanU] = true
			gecos := cleanNSSField(strings.ReplaceAll(lu.Comment, ":", " "))
			home := cleanNSSField(lu.HomeDir)
			if home == "" {
				home = "/home/" + cleanU
			}
			sh := cleanNSSField(lu.Shell)
			if sh == "" {
				sh = DefaultShellForRole(lu.ApplianceRole)
			}
			newPasswdLines = append(newPasswdLines, fmt.Sprintf("%s:x:%d:%d:%s:%s:%s", cleanU, lu.UID, lu.GID, gecos, home, sh))
		}
		newPasswdContent := strings.Join(newPasswdLines, "\n") + "\n"
		if newPasswdContent != string(passwdBytes) {
			_ = writeAtomicNSSFile("/etc/passwd", []byte(newPasswdContent), 0644)
		}
	}

	// 3. Synchronize /etc/shadow (use '*' for unlocked LDAP accounts so OpenSSH without PAM permits publickey auth)
	if shadowBytes, err := os.ReadFile("/etc/shadow"); err == nil {
		var newShadowLines []string
		seenShadow := make(map[string]bool)
		for _, line := range strings.Split(string(shadowBytes), "\n") {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" || strings.HasPrefix(trimmed, "#") {
				if line != "" {
					newShadowLines = append(newShadowLines, line)
				}
				continue
			}
			parts := strings.Split(trimmed, ":")
			if len(parts) < 2 {
				newShadowLines = append(newShadowLines, line)
				continue
			}
			uName := parts[0]
			if !validUsers[uName] || (deletedUser != "" && uName == deletedUser) {
				continue
			}
			if lu, ok := ldapUserByName[uName]; ok && uName != "root" {
				seenShadow[uName] = true
				if lu.PasswordLocked {
					parts[1] = "!"
				} else if parts[1] == "" || strings.HasPrefix(parts[1], "!") {
					parts[1] = "*"
				}
				newShadowLines = append(newShadowLines, strings.Join(parts, ":"))
			} else {
				newShadowLines = append(newShadowLines, line)
			}
		}
		for _, lu := range ldapUsers {
			cleanU := cleanNSSField(lu.Username)
			if !isValidNSSIdent(cleanU) || seenShadow[cleanU] || cleanU == "root" || (deletedUser != "" && cleanU == deletedUser) {
				continue
			}
			pwField := "*"
			if lu.PasswordLocked {
				pwField = "!"
			}
			newShadowLines = append(newShadowLines, fmt.Sprintf("%s:%s:19723:0:99999:7:::", cleanU, pwField))
		}
		newShadowContent := strings.Join(newShadowLines, "\n") + "\n"
		if newShadowContent != string(shadowBytes) {
			_ = writeAtomicNSSFile("/etc/shadow", []byte(newShadowContent), 0640)
		}
	}
}

// axonwallSshdConfPath is the sshd drop-in written by SyncRootSshPolicy.
// It is a variable so tests can point it at a fixture path.
var axonwallSshdConfPath = "/etc/ssh/sshd_config.d/axonwall.conf"

// SyncRootSshPolicy checks whether at least one active axonwall-admin user exists in OpenLDAP.
// Once an admin user exists (and DisableRootSshWhenAdminExists is true), it sets PermitRootLogin no
// in /etc/ssh/sshd_config.d/axonwall.conf and reloads sshd.
func (d *DirectoryManager) SyncRootSshPolicy() error {
	d.mu.RLock()
	disableRoot := d.policy.DisableRootSshWhenAdminExists
	d.mu.RUnlock()

	adminCount := 0
	if users, err := d.listLDAPUsersInternal(); err == nil {
		for _, u := range users {
			// Count unlocked admin users (specifically human admins with SSH keys or custom accounts, or any unlocked admin)
			if u.ApplianceRole == "admin" && !u.PasswordLocked && (u.Username != "admin" || u.HasSSHKeys) {
				adminCount++
			}
		}
	}

	permitRoot := "prohibit-password"
	if disableRoot && adminCount > 0 {
		permitRoot = "no"
	}

	usePAMLine := ""
	if _, err := os.Stat("/etc/pam.d/sshd"); err == nil {
		usePAMLine = "UsePAM yes\n"
	}

	sshdConf := fmt.Sprintf(`# ==============================================================================
# Axonwall Hardened SSH Configuration (Keys Only + SSSD/OpenLDAP Integration)
# ==============================================================================
PermitRootLogin %s
PasswordAuthentication no
KbdInteractiveAuthentication no
AuthenticationMethods publickey
%sAuthorizedKeysCommand /usr/bin/sss_ssh_authorizedkeys %%u
AuthorizedKeysCommandUser nobody
X11Forwarding no
MaxAuthTries 3
`, permitRoot, usePAMLine)

	confPath := axonwallSshdConfPath
	existing, _ := os.ReadFile(confPath)
	if string(existing) != sshdConf {
		// A-L30: the old code swallowed both the config write and
		// the reload, returning nil while the running sshd kept
		// the old root-login policy. Both failures are errors now.
		if err := os.MkdirAll(filepath.Dir(confPath), 0755); err != nil {
			return fmt.Errorf("failed to create sshd config dir %s: %w", filepath.Dir(confPath), err)
		}
		if err := os.WriteFile(confPath, []byte(sshdConf), 0644); err != nil {
			return fmt.Errorf("failed to write sshd config %s: %w", confPath, err)
		}
		if exec.Command("systemctl", "reload", "ssh").Run() != nil {
			if exec.Command("systemctl", "reload", "sshd").Run() != nil {
				if err := exec.Command("rc-service", "sshd", "reload").Run(); err != nil {
					return fmt.Errorf("failed to reload sshd after updating %s (tried systemctl reload ssh, systemctl reload sshd, rc-service sshd reload): %w", confPath, err)
				}
			}
		}
	}
	return nil
}

// MigrateLocalHumanUsers migrates any human accounts (1000 <= UID < 60000) from /etc/passwd,
// /etc/shadow, and ~/.ssh/authorized_keys into OpenLDAP, preserving their password hashes and SSH keys.
func (d *DirectoryManager) MigrateLocalHumanUsers() ([]string, error) {
	if err := d.checkWritePermitted(); err != nil {
		return nil, err
	}

	osUsers, err := d.localUsers.ParsePasswd()
	if err != nil {
		return nil, err
	}
	shadowMap, _ := d.localUsers.parseShadowInternal()
	ldapUsers, err := d.listLDAPUsersInternal()
	if err != nil {
		return nil, err
	}

	inLDAP := make(map[string]bool)
	for _, u := range ldapUsers {
		inLDAP[u.Username] = true
	}

	d.mu.RLock()
	baseDN := d.baseDN
	d.mu.RUnlock()

	var migrated []string
	for _, u := range osUsers {
		if u.IsSystem || u.Username == "root" || u.Username == "nobody" || inLDAP[u.Username] {
			continue
		}

		// Preserve existing shadow crypt hash if present
		passAttr := "userPassword: !"
		if sh, ok := shadowMap[u.Username]; ok && sh != "" && sh != "!" && sh != "*" && sh != "x" {
			passAttr = "userPassword: {CRYPT}" + sh
		}

		_, _ = d.EnsureLDAPGroupExists(u.Username, u.GID)

		comment := cleanNSSField(strings.TrimSpace(u.Comment))
		if comment == "" {
			comment = u.Username
		}
		shell := strings.TrimSpace(u.Shell)
		if shell == "" || shell == "/bin/bash" || !allowedLoginShells[shell] {
			shell = "/usr/bin/zsh"
		}

		var sshLines strings.Builder
		for _, k := range u.SSHKeys {
			if strings.ContainsAny(k, "\n\r\x00") {
				continue
			}
			k = strings.TrimSpace(k)
			if k != "" {
				sshLines.WriteString("sshPublicKey: " + k + "\n")
			}
		}

		ldif := fmt.Sprintf(`dn: uid=%s,ou=users,%s
objectClass: top
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
objectClass: ldapPublicKey
uid: %s
cn: %s
sn: %s
gecos: %s
uidNumber: %d
gidNumber: %d
homeDirectory: /home/%s
loginShell: %s
%s
%s`, u.Username, baseDN, u.Username, comment, u.Username, comment, u.UID, u.GID, u.Username, shell, passAttr, sshLines.String())

		cmd := exec.Command("ldapadd", "-Y", "EXTERNAL", "-H", "ldapi:///")
		cmd.Stdin = strings.NewReader(ldif)
		if out, err := cmd.CombinedOutput(); err != nil && !strings.Contains(string(out), "Already exists") {
			log.Printf("[Directory] Failed to migrate local user %s to LDAP: %s", u.Username, string(out))
			continue
		}

		// Migrate group memberships and map sudo -> axonwall-admin
		role := u.ApplianceRole
		for _, g := range u.Groups {
			if g == u.Username {
				continue
			}
			_, _ = d.EnsureLDAPGroupExists(g, 0)
			_ = d.setGroupMembership(g, u.Username, true)
		}
		for _, g := range RoleToGroups(role) {
			_, _ = d.EnsureLDAPGroupExists(g, 0)
			_ = d.setGroupMembership(g, u.Username, true)
		}

		seedUserZshrc("/home/"+u.Username, u.UID, u.GID)
		migrated = append(migrated, u.Username)
		InvalidateSSSDCache(u.Username)
	}

	if len(migrated) > 0 {
		d.syncLocalNSSMirrorIfNoSSSD("")
		_ = d.SyncRootSshPolicy()
	}
	return migrated, nil
}

// GetStatus returns live health, replication CSN, clock skew, and policy status for the Identity Directory.
func (d *DirectoryManager) GetStatus() DirectoryStatus {
	d.syncLocalNSSMirrorIfNoSSSD("")

	d.mu.RLock()
	status := DirectoryStatus{
		BaseDN:         d.baseDN,
		ServerID:       d.serverID,
		HaSyncEnabled:  d.haEnabled,
		HaRole:         d.haRole,
		PeerURI:        d.peerURI,
		AdminSeedError: d.adminSeedError,
		PasswordPolicy: d.policy,
	}
	d.mu.RUnlock()

	status.SlapdRunning = exec.Command("systemctl", "is-active", "--quiet", "slapd").Run() == nil ||
		exec.Command("pgrep", "-x", "slapd").Run() == nil
	status.SssdRunning = exec.Command("systemctl", "is-active", "--quiet", "sssd").Run() == nil ||
		exec.Command("pgrep", "-x", "sssd").Run() == nil ||
		(!hasSSSD() && status.SlapdRunning)

	// Check local contextCSN
	if status.SlapdRunning && status.BaseDN != "" {
		cmd := exec.Command("ldapsearch", "-LLL", "-Y", "EXTERNAL", "-H", "ldapi:///", "-b", status.BaseDN, "-s", "base", "contextCSN")
		if out, err := cmd.Output(); err == nil {
			entries := ParseLDIFEntries(string(out))
			if len(entries) > 0 {
				status.ContextCSN = strings.Join(entries[0]["contextcsn"], " | ")
			}
		}
	}

	// Check peer contextCSN if HA sync is enabled and peerURI is configured
	if status.HaSyncEnabled && status.PeerURI != "" && status.BaseDN != "" {
		replPassBytes, _ := os.ReadFile(LDAPReplPassFile)
		replPass := strings.TrimSpace(string(replPassBytes))
		if replPass != "" {
			_ = os.MkdirAll("/run/axonwall", 0750)
			if tmp, err := os.CreateTemp("/run/axonwall", "replcheck-*"); err == nil {
				tmpPath := tmp.Name()
				_ = os.Chmod(tmpPath, 0600)
				_, _ = tmp.WriteString(replPass)
				_ = tmp.Close()
				ctxCmd := exec.Command("ldapsearch", "-LLL", "-x", "-H", status.PeerURI, "-D", "cn=replicator,"+status.BaseDN, "-y", tmpPath, "-b", status.BaseDN, "-s", "base", "contextCSN")
				ctxCmd.Env = append(os.Environ(), "LDAPTLS_CACERT="+HAPKICACertPath)
				if out, err := ctxCmd.Output(); err == nil {
					entries := ParseLDIFEntries(string(out))
					if len(entries) > 0 {
						status.PeerContextCSN = strings.Join(entries[0]["contextcsn"], " | ")
					}
				}
				_ = os.Remove(tmpPath)
			}
		}
		status.InSync = status.ContextCSN != "" && status.ContextCSN == status.PeerContextCSN
	} else {
		status.InSync = status.SlapdRunning
	}

	// Measure chrony clock skew
	if out, err := exec.Command("chronyc", "-c", "tracking").Output(); err == nil {
		// CSV format: field 4 is System time offset in seconds
		parts := strings.Split(strings.TrimSpace(string(out)), ",")
		if len(parts) > 4 {
			if sec, err := strconv.ParseFloat(parts[4], 64); err == nil {
				status.ClockSkewMs = sec * 1000.0
			}
		}
	}

	// Check sshd root login status
	if sshdBytes, err := os.ReadFile("/etc/ssh/sshd_config.d/axonwall.conf"); err == nil {
		status.RootSshDisabled = strings.Contains(string(sshdBytes), "PermitRootLogin no")
	}

	// Count LDAP users and unmigrated local users
	ldapUsers, _ := d.listLDAPUsersInternal()
	status.TotalDirectoryUsers = len(ldapUsers)
	inLDAP := make(map[string]bool)
	for _, u := range ldapUsers {
		inLDAP[u.Username] = true
		if u.ApplianceRole == "admin" && !u.PasswordLocked {
			status.AdminUsersCount++
		}
	}
	if osUsers, err := d.localUsers.ParsePasswd(); err == nil {
		for _, u := range osUsers {
			if !u.IsSystem && u.Username != "root" && !inLDAP[u.Username] {
				status.UnmigratedLocalCount++
			}
		}
	}

	_ = time.Now()
	return status
}

// ldapPluginClientsDir and ldapPluginSecretsDir mirror the
// LDAPPlugin* constants but are variables so tests can redirect the
// binding and secret files at fixtures.
var (
	ldapPluginClientsDir = LDAPPluginClientsDir
	ldapPluginSecretsDir = LDAPPluginSecretsDir
)

// EnsurePluginLDAPIntegration idempotently provisions a dedicated least-privilege LDAP
// service bind account in ou=services,<baseDN>, creates plugin POSIX groups in ou=groups,<baseDN>,
// and writes standard credentials to /etc/axonwall/ldap-plugins/<pluginId>.json and .env.
func (d *DirectoryManager) EnsurePluginLDAPIntegration(pluginID string, spec PluginLDAPSpec) (*PluginLDAPBinding, error) {
	d.mu.RLock()
	baseDN := d.baseDN
	d.mu.RUnlock()

	if baseDN == "" {
		var err error
		baseDN, _, err = ResolveOrCreateBaseDN("axonwall.local")
		if err != nil {
			return nil, fmt.Errorf("failed to resolve LDAP base DN: %w", err)
		}
		d.mu.Lock()
		d.baseDN = baseDN
		d.mu.Unlock()
	}

	_ = os.MkdirAll(ldapPluginClientsDir, 0755)
	_ = os.MkdirAll(ldapPluginSecretsDir, 0700)

	// Ensure ou=services,<baseDN> exists
	ouLdif := fmt.Sprintf("dn: ou=services,%s\nobjectClass: top\nobjectClass: organizationalUnit\nou: services\n", baseDN)
	ouCmd := exec.Command("ldapadd", "-c", "-Y", "EXTERNAL", "-H", "ldapi:///")
	ouCmd.Stdin = strings.NewReader(ouLdif)
	_ = ouCmd.Run()

	svcCN := spec.ServiceAccountCN
	if svcCN == "" {
		svcCN = "svc-" + pluginID
	}
	svcDN := fmt.Sprintf("cn=%s,ou=services,%s", svcCN, baseDN)

	secretFile := filepath.Join(ldapPluginSecretsDir, pluginID+".pw")
	secret, err := ensureRandomSecretFile(secretFile)
	if err != nil {
		return nil, fmt.Errorf("failed to generate plugin LDAP secret: %w", err)
	}

	sshaHash, err := HashSSHA(secret)
	if err != nil {
		return nil, fmt.Errorf("failed to hash plugin LDAP secret: %w", err)
	}

	// Ensure service account exists
	addLdif := fmt.Sprintf(`dn: %s
objectClass: top
objectClass: simpleSecurityObject
objectClass: organizationalRole
cn: %s
description: Axonwall Dedicated LDAP Service Account for %s
userPassword: %s
`, svcDN, svcCN, pluginID, sshaHash)
	cmd := exec.Command("ldapadd", "-c", "-Y", "EXTERNAL", "-H", "ldapi:///")
	cmd.Stdin = strings.NewReader(addLdif)
	out, addErr := cmd.CombinedOutput()
	if addErr != nil && strings.Contains(string(out), "Already exists") {
		modLdif := fmt.Sprintf("dn: %s\nchangetype: modify\nreplace: userPassword\nuserPassword: %s\n", svcDN, sshaHash)
		mCmd := exec.Command("ldapmodify", "-Y", "EXTERNAL", "-H", "ldapi:///")
		mCmd.Stdin = strings.NewReader(modLdif)
		// A-L32: the password rotation was discarded. If the
		// service-account entry exists without a userPassword, a
		// failed rotation leaves the binding's password wrong
		// while the function reports success.
		if modOut, modErr := mCmd.CombinedOutput(); modErr != nil {
			return nil, fmt.Errorf("failed to rotate plugin LDAP service account password for %s: %s (%w)", pluginID, string(modOut), modErr)
		}
	}

	roleGroups := make(map[string][]string)
	if spec.InheritApplianceRoleGroups {
		roleGroups["admin"] = append(roleGroups["admin"], "axonwall-admin")
		roleGroups["operator"] = append(roleGroups["operator"], "axonwall-operator")
		roleGroups["readonly"] = append(roleGroups["readonly"], "axonwall-readonly")
	}

	// Ensure groups exist
	for _, g := range spec.Groups {
		if g.CN != "" {
			_, _ = d.EnsureLDAPGroupExists(g.CN, g.GIDNumber)
			if g.Role != "" {
				roleGroups[g.Role] = append(roleGroups[g.Role], g.CN)
			}
		}
	}

	binding := &PluginLDAPBinding{
		PluginID:          pluginID,
		Enabled:           true,
		URL:               "ldap://127.0.0.1:389",
		BaseDN:            baseDN,
		BindDN:            svcDN,
		BindPassword:      secret,
		UserSearchBase:    "ou=users," + baseDN,
		UserSearchFilter:  "(uid={username})",
		GroupSearchBase:   "ou=groups," + baseDN,
		GroupSearchFilter: "(|(memberUid={username})(member={userDn}))",
		RoleGroups:        roleGroups,
		UpdatedAt:         time.Now().UTC().Format(time.RFC3339),
	}

	// Write /etc/axonwall/ldap-plugins/<pluginId>.json
	// A-L32: the binding-file writes were discarded, so a plugin
	// could be told it was integrated while its binding file did
	// not exist (disk full, read-only dir). The primary files are
	// errors; the per-plugin mirrors below are best-effort copies
	// of the same data and only warn on failure.
	jsonPath := filepath.Join(ldapPluginClientsDir, pluginID+".json")
	jsonData, _ := json.MarshalIndent(binding, "", "  ")
	if err := os.WriteFile(jsonPath, append(jsonData, '\n'), 0640); err != nil {
		return nil, fmt.Errorf("failed to write plugin LDAP binding %s: %w", jsonPath, err)
	}

	// Write /etc/axonwall/ldap-plugins/<pluginId>.env
	envPrefix := spec.EnvPrefix
	if envPrefix == "" {
		envPrefix = strings.ToUpper(strings.ReplaceAll(pluginID, "-", "_")) + "_LDAP_"
	}
	var envBuf strings.Builder
	envBuf.WriteString(fmt.Sprintf("# Managed by Axonwall Identity Engine for %s\n", pluginID))
	envBuf.WriteString(fmt.Sprintf("%sENABLED=true\n", envPrefix))
	envBuf.WriteString(fmt.Sprintf("%sURL=ldap://127.0.0.1:389\n", envPrefix))
	envBuf.WriteString(fmt.Sprintf("%sBASE_DN=%s\n", envPrefix, baseDN))
	envBuf.WriteString(fmt.Sprintf("%sBIND_DN=%s\n", envPrefix, svcDN))
	envBuf.WriteString(fmt.Sprintf("%sBIND_PASSWORD=%s\n", envPrefix, secret))
	envBuf.WriteString(fmt.Sprintf("%sUSER_SEARCH_BASE=ou=users,%s\n", envPrefix, baseDN))
	envBuf.WriteString(fmt.Sprintf("%sUSER_SEARCH_FILTER=(uid={username})\n", envPrefix))
	envBuf.WriteString(fmt.Sprintf("%sGROUP_SEARCH_BASE=ou=groups,%s\n", envPrefix, baseDN))
	envBuf.WriteString(fmt.Sprintf("%sADMIN_GROUPS=%s\n", envPrefix, strings.Join(roleGroups["admin"], ",")))
	envBuf.WriteString(fmt.Sprintf("%sOPERATOR_GROUPS=%s\n", envPrefix, strings.Join(roleGroups["operator"], ",")))
	envBuf.WriteString(fmt.Sprintf("%sREADONLY_GROUPS=%s\n", envPrefix, strings.Join(roleGroups["readonly"], ",")))

	envPath := filepath.Join(ldapPluginClientsDir, pluginID+".env")
	if err := os.WriteFile(envPath, []byte(envBuf.String()), 0640); err != nil {
		return nil, fmt.Errorf("failed to write plugin LDAP binding %s: %w", envPath, err)
	}

	// Also ensure per-plugin destination config dir exists and has copy if standard.
	// These are redundant mirrors of the primary files above: a
	// failed mirror is logged, not fatal.
	var mirrorErrs []string
	mirrorWrite := func(path string, data []byte) {
		if err := os.WriteFile(path, data, 0640); err != nil {
			mirrorErrs = append(mirrorErrs, fmt.Sprintf("%s: %v", path, err))
		}
	}
	if pluginID == "eluvix" {
		_ = os.MkdirAll("/etc/axonwall/eluvix", 0755)
		mirrorWrite("/etc/axonwall/eluvix/ldap.json", append(jsonData, '\n'))
	}
	if pluginID == "vigilant-octo-waffle" {
		_ = os.MkdirAll("/etc/axonwall/vow", 0755)
		mirrorWrite("/etc/axonwall/vow/ldap.json", append(jsonData, '\n'))
	}
	if pluginID == "core-vigilante" || pluginID == "vigilante" {
		mirrorWrite(filepath.Join(ldapPluginClientsDir, "vigilante.json"), append(jsonData, '\n'))
		mirrorWrite(filepath.Join(ldapPluginClientsDir, "vigilante.env"), []byte(envBuf.String()))
		mirrorWrite(filepath.Join(ldapPluginClientsDir, "core-vigilante.json"), append(jsonData, '\n'))
		mirrorWrite(filepath.Join(ldapPluginClientsDir, "core-vigilante.env"), []byte(envBuf.String()))
		_ = os.MkdirAll("/etc/axonwall/vigilante", 0755)
		mirrorWrite("/etc/axonwall/vigilante/ldap.json", append(jsonData, '\n'))
		_ = os.MkdirAll("/var/lib/axonwall/vigilante", 0755)
		mirrorWrite("/var/lib/axonwall/vigilante/ldap.json", append(jsonData, '\n'))
	}
	if len(mirrorErrs) > 0 {
		log.Printf("[Directory] Warning: failed to write plugin LDAP binding mirrors for %s: %s", pluginID, strings.Join(mirrorErrs, "; "))
	}

	return binding, nil
}

// EnsureAllDefaultPluginLDAPIntegrations provisions OpenLDAP service accounts, groups,
// and binding files for core-vigilante and all extension plugins with EnabledByDefault.
func (d *DirectoryManager) EnsureAllDefaultPluginLDAPIntegrations() {
	if _, err := d.EnsurePluginLDAPIntegration("core-vigilante", GetCoreVigilanteLDAPSpec()); err != nil {
		log.Printf("[Directory] Warning provisioning core-vigilante LDAP integration: %v", err)
	}
	for _, def := range GetExtensionPluginDefinitions() {
		if def.LdapIntegration != nil && def.LdapIntegration.EnabledByDefault {
			if _, err := d.EnsurePluginLDAPIntegration(def.ID, *def.LdapIntegration); err != nil {
				log.Printf("[Directory] Warning provisioning %s LDAP integration: %v", def.ID, err)
			}
		}
	}
}

// GetPluginLDAPBinding reads the persisted plugin LDAP binding configuration.
func (d *DirectoryManager) GetPluginLDAPBinding(pluginID string) (*PluginLDAPBinding, error) {
	jsonPath := filepath.Join(LDAPPluginClientsDir, pluginID+".json")
	data, err := os.ReadFile(jsonPath)
	if err != nil {
		return nil, err
	}
	var binding PluginLDAPBinding
	if err := json.Unmarshal(data, &binding); err != nil {
		return nil, err
	}
	return &binding, nil
}
