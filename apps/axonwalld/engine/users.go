package engine

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

var validUsernameRegex = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
var validGroupNameRegex = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

type LocalUser struct {
	Username       string   `json:"username"`
	UID            int      `json:"uid"`
	GID            int      `json:"gid"`
	Comment        string   `json:"comment"`
	HomeDir        string   `json:"homeDir"`
	Shell          string   `json:"shell"`
	Groups         []string `json:"groups"`
	PrimaryGroup   string   `json:"primaryGroup"`
	IsSystem       bool     `json:"isSystem"`
	Protected      bool     `json:"protected"`
	ApplianceRole  string   `json:"applianceRole"` // "admin", "operator", "readonly", "os_only"
	HasSSHKeys     bool     `json:"hasSSHKeys"`
	SSHKeysCount   int      `json:"sshKeysCount"`
	SSHKeys        []string `json:"sshKeys,omitempty"`
	HasPassword    bool     `json:"hasPassword"`
	PasswordLocked bool     `json:"passwordLocked"`
}

type LocalGroup struct {
	Name      string   `json:"name"`
	GID       int      `json:"gid"`
	Members   []string `json:"members"`
	IsSystem  bool     `json:"isSystem"`
	Protected bool     `json:"protected"`
}

type CreateUserRequest struct {
	Username      string   `json:"username"`
	Comment       string   `json:"comment,omitempty"`
	Password      string   `json:"password,omitempty"`
	Shell         string   `json:"shell,omitempty"`
	ApplianceRole string   `json:"applianceRole,omitempty"` // admin, operator, readonly, os_only
	Groups        []string `json:"groups,omitempty"`
	SSHKeys       []string `json:"sshKeys,omitempty"`
}

type UpdateUserRequest struct {
	Comment        *string   `json:"comment,omitempty"`
	Password       *string   `json:"password,omitempty"`
	Shell          *string   `json:"shell,omitempty"`
	ApplianceRole  *string   `json:"applianceRole,omitempty"`
	Groups         *[]string `json:"groups,omitempty"`
	SSHKeys        *[]string `json:"sshKeys,omitempty"`
	PasswordLocked *bool     `json:"passwordLocked,omitempty"`
}

type AuthUserRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type AuthUserResponse struct {
	Success       bool     `json:"success"`
	Username      string   `json:"username"`
	ApplianceRole string   `json:"applianceRole"`
	Groups        []string `json:"groups"`
	Message       string   `json:"message,omitempty"`
}

type UserManager struct {
	mu         sync.RWMutex
	passwdPath string
	groupPath  string
	shadowPath string
	etckeeper  *EtckeeperManager
}

func NewUserManager(etckeeper *EtckeeperManager) *UserManager {
	return &UserManager{
		passwdPath: "/etc/passwd",
		groupPath:  "/etc/group",
		shadowPath: "/etc/shadow",
		etckeeper:  etckeeper,
	}
}

func NewCustomUserManager(passwdPath, groupPath, shadowPath string, etckeeper *EtckeeperManager) *UserManager {
	return &UserManager{
		passwdPath: passwdPath,
		groupPath:  groupPath,
		shadowPath: shadowPath,
		etckeeper:  etckeeper,
	}
}

// IsSystemUID returns true if the UID represents a system daemon account
func IsSystemUID(uid int, username string) bool {
	if uid == 0 {
		// root is system privileged, but treated as human administrator in UI
		return false
	}
	if username == "nobody" || uid == 65534 {
		return true
	}
	if uid < 1000 || uid >= 60000 {
		return true
	}
	return false
}

// IsProtectedUser returns true if user cannot be deleted or renamed
func IsProtectedUser(username string, uid int) bool {
	if uid == 0 || username == "root" {
		return true
	}
	if username == "axonwall" || username == "sshd" || username == "nobody" {
		return true
	}
	if IsSystemUID(uid, username) {
		return true
	}
	return false
}

// ResolveApplianceRole maps POSIX groups to high-level appliance role
func ResolveApplianceRole(groups []string, username string) string {
	if username == "root" {
		return "admin"
	}
	groupSet := make(map[string]bool)
	for _, g := range groups {
		groupSet[g] = true
	}
	if groupSet["axonwall-admin"] || groupSet["sudo"] || groupSet["wheel"] {
		return "admin"
	}
	if groupSet["axonwall-operator"] {
		return "operator"
	}
	if groupSet["axonwall-readonly"] {
		return "readonly"
	}
	return "os_only"
}

// RoleToGroups returns the required POSIX groups for an appliance role
func RoleToGroups(role string) []string {
	switch role {
	case "admin":
		// Provide axonwall-admin and sudo/wheel
		return []string{"axonwall-admin", "sudo", "adm"}
	case "operator":
		return []string{"axonwall-operator", "adm"}
	case "readonly":
		return []string{"axonwall-readonly"}
	default:
		return nil
	}
}

// ParsePasswd reads users from the passwd file
func (m *UserManager) ParsePasswd() ([]LocalUser, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	file, err := os.Open(m.passwdPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open passwd file %s: %w", m.passwdPath, err)
	}
	defer file.Close()

	// Build map of GID to group name and group memberships
	gidToName, userGroups, err := m.parseGroupsInternal()
	if err != nil {
		gidToName = make(map[int]string)
		userGroups = make(map[string][]string)
	}

	// Build map of shadow status
	shadowMap, _ := m.parseShadowInternal()

	var users []LocalUser
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) < 7 {
			continue
		}

		username := parts[0]
		uid, _ := strconv.Atoi(parts[2])
		gid, _ := strconv.Atoi(parts[3])
		comment := parts[4]
		homeDir := parts[5]
		shell := parts[6]

		primaryGroup := gidToName[gid]
		if primaryGroup == "" {
			primaryGroup = strconv.Itoa(gid)
		}

		groups := userGroups[username]
		// Ensure primary group is included in groups list if not already
		hasPrimary := false
		for _, g := range groups {
			if g == primaryGroup {
				hasPrimary = true
				break
			}
		}
		if !hasPrimary && primaryGroup != "" {
			groups = append([]string{primaryGroup}, groups...)
		}

		isSystem := IsSystemUID(uid, username)
		protected := IsProtectedUser(username, uid)
		role := ResolveApplianceRole(groups, username)

		// Check SSH keys
		sshKeys := m.readUserSSHKeys(homeDir)
		hasSSHKeys := len(sshKeys) > 0

		// Shadow info
		hasPassword := false
		passwordLocked := false
		if sh, ok := shadowMap[username]; ok {
			if sh == "!" || sh == "*" || sh == "x" || sh == "" {
				hasPassword = false
				passwordLocked = true
			} else if strings.HasPrefix(sh, "!") {
				hasPassword = true
				passwordLocked = true
			} else {
				hasPassword = true
				passwordLocked = false
			}
		}

		users = append(users, LocalUser{
			Username:       username,
			UID:            uid,
			GID:            gid,
			Comment:        comment,
			HomeDir:        homeDir,
			Shell:          shell,
			Groups:         groups,
			PrimaryGroup:   primaryGroup,
			IsSystem:       isSystem,
			Protected:      protected,
			ApplianceRole:  role,
			HasSSHKeys:     hasSSHKeys,
			SSHKeysCount:   len(sshKeys),
			SSHKeys:        sshKeys,
			HasPassword:    hasPassword,
			PasswordLocked: passwordLocked,
		})
	}

	return users, scanner.Err()
}

// ParseGroups reads groups and members
func (m *UserManager) ParseGroups() ([]LocalGroup, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	file, err := os.Open(m.groupPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open group file %s: %w", m.groupPath, err)
	}
	defer file.Close()

	var groups []LocalGroup
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) < 4 {
			continue
		}

		name := parts[0]
		gid, _ := strconv.Atoi(parts[2])
		members := []string{}
		if parts[3] != "" {
			for _, m := range strings.Split(parts[3], ",") {
				m = strings.TrimSpace(m)
				if m != "" {
					members = append(members, m)
				}
			}
		}

		isSystem := gid < 1000
		protected := isSystem || name == "root" || name == "sudo" || name == "wheel" || name == "axonwall" || strings.HasPrefix(name, "axonwall-")

		groups = append(groups, LocalGroup{
			Name:      name,
			GID:       gid,
			Members:   members,
			IsSystem:  isSystem,
			Protected: protected,
		})
	}

	return groups, scanner.Err()
}

func (m *UserManager) parseGroupsInternal() (map[int]string, map[string][]string, error) {
	file, err := os.Open(m.groupPath)
	if err != nil {
		return nil, nil, err
	}
	defer file.Close()

	gidToName := make(map[int]string)
	userGroups := make(map[string][]string)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) < 4 {
			continue
		}
		name := parts[0]
		gid, _ := strconv.Atoi(parts[2])
		gidToName[gid] = name

		if parts[3] != "" {
			for _, u := range strings.Split(parts[3], ",") {
				u = strings.TrimSpace(u)
				if u != "" {
					userGroups[u] = append(userGroups[u], name)
				}
			}
		}
	}

	return gidToName, userGroups, scanner.Err()
}

func (m *UserManager) parseShadowInternal() (map[string]string, error) {
	file, err := os.Open(m.shadowPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	shadowMap := make(map[string]string)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) >= 2 {
			shadowMap[parts[0]] = parts[1]
		}
	}
	return shadowMap, scanner.Err()
}

func (m *UserManager) readUserSSHKeys(homeDir string) []string {
	if homeDir == "" {
		return nil
	}
	authKeyPath := filepath.Join(homeDir, ".ssh", "authorized_keys")
	data, err := os.ReadFile(authKeyPath)
	if err != nil {
		return nil
	}
	var keys []string
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			keys = append(keys, line)
		}
	}
	return keys
}

func (m *UserManager) writeUserSSHKeys(username, homeDir string, keys []string) error {
	if homeDir == "" {
		return fmt.Errorf("user %s has no home directory", username)
	}
	sshDir := filepath.Join(homeDir, ".ssh")
	if err := os.MkdirAll(sshDir, 0700); err != nil {
		return fmt.Errorf("failed to create %s: %w", sshDir, err)
	}

	// Lookup user uid and gid
	u, err := user.Lookup(username)
	if err == nil {
		uid, _ := strconv.Atoi(u.Uid)
		gid, _ := strconv.Atoi(u.Gid)
		_ = os.Chown(sshDir, uid, gid)
	}

	authKeyPath := filepath.Join(sshDir, "authorized_keys")
	content := strings.Join(keys, "\n")
	if len(keys) > 0 {
		content += "\n"
	}

	if err := os.WriteFile(authKeyPath, []byte(content), 0600); err != nil {
		return fmt.Errorf("failed to write %s: %w", authKeyPath, err)
	}

	if u != nil {
		uid, _ := strconv.Atoi(u.Uid)
		gid, _ := strconv.Atoi(u.Gid)
		_ = os.Chown(authKeyPath, uid, gid)
	}

	return nil
}

// EnsureGroupExists creates a group if it doesn't already exist
func (m *UserManager) EnsureGroupExists(groupName string) error {
	if !validGroupNameRegex.MatchString(groupName) {
		return fmt.Errorf("invalid group name: %s", groupName)
	}
	groups, err := m.ParseGroups()
	if err == nil {
		for _, g := range groups {
			if g.Name == groupName {
				return nil
			}
		}
	}

	// Try groupadd or addgroup
	if path, err := exec.LookPath("groupadd"); err == nil {
		out, err := exec.Command(path, groupName).CombinedOutput()
		if err != nil && !strings.Contains(string(out), "already exists") {
			return fmt.Errorf("groupadd failed: %s (%w)", string(out), err)
		}
		return nil
	}
	if path, err := exec.LookPath("addgroup"); err == nil {
		out, err := exec.Command(path, groupName).CombinedOutput()
		if err != nil && !strings.Contains(string(out), "already exists") {
			return fmt.Errorf("addgroup failed: %s (%w)", string(out), err)
		}
		return nil
	}

	return fmt.Errorf("neither groupadd nor addgroup found on system")
}

// CreateUser provisions a new local Linux user
func (m *UserManager) CreateUser(req CreateUserRequest) error {
	username := strings.TrimSpace(req.Username)
	if !validUsernameRegex.MatchString(username) {
		return fmt.Errorf("invalid username '%s': must be 1-32 chars, lowercase alphanumeric, starting with a letter", username)
	}

	// Check if already exists
	users, err := m.ParsePasswd()
	if err == nil {
		for _, u := range users {
			if u.Username == username {
				return fmt.Errorf("user '%s' already exists", username)
			}
		}
	}

	shell := req.Shell
	if shell == "" {
		if _, err := os.Stat("/bin/bash"); err == nil {
			shell = "/bin/bash"
		} else {
			shell = "/bin/sh"
		}
	}

	// Determine groups to attach
	groupsToAttach := make(map[string]bool)
	for _, g := range req.Groups {
		g = strings.TrimSpace(g)
		if g != "" {
			groupsToAttach[g] = true
		}
	}

	// Add role groups
	if req.ApplianceRole != "" {
		for _, g := range RoleToGroups(req.ApplianceRole) {
			groupsToAttach[g] = true
		}
	}

	// Ensure all required groups exist on system
	for g := range groupsToAttach {
		_ = m.EnsureGroupExists(g)
	}

	var groupList []string
	for g := range groupsToAttach {
		groupList = append(groupList, g)
	}

	// Execute useradd or adduser
	if useraddPath, err := exec.LookPath("useradd"); err == nil {
		args := []string{"-m", "-s", shell}
		if req.Comment != "" {
			args = append(args, "-c", req.Comment)
		}
		if len(groupList) > 0 {
			args = append(args, "-G", strings.Join(groupList, ","))
		}
		args = append(args, username)

		out, err := exec.Command(useraddPath, args...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("useradd failed: %s (%w)", string(out), err)
		}
	} else if adduserPath, err := exec.LookPath("adduser"); err == nil {
		// Alpine syntax: adduser -D -s <shell> -g <comment> <username>
		args := []string{"-D", "-s", shell}
		if req.Comment != "" {
			args = append(args, "-g", req.Comment)
		}
		args = append(args, username)
		out, err := exec.Command(adduserPath, args...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("adduser failed: %s (%w)", string(out), err)
		}

		// Add to groups in Alpine
		if addgroupPath, err := exec.LookPath("addgroup"); err == nil {
			for _, g := range groupList {
				_ = exec.Command(addgroupPath, username, g).Run()
			}
		}
	} else {
		return fmt.Errorf("neither useradd nor adduser found on system")
	}

	// Set password if provided
	if req.Password != "" {
		if err := m.SetPassword(username, req.Password); err != nil {
			return fmt.Errorf("created user %s, but failed to set password: %w", username, err)
		}
	}

	// Set SSH keys if provided
	if len(req.SSHKeys) > 0 {
		u, err := user.Lookup(username)
		if err == nil {
			_ = m.writeUserSSHKeys(username, u.HomeDir, req.SSHKeys)
		}
	}

	if m.etckeeper != nil {
		m.etckeeper.ScheduleCommit(fmt.Sprintf("Created local user %s via web console", username), "axonwall-ui")
	}

	return nil
}

// UpdateUser modifies an existing user
func (m *UserManager) UpdateUser(username string, req UpdateUserRequest) error {
	username = strings.TrimSpace(username)
	if !validUsernameRegex.MatchString(username) {
		return fmt.Errorf("invalid username: %s", username)
	}

	u, err := user.Lookup(username)
	if err != nil {
		return fmt.Errorf("user '%s' not found: %w", username, err)
	}
	uid, _ := strconv.Atoi(u.Uid)
	if IsSystemUID(uid, username) && username != "root" {
		return fmt.Errorf("cannot modify system daemon user '%s'", username)
	}

	// Update comment / shell / groups via usermod if available
	if req.Comment != nil || req.Shell != nil || req.Groups != nil || req.ApplianceRole != nil {
		if usermodPath, err := exec.LookPath("usermod"); err == nil {
			var args []string
			if req.Comment != nil {
				args = append(args, "-c", *req.Comment)
			}
			if req.Shell != nil {
				args = append(args, "-s", *req.Shell)
			}
			if req.Groups != nil || req.ApplianceRole != nil {
				// Collect groups
				groupMap := make(map[string]bool)
				if req.Groups != nil {
					for _, g := range *req.Groups {
						g = strings.TrimSpace(g)
						if g != "" {
							groupMap[g] = true
						}
					}
				} else {
					// Keep existing groups
					groups, _ := m.ParseGroups()
					for _, g := range groups {
						for _, mem := range g.Members {
							if mem == username && g.Name != "axonwall-admin" && g.Name != "axonwall-operator" && g.Name != "axonwall-readonly" {
								groupMap[g.Name] = true
							}
						}
					}
				}

				if req.ApplianceRole != nil {
					// Remove other appliance roles
					delete(groupMap, "axonwall-admin")
					delete(groupMap, "axonwall-operator")
					delete(groupMap, "axonwall-readonly")
					for _, g := range RoleToGroups(*req.ApplianceRole) {
						groupMap[g] = true
					}
				}

				for g := range groupMap {
					_ = m.EnsureGroupExists(g)
				}

				var gList []string
				for g := range groupMap {
					gList = append(gList, g)
				}
				args = append(args, "-G", strings.Join(gList, ","))
			}

			if len(args) > 0 {
				args = append(args, username)
				out, err := exec.Command(usermodPath, args...).CombinedOutput()
				if err != nil {
					return fmt.Errorf("usermod failed: %s (%w)", string(out), err)
				}
			}
		}
	}

	// Update password if provided
	if req.Password != nil && *req.Password != "" {
		if err := m.SetPassword(username, *req.Password); err != nil {
			return fmt.Errorf("failed to set password: %w", err)
		}
	}

	// Update lock status
	if req.PasswordLocked != nil {
		if *req.PasswordLocked {
			if usermodPath, err := exec.LookPath("usermod"); err == nil {
				_ = exec.Command(usermodPath, "-L", username).Run()
			} else if passwdPath, err := exec.LookPath("passwd"); err == nil {
				_ = exec.Command(passwdPath, "-l", username).Run()
			}
		} else {
			if usermodPath, err := exec.LookPath("usermod"); err == nil {
				_ = exec.Command(usermodPath, "-U", username).Run()
			} else if passwdPath, err := exec.LookPath("passwd"); err == nil {
				_ = exec.Command(passwdPath, "-u", username).Run()
			}
		}
	}

	// Update SSH keys if provided
	if req.SSHKeys != nil {
		if err := m.writeUserSSHKeys(username, u.HomeDir, *req.SSHKeys); err != nil {
			return fmt.Errorf("failed to update SSH keys: %w", err)
		}
	}

	if m.etckeeper != nil {
		m.etckeeper.ScheduleCommit(fmt.Sprintf("Updated local user %s via web console", username), "axonwall-ui")
	}

	return nil
}

// DeleteUser deletes an existing local user
func (m *UserManager) DeleteUser(username string, removeHome bool) error {
	username = strings.TrimSpace(username)
	if !validUsernameRegex.MatchString(username) {
		return fmt.Errorf("invalid username: %s", username)
	}

	u, err := user.Lookup(username)
	if err != nil {
		return fmt.Errorf("user '%s' not found: %w", username, err)
	}
	uid, _ := strconv.Atoi(u.Uid)

	if IsProtectedUser(username, uid) {
		return fmt.Errorf("cannot delete protected user '%s' (UID %d)", username, uid)
	}

	if userdelPath, err := exec.LookPath("userdel"); err == nil {
		args := []string{}
		if removeHome {
			args = append(args, "-r")
		}
		args = append(args, username)
		out, err := exec.Command(userdelPath, args...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("userdel failed: %s (%w)", string(out), err)
		}
	} else if deluserPath, err := exec.LookPath("deluser"); err == nil {
		args := []string{}
		if removeHome {
			args = append(args, "--remove-home")
		}
		args = append(args, username)
		out, err := exec.Command(deluserPath, args...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("deluser failed: %s (%w)", string(out), err)
		}
	} else {
		return fmt.Errorf("neither userdel nor deluser found on system")
	}

	if m.etckeeper != nil {
		m.etckeeper.ScheduleCommit(fmt.Sprintf("Deleted local user %s via web console", username), "axonwall-ui")
	}

	return nil
}

// SetPassword sets a user's password using chpasswd
func (m *UserManager) SetPassword(username, password string) error {
	chpasswdPath, err := exec.LookPath("chpasswd")
	if err != nil {
		return fmt.Errorf("chpasswd not found: %w", err)
	}

	cmd := exec.Command(chpasswdPath)
	cmd.Stdin = strings.NewReader(fmt.Sprintf("%s:%s\n", username, password))
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("chpasswd failed: %s (%w)", string(out), err)
	}
	return nil
}

// Authenticate verifies username and password against Linux shadow/PAM
func (m *UserManager) Authenticate(req AuthUserRequest) AuthUserResponse {
	username := strings.TrimSpace(req.Username)
	password := req.Password

	if username == "" || password == "" {
		return AuthUserResponse{Success: false, Message: "Username and password required"}
	}

	// 1. Get user shadow entry
	shadowMap, err := m.parseShadowInternal()
	if err != nil {
		return AuthUserResponse{Success: false, Message: fmt.Sprintf("Failed to read shadow database: %v", err)}
	}

	hash, exists := shadowMap[username]
	if !exists {
		return AuthUserResponse{Success: false, Message: "Invalid credentials"}
	}

	if hash == "!" || hash == "*" || hash == "x" || hash == "" || strings.HasPrefix(hash, "!") {
		return AuthUserResponse{Success: false, Message: "Account or password locked"}
	}

	// Verify password
	verified := false

	// Strategy A: perl crypt()
	if perlPath, err := exec.LookPath("perl"); err == nil {
		cmd := exec.Command(perlPath, "-e", "exit(crypt($ARGV[0], $ARGV[1]) eq $ARGV[1] ? 0 : 1)", password, hash)
		if err := cmd.Run(); err == nil {
			verified = true
		}
	}

	// Strategy B: python3 crypt (if perl not available or failed)
	if !verified {
		if pyPath, err := exec.LookPath("python3"); err == nil {
			script := `import crypt, sys; sys.exit(0 if crypt.crypt(sys.argv[1], sys.argv[2]) == sys.argv[2] else 1)`
			cmd := exec.Command(pyPath, "-c", script, password, hash)
			if err := cmd.Run(); err == nil {
				verified = true
			}
		}
	}

	// Strategy C: unix_chkpwd
	if !verified {
		for _, path := range []string{"/usr/bin/unix_chkpwd", "/sbin/unix_chkpwd"} {
			if _, err := os.Stat(path); err == nil {
				cmd := exec.Command(path, username, "nullok")
				cmd.Stdin = bytes.NewReader([]byte(password + "\x00"))
				if err := cmd.Run(); err == nil {
					verified = true
					break
				}
			}
		}
	}

	if !verified {
		return AuthUserResponse{Success: false, Message: "Invalid credentials"}
	}

	// Resolve user groups and role
	_, userGroups, _ := m.parseGroupsInternal()
	groups := userGroups[username]
	role := ResolveApplianceRole(groups, username)

	return AuthUserResponse{
		Success:       true,
		Username:      username,
		ApplianceRole: role,
		Groups:        groups,
	}
}
