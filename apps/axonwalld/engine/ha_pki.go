package engine

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
	"time"
)

const (
	HAPKIDir          = "/var/lib/axonwall/secrets/ha-pki"
	HAPKICACertPath   = "/var/lib/axonwall/secrets/ha-pki/ca.crt"
	HAPKICAKeyPath    = "/var/lib/axonwall/secrets/ha-pki/ca.key"
	HAPKINodeCertPath = "/var/lib/axonwall/secrets/ha-pki/node.crt"
	HAPKINodeKeyPath  = "/var/lib/axonwall/secrets/ha-pki/node.key"
	HAPKIPeerCertPath = "/var/lib/axonwall/secrets/ha-pki/peer-node.crt"
)

type HAPKIBundle struct {
	CACertPEM      string `json:"caCertPem"`
	CAKeyPEM       string `json:"caKeyPem,omitempty"`
	NodeCertPEM    string `json:"nodeCertPem"`
	NodeKeyPEM     string `json:"nodeKeyPem,omitempty"`
	LDAPReplSecret string `json:"ldapReplSecret"`
	LDAPBaseDN     string `json:"ldapBaseDn"`
}

type HAPKICSRRequest struct {
	CSRPEM   string   `json:"csrPem"`
	ExtraIPs []string `json:"extraIps,omitempty"`
}

type HAPKICSRResponse struct {
	CACertPEM         string `json:"caCertPem"`
	SignedCertPEM     string `json:"signedCertPem"`
	PeerSignerCertPEM string `json:"peerSignerCertPem"`
	LDAPReplSecret    string `json:"ldapReplSecret"`
	LDAPBaseDN        string `json:"ldapBaseDn"`
}

// HasHAPKI reports whether valid HA PKI mTLS certificates and keys are installed on this node.
func HasHAPKI() bool {
	_, err := LoadHAPKITLSConfig()
	return err == nil
}

// EnsureHAPKICerts generates or loads the internal HA Root CA and node leaf certificate
// (with IP SANs for 127.0.0.1, localSyncIP, and peerSyncIP) in /var/lib/axonwall/secrets/ha-pki/.
func EnsureHAPKICerts(hostname, localSyncIP, peerSyncIP string) error {
	if err := EnsureHAPKICertsInDir(HAPKIDir, HAPKICACertPath, HAPKICAKeyPath, HAPKINodeCertPath, HAPKINodeKeyPath, hostname, localSyncIP, peerSyncIP); err != nil {
		return err
	}
	fixHAPKIPermissions()
	return nil
}

// EnsureHAPKICertsInDir generates or loads the HA Root CA and node leaf certificate at custom paths.
func EnsureHAPKICertsInDir(dir, caCertPath, caKeyPath, nodeCertPath, nodeKeyPath, hostname, localSyncIP, peerSyncIP string) error {
	if err := os.MkdirAll(dir, 0750); err != nil {
		return err
	}

	// 1. Ensure Root CA exists
	var caCert *x509.Certificate
	var caKey *ecdsa.PrivateKey

	caCertBytes, errCert := os.ReadFile(caCertPath)
	caKeyBytes, errKey := os.ReadFile(caKeyPath)
	if errCert == nil && errKey == nil {
		certBlock, _ := pem.Decode(caCertBytes)
		keyBlock, _ := pem.Decode(caKeyBytes)
		if certBlock != nil && keyBlock != nil {
			caCert, _ = x509.ParseCertificate(certBlock.Bytes)
			caKey, _ = x509.ParseECPrivateKey(keyBlock.Bytes)
		}
	}

	if caCert == nil || caKey == nil {
		var err error
		caKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return fmt.Errorf("failed to generate HA CA key: %w", err)
		}
		serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
		tmpl := &x509.Certificate{
			SerialNumber: serial,
			Subject: pkix.Name{
				Organization: []string{"Axonwall High Availability Cluster"},
				CommonName:   "Axonwall HA Internal Root CA",
			},
			NotBefore:             time.Now().Add(-1 * time.Hour),
			NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
			BasicConstraintsValid: true,
			IsCA:                  true,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &caKey.PublicKey, caKey)
		if err != nil {
			return fmt.Errorf("failed to create HA CA certificate: %w", err)
		}
		caCert, _ = x509.ParseCertificate(der)

		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		keyDER, _ := x509.MarshalECPrivateKey(caKey)
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

		if err := os.WriteFile(caCertPath, certPEM, 0644); err != nil {
			return err
		}
		if err := os.WriteFile(caKeyPath, keyPEM, 0600); err != nil {
			return err
		}
	}

	// 2. Generate or regenerate node leaf certificate if missing or missing required IP SAN
	needNodeCert := false
	if nodeBytes, err := os.ReadFile(nodeCertPath); err != nil {
		needNodeCert = true
	} else if block, _ := pem.Decode(nodeBytes); block != nil {
		if parsed, err := x509.ParseCertificate(block.Bytes); err == nil {
			if localSyncIP != "" {
				hasIP := false
				for _, ip := range parsed.IPAddresses {
					if ip.String() == localSyncIP {
						hasIP = true
						break
					}
				}
				if !hasIP {
					needNodeCert = true
				}
			}
		} else {
			needNodeCert = true
		}
	} else {
		needNodeCert = true
	}

	if needNodeCert {
		if err := issueNodeCert(caCert, caKey, hostname, localSyncIP, peerSyncIP, nodeCertPath, nodeKeyPath); err != nil {
			return err
		}
	}

	return nil
}

func issueNodeCert(caCert *x509.Certificate, caKey *ecdsa.PrivateKey, hostname, ip1, ip2, certOut, keyOut string) error {
	nodeKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	if hostname == "" {
		hostname = "axonwall-ha-node"
	}
	ips := []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
	for _, rawIP := range []string{ip1, ip2} {
		clean := strings.Split(strings.TrimSpace(rawIP), "/")[0]
		if parsed := net.ParseIP(clean); parsed != nil {
			ips = append(ips, parsed)
		}
	}

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"Axonwall High Availability Cluster"},
			CommonName:   hostname,
		},
		NotBefore:   time.Now().Add(-1 * time.Hour),
		NotAfter:    time.Now().Add(5 * 365 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:    []string{hostname, "localhost", "axonwall.local"},
		IPAddresses: ips,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &nodeKey.PublicKey, caKey)
	if err != nil {
		return err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, _ := x509.MarshalECPrivateKey(nodeKey)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	if err := os.WriteFile(certOut, certPEM, 0644); err != nil {
		return err
	}
	if err := os.WriteFile(keyOut, keyPEM, 0640); err != nil {
		return err
	}
	return nil
}

func fixHAPKIPermissions() {
	_ = os.Chmod("/var/lib/axonwall/secrets", 0750)
	_ = os.Chmod(HAPKIDir, 0750)
	if u, err := user.Lookup("openldap"); err == nil {
		gid, _ := strconv.Atoi(u.Gid)
		_ = os.Chown("/var/lib/axonwall/secrets", 0, gid)
		_ = os.Chown(HAPKIDir, 0, gid)
		_ = os.Chown(HAPKICACertPath, 0, gid)
		_ = os.Chown(HAPKINodeCertPath, 0, gid)
		_ = os.Chown(HAPKINodeKeyPath, 0, gid)
		_ = os.Chmod(HAPKINodeKeyPath, 0640)
	}
}

// ExportHAPKIBundle exports the public HA CA and node certificate (never private keys) for a peer node.
func ExportHAPKIBundle(peerIP string) (*HAPKIBundle, error) {
	if err := EnsureHAPKICerts("axonwall-primary", "", peerIP); err != nil {
		return nil, err
	}
	caCertBytes, err := os.ReadFile(HAPKICACertPath)
	if err != nil {
		return nil, err
	}
	nodeCertBytes, err := os.ReadFile(HAPKINodeCertPath)
	if err != nil {
		return nil, err
	}
	replPass, _ := os.ReadFile(LDAPReplPassFile)
	baseDN, _ := os.ReadFile(LDAPBaseDNFile)

	return &HAPKIBundle{
		CACertPEM:      string(caCertBytes),
		CAKeyPEM:       "",
		NodeCertPEM:    string(nodeCertBytes),
		NodeKeyPEM:     "",
		LDAPReplSecret: strings.TrimSpace(string(replPass)),
		LDAPBaseDN:     strings.TrimSpace(string(baseDN)),
	}, nil
}

// GenerateHAPKICSR generates or loads the local node ECDSA P-256 private key (mode 0600)
// and creates a PEM-encoded X.509 Certificate Signing Request (CSR) for HA PKI enrollment.
func GenerateHAPKICSR(extraIPs []string) ([]byte, error) {
	if err := os.MkdirAll(HAPKIDir, 0750); err != nil {
		return nil, err
	}
	var nodeKey *ecdsa.PrivateKey
	if keyBytes, err := os.ReadFile(HAPKINodeKeyPath); err == nil {
		if block, _ := pem.Decode(keyBytes); block != nil {
			nodeKey, _ = x509.ParseECPrivateKey(block.Bytes)
		}
	}
	if nodeKey == nil {
		var err error
		nodeKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("failed to generate HA node key: %w", err)
		}
		keyDER, err := x509.MarshalECPrivateKey(nodeKey)
		if err != nil {
			return nil, err
		}
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
		if err := os.WriteFile(HAPKINodeKeyPath, keyPEM, 0600); err != nil {
			return nil, err
		}
		if err := os.MkdirAll("/etc/axonwall/pki", 0750); err == nil {
			_ = os.WriteFile("/etc/axonwall/pki/node.key", keyPEM, 0600)
		}
	}

	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "axonwall-ha-backup"
	}
	ips := []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
	for _, rawIP := range extraIPs {
		clean := strings.Split(strings.TrimSpace(rawIP), "/")[0]
		if parsed := net.ParseIP(clean); parsed != nil {
			ips = append(ips, parsed)
		}
	}

	csrTmpl := &x509.CertificateRequest{
		Subject: pkix.Name{
			Organization: []string{"Axonwall High Availability Cluster"},
			CommonName:   hostname,
		},
		DNSNames:    []string{hostname, "localhost", "axonwall.local"},
		IPAddresses: ips,
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTmpl, nodeKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create HA CSR: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}), nil
}

// SignHAPKICSR validates a peer's CSR, signs a 3-year client/server certificate with the local HA CA,
// persists the peer's leaf certificate to peer-node.crt, and returns the public certs and LDAP repl secret.
func SignHAPKICSR(csrPEM []byte, extraIPs []string) (*HAPKICSRResponse, error) {
	peerIP := ""
	if len(extraIPs) > 0 {
		peerIP = extraIPs[0]
	}
	if err := EnsureHAPKICerts("axonwall-primary", "", peerIP); err != nil {
		return nil, err
	}

	block, _ := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("invalid CSR PEM")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("CSR signature verification failed: %w", err)
	}

	caCertBytes, err := os.ReadFile(HAPKICACertPath)
	if err != nil {
		return nil, err
	}
	caKeyBytes, err := os.ReadFile(HAPKICAKeyPath)
	if err != nil {
		return nil, err
	}
	caCertBlock, _ := pem.Decode(caCertBytes)
	caKeyBlock, _ := pem.Decode(caKeyBytes)
	if caCertBlock == nil || caKeyBlock == nil {
		return nil, fmt.Errorf("invalid CA cert or key PEM")
	}
	caCert, err := x509.ParseCertificate(caCertBlock.Bytes)
	if err != nil {
		return nil, err
	}
	caKey, err := x509.ParseECPrivateKey(caKeyBlock.Bytes)
	if err != nil {
		return nil, err
	}

	ipMap := make(map[string]net.IP)
	var ips []net.IP
	addIP := func(ip net.IP) {
		if ip == nil {
			return
		}
		s := ip.String()
		if _, exists := ipMap[s]; !exists {
			ipMap[s] = ip
			ips = append(ips, ip)
		}
	}
	addIP(net.ParseIP("127.0.0.1"))
	addIP(net.ParseIP("::1"))
	for _, ip := range csr.IPAddresses {
		addIP(ip)
	}
	for _, rawIP := range extraIPs {
		clean := strings.Split(strings.TrimSpace(rawIP), "/")[0]
		addIP(net.ParseIP(clean))
	}

	dnsNames := csr.DNSNames
	if len(dnsNames) == 0 {
		cn := csr.Subject.CommonName
		if cn == "" {
			cn = "axonwall-ha-peer"
		}
		dnsNames = []string{cn, "localhost", "axonwall.local"}
	}

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      csr.Subject,
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(3 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:     dnsNames,
		IPAddresses:  ips,
	}

	signedDER, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, csr.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign peer CSR: %w", err)
	}
	signedPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: signedDER})

	_ = os.WriteFile(HAPKIPeerCertPath, signedPEM, 0644)
	if err := os.MkdirAll("/etc/axonwall/pki", 0750); err == nil {
		_ = os.WriteFile("/etc/axonwall/pki/peer-node.crt", signedPEM, 0644)
		_ = os.WriteFile("/etc/axonwall/pki/ca.crt", caCertBytes, 0644)
	}

	primaryNodeCertBytes, err := os.ReadFile(HAPKINodeCertPath)
	if err != nil {
		return nil, err
	}
	replPass, _ := os.ReadFile(LDAPReplPassFile)
	baseDN, _ := os.ReadFile(LDAPBaseDNFile)

	return &HAPKICSRResponse{
		CACertPEM:         string(caCertBytes),
		SignedCertPEM:     string(signedPEM),
		PeerSignerCertPEM: string(primaryNodeCertBytes),
		LDAPReplSecret:    strings.TrimSpace(string(replPass)),
		LDAPBaseDN:        strings.TrimSpace(string(baseDN)),
	}, nil
}

// InstallHAPKICSRResponse installs the CA certificate, signed local leaf certificate,
// peer signer certificate, and LDAP replication secret received from CSR enrollment.
func InstallHAPKICSRResponse(resp *HAPKICSRResponse) error {
	if resp == nil || resp.CACertPEM == "" || resp.SignedCertPEM == "" {
		return fmt.Errorf("incomplete CSR enrollment response")
	}
	if err := os.MkdirAll(HAPKIDir, 0750); err != nil {
		return err
	}
	if err := os.WriteFile(HAPKICACertPath, []byte(resp.CACertPEM), 0644); err != nil {
		return err
	}
	if err := os.WriteFile(HAPKINodeCertPath, []byte(resp.SignedCertPEM), 0644); err != nil {
		return err
	}
	if resp.PeerSignerCertPEM != "" {
		_ = os.WriteFile(HAPKIPeerCertPath, []byte(resp.PeerSignerCertPEM), 0644)
	}
	if err := os.MkdirAll("/etc/axonwall/pki", 0750); err == nil {
		_ = os.WriteFile("/etc/axonwall/pki/ca.crt", []byte(resp.CACertPEM), 0644)
		_ = os.WriteFile("/etc/axonwall/pki/node.crt", []byte(resp.SignedCertPEM), 0644)
		if resp.PeerSignerCertPEM != "" {
			_ = os.WriteFile("/etc/axonwall/pki/peer-node.crt", []byte(resp.PeerSignerCertPEM), 0644)
		}
	}
	fixHAPKIPermissions()

	if resp.LDAPReplSecret != "" {
		_ = os.MkdirAll(LDAPSecretsDir, 0700)
		_ = os.WriteFile(LDAPReplPassFile, []byte(resp.LDAPReplSecret+"\n"), 0600)
	}
	if resp.LDAPBaseDN != "" {
		_ = os.MkdirAll(LDAPBaseDir, 0750)
		_ = os.WriteFile(LDAPBaseDNFile, []byte(resp.LDAPBaseDN+"\n"), 0644)
	}
	return nil
}

// ImportHAPKIBundle installs the HA PKI bundle and LDAP replication secret received from the primary HA node.
func ImportHAPKIBundle(bundle HAPKIBundle) error {
	if err := os.MkdirAll(HAPKIDir, 0750); err != nil {
		return err
	}
	if err := os.WriteFile(HAPKICACertPath, []byte(bundle.CACertPEM), 0644); err != nil {
		return err
	}
	if bundle.CAKeyPEM != "" {
		_ = os.WriteFile(HAPKICAKeyPath, []byte(bundle.CAKeyPEM), 0600)
	}
	if err := os.WriteFile(HAPKINodeCertPath, []byte(bundle.NodeCertPEM), 0644); err != nil {
		return err
	}
	if err := os.WriteFile(HAPKINodeKeyPath, []byte(bundle.NodeKeyPEM), 0640); err != nil {
		return err
	}
	fixHAPKIPermissions()

	if bundle.LDAPReplSecret != "" {
		_ = os.MkdirAll(LDAPSecretsDir, 0700)
		_ = os.WriteFile(LDAPReplPassFile, []byte(bundle.LDAPReplSecret+"\n"), 0600)
	}
	if bundle.LDAPBaseDN != "" {
		_ = os.MkdirAll(LDAPBaseDir, 0750)
		_ = os.WriteFile(LDAPBaseDNFile, []byte(bundle.LDAPBaseDN+"\n"), 0644)
	}
	return nil
}

// LoadHAPKITLSConfig returns a mutual-TLS *tls.Config if the HA PKI certificates are present.
func LoadHAPKITLSConfig() (*tls.Config, error) {
	return LoadHAPKITLSConfigFromPaths(HAPKICACertPath, HAPKINodeCertPath, HAPKINodeKeyPath)
}

// LoadHAPKITLSConfigFromPaths is LoadHAPKITLSConfig with explicit file
// locations, so the sync transport wiring (and its tests) can build the
// config for PKI material outside the packaged paths.
func LoadHAPKITLSConfigFromPaths(caCertPath, nodeCertPath, nodeKeyPath string) (*tls.Config, error) {
	caBytes, err := os.ReadFile(caCertPath)
	if err != nil {
		return nil, err
	}
	cert, err := tls.LoadX509KeyPair(nodeCertPath, nodeKeyPath)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caBytes) {
		return nil, fmt.Errorf("failed to parse HA CA certificate")
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		ClientCAs:    pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
	}, nil
}

// ConfigureMultiProviderSyncrepl configures OpenLDAP cn=config with TLS certificates,
// serverID, olcMultiProvider: TRUE, and refreshAndPersist syncrepl over ldaps://<peerIP>:636.
func ConfigureMultiProviderSyncrepl(serverID int, peerIP string, baseDN string) error {
	cleanPeerIP := strings.Split(strings.TrimSpace(peerIP), ":")[0]
	cleanPeerIP = strings.Split(cleanPeerIP, "/")[0]
	if cleanPeerIP == "" {
		return nil
	}

	if err := EnsureHAPKICerts("axonwall-ha", "", cleanPeerIP); err != nil {
		return fmt.Errorf("failed to ensure HA PKI certificates: %w", err)
	}

	replBytes, err := os.ReadFile(LDAPReplPassFile)
	if err != nil {
		return fmt.Errorf("missing LDAP replication password: %w", err)
	}
	replPass := strings.TrimSpace(string(replBytes))

	// Update cn=replicator password in local DIT to match repl.pw
	if replHash, err := HashSSHA(replPass); err == nil {
		replLDIF := fmt.Sprintf("dn: cn=replicator,%s\nchangetype: modify\nreplace: userPassword\nuserPassword: %s\n", baseDN, replHash)
		cmd := exec.Command("ldapmodify", "-Y", "EXTERNAL", "-H", "ldapi:///")
		cmd.Stdin = strings.NewReader(replLDIF)
		_ = cmd.Run()
	}

	// Configure cn=config with TLS certificates and ServerID
	globalLDIF := fmt.Sprintf(`dn: cn=config
changetype: modify
replace: olcServerID
olcServerID: %d
-
replace: olcTLSCACertificateFile
olcTLSCACertificateFile: %s
-
replace: olcTLSCertificateFile
olcTLSCertificateFile: %s
-
replace: olcTLSCertificateKeyFile
olcTLSCertificateKeyFile: %s
`, serverID, HAPKICACertPath, HAPKINodeCertPath, HAPKINodeKeyPath)

	cmdGlobal := exec.Command("ldapmodify", "-Y", "EXTERNAL", "-H", "ldapi:///")
	cmdGlobal.Stdin = strings.NewReader(globalLDIF)
	if out, err := cmdGlobal.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to configure slapd TLS/ServerID: %s (%w)", string(out), err)
	}

	// Configure olcDatabase={1}mdb with olcSyncrepl and olcMultiProvider: TRUE
	peerURI := fmt.Sprintf("ldaps://%s:636", cleanPeerIP)
	syncreplVal := fmt.Sprintf(
		`{0}rid=001 provider=%s bindmethod=simple binddn="cn=replicator,%s" credentials=%s searchbase="%s" type=refreshAndPersist retry="5 5 300 +" tls_cacert=%s tls_reqcert=demand`,
		peerURI, baseDN, replPass, baseDN, HAPKICACertPath,
	)

	mdbLDIF := fmt.Sprintf(`dn: olcDatabase={1}mdb,cn=config
changetype: modify
replace: olcSyncrepl
olcSyncrepl: %s
-
replace: olcMultiProvider
olcMultiProvider: TRUE
`, syncreplVal)

	cmdMdb := exec.Command("ldapmodify", "-Y", "EXTERNAL", "-H", "ldapi:///")
	cmdMdb.Stdin = strings.NewReader(mdbLDIF)
	if out, err := cmdMdb.CombinedOutput(); err != nil {
		// Fallback for older OpenLDAP schemas using olcMirrorMode instead of olcMultiProvider
		mdbFallback := strings.ReplaceAll(mdbLDIF, "olcMultiProvider", "olcMirrorMode")
		cmdFallback := exec.Command("ldapmodify", "-Y", "EXTERNAL", "-H", "ldapi:///")
		cmdFallback.Stdin = strings.NewReader(mdbFallback)
		if out2, err2 := cmdFallback.CombinedOutput(); err2 != nil {
			return fmt.Errorf("failed to configure slapd syncrepl: %s / %s (%w)", string(out), string(out2), err)
		}
	}

	// Also update SSSD failover URI
	_ = EnsureSSSDConfiguredWithPeer(baseDN, peerURI)
	return nil
}

// --- HA payload signing (audit D-04 Phase 2) ---
//
// The sync master signs the SHA-256 digest of the /db and /state payloads
// with the HA node key and sends the signature in the
// X-Axonwall-Payload-Signature header; the poller verifies it against the
// HA node certificate before applying anything. Both pair members hold the
// same node keypair (it is part of the enrollment bundle), so a valid
// signature proves "produced by a holder of the pair's node key" -- a
// network attacker who has only the shared sync token cannot forge state
// the peer will accept. Signatures are ECDSA P-256 over the raw 32-byte
// digest, ASN.1-encoded and base64'd for the header.

// signPayloadDigest signs a 32-byte SHA-256 digest with key.
func signPayloadDigest(key *ecdsa.PrivateKey, digest []byte) (string, error) {
	if key == nil {
		return "", fmt.Errorf("no HA node key")
	}
	sig, err := ecdsa.SignASN1(rand.Reader, key, digest)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(sig), nil
}

// verifyPayloadSignatureWithCert verifies a signature produced by
// signPayloadDigest against the public key in cert.
func verifyPayloadSignatureWithCert(cert *x509.Certificate, digest []byte, sigB64 string) bool {
	if cert == nil {
		return false
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return false
	}
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return false
	}
	return ecdsa.VerifyASN1(pub, digest, sig)
}

func loadHANodeKey() (*ecdsa.PrivateKey, error) {
	data, err := os.ReadFile(HAPKINodeKeyPath)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("HA node key is not PEM")
	}
	return x509.ParseECPrivateKey(block.Bytes)
}

func loadHANodeCert() (*x509.Certificate, error) {
	data, err := os.ReadFile(HAPKINodeCertPath)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("HA node certificate is not PEM")
	}
	return x509.ParseCertificate(block.Bytes)
}

// signPayloadDigestFromPKI signs with the packaged HA node key. It fails
// when the pair has not enrolled (no PKI material), in which case callers
// serve the payload unsigned and the receiver's policy decides.
func signPayloadDigestFromPKI(digest []byte) (string, error) {
	key, err := loadHANodeKey()
	if err != nil {
		return "", err
	}
	return signPayloadDigest(key, digest)
}

// verifyPayloadSignatureFromPKI verifies against the peer's enrolled HA node
// certificate (or the local HA node certificate if peer-node.crt is absent).
// Any error (no PKI, unparsable signature) is a failed verification.
func verifyPayloadSignatureFromPKI(digest []byte, sigB64 string) bool {
	for _, p := range []string{HAPKIPeerCertPath, "/etc/axonwall/pki/peer-node.crt"} {
		if data, err := os.ReadFile(p); err == nil {
			if block, _ := pem.Decode(data); block != nil {
				if peerCert, err := x509.ParseCertificate(block.Bytes); err == nil {
					if verifyPayloadSignatureWithCert(peerCert, digest, sigB64) {
						return true
					}
				}
			}
		}
	}
	cert, err := loadHANodeCert()
	if err != nil {
		return false
	}
	return verifyPayloadSignatureWithCert(cert, digest, sigB64)
}

// payloadSigningAvailable reports whether this node can sign sync
// payloads, i.e. the HA node private key is present and parseable
// (audit D-04 Phase 4b). It mirrors exactly the condition under which
// signPayloadDigestFromPKI succeeds, so the capability a master
// advertises in its sync status is the behavior peers will observe.
func payloadSigningAvailable() bool {
	_, err := loadHANodeKey()
	return err == nil
}

// Test seams: the sync handlers and poller call these variables so tests
// can substitute PKI material from a temporary directory.
var (
	haSignPayloadDigest       = signPayloadDigestFromPKI
	haVerifyPayloadSignature  = verifyPayloadSignatureFromPKI
	haPayloadSigningAvailable = payloadSigningAvailable
)

// certFingerprintSHA256 renders a certificate's SHA-256 fingerprint in
// the colon-separated uppercase hex form operators are used to comparing
// out-of-band (audit D-04 Phase 3).
func certFingerprintSHA256(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	sum := sha256.Sum256(cert.Raw)
	parts := make([]string, len(sum))
	for i, b := range sum {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return strings.Join(parts, ":")
}

func loadHACACert() (*x509.Certificate, error) {
	data, err := os.ReadFile(HAPKICACertPath)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("HA CA certificate is not PEM")
	}
	return x509.ParseCertificate(block.Bytes)
}
