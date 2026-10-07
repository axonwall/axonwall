package engine

import (
	"fmt"
	"os"
	"path/filepath"
	"text/template"
)

const suricataConfigTpl = `
%YAML 1.1
---
vars:
  address-groups:
    HOME_NET: "[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]"
    EXTERNAL_NET: "!$HOME_NET"
  port-groups:
    HTTP_PORTS: "80"
    SHELLCODE_PORTS: "!80"
    ORACLE_PORTS: 1521
    SSH_PORTS: 22
    DNP3_PORTS: 20000
    MODBUS_PORTS: 502
    FILEINFO_PORTS: "21,25,139,110,143,445,514"

af-packet:
{{- range .Interfaces }}
  - interface: {{ . }}
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes
{{- end }}

outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      types:
        - alert:
            payload: yes
            payload-buffer-size: 4kb
            payload-printable: yes
            packet: yes
        - http:
            extended: yes
        - dns:
            query: yes
            answer: yes
        - tls:
            extended: yes
        - files:
            force-magic: no

default-rule-path: /var/lib/suricata/rules
rule-files:
  - suricata.rules
`

type SuricataConfig struct {
	Interfaces []string
}

// GenerateSuricataConfig generates /etc/suricata/suricata.yaml
func GenerateSuricataConfig(interfaces []string) error {
	configDir := "/etc/suricata"
	configPath := filepath.Join(configDir, "suricata.yaml")

	err := os.MkdirAll(configDir, 0755)
	if err != nil {
		return fmt.Errorf("failed to create suricata directory: %w", err)
	}

	tpl, err := template.New("suricata").Parse(suricataConfigTpl)
	if err != nil {
		return fmt.Errorf("failed to parse suricata template: %w", err)
	}

	// Default to eth1 if no LAN interfaces found to avoid empty list
	if len(interfaces) == 0 {
		interfaces = append(interfaces, "eth1")
	}

	f, err := os.OpenFile(configPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC|0x20000, 0644)
	if err != nil {
		return fmt.Errorf("failed to open suricata.yaml: %w", err)
	}
	defer f.Close()

	sc := SuricataConfig{
		Interfaces: interfaces,
	}

	if err := tpl.Execute(f, sc); err != nil {
		return fmt.Errorf("failed to execute suricata template: %w", err)
	}

	return nil
}
