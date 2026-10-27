# ==============================================================================
# Oh My Zsh — axonwall plugin
# Comprehensive ZSH Tab Completions & Aliases for the Entire Axonwall Stack:
#   - axonwallctl / ctl, axonwall-tui / tui, axonwall-update, axonwall-import
#   - OpenZFS (zpool, zfs) with live pool/dataset/snapshot completion
#   - Linux nftables (nft) & iproute2 (ip, ethtool, tcpdump) with live NICs
#   - WireGuard (wg, wg-quick), Rosenpass Post-Quantum VPN, Headscale, Tailscale
#   - K3s Kubernetes runtime (k3s, crictl)
#   - KVM/QEMU Hypervisor (virsh) & LXC Containers with live VM/CT names
#   - FRRouting (vtysh) & Suricata IDS/IPS (suricatasc)
# ==============================================================================

# ------------------------------------------------------------------------------
# 1. axonwallctl & ctl completion
# ------------------------------------------------------------------------------
_axonwallctl_completion() {
  local -a subcmds sections plugin_cmds plugin_ids mcp_cmds shells slots
  subcmds=(
    'status:Show live appliance health, YAML validation state, and daemon connectivity'
    'validate:Validate syntax and Zod schema of /etc/axonwall/*.yaml'
    'check:Alias for validate'
    'diff:Show pending changes between /etc/axonwall/*.yaml and live state'
    'apply:Compile and apply /etc/axonwall/*.yaml with Commit-Confirm safety'
    'reload:Alias for apply — reload all services and Web GUI state'
    'confirm:Confirm active candidate configuration before rollback timer expires'
    'rollback:Immediately revert to Last-Known-Good (LKG) configuration'
    'update:Update Axonwall packages in-place (Rolling) or flash standby slot (A/B)'
    'upgrade:Alias for update'
    'plugin:Manage core appliance roles & extension plugins'
    'plugins:Alias for plugin'
    'mcp:Manage Model Context Protocol (MCP) server status & tactical leases'
    'cloudinit:Reconcile or export cloud-init (#cloud-config) & NoCloud ISO'
    'cloud-init:Alias for cloudinit'
    'config:Launch Neovim Super Configurator (zero-chrome Lua TUI + full Vim motions)'
    'nvim:Alias for config — launch Neovim Super Configurator'
    'super:Alias for config — launch Neovim Super Configurator'
    'edit:Open /etc/axonwall/<section>.yaml in $EDITOR, validate, and apply'
    'dump-json:Export validated DesiredState as JSON to stdout'
    'save-json:Validate and persist DesiredState JSON to /etc/axonwall/*.yaml'
    'export:Export unified running configuration to stdout as YAML'
    'completion:Output shell completion script (zsh, bash, fish)'
    'help:Show axonwallctl usage and available YAML sections'
  )
  sections=(
    'system:Appliance hostname, DNS, management ports, capabilities, plugins, AI, SNMP, UPS, ACME'
    'interfaces:Physical NICs, VLANs, bridges, LAGG bonds, VIPs, and VRFs'
    'routing:Upstream gateways, gateway groups, static routes, and FRR BGP/OSPF'
    'firewall:Aliases, stateful zone firewall rules, NAT/port forwards, and QoS traffic shaper'
    'vpn:WireGuard, Rosenpass Post-Quantum, IPsec, OpenVPN, and Headscale mesh'
    'services:Kea DHCPv4, Unbound DNS, Captive Portal, HAProxy, and FreeRADIUS'
    'security:Suricata IDS/IPS, CrowdSec, GeoIP, SSO/LDAP, TLS decryption, Zero-Trust, MCP'
    'ha:High Availability VRRP instances, Conntrackd, and pfsync state replication'
    'storage:TrueNAS-grade OpenZFS pools, datasets, snapshots, SMB, NFSv4, and iSCSI'
    'k3s:Kubernetes (K3s) cluster, Flannel WireGuard mesh, OpenEBS ZFS-LocalPV, workloads'
    'virt:KVM/QEMU virtual machines, LXC containers, VFIO passthrough, VXLAN, backups'
    'vigilante:Vigilante Cyber Defense, SOAR active containment, and autonomous SOC'
  )
  plugin_cmds=(
    'list:List all core appliance roles and extension plugins'
    'enable:Enable a core role or extension plugin'
    'disable:Disable a core role or extension plugin (reduces attack surface)'
    'install:Install an extension plugin OS package bundle'
    'remove:Uninstall an extension plugin OS package bundle'
    're-sync:Re-provision configuration files for a plugin (e.g. cli-workstation, rosenpass)'
    'reconfigure:Alias for re-sync'
  )
  plugin_ids=(
    'core-firewall:Axonwall Enterprise NGFW & Router Engine'
    'core-nas:Axonwall TrueNAS-Grade OpenZFS Storage & Shares'
    'core-k3s:Kubernetes (K3s) & OpenEBS Distributed Storage'
    'core-virt:Axonwall Hypervisor (KVM/QEMU & LXC Containers)'
    'core-vigilante:Vigilante Cyber Defense, SOAR & Autonomous SOC'
    'cli-workstation:Modern Operator Shell & Editor (ZSH, Oh My Zsh, Starship & VIM)'
    'cli-diagnostics-nastymap:NastyMap & Live CLI Telemetry Suite'
    'rosenpass:Rosenpass Post-Quantum WireGuard (McEliece + ML-KEM)'
    'haproxy:HAProxy Load Balancer & Reverse Proxy'
    'freeradius:FreeRADIUS AAA Suite'
    'snmp:Net-SNMP Daemon & MIBs'
    'nut-ups:Network UPS Tools (NUT)'
    'headscale:Headscale Mesh VPN Coordination Server'
    'tailscale:Tailscale Mesh VPN'
    'ntopng:ntopng High-Speed Flow Analysis'
    'vigilant-octo-waffle:Vigilant Octo Waffle K8s GitOps & App Platform (requires core-k3s)'
  )
  mcp_cmds=(
    'status:Show MCP server master switch status (disabled by default)'
    'enable:Explicitly enable the MCP server in /etc/axonwall/mcp-settings.json'
    'disable:Disable the MCP server and flush active AI tactical leases'
    'flush:Emergency panic flush of all active MCP tactical leases'
  )
  shells=('zsh' 'bash' 'fish')
  slots=('A' 'B')

  if (( CURRENT == 2 )); then
    _describe 'axonwallctl command' subcmds
    return
  fi

  case "${words[2]}" in
    edit|config|nvim|super)
      _describe 'YAML configuration section' sections
      ;;
    plugin|plugins)
      if (( CURRENT == 3 )); then
        _describe 'plugin subcommand' plugin_cmds
      elif (( CURRENT == 4 )); then
        _describe 'plugin ID' plugin_ids
      fi
      ;;
    mcp)
      if (( CURRENT == 3 )); then
        _describe 'mcp subcommand' mcp_cmds
      fi
      ;;
    apply|reload)
      _arguments '--no-confirm[Apply with 120s commit-confirm timer without auto-confirming]'
      ;;
    update|upgrade)
      _arguments \
        '--apt[Run Debian APT package upgrade before updating]' \
        '--apt-upgrade[Run Debian APT package upgrade]' \
        '--version[Target release version]:version:' \
        '--slot[Target A/B partition slot]:slot:(A B)'
      ;;
    cloudinit|cloud-init)
      if (( CURRENT == 3 )); then
        local -a ci_cmds
        ci_cmds=('export:Export running system to #cloud-config YAML or NoCloud ISO')
        _describe 'cloudinit subcommand' ci_cmds
        _files
      else
        _arguments \
          '-o[Output YAML file path]:file:_files' \
          '--iso[Generate bootable NoCloud cidata.iso at path]:file:_files' \
          '--template[Sanitize for golden clone template]' \
          '--no-redact[Include raw secrets without redaction]' \
          '--hostname[Override exported hostname]:hostname:'
      fi
      ;;
    completion)
      _describe 'shell' shells
      ;;
    *)
      _files
      ;;
  esac
}
compdef _axonwallctl_completion axonwallctl ctl 2>/dev/null || true

# ------------------------------------------------------------------------------
# 2. axonwall-tui & tui completion
# ------------------------------------------------------------------------------
_axonwall_tui_completion() {
  local -a tabs
  tabs=(
    'dashboard:System Telemetry, Active Roles, Gateways & MCP/Shell Status'
    'interfaces:Physical Interfaces, VLANs, Bridges & LAGG Bonds'
    'firewall:Stateful Zone Firewall Rules, NAT Port Forwards & Aliases'
    'nat:SNAT Masquerade & Port Forwards (DNAT)'
    'routing:Upstream Gateways, Static Routes & FRR BGP/OSPF'
    'services:DHCPv4 (Kea), DNS (Unbound), WireGuard, Rosenpass, HA & MCP Switch'
    'vpn:WireGuard, Rosenpass Post-Quantum & Headscale Mesh VPN'
    'mcp:Model Context Protocol (MCP) Master Switch & Security Posture'
    'storage:OpenZFS Storage Pools, Datasets, Snapshots & SMB/NFS/iSCSI Shares'
    'zfs:OpenZFS Storage Pools & Datasets'
    'k3s:Kubernetes (K3s + OpenEBS), KVM/LXC Hypervisor & Vigilante SOC'
    'virt:KVM/QEMU Virtual Machines & LXC Containers'
    'vigilante:Vigilante Autonomous SOC & SOAR Containment'
    'plugins:Core Appliance Roles, Extension Plugins & Oh My Zsh Shell Config'
    'shell:ZSH, Oh My Zsh, Starship & VIM Workstation Plugin Control'
    'nastymap:NastyMap Interactive Nmap Scanner, Topology & Host Inventory'
    'cli_ops:CLI Ops Toolkit (btop, slurm, iftop, iotop, sysstat, dig, nft, zpool, kubectl)'
    'cli-tools:Alias for cli_ops'
    'logs:Live System & Daemon Journal Logs'
  )
  _arguments \
    '(--tab -t --view)'{--tab,-t,--view}'[Open directly to specific TUI workspace tab]:tab:->tabs' \
    '(--readonly -r)'{--readonly,-r}'[Launch TUI in read-only operator mode]' \
    '(--help -h)'{--help,-h}'[Show TUI usage help]'
  if [[ "$state" == "tabs" ]]; then
    _describe 'TUI tab' tabs
  fi
}
compdef _axonwall_tui_completion axonwall-tui tui webtui 2>/dev/null || true

# ------------------------------------------------------------------------------
# 2b. axonwall-config / nui / cfg (Neovim Super Configurator) completion
# ------------------------------------------------------------------------------
_axonwall_config_completion() {
  local -a domains
  domains=(
    'system:Appliance Hostname, DNS, Anti-Lockout, Capabilities & Plugins'
    'interfaces:Physical NICs, IPv4 CIDR, Gateways & MTUs'
    'firewall:Stateful Zone Firewall Rules (Pass/Block/Reject)'
    'nat:Port Forwarding (DNAT) & Outbound NAT'
    'aliases:Host, Network & Port Group Aliases'
    'routing:Static Routes, BGP Autonomous System & OSPF'
    'services:Kea DHCPv4 Server & Unbound DNS Resolver (DNSSEC/DoT)'
    'vpn:WireGuard, Rosenpass Post-Quantum & Headscale Mesh'
    'security:Suricata IDS/IPS, CrowdSec & GeoIP Country Blocking'
    'ha:Active/Passive High Availability (VRRP + Conntrackd)'
    'storage:TrueNAS-Grade OpenZFS Pools, Datasets & SMB/NFS'
    'compute:Kubernetes (K3s), KVM/LXC Hypervisor & Vigilante SOC'
  )
  _describe 'Super Configurator domain' domains
}
compdef _axonwall_config_completion axonwall-config nui cfg superedit 2>/dev/null || true

# ------------------------------------------------------------------------------
# 3. axonwall-update, axonwall-import, axonwall-rotate-hub-cert completions
# ------------------------------------------------------------------------------
_axonwall_update_completion() {
  _arguments \
    '--slot[Target partition slot]:slot:(A B)' \
    '--version[Target version string]:version:' \
    '--rolling[Perform in-place rolling update]' \
    '--help[Show help]'
}
compdef _axonwall_update_completion axonwall-update 2>/dev/null || true

_axonwall_import_completion() {
  _arguments \
    '--format[Source firewall configuration format]:format:(opnsense pfsense iptables nftables cisco mikrotik vyos firewalld bundle)' \
    '--input[Path to configuration file to import]:file:_files' \
    '--apply[Immediately compile and apply imported state]' \
    '--dry-run[Validate and preview imported state without saving]'
}
compdef _axonwall_import_completion axonwall-import 2>/dev/null || true

_axonwall_rotate_cert_completion() {
  _arguments \
    '--ensure[Idempotently ensure CA and hub TLS certificate exist]' \
    '--force[Force rotation of the hub leaf certificate]' \
    '--san[Additional SubjectAltName entries]:san:' \
    '--days[Certificate validity in days]:days:' \
    '--help[Show usage help]'
}
compdef _axonwall_rotate_cert_completion axonwall-rotate-hub-cert 2>/dev/null || true

# ------------------------------------------------------------------------------
# 4. OpenZFS (zpool & zfs) completions with live pool & dataset discovery
# ------------------------------------------------------------------------------
_axonwall_zpool_list() {
  local -a pools
  pools=(${(f)"$(zpool list -H -o name 2>/dev/null)"})
  _describe 'ZFS storage pool' pools
}

_axonwall_zpool_completion() {
  local -a subcmds
  subcmds=(
    'status:Display detailed health and vdev status of ZFS storage pools'
    'list:List storage pools with capacity, fragmentation, and health metrics'
    'iostat:Display real-time I/O statistics for ZFS pools and vdevs'
    'scrub:Begin or resume a data integrity scrub on a ZFS pool'
    'import:List or import available ZFS storage pools'
    'export:Export a ZFS pool from the system'
    'create:Create a new ZFS storage pool (stripe, mirror, raidz1/2/3, draid)'
    'destroy:Destroy a ZFS storage pool'
    'add:Add new virtual devices (vdevs) to an existing pool'
    'attach:Attach a mirror device to an existing vdev'
    'detach:Detach a device from a mirroring vdev'
    'replace:Replace a failed or degraded disk in a pool'
    'online:Bring a physical disk online in a pool'
    'offline:Take a physical disk offline in a pool'
    'clear:Clear device errors in a ZFS pool'
    'trim:Initiate manual SSD/NVMe TRIM on a ZFS pool'
    'get:Retrieve pool properties'
    'set:Set a property on a ZFS pool'
    'history:Display command history of ZFS pool operations'
    'events:Display recent ZFS kernel events'
    'upgrade:Manage on-disk ZFS feature flags'
  )
  if (( CURRENT == 2 )); then
    _describe 'zpool command' subcmds
  else
    case "${words[2]}" in
      status|list|iostat|scrub|export|destroy|clear|trim|history|upgrade)
        _axonwall_zpool_list
        ;;
      *)
        _axonwall_zpool_list
        _files
        ;;
    esac
  fi
}
compdef _axonwall_zpool_completion zpool 2>/dev/null || true

_axonwall_zfs_datasets() {
  local -a datasets
  datasets=(${(f)"$(zfs list -H -o name -t filesystem,volume,snapshot 2>/dev/null)"})
  _describe 'ZFS dataset or snapshot' datasets
}

_axonwall_zfs_completion() {
  local -a subcmds
  subcmds=(
    'list:List ZFS datasets, volumes (zvols), and snapshots'
    'get:Get properties of ZFS datasets (compression, quota, recordsize, mountpoint)'
    'set:Set property on a ZFS dataset'
    'create:Create a new ZFS filesystem dataset or block volume (-V)'
    'destroy:Destroy a ZFS dataset or snapshot (-r)'
    'snapshot:Create an atomic read-only ZFS snapshot (dataset@snap)'
    'rollback:Roll back a dataset to a previous snapshot'
    'clone:Create a writable clone from a snapshot'
    'rename:Rename or relocate a ZFS dataset or snapshot'
    'send:Generate a ZFS replication stream to stdout'
    'receive:Receive a ZFS replication stream from stdin'
    'mount:Mount ZFS filesystems'
    'unmount:Unmount ZFS filesystems'
    'share:Share ZFS datasets via NFS or SMB'
    'diff:Show file-level changes between a snapshot and current dataset'
    'holds:List user holds on snapshots'
  )
  if (( CURRENT == 2 )); then
    _describe 'zfs command' subcmds
  else
    _axonwall_zfs_datasets
  fi
}
compdef _axonwall_zfs_completion zfs 2>/dev/null || true

# ------------------------------------------------------------------------------
# 5. Linux nftables (nft) & iproute2 (ip, ethtool, tcpdump) completions
# ------------------------------------------------------------------------------
_axonwall_nft_completion() {
  local -a cmds objects
  cmds=(
    'list:List ruleset, tables, chains, sets, maps, or counters'
    'flush:Flush ruleset, table, chain, or set'
    'add:Add table, chain, rule, set, or element'
    'insert:Insert rule at the beginning of a chain'
    'delete:Delete table, chain, rule, set, or element'
    'replace:Replace a rule by handle'
    'monitor:Monitor live netlink firewall events in real time'
  )
  objects=(
    'ruleset:Complete active nftables ruleset'
    'tables:All netfilter tables (inet axonwall, ip axonwall_nat, inet axonwall_mcp)'
    'chains:Firewall chains'
    'sets:IP/Port dynamic sets (@blocked_ips, @mcp_blackhole_v4, etc.)'
    'maps:Verdict and NAT maps'
    'flowtables:Hardware/software fastpath flowtables'
    'counters:Packet and byte counters'
  )
  if (( CURRENT == 2 )); then
    _describe 'nft command' cmds
    _arguments \
      '-f[Read commands from file]:file:_files' \
      '-c[Check command validity without applying]' \
      '-j[Format output as JSON]' \
      '-a[Show rule handles]' \
      '-n[Show numerical addresses]'
  elif (( CURRENT == 3 )); then
    _describe 'nft object' objects
  else
    _files
  fi
}
compdef _axonwall_nft_completion nft 2>/dev/null || true

_axonwall_net_ifaces() {
  local -a ifaces
  ifaces=(/sys/class/net/*(N:t))
  _describe 'network interface' ifaces
}

_axonwall_ethtool_completion() {
  _arguments \
    '-i[Show NIC driver and firmware version]' \
    '-S[Show NIC hardware statistics]' \
    '-k[Show hardware offload features (TSO, GRO, LRO)]' \
    '-K[Modify hardware offload features]' \
    '-g[Show ring buffer sizes]' \
    '-p[Blink physical NIC LED]' \
    '*:interface:_axonwall_net_ifaces'
}
compdef _axonwall_ethtool_completion ethtool 2>/dev/null || true

# ------------------------------------------------------------------------------
# 6. WireGuard (wg, wg-quick), Rosenpass, Headscale & Tailscale completions
# ------------------------------------------------------------------------------
_axonwall_wg_completion() {
  local -a subcmds wg_ifaces
  subcmds=(
    'show:Show current WireGuard status, peers, handshakes, and transfer counters'
    'showconf:Output current configuration of a WireGuard interface'
    'set:Change peer configuration, preshared-key, or listen-port'
    'setconf:Apply a configuration file to a WireGuard interface'
    'addconf:Append a configuration file to a WireGuard interface'
    'syncconf:Synchronize a WireGuard interface with a configuration file seamlessly'
    'genkey:Generate a new Curve25519 private key'
    'genpsk:Generate a new 256-bit pre-shared key'
    'pubkey:Calculate public key from private key on stdin'
  )
  if (( CURRENT == 2 )); then
    _describe 'wg subcommand' subcmds
  elif (( CURRENT == 3 )); then
    wg_ifaces=(${(f)"$(wg show interfaces 2>/dev/null)"})
    wg_ifaces+=('all' 'interfaces')
    _describe 'WireGuard interface' wg_ifaces
  else
    _files
  fi
}
compdef _axonwall_wg_completion wg 2>/dev/null || true

_axonwall_rosenpass_completion() {
  local -a subcmds
  subcmds=(
    'gen-keys:Generate Classic McEliece 460896 + ML-KEM-512 post-quantum keypair'
    'pubkey:Extract public key from secret key'
    'exchange:Run post-quantum key exchange with peers via CLI flags'
    'exchange-config:Run post-quantum key exchange daemon from /etc/rosenpass/config.toml'
    'validate:Validate Rosenpass TOML configuration file'
    'man:Display manual page'
  )
  if (( CURRENT == 2 )); then
    _describe 'rosenpass subcommand' subcmds
  else
    _files
  fi
}
compdef _axonwall_rosenpass_completion rosenpass 2>/dev/null || true

_axonwall_headscale_completion() {
  local -a subcmds
  subcmds=(
    'nodes:Manage mesh nodes (list, register, delete, expire, rename, tag)'
    'users:Manage Headscale users/namespaces (list, create, destroy, rename)'
    'preauthkeys:Manage pre-authentication keys (list, create, expire)'
    'routes:Manage advertised subnet routes (list, enable, disable)'
    'apikeys:Manage Headscale API keys (list, create, expire)'
    'policy:Manage ACL policy configuration'
    'derp:Inspect embedded DERP relay map'
    'serve:Start the Headscale coordination server'
    'version:Print Headscale version'
  )
  if (( CURRENT == 2 )); then
    _describe 'headscale subcommand' subcmds
  else
    _files
  fi
}

if (( $+commands[headscale] )); then
  if [[ ! -f "${ZSH_CACHE_DIR}/completions/_headscale" ]]; then
    headscale completion zsh 2>/dev/null >| "${ZSH_CACHE_DIR}/completions/_headscale" &|
  fi
  [[ -s "${ZSH_CACHE_DIR}/completions/_headscale" ]] && source "${ZSH_CACHE_DIR}/completions/_headscale" 2>/dev/null
else
  compdef _axonwall_headscale_completion headscale 2>/dev/null || true
fi

_axonwall_tailscale_completion() {
  local -a subcmds
  subcmds=(
    'up:Connect to Tailscale/Headscale mesh network'
    'down:Disconnect from mesh network'
    'status:Show state of tailscaled and mesh peers'
    'ip:Show Tailscale mesh IPv4/IPv6 addresses'
    'ping:Ping a host at the Tailscale layer'
    'netcheck:Analyze local network conditions and DERP latency'
    'whois:Show machine and user info for a Tailscale IP'
    'set:Change specified preferences (advertise-routes, exit-node)'
    'login:Log in to a Headscale/Tailscale coordination server'
    'logout:Disconnect and expire current node key'
    'version:Print Tailscale version'
  )
  if (( CURRENT == 2 )); then
    _describe 'tailscale subcommand' subcmds
  else
    _files
  fi
}

if (( $+commands[tailscale] )); then
  if [[ ! -f "${ZSH_CACHE_DIR}/completions/_tailscale" ]]; then
    tailscale completion zsh 2>/dev/null >| "${ZSH_CACHE_DIR}/completions/_tailscale" &|
  fi
  [[ -s "${ZSH_CACHE_DIR}/completions/_tailscale" ]] && source "${ZSH_CACHE_DIR}/completions/_tailscale" 2>/dev/null
else
  compdef _axonwall_tailscale_completion tailscale 2>/dev/null || true
fi

# ------------------------------------------------------------------------------
# 7. K3s, KVM/QEMU (virsh), LXC, FRRouting (vtysh) & Suricata completions
# ------------------------------------------------------------------------------
_axonwall_k3s_completion() {
  local -a subcmds
  subcmds=(
    'server:Run K3s Kubernetes control plane and node agent'
    'agent:Run K3s worker node agent'
    'kubectl:Run embedded kubectl CLI'
    'crictl:Run embedded CRI container CLI'
    'ctr:Run embedded containerd CLI'
    'etcd-snapshot:Trigger or manage embedded etcd cluster snapshots'
    'secrets-encrypt:Control Kubernetes secrets encryption at rest'
    'cert:Manage K3s TLS certificates'
    'token:Manage K3s node join tokens'
    'check-config:Verify kernel & system readiness for K3s'
  )
  if (( CURRENT == 2 )); then
    _describe 'k3s subcommand' subcmds
  else
    _files
  fi
}
compdef _axonwall_k3s_completion k3s 2>/dev/null || true

_axonwall_virsh_completion() {
  local -a subcmds vms
  subcmds=(
    'list:List running or all (--all) KVM virtual machines'
    'start:Start an inactive virtual machine'
    'shutdown:Gracefully shut down a running virtual machine'
    'destroy:Forcefully power off a virtual machine'
    'reboot:Reboot a virtual machine'
    'console:Connect to the serial console of a VM'
    'dominfo:Show VM CPU, memory, and state summary'
    'domifaddr:Show IP addresses of a running VM'
    'dumpxml:Output VM XML domain definition'
    'edit:Edit VM XML definition in $EDITOR'
    'snapshot-list:List snapshots for a VM'
    'snapshot-create-as:Create a new VM snapshot'
    'snapshot-revert:Revert VM to a snapshot'
    'net-list:List virtual networks'
    'pool-list:List storage pools'
  )
  if (( CURRENT == 2 )); then
    _describe 'virsh command' subcmds
  elif (( CURRENT == 3 )); then
    vms=(${(f)"$(virsh list --all --name 2>/dev/null)"})
    _describe 'KVM virtual machine' vms
  else
    _files
  fi
}
compdef _axonwall_virsh_completion virsh 2>/dev/null || true

# Stack Convenience Aliases for ZFS, WireGuard, Rosenpass, FRR & Suricata
alias zp='zpool status'
alias zpl='zpool list'
alias zpio='zpool iostat -v 1'
alias zl='zfs list'
alias zsnap='zfs list -t snapshot'
alias wgs='wg show'
alias rpstatus='systemctl status rosenpass'
alias bgp='vtysh -c "show ip bgp summary"'
alias ospf='vtysh -c "show ip ospf neighbor"'
alias frrroutes='vtysh -c "show ip route"'
alias idsstatus='systemctl status suricata'
alias vms='virsh list --all'
alias cts='lxc-ls -f'
