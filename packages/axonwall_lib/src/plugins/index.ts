import { PluginManifestSchema, VowConfigSchema, VigilanteConfigSchema, HostMalwareDefenseConfigSchema, ThreatHarvesterConfigSchema, EluvixConfigSchema, type PluginManifest, type DesiredState, type CoreCapabilities } from '../schemas/index.js';
export type { PluginManifest };

export const CORE_ROLE_PLUGIN_IDS = new Set([
  'core-firewall',
  'core-nas',
  'core-k3s',
  'core-virt',
  'core-vigilante',
]);

export const BUILTIN_PLUGINS: PluginManifest[] = [
  {
    id: 'core-firewall',
    name: 'Axonwall Enterprise NGFW & Router Engine',
    version: '0.3.1',
    category: 'core_role',
    description: 'Stateful nftables firewall, NAT/PAT, Multi-WAN SD-WAN, BGP/OSPF (FRR), Suricata IDS/IPS, CrowdSec, VPN concentrator, and Kea DHCP.',
    author: 'Axonwall Core',
    systemdUnits: ['nftables.service', 'suricata.service', 'frr.service', 'kea-dhcp4-server.service', 'conntrackd.service'],
    privileges: ['firewall.rules', 'network.routing', 'vpn.admin'],
    packages: {
      debian: ['nftables', 'suricata', 'frr', 'kea-dhcp4-server', 'conntrackd', 'unbound'],
      alpine: ['nftables', 'suricata', 'frr', 'kea-dhcp4', 'conntrack-tools', 'unbound'],
      arch: ['nftables', 'suricata', 'frr', 'kea', 'conntrack-tools', 'unbound'],
    },
    nftHooks: [
      { table: 'inet axonwall', chain: 'forward', priority: 0 },
      { table: 'ip axonwall_nat', chain: 'postrouting', priority: 100 },
    ],
    menuEntry: {
      title: 'Firewall Rules',
      path: '/firewall',
      icon: 'Shield',
    },
  },
  {
    id: 'core-nas',
    name: 'Axonwall Enterprise Grade OpenZFS Storage & Shares',
    version: '0.3.1',
    category: 'core_role',
    description: 'Full OpenZFS pool/vdev manager (Stripe, Mirror, RAID-Z1/2/3, dRAID), datasets, zvols, automated snapshots, real-time HA ZFS replication, and SMB/NFSv4/iSCSI/S3 sharing.',
    author: 'Axonwall Core',
    systemdUnits: ['zfs-import.target', 'zfs-mount.service', 'smbd.service', 'nfs-server.service', 'iscsid.service'],
    privileges: ['storage.zfs', 'storage.shares', 'system.hardware'],
    packages: {
      debian: ['zfsutils-linux', 'samba', 'nfs-kernel-server', 'open-iscsi'],
      alpine: ['zfs', 'samba', 'nfs-utils', 'open-iscsi'],
      arch: ['zfs-utils', 'samba', 'nfs-utils', 'open-iscsi'],
    },
    nftHooks: [
      { table: 'inet axonwall', chain: 'input', priority: 0 },
    ],
    menuEntry: {
      title: 'ZFS Storage Pools',
      path: '/storage/pools',
      icon: 'HardDrive',
    },
  },
  {
    id: 'core-k3s',
    name: 'Kubernetes (K3s) & OpenEBS Distributed Storage',
    version: '1.31.2',
    category: 'core_role',
    description: 'Lightweight multi-node Kubernetes control plane with automatic HA second-node cluster join, OpenEBS ZFS-LocalPV, and synchronous 2-node Replicated Persistent Volumes.',
    author: 'CNCF / OpenEBS / Axonwall Core',
    systemdUnits: ['k3s.service'],
    privileges: ['k3s.cluster', 'storage.openebs'],
    packages: {
      debian: ['curl', 'iptables', 'open-iscsi'],
      alpine: ['curl', 'iptables', 'open-iscsi'],
      arch: ['curl', 'iptables-nft', 'open-iscsi'],
    },
    // Bundled binaries (k3s + k9s), shipped in the plugin's own
    // directory (<baseDataDir>/core-k3s/bin/) instead of
    // /usr/local/bin — see the Go-side definition in
    // GetCorePluginDefinitions (apps/axonwalld/engine/plugins.go),
    // which is the daemon's copy of this entry. The two must stay in
    // sync (same versions, URLs and sha256s). No distroPackage
    // entries: both binaries are upstream release artifacts.
    //
    // k3s v1.32.3+k3s1 is a raw single-file download (kind
    // 'binary'); its sha256 is the upstream-published digest from
    // https://github.com/k3s-io/k3s/releases/download/v1.32.3%2Bk3s1/sha256sum-amd64.txt
    // and matches the pin the builders carried before this move.
    // k9s v0.51.0 is a tarball (kind 'archive', format 'tar.gz');
    // its sha256 is the upstream-published digest for
    // k9s_Linux_amd64.tar.gz from
    // https://github.com/derailed/k9s/releases/download/v0.51.0/checksums.sha256.
    // The tarball's members sit at the top level (LICENSE,
    // README.md, k9s — no wrapping directory), so pathInArchive
    // defaults to the binary name 'k9s'.
    binaries: [
      {
        kind: 'binary',
        name: 'k3s',
        url: 'https://github.com/k3s-io/k3s/releases/download/v1.32.3%2Bk3s1/k3s',
        sha256: 'b19216803650b567bf980888dec39035edaf664339c55bc4462f7a003edbef83',
      },
      {
        kind: 'archive',
        name: 'k9s',
        url: 'https://github.com/derailed/k9s/releases/download/v0.51.0/k9s_Linux_amd64.tar.gz',
        sha256: 'c3752ad51a5a4015a113819c4eeb6e55a4d0e4b8e652494797532f6fc8161dd7',
        format: 'tar.gz',
      },
    ],
    binDirs: ['bin'],
    nftHooks: [
      { table: 'inet axonwall', chain: 'input', priority: 0 },
    ],
    menuEntry: {
      title: 'K3s & OpenEBS Cluster',
      path: '/k3s/cluster',
      icon: 'Boxes',
    },
  },
  {
    id: 'core-virt',
    name: 'Axonwall Hypervisor (KVM/QEMU & LXC Containers)',
    version: '0.3.1',
    category: 'core_role',
    description: 'Proxmox VE parity hypervisor with KVM hardware virtualization, Cloud-Init, LXC system containers, PCIe VFIO passthrough, and deduplicated backup engine.',
    author: 'Axonwall Core',
    systemdUnits: ['lxc.service'],
    privileges: ['virt.vms', 'virt.containers', 'system.hardware'],
    packages: {
      debian: ['qemu-system-x86', 'ovmf', 'swtpm', 'lxc', 'dnsmasq-base'],
      alpine: ['qemu-system-x86_64', 'ovmf', 'swtpm', 'lxc', 'dnsmasq'],
      arch: ['qemu-full', 'edk2-ovmf', 'swtpm', 'lxc', 'dnsmasq'],
    },
    nftHooks: [
      { table: 'inet axonwall', chain: 'forward', priority: 0 },
    ],
    menuEntry: {
      title: 'Virtual Machines',
      path: '/compute/vms',
      icon: 'Cpu',
    },
  },
  {
    id: 'core-vigilante',
    name: 'Vigilante Cyber Defense, SOAR & Autonomous SOC',
    version: '0.1.0',
    category: 'core_role',
    description: 'Autonomous Cyber Defense Operations, real-time SOAR active containment, honeynet deception mesh, embedded security data lake, PCAP forensics, eBPF lineage, and 12 modular security packages.',
    author: 'DeployCoop / Axonwall Core',
    dependencies: ['core-k3s'],
    systemdUnits: ['axonwall-vigilante.service', 'k3s.service'],
    privileges: ['security.vigilante', 'security.soar', 'security.forensics', 'k3s.cluster', 'firewall.rules'],
    ldapIntegration: {
      enabledByDefault: true,
      serviceAccountCn: 'svc-vigilante',
      inheritApplianceRoleGroups: true,
      envPrefix: 'VIGILANTE_LDAP_',
      groups: [
        {
          cn: 'vigilante-admin',
          gidNumber: 10230,
          description: 'Vigilante SOC & SOAR Administrators',
          role: 'admin',
        },
        {
          cn: 'vigilante-operator',
          gidNumber: 10231,
          description: 'Vigilante SOC Analysts, Threat Hunters & Incident Responders',
          role: 'operator',
        },
        {
          cn: 'vigilante-readonly',
          gidNumber: 10232,
          description: 'Vigilante SOC Read-Only Auditors & Observers',
          role: 'readonly',
        },
      ],
    },
    nftHooks: [
      { table: 'inet axonwall', chain: 'input', priority: -10 },
      { table: 'inet axonwall', chain: 'forward', priority: -10 },
    ],
    menuEntry: {
      title: 'Vigilante SOC & SOAR',
      path: '/vigilante/battlestation',
      icon: 'Radar',
    },
  },
  {
    id: 'haproxy',
    name: 'HAProxy Load Balancer & Reverse Proxy',
    version: '2.8.3',
    category: 'extension',
    description: 'High performance TCP/HTTP load balancer, reverse proxy, and SSL/TLS termination with ACME integration.',
    author: 'HAProxy Technologies / Axonwall Core',
    systemdUnits: ['haproxy.service'],
    privileges: ['services.haproxy', 'system.certificates'],
    packages: {
      debian: ['haproxy'],
      alpine: ['haproxy'],
      arch: ['haproxy'],
    },
    cliBinaries: ['haproxy'],
    nftHooks: [
      { table: 'inet axonwall', chain: 'input', priority: 0 },
    ],
    menuEntry: {
      title: 'HAProxy Reverse Proxy',
      path: '/system/services',
      icon: 'Network',
    },
  },
  {
    id: 'freeradius',
    name: 'FreeRADIUS AAA Suite',
    version: '3.2.3',
    category: 'extension',
    description: 'High-performance RADIUS authentication and accounting server integrated with internal OpenLDAP.',
    author: 'Network RADIUS / Axonwall Core',
    systemdUnits: ['freeradius.service'],
    privileges: ['services.freeradius', 'system.users'],
    packages: {
      debian: ['freeradius', 'freeradius-ldap', 'freeradius-utils'],
      alpine: ['freeradius', 'freeradius-ldap'],
      arch: ['freeradius'],
    },
    cliBinaries: ['freeradius', 'radtest'],
    ldapIntegration: {
      enabledByDefault: true,
      serviceAccountCn: 'svc-freeradius',
      inheritApplianceRoleGroups: true,
      envPrefix: 'FREERADIUS_LDAP_',
      groups: [
        {
          cn: 'radius-users',
          gidNumber: 10210,
          description: 'FreeRADIUS 802.1X and VPN Authenticated Users',
          role: 'operator',
        },
      ],
    },
    menuEntry: {
      title: 'FreeRADIUS Server',
      path: '/system/services',
      icon: 'ShieldCheck',
    },
  },
  {
    id: 'snmp',
    name: 'Net-SNMP Daemon & MIBs',
    version: '5.9.3',
    category: 'extension',
    description: 'SNMPv2c and SNMPv3 monitoring agent with standard MIBs for network management systems.',
    author: 'Net-SNMP Team / Axonwall Core',
    systemdUnits: ['snmpd.service'],
    privileges: ['system.monitoring'],
    packages: {
      debian: ['snmpd', 'snmp'],
      alpine: ['net-snmp', 'net-snmp-tools'],
      arch: ['net-snmp'],
    },
    cliBinaries: ['snmpd', 'snmpwalk'],
    menuEntry: {
      title: 'SNMP Monitoring',
      path: '/system/services',
      icon: 'Radio',
    },
  },
  {
    id: 'nut-ups',
    name: 'Network UPS Tools (NUT)',
    version: '2.8.0',
    category: 'extension',
    description: 'Reliable UPS monitoring and automated graceful shutdown for battery backups over USB and serial.',
    author: 'NUT Project / Axonwall Core',
    systemdUnits: ['nut-server.service', 'nut-client.service'],
    privileges: ['system.hardware', 'system.power'],
    packages: {
      debian: ['nut', 'nut-server', 'nut-client'],
      alpine: ['nut'],
      arch: ['nut'],
    },
    cliBinaries: ['upsc', 'upsd', 'upsmon'],
    menuEntry: {
      title: 'UPS Battery (NUT)',
      path: '/system/ups',
      icon: 'BatteryCharging',
    },
  },
  {
    id: 'headscale',
    name: 'Headscale Mesh VPN Coordination Server',
    version: '0.29.4',
    category: 'extension',
    description: 'Self-hosted, open source WireGuard mesh coordination server with MagicDNS, multi-tenant namespaces, and route distribution.',
    author: 'Juan Font / Axonwall Core',
    systemdUnits: ['headscale.service'],
    privileges: ['vpn.admin', 'network.interfaces'],
    packages: {
      debian: ['wireguard-tools', 'sqlite3'],
      alpine: ['wireguard-tools', 'sqlite'],
      arch: ['headscale', 'wireguard-tools', 'sqlite'],
    },
    cliBinaries: ['headscale', 'wg'],
    menuEntry: {
      title: 'Mesh VPN (Headscale)',
      path: '/vpn/mesh',
      icon: 'Network',
    },
  },
  {
    id: 'tailscale',
    name: 'Tailscale Mesh VPN',
    version: '1.74.0',
    category: 'extension',
    description: 'Zero-config WireGuard mesh VPN for secure fleet connectivity and subnet routing.',
    author: 'Tailscale Inc. / Axonwall Community',
    systemdUnits: ['tailscaled.service'],
    privileges: ['vpn.tailscale', 'network.interfaces'],
    packages: {
      debian: ['wireguard-tools', 'ca-certificates', 'curl'],
      alpine: ['tailscale', 'wireguard-tools'],
      arch: ['tailscale', 'wireguard-tools', 'ca-certificates', 'curl'],
    },
    cliBinaries: ['tailscale', 'tailscaled'],
    menuEntry: {
      title: 'Tailscale Mesh',
      path: '/vpn/mesh',
      icon: 'Globe',
    },
  },
  {
    id: 'ntopng',
    name: 'ntopng High-Speed Flow Analysis',
    version: '5.6.0',
    category: 'extension',
    description: 'Next-generation web-based traffic analysis and flow visibility.',
    author: 'ntop / Axonwall Community',
    systemdUnits: ['ntopng.service'],
    privileges: ['reporting.flows', 'system.monitoring'],
    packages: {
      debian: ['tcpdump', 'ethtool'],
      alpine: ['tcpdump', 'ethtool'],
      arch: ['tcpdump', 'ethtool'],
    },
    cliBinaries: ['ntopng', 'tcpdump'],
    menuEntry: {
      title: 'ntopng Flow Analyzer',
      path: '/reporting/flows',
      icon: 'Activity',
    },
  },
  {
    id: 'cli-workstation',
    name: 'Modern Operator Shell & Editor (ZSH, Oh My Zsh, Starship, VIM & Neovim Super Configurator)',
    version: '1.2.0',
    category: 'extension',
    defaultEnabled: true,
    description:
      'Enabled by default: first-class shell environment with ZSH, Oh My Zsh (https://ohmyz.sh), Starship cyber-emerald prompt, Neovim Super Configurator (axonwall-config / nui — zero-chrome Lua form TUI with full Vim motions), VIM syntax defaults, Tmux multiplexer, and deep stack autocompletions (kubectl, helm, k3s, zfs/zpool, nftables, wireguard, rosenpass, virsh, lxc, axonwallctl, axonwall-tui, axonwall-config). Can be disabled to minimize attack surface.',
    author: 'Axonwall Core',
    systemdUnits: [],
    privileges: ['system.users', 'system.hardware'],
    packages: {
      debian: [
        'zsh',
        'vim',
        'neovim',
        'tmux',
        'zsh-autosuggestions',
        'zsh-syntax-highlighting',
        'fzf',
        'zoxide',
        'bat',
        'ripgrep',
        'fd-find',
        'git',
        'kubectl',
      ],
      alpine: [
        'zsh',
        'vim',
        'neovim',
        'starship',
        'tmux',
        'zsh-vcs',
        'fzf',
        'zoxide',
        'bat',
        'ripgrep',
        'fd',
        'git',
        'kubectl',
      ],
      arch: [
        'zsh',
        'vim',
        'neovim',
        'starship',
        'tmux',
        'zsh-autosuggestions',
        'zsh-syntax-highlighting',
        'fzf',
        'zoxide',
        'bat',
        'ripgrep',
        'fd',
        'git',
        'kubectl',
      ],
    },
    cliBinaries: ['zsh', 'vim', 'nvim', 'starship', 'tmux', 'kubectl', 'helm'],
  },
  {
    // GNU Emacs, bundled — not system-installed. The trixie amd64
    // .debs are downloaded, sha256-verified, and extracted
    // (dpkg-deb -x layout) into the plugin's own directory; nothing
    // is installed into the system, so `packages` is deliberately
    // OMITTED here (the os_and_fixes test requires any present
    // packages.arch to be non-empty, and an empty packages block
    // would also invite InstallPlugin to apt-get install it).
    // VERSION DEVIATION (coordinator decision): pinned
    // 1:30.1+1-6+deb13u1, the current trixie security update, NOT
    // the 1:30.1+1-6 named in the original plan — 1:30.1+1-6 is
    // superseded and only available from snapshot.debian.org now.
    // All sha256s below were verified by downloading the .debs and
    // hashing locally against the live trixie Packages index.
    // The three emacs .debs alone do NOT run: the extracted binary
    // is usr/bin/emacs-nox (no /usr/bin/emacs alternatives symlink
    // under dpkg-deb -x — bin/emacs is a launcher written at
    // install time) and it hard-links libgccjit.so.0,
    // libasound.so.2 and liblcms2.so.2, none of which are in the
    // base image. The bundle also carries libgccjit0 (+ its .so
    // deps libisl23, libmpc3, libmpfr6), libasound2t64 (+ tiny
    // libasound2-data) and liblcms2-2; the lib .debs' binary
    // packages are built from differently-named source packages,
    // hence the `source` field on each. Full bundle: ~35.6 MB
    // download, ~169 MB on disk. emacs-el is deliberately SKIPPED:
    // only the .el sources (19.5 MB) — the .elc files live in
    // emacs-common itself. Native-comp: VERIFIED live 2026-11-20
    // that JIT-compiling new code FAILS at the link step ("ld:
    // cannot find crtbeginS.o", a gcc-14 file, not bundled), so the
    // plugin ships byte-compiled-only — init.el sets
    // native-comp-jit-compilation to nil; the prebuilt .eln files
    // for the preloaded libs still load.
    id: 'cli-emacs',
    name: 'Emacs Editor (GNU Emacs, no-X) for /etc/axonwall',
    version: '0.1.0',
    category: 'extension',
    description:
      'GNU Emacs (no-X) for editing /etc/axonwall configuration files, bundled with the plugin: the Debian emacs-nox 30.1 tree plus its missing shared libraries are downloaded, checksum-verified, and extracted into the plugin\'s own directory, and its bin directory is added to PATH for daemon invocations and interactive shells. Nothing is installed into the system.',
    author: 'Axonwall Core',
    systemdUnits: [],
    privileges: ['system.users', 'system.config.write'],
    cliBinaries: ['emacs', 'emacs-nox'],
    binaries: [
      {
        kind: 'distroPackage',
        name: 'emacs-nox',
        sha256: 'fee9e5bc5d4c0da716e3e12eee8e1b063bd24a58a6ca6755be2516b377d50364',
        distro: 'debian',
        package: 'emacs-nox',
        source: 'emacs',
        version: '1:30.1+1-6+deb13u1',
        arch: 'amd64',
      },
      {
        kind: 'distroPackage',
        name: 'emacs-bin-common',
        sha256: '86ad88ffb8d0024fe22a4b95863918655ecb10523c4bcdd199540da75f67c4db',
        distro: 'debian',
        package: 'emacs-bin-common',
        source: 'emacs',
        version: '1:30.1+1-6+deb13u1',
        arch: 'amd64',
      },
      {
        kind: 'distroPackage',
        name: 'emacs-common',
        sha256: '1a20b06410720a432bd6c82a455a919b7083011e02a3c7b46243e65d8582791b',
        distro: 'debian',
        package: 'emacs-common',
        source: 'emacs',
        version: '1:30.1+1-6+deb13u1',
        arch: 'all',
      },
      {
        kind: 'distroPackage',
        name: 'libgccjit0',
        sha256: 'cab79f341f9b1ee14a03bc6ca1c1ecdb2d52b2a346d1e011c47682e5f45453f9',
        distro: 'debian',
        package: 'libgccjit0',
        source: 'gcc-14',
        version: '14.2.0-19',
        arch: 'amd64',
      },
      {
        kind: 'distroPackage',
        name: 'libisl23',
        sha256: 'ac8518042e81c00de1effb72bba7e88ac4ecd488f7ea8b9e3ebc63159cb53b35',
        distro: 'debian',
        package: 'libisl23',
        source: 'isl',
        version: '0.27-1',
        arch: 'amd64',
      },
      {
        kind: 'distroPackage',
        name: 'libmpc3',
        sha256: '2af0a5c128e03694a41c0b011bd8a958b7297436cdb3a15ddad7866dae8c300b',
        distro: 'debian',
        package: 'libmpc3',
        source: 'mpclib3',
        version: '1.3.1-1+b3',
        arch: 'amd64',
      },
      {
        kind: 'distroPackage',
        name: 'libmpfr6',
        sha256: '75dddce11dabc7fc543712c33dc27b7f2ee66a111763eb5eac654d010b42cd92',
        distro: 'debian',
        package: 'libmpfr6',
        source: 'mpfr4',
        version: '4.2.2-1',
        arch: 'amd64',
      },
      {
        kind: 'distroPackage',
        name: 'libasound2t64',
        sha256: '5495496142d57e5ad6d581ac5456ec3c87f872c109a2bfb815d154b673eebc67',
        distro: 'debian',
        package: 'libasound2t64',
        source: 'alsa-lib',
        version: '1.2.14-1+deb13u1',
        arch: 'amd64',
      },
      {
        kind: 'distroPackage',
        name: 'libasound2-data',
        sha256: '04688afdff3769c0f685541daed7b2f6f0cb946799ddf1d5847ddf11fe245559',
        distro: 'debian',
        package: 'libasound2-data',
        source: 'alsa-lib',
        version: '1.2.14-1+deb13u1',
        arch: 'all',
      },
      {
        kind: 'distroPackage',
        name: 'liblcms2-2',
        sha256: '32e53c2002ccea8c60c02779bea0ba49ac132fef702988a30d64af79b6617806',
        distro: 'debian',
        package: 'liblcms2-2',
        source: 'lcms2',
        version: '2.16-2+deb13u2',
        arch: 'amd64',
      },
    ],
    // bin/ first: the bin/emacs launcher (written at install time)
    // wins over the raw usr/bin/emacs-nox for PATH resolution.
    binDirs: ['bin', 'usr/bin'],
    env: {
      // EMACSDATA is the *etc* directory, not the version
      // directory: data-directory IS the etc dir (GNU Emacs FAQ),
      // and the startup charsets check looks for
      // <EMACSDATA>/charsets. Pointing it at the version dir makes
      // that check fail; verified live 2026-11-20.
      EMACSDATA: '${PLUGIN_DIR}/usr/share/emacs/30.1/etc',
      // EMACSPATH is the arch-dependent (libexec) dir. It does NOT
      // redirect the pdmp lookup — install time symlinks the dump
      // to usr/bin/emacs-nox.pdmp for that.
      EMACSPATH: '${PLUGIN_DIR}/usr/libexec/emacs/30.1/x86_64-linux-gnu',
      // EMACSLOADPATH is the lisp tree: the dumped load-path still
      // names the compiled-in /usr/share/emacs/30.1/lisp, so
      // without this emacs cannot find simple.el or any mode.
      // Startup adds the lisp subdirectories automatically.
      EMACSLOADPATH: '${PLUGIN_DIR}/usr/share/emacs/30.1/lisp:${PLUGIN_DIR}/usr/share/emacs/site-lisp',
      // The bundled lib .debs extract to
      // <plugindir>/usr/lib/x86_64-linux-gnu/ — the loader does NOT
      // search there by default, so daemon invocations need it on
      // LD_LIBRARY_PATH. The bin/emacs launcher sets the same value
      // for interactive shells (the shell PATH snippets carry PATH
      // only, not Env).
      LD_LIBRARY_PATH: '${PLUGIN_DIR}/usr/lib/x86_64-linux-gnu',
    },
  },
  {
    // Doom Emacs, sharing the cli-emacs binary — no second copy of
    // the emacs binary/data tree (no `binaries` entry for emacs here,
    // by design; bin/emacs-doom execs the sibling cli-emacs plugin's
    // usr/bin/emacs-nox). `dependencies: ['cli-emacs']` activates
    // the generic guard (cli-emacs cannot be disabled/uninstalled
    // while this plugin is enabled) and the DesiredState
    // auto-enable. `packages` is deliberately OMITTED (like
    // cli-emacs): nothing is system-installed.
    // PINS (observed by cloning upstream 2026-11-20):
    //   doomemacs/core    eab52d2fe5e58303696e129717553ec5bf031bb0 (2026-11-15)
    //   doomemacs/modules f054be8fcdd2a0446eb8259d76dd4f6f76acc0b7 (2026-11-03)
    // Doom pins are real: every package carries a :pin and `doom sync`
    // (run at install time) respects them. DECISIONS: no evil
    // (operators are emacs-preferring; one-line change to add it); no
    // +lsp, no vterm, no flycheck (no Node/cmake/checkers on the box);
    // no -nw forced. Module set: completion corfu+vertico, ui doom
    // hl-todo, emacs dired electric undo vc, term eshell, tools magit
    // editorconfig, os tty, lang data emacs-lisp json sh yaml, config
    // default+bindings+smartparens. UNVERIFIED: non-interactive
    // `doom sync`, `doom doctor` on Emacs 30.1, magit full clone,
    // installed size, fd/fdfind — live first launch still mandatory.
    id: 'cli-emacs-doom',
    name: 'Doom Emacs for /etc/axonwall',
    version: '0.1.0',
    category: 'extension',
    description:
      'Doom Emacs for editing /etc/axonwall configuration files, sharing the cli-emacs bundled GNU Emacs 30.1 binary: the Doom core and modules are cloned at pinned commits and packages installed with doom sync at install time. No evil mode (operators are emacs-preferring), no LSP or vterm (no language servers or C toolchain on the box).',
    author: 'Axonwall Core',
    dependencies: ['cli-emacs'],
    systemdUnits: [],
    privileges: ['system.users', 'system.config.write'],
    cliBinaries: ['emacs-doom'],
    binDirs: ['bin'],
  },
  {
    // Spacemacs (develop branch), sharing the cli-emacs binary — no
    // second copy of the emacs binary/data tree (no `binaries` entry
    // for emacs here, by design). `dependencies: ['cli-emacs']`
    // activates the generic guard and the DesiredState auto-enable.
    // `packages` is deliberately OMITTED: nothing is
    // system-installed.
    // PIN (observed by cloning upstream 2026-11-20):
    //   syl20bnr/spacemacs develop
    //     1f69b2a854a7a46f709def08412dbd5d6dc073a1 (2026-11-09)
    // LATEST-AT-INSTALL, NOT PINNED: Spacemacs has no per-package
    // version pinning (upstream issue #6531). Only the Spacemacs
    // commit is pinned; first start downloads the latest snapshot of
    // every layer package from MELPA/GNU ELPA and needs network. Do
    // not describe this install as pinned. The vendored-elpa-snapshot
    // follow-up is what would make it reproducible; it is NOT done
    // on this branch. Install does no first start and no package
    // install; the pre-seeded dotfile is the attempt at suppressing
    // the first-start wizard, and whether it fully suppresses it is
    // UNVERIFIED. DECISIONS: editing style 'emacs, NOT vim; shell
    // layer uses eshell, NEVER vterm; prettier-js/web-beautify
    // excluded (need Node). Layer set: helm, auto-completion,
    // better-defaults, emacs-lisp, git, version-control, shell
    // (eshell), syntax-checking, yaml, json. No -nw forced. Install
    // fails closed if ~/.spacemacs exists (it always wins over
    // SPACEMACSDIR). No explicit upstream "supports Emacs 30.1"
    // statement — first-start smoke test on the box is mandatory.
    id: 'cli-emacs-spacemacs',
    name: 'Spacemacs for /etc/axonwall',
    version: '0.1.0',
    category: 'extension',
    description:
      'Spacemacs (develop branch) for editing /etc/axonwall configuration files, sharing the cli-emacs bundled GNU Emacs 30.1 binary. The Spacemacs core is cloned at a pinned commit; its packages are downloaded from MELPA/GNU ELPA on first start (latest versions — Spacemacs cannot pin package versions), so a first start needs network. Emacs editing style, not vim.',
    author: 'Axonwall Core',
    dependencies: ['cli-emacs'],
    systemdUnits: [],
    privileges: ['system.users', 'system.config.write'],
    cliBinaries: ['emacs-spacemacs'],
    binDirs: ['bin'],
  },
  {
    id: 'cli-diagnostics-nastymap',
    name: 'NastyMap & Live CLI Telemetry Suite',
    version: '1.0.0',
    category: 'extension',
    description: 'Autonomous host discovery and vulnerability auditing with NastyMap & Nmap, plus real-time system/network monitors (btop, htop, iftop, iotop, slurm, sysstat, dnsutils).',
    author: 'Axonwall Core / NastyMap',
    systemdUnits: [],
    privileges: ['system.monitoring', 'network.interfaces'],
    packages: {
      debian: ['nmap', 'dnsutils', 'net-tools', 'btop', 'htop', 'iftop', 'iotop', 'slurm', 'sysstat'],
      alpine: ['nmap', 'bind-tools', 'net-tools', 'btop', 'htop', 'iftop', 'sysstat'],
      arch: ['nmap', 'bind', 'net-tools', 'btop', 'htop', 'iftop', 'iotop-c', 'sysstat'],
    },
    cliBinaries: ['nmap', 'dig', 'netstat', 'btop', 'htop', 'iftop', 'iostat', 'mpstat'],
    menuEntry: {
      title: 'Diagnostics & NastyMap',
      path: '/diagnostics',
      icon: 'Terminal',
    },
  },
  {
    id: 'rosenpass',
    name: 'Rosenpass Post-Quantum WireGuard (McEliece + ML-KEM)',
    version: '0.2.3',
    category: 'extension',
    description:
      'Hybrid Dual-KEM post-quantum key exchange daemon (Classic McEliece 460896 static authentication + ephemeral ML-KEM-512 forward secrecy) that rotates kernel WireGuard pre-shared keys every 120s with fail-closed boot protection.',
    author: 'Rosenpass Project / Axonwall Core',
    systemdUnits: ['rosenpass.service'],
    privileges: ['vpn.admin', 'network.interfaces'],
    nftHooks: [{ table: 'inet axonwall', chain: 'input', priority: 0 }],
    packages: {
      debian: ['wireguard-tools'],
      alpine: ['rosenpass', 'wireguard-tools'],
      arch: ['rosenpass', 'wireguard-tools'],
    },
    cliBinaries: ['rosenpass', 'wg'],
    // Bundled (was: unverified `curl | tar` into /usr/local/bin at
    // install time). The v0.2.3 release tarball is now downloaded,
    // sha256-verified, and extracted into the plugin's own directory
    // (<plugindir>/bin/rosenpass); the systemd unit's ExecStart
    // points there. Behaviour change: the binary moves from
    // /usr/local/bin to the plugin dir; same version (0.2.3), same
    // unit semantics. Uninstall removes the legacy
    // /usr/local/bin/rosenpass and /usr/local/bin/rp if present.
    // CHECKSUM CAVEAT: rosenpass publishes NO checksum for this
    // tarball — the sha256 below was computed locally from the bytes
    // GitHub served for that asset URL on 2026-11-20 (asset size
    // 4,802,560 bytes). Do NOT claim it is an official published
    // checksum. No second entry for `rp`: the tarball also contains
    // bin/rp, but `rp` is used nowhere in the codebase, so it is not
    // bundled.
    binaries: [
      {
        kind: 'archive',
        name: 'rosenpass',
        sha256: '53158a8c339e3be1a9520b91c33a9e83eab05ea49af346cdb7e6eec522f2318b',
        url: 'https://github.com/rosenpass/rosenpass/releases/download/v0.2.3/rosenpass-x86_64-linux-0.2.3.tar',
        format: 'tar',
        pathInArchive: 'bin/rosenpass',
      },
    ],
    binDirs: ['bin'],
    menuEntry: {
      title: 'Post-Quantum (Rosenpass)',
      path: '/vpn/rosenpass',
      icon: 'ShieldCheck',
    },
  },
  {
    id: 'vigilant-octo-waffle',
    name: 'Vigilant Octo Waffle (K8s GitOps & App Platform)',
    version: '1.0.0',
    category: 'extension',
    defaultEnabled: false,
    dependencies: ['core-k3s'],
    description:
      'Cloud-native Kubernetes GitOps & App Platform for K3s with dual ArgoCD + FluxCD runners (automatic Argo-to-Flux synthesis), 45+ curated apps (Harbor, Rancher, Keycloak, OpenBao, Supabase, Kubeflow, Ollama, vLLM, Nextcloud), Waffle Blueprints, local mkcert TLS + Unbound DNS auto-zones, and 33-permission CASL authorization.',
    author: 'DeployCoop / Axonwall Core',
    systemdUnits: ['k3s.service'],
    privileges: ['k3s.cluster', 'services.vow', 'security.certificates', 'services.dns'],
    menuEntry: {
      title: 'Vigilant Octo Waffle',
      path: '/k3s/vow',
      icon: 'Layers',
    },
    packages: {
      debian: ['kubectl', 'mkcert', 'libnss3-tools', 'gettext-base', 'git', 'curl', 'jq'],
      alpine: ['mkcert', 'nss-tools', 'gettext', 'git', 'curl', 'jq'],
      arch: ['kubectl', 'mkcert', 'nss', 'gettext', 'git', 'curl', 'jq'],
    },
    cliBinaries: ['vow', 'kubectl', 'helm', 'mkcert'],
    ldapIntegration: {
      enabledByDefault: true,
      serviceAccountCn: 'svc-vow',
      inheritApplianceRoleGroups: true,
      envPrefix: 'VOW_LDAP_',
      groups: [
        {
          cn: 'vow-admin',
          gidNumber: 10220,
          description: 'Vigilant Octo Waffle Platform Administrators',
          role: 'admin',
        },
        {
          cn: 'vow-operator',
          gidNumber: 10221,
          description: 'Vigilant Octo Waffle GitOps & Workload Operators',
          role: 'operator',
        },
        {
          cn: 'vow-readonly',
          gidNumber: 10222,
          description: 'Vigilant Octo Waffle Read-Only Viewers',
          role: 'readonly',
        },
      ],
    },
  },
  {
    id: 'host-malware-rootkit',
    name: 'Host Malware, Rootkit & Ghost-in-the-Ring Kernel Hunter',
    version: '1.0.0',
    category: 'extension',
    defaultEnabled: true,
    description:
      'Defense-in-depth host malware, rootkit, and Ring-0 implant suite combining classic scanners (rkhunter, chkrootkit, ClamAV, AIDE, Lynis, YARA, unhide, debsums) with Ghost-in-the-Ring telemetry: io_uring SQPOLL/FIXED_FILE implant hunting (Curing/RingReaper), drgn /proc/kcore prog_idr XArray vs sys_bpf diffing for self-hiding eBPF rootkits (TripleCross/Boopkit/Symbiote), Silicon PMU LBR/BRS branch tracing, and preventive BPF_LSM + sysctl kernel lockdown.',
    author: 'Tekromancy / Axonwall Core',
    systemdUnits: ['clamav-freshclam.service'],
    privileges: ['security.forensics', 'system.hardware', 'system.monitoring'],
    menuEntry: {
      title: 'Rootkit & Kernel Hunter',
      path: '/security/rootkit-hunter',
      icon: 'ShieldAlert',
    },
    packages: {
      debian: [
        'rkhunter',
        'chkrootkit',
        'clamav',
        'clamav-freshclam',
        'lynis',
        'aide',
        'yara',
        'unhide',
        'debsums',
        'bpftool',
        'bpftrace',
        'python3-drgn',
        'linux-perf',
      ],
      alpine: [
        'rkhunter',
        'chkrootkit',
        'clamav',
        'lynis',
        'aide',
        'yara',
        'bpftool',
        'bpftrace',
        'perf',
      ],
      arch: [
        'rkhunter',
        'clamav',
        'lynis',
        'aide',
        'yara',
        'bpf',
        'bpftrace',
        'drgn',
        'perf',
      ],
    },
    cliBinaries: [
      'rkhunter',
      'chkrootkit',
      'clamscan',
      'lynis',
      'aide',
      'yara',
      'unhide',
      'debsums',
      'bpftool',
      'bpftrace',
      'drgn',
      'perf',
      'axonwall-hunt-rootkits',
      'hunt-io-uring-implants.sh',
      'hunt-ebpf-rootkits.sh',
      'audit_hidden_bpf_prog_idr.py',
    ],
  },
  {
    id: 'eluvix',
    name: 'Eluvix Sovereign AI Router, Enterprise Tokenomics & Prompt/PII Guard',
    version: '1.0.0',
    category: 'extension',
    defaultEnabled: false,
    description:
      'Enterprise-wide LLM routing gateway (git@github.com:Eluvixrouter/eluvix.git) delivering up to 85% tokenomics savings via Switchyard cost-complexity routing, sub-2ms Semantic Caching, and DeepSeek MLA FP8 / RDMA KV-cache disaggregation (vLLM NIXL & SGLang Mooncake), paired with inline PromptGuard injection defense, PrivacyGuard PII/secret DLP redaction, confidential TEE attestation, and an 8-harness agent mesh (OpenCode, ACP, TrueForge, OpenHands, Mastra, Letta, A2A, Hermes).',
    author: 'Eluvix Router / Axonwall Core',
    systemdUnits: ['eluvix.service'],
    privileges: ['system.ai', 'security.forensics', 'services.dns'],
    ldapIntegration: {
      enabledByDefault: true,
      serviceAccountCn: 'svc-eluvix',
      inheritApplianceRoleGroups: true,
      envPrefix: 'ELUVIX_LDAP_',
      groups: [
        {
          cn: 'eluvix-admin',
          gidNumber: 10200,
          description: 'Eluvix AI Router Full Administrators',
          role: 'admin',
        },
        {
          cn: 'eluvix-operator',
          gidNumber: 10201,
          description: 'Eluvix AI Router Operators (Chat & Playground)',
          role: 'operator',
        },
        {
          cn: 'eluvix-readonly',
          gidNumber: 10202,
          description: 'Eluvix AI Router Read-Only Auditors',
          role: 'readonly',
        },
      ],
    },
    nftHooks: [{ table: 'inet axonwall', chain: 'input', priority: 0 }],
    menuEntry: {
      title: 'Eluvix AI Router & DLP',
      path: '/ai/eluvix',
      icon: 'Sparkles',
    },
    packages: {
      debian: ['nodejs', 'git', 'curl', 'jq', 'sqlite3'],
      alpine: ['nodejs', 'git', 'curl', 'jq', 'sqlite'],
      arch: ['nodejs', 'git', 'curl', 'jq', 'sqlite'],
    },
    cliBinaries: ['eluvix', 'opencode', 'agy'],
  },
  {
    id: 'coroot-ebpf-apm',
    name: 'Coroot eBPF APM, L7 RED Dissector, Continuous Profiler & Automated RCA',
    version: '1.14.0',
    category: 'extension',
    defaultEnabled: true,
    description:
      'Zero-instrumentation eBPF APM & Root-Cause Analysis engine (inspired by coroot/coroot & coroot-node-agent): automatic Service Dependency Map, L7 protocol RED metrics (HTTP, gRPC, PostgreSQL, MySQL, Redis, Kafka, ClickHouse, DNS), optional OpenSSL/Go TLS uprobes, 99 Hz perf_event continuous CPU & Disk I/O FlameGraph profiling, and 35+ deterministic SLO/RCA health inspections.',
    author: 'Coroot / Axonwall Core',
    systemdUnits: ['coroot-node-agent.service'],
    privileges: ['system.monitoring', 'reporting.flows', 'system.hardware'],
    packages: {
      debian: ['bpftool', 'linux-perf'],
      alpine: ['bpftool', 'perf'],
      arch: ['bpf', 'perf'],
    },
    cliBinaries: ['coroot-node-agent', 'bpftool', 'perf'],
    menuEntry: {
      title: 'eBPF & K3s Observability',
      path: '/reporting/ebpf',
      icon: 'Cpu',
    },
  },
  {
    id: 'ebpf-threat-harvester',
    name: 'Axonwall Blackbox: Extreme eBPF Threat-LLM Harvester',
    version: '0.3.1',
    category: 'extension',
    defaultEnabled: false,
    description:
      'Opt-in Ring-0 eBPF flight recorder & dataset harvester capturing correlated wire flows (TCX), execve/memfd_create process lineage, and guarded TLS uprobes into Causal Episode SFT/RLVR JSONL + Apache Parquet corpora for training threat-detection LLMs.',
    author: 'Axonwall Core',
    systemdUnits: [],
    privileges: ['firewall.rules', 'system.monitoring', 'reporting.flows'],
    nftHooks: [
      { table: 'inet axonwall', chain: 'forward', priority: 0 },
    ],
    menuEntry: {
      title: 'Blackbox Harvester',
      path: '/security/threat-harvester',
      icon: 'Binary',
    },
    packages: {
      debian: ['bpftool', 'zstd'],
      alpine: ['bpftool', 'zstd'],
      arch: ['bpf', 'zstd'],
    },
    cliBinaries: ['axonwallctl'],
  },
];

export function resolveCapabilities(state?: Partial<DesiredState>): CoreCapabilities {
  const plugins = state?.plugins ?? [];
  const fwPlugin = plugins.find((p) => p.id === 'core-firewall');
  const nasPlugin = plugins.find((p) => p.id === 'core-nas');
  const k3sPlugin = plugins.find((p) => p.id === 'core-k3s');
  const virtPlugin = plugins.find((p) => p.id === 'core-virt');
  const vigilantePlugin = plugins.find((p) => p.id === 'core-vigilante');

  const firewallEnabled =
    state?.capabilities?.firewallEnabled !== undefined
      ? state.capabilities.firewallEnabled
      : fwPlugin !== undefined
        ? fwPlugin.enabled
        : true;

  const nasEnabled =
    state?.capabilities?.nasEnabled !== undefined
      ? state.capabilities.nasEnabled
      : nasPlugin !== undefined
        ? nasPlugin.enabled
        : Boolean(state?.nas?.enabled);

  const k3sEnabled =
    state?.capabilities?.k3sEnabled !== undefined
      ? state.capabilities.k3sEnabled
      : k3sPlugin !== undefined
        ? k3sPlugin.enabled
        : Boolean(state?.k3s?.enabled);

  const virtEnabled =
    state?.capabilities?.virtEnabled !== undefined
      ? state.capabilities.virtEnabled
      : virtPlugin !== undefined
        ? virtPlugin.enabled
        : Boolean(state?.virt?.enabled);

  const vigilanteEnabled =
    state?.capabilities?.vigilanteEnabled !== undefined
      ? state.capabilities.vigilanteEnabled
      : vigilantePlugin !== undefined
        ? vigilantePlugin.enabled
        : Boolean(state?.vigilante?.enabled);

  return {
    firewallEnabled,
    nasEnabled,
    k3sEnabled,
    virtEnabled,
    vigilanteEnabled,
  };
}

export function validatePluginManifest(manifest: unknown): PluginManifest {
  return PluginManifestSchema.parse(manifest);
}

export function findPluginById(id: string): PluginManifest | undefined {
  return BUILTIN_PLUGINS.find((p) => p.id === id);
}

const PLUGIN_PRIVILEGE_ALIASES: Record<string, string[]> = {
  'network.routing': ['routing.read', 'routing.write'],
  'network.interfaces': ['interfaces.read', 'interfaces.write'],
  'vpn.admin': ['vpn.wireguard.read', 'vpn.wireguard.write'],
  'vpn.tailscale': ['vpn.wireguard.read', 'vpn.wireguard.write'],
  'system.monitoring': ['system.status.read'],
  'system.power': ['system.reboot'],
  'system.hardware': ['system.status.read', 'system.config.write'],
  'system.certificates': ['system.config.read', 'system.config.write'],
  'reporting.flows': ['diagnostics.read', 'system.status.read'],
  'services.haproxy': ['system.config.read', 'system.config.write'],
  'services.freeradius': ['system.config.read', 'system.config.write'],
};

export function isPluginAllowed(manifest: PluginManifest, grantedPrivileges: string[]): boolean {
  if (grantedPrivileges.includes('system.superuser') || grantedPrivileges.includes('*')) {
    return true;
  }
  return manifest.privileges.every((priv) => {
    if (grantedPrivileges.includes(priv)) return true;
    if (grantedPrivileges.some((g) => g.startsWith(`${priv}.`))) return true;
    const mapped = PLUGIN_PRIVILEGE_ALIASES[priv];
    if (mapped && mapped.some((m) => grantedPrivileges.includes(m))) return true;
    return false;
  });
}

export function getPluginDependencies(pluginId: string): string[] {
  const manifest = findPluginById(pluginId);
  return manifest?.dependencies ?? [];
}

export function getDependentPlugins(pluginId: string): PluginManifest[] {
  return BUILTIN_PLUGINS.filter((p) => (p.dependencies ?? []).includes(pluginId));
}

export function arePluginDependenciesMet(
  pluginId: string,
  state?: Partial<DesiredState> | null
): { met: boolean; missing: string[] } {
  const deps = getPluginDependencies(pluginId);
  if (deps.length === 0) {
    return { met: true, missing: [] };
  }
  const missing = deps.filter((depId) => !isPluginEnabled(depId, state));
  return {
    met: missing.length === 0,
    missing,
  };
}

export function isPluginEnabled(pluginId: string, state?: Partial<DesiredState> | null): boolean {
  if (!state) {
    return (
      pluginId === 'core-firewall' ||
      pluginId === 'cli-workstation' ||
      pluginId === 'host-malware-rootkit' ||
      pluginId === 'coroot-ebpf-apm'
    );
  }

  // Enforce plugin dependencies first (e.g., vigilant-octo-waffle requires core-k3s)
  const deps = getPluginDependencies(pluginId);
  for (const depId of deps) {
    if (depId !== pluginId && !isPluginEnabled(depId, state)) {
      return false;
    }
  }

  // Check core roles
  if (pluginId === 'core-firewall') {
    return state.capabilities?.firewallEnabled !== false;
  }
  if (pluginId === 'core-nas') {
    return Boolean(state.capabilities?.nasEnabled ?? state.nas?.enabled);
  }
  if (pluginId === 'core-k3s') {
    return Boolean(state.capabilities?.k3sEnabled ?? state.k3s?.enabled);
  }
  if (pluginId === 'core-virt') {
    return Boolean(state.capabilities?.virtEnabled ?? state.virt?.enabled);
  }
  if (pluginId === 'core-vigilante') {
    return Boolean(state.capabilities?.vigilanteEnabled ?? state.vigilante?.enabled);
  }

  // Modern Operator Shell & Editor (ZSH, Oh My Zsh, Starship, VIM) is enabled by default
  if (pluginId === 'cli-workstation') {
    const entry = state.plugins?.find((p) => p.id === 'cli-workstation');
    return entry ? entry.enabled !== false : true;
  }

  // Host Malware, Rootkit & Ghost-in-the-Ring Kernel Hunter is enabled by default
  if (pluginId === 'host-malware-rootkit') {
    if (state.hostDefense?.enabled !== undefined) {
      return state.hostDefense.enabled;
    }
    const entry = state.plugins?.find((p) => p.id === 'host-malware-rootkit');
    return entry ? entry.enabled !== false : true;
  }

  // Axonwall Blackbox: Extreme eBPF Threat-LLM Harvester is strictly opt-in
  if (pluginId === 'ebpf-threat-harvester') {
    if (state.threatHarvester?.enabled !== undefined) {
      return state.threatHarvester.enabled;
    }
    return Boolean(state.plugins?.some((p) => p.id === 'ebpf-threat-harvester' && p.enabled));
  }

  // Check specific service/extension plugins
  if (pluginId === 'vigilant-octo-waffle') {
    if (state.vow?.enabled !== undefined) {
      return state.vow.enabled;
    }
    return Boolean(state.plugins?.some((p) => p.id === 'vigilant-octo-waffle' && p.enabled));
  }
  if (pluginId === 'eluvix') {
    return Boolean(state.eluvix?.enabled) || Boolean(state.plugins?.some((p) => p.id === 'eluvix' && p.enabled));
  }
  if (pluginId === 'nut-ups') {
    return Boolean(state.ups?.enabled) || Boolean(state.plugins?.some((p) => p.id === 'nut-ups' && p.enabled));
  }
  if (pluginId === 'headscale') {
    return Boolean(state.headscale?.enabled) || Boolean(state.plugins?.some((p) => p.id === 'headscale' && p.enabled));
  }
  if (pluginId === 'rosenpass') {
    return Boolean(state.rosenpass?.enabled) || Boolean(state.plugins?.some((p) => p.id === 'rosenpass' && p.enabled));
  }
  if (pluginId === 'haproxy') {
    return Boolean(state.haproxy?.enabled) || Boolean(state.plugins?.some((p) => p.id === 'haproxy' && p.enabled));
  }
  if (pluginId === 'freeradius') {
    return Boolean(state.freeradius?.enabled) || Boolean(state.plugins?.some((p) => p.id === 'freeradius' && p.enabled));
  }
  if (pluginId === 'snmp') {
    return Boolean(state.snmp?.enabled) || Boolean(state.plugins?.some((p) => p.id === 'snmp' && p.enabled));
  }
  if (pluginId === 'coroot-ebpf-apm') {
    const pluginEntry = state.plugins?.find((p) => p.id === 'coroot-ebpf-apm');
    if (state.observability?.ebpfApm?.enabled !== undefined) {
      return state.observability.ebpfApm.enabled && (pluginEntry ? pluginEntry.enabled !== false : true);
    }
    return pluginEntry ? pluginEntry.enabled !== false : true;
  }

  // Generic extension plugin check
  return Boolean(state.plugins?.some((p) => p.id === pluginId && p.enabled));
}

/**
 * Enables a plugin in DesiredState and automatically enables any required plugin dependencies
 * (such as enabling `core-k3s` when `vigilant-octo-waffle` is enabled).
 */
export function enablePluginWithDependencies(
  pluginId: string,
  inputState: DesiredState
): { state: DesiredState; autoEnabledDependencies: string[] } {
  const next = structuredClone(inputState);
  const autoEnabledDependencies: string[] = [];

  const enableSingle = (id: string, isAutoDep = false) => {
    // Recursively enable dependencies first
    for (const depId of getPluginDependencies(id)) {
      if (!isPluginEnabled(depId, next)) {
        enableSingle(depId, true);
      }
    }

    if (isAutoDep && !autoEnabledDependencies.includes(id)) {
      autoEnabledDependencies.push(id);
    }

    if (id === 'core-k3s') {
      next.capabilities = {
        firewallEnabled: next.capabilities?.firewallEnabled !== false,
        nasEnabled: Boolean(next.capabilities?.nasEnabled ?? next.nas?.enabled),
        k3sEnabled: true,
        virtEnabled: Boolean(next.capabilities?.virtEnabled ?? next.virt?.enabled),
        vigilanteEnabled: Boolean(next.capabilities?.vigilanteEnabled ?? next.vigilante?.enabled),
      };
      next.k3s = next.k3s || {
        enabled: true,
        clusterCidr: '10.42.0.0/16',
        serviceCidr: '10.43.0.0/16',
        nodeIpInterface: 'lan',
        flannelBackend: 'wireguard-native',
        disableTraefik: false,
        autoJoinHaPeer: true,
        enableUserNamespaces: false,
        bpfTokenProfiles: [],
        openEbs: {
          enabled: true,
          zfsLocalPvEnabled: true,
          zfsLocalPvPool: 'tank',
          replicatedStorageEnabled: true,
          defaultReplicaCount: 2,
          replicatedBackingPool: 'tank/openebs-replicated',
        },
        workloads: [],
      };
      next.k3s.enabled = true;
    } else if (id === 'core-vigilante') {
      next.capabilities = {
        firewallEnabled: next.capabilities?.firewallEnabled !== false,
        nasEnabled: Boolean(next.capabilities?.nasEnabled ?? next.nas?.enabled),
        k3sEnabled: Boolean(next.capabilities?.k3sEnabled ?? next.k3s?.enabled ?? true),
        virtEnabled: Boolean(next.capabilities?.virtEnabled ?? next.virt?.enabled),
        vigilanteEnabled: true,
      };
      next.vigilante = next.vigilante
        ? { ...next.vigilante, enabled: true }
        : VigilanteConfigSchema.parse({ enabled: true });
    } else if (id === 'vigilant-octo-waffle') {
      next.vow = next.vow ? { ...next.vow, enabled: true } : VowConfigSchema.parse({ enabled: true });
    } else if (id === 'host-malware-rootkit') {
      next.hostDefense = next.hostDefense
        ? { ...next.hostDefense, enabled: true }
        : HostMalwareDefenseConfigSchema.parse({ enabled: true });
    } else if (id === 'ebpf-threat-harvester') {
      next.threatHarvester = next.threatHarvester
        ? { ...next.threatHarvester, enabled: true }
        : ThreatHarvesterConfigSchema.parse({ enabled: true });
    } else if (id === 'eluvix') {
      next.eluvix = next.eluvix
        ? { ...next.eluvix, enabled: true }
        : EluvixConfigSchema.parse({ enabled: true });
    }

    const plugins = next.plugins || [];
    const idx = plugins.findIndex((p) => p.id === id);
    if (idx >= 0) {
      plugins[idx].enabled = true;
    } else {
      plugins.push({ id, enabled: true, installedAt: new Date().toISOString() });
    }
    next.plugins = plugins;
  };

  enableSingle(pluginId, false);
  return { state: next, autoEnabledDependencies };
}

/**
 * Disables a plugin in DesiredState and automatically disables any plugins that depend on it
 * (such as disabling `vigilant-octo-waffle` and `core-vigilante` when `core-k3s` is disabled).
 */
export function disablePluginWithDependents(
  pluginId: string,
  inputState: DesiredState
): { state: DesiredState; autoDisabledDependents: string[] } {
  const next = structuredClone(inputState);
  const autoDisabledDependents: string[] = [];

  const disableSingle = (id: string, isAutoDependent = false) => {
    for (const depPlugin of getDependentPlugins(id)) {
      if (
        isPluginEnabled(depPlugin.id, next) ||
        (depPlugin.id === 'vigilant-octo-waffle' && next.vow?.enabled) ||
        (depPlugin.id === 'core-vigilante' && (next.capabilities?.vigilanteEnabled || next.vigilante?.enabled))
      ) {
        disableSingle(depPlugin.id, true);
      }
    }

    if (isAutoDependent && !autoDisabledDependents.includes(id)) {
      autoDisabledDependents.push(id);
    }

    if (id === 'core-firewall') {
      if (next.capabilities) {
        next.capabilities.firewallEnabled = false;
      }
    } else if (id === 'core-nas') {
      if (next.capabilities) {
        next.capabilities.nasEnabled = false;
      }
      if (next.nas) {
        next.nas.enabled = false;
      }
    } else if (id === 'core-virt') {
      if (next.capabilities) {
        next.capabilities.virtEnabled = false;
      }
      if (next.virt) {
        next.virt.enabled = false;
      }
    } else if (id === 'core-k3s') {
      if (next.capabilities) {
        next.capabilities.k3sEnabled = false;
      }
      if (next.k3s) {
        next.k3s.enabled = false;
      }
    } else if (id === 'core-vigilante') {
      if (next.capabilities) {
        next.capabilities.vigilanteEnabled = false;
      }
      if (next.vigilante) {
        next.vigilante.enabled = false;
      }
    } else if (id === 'vigilant-octo-waffle') {
      if (next.vow) {
        next.vow.enabled = false;
      }
    } else if (id === 'host-malware-rootkit') {
      if (next.hostDefense) {
        next.hostDefense.enabled = false;
      }
    } else if (id === 'ebpf-threat-harvester') {
      if (next.threatHarvester) {
        next.threatHarvester.enabled = false;
      }
    } else if (id === 'eluvix') {
      if (next.eluvix) {
        next.eluvix.enabled = false;
      }
    } else if (id === 'haproxy') {
      if (next.haproxy) {
        next.haproxy.enabled = false;
      }
    } else if (id === 'rosenpass') {
      if (next.rosenpass) {
        next.rosenpass.enabled = false;
      }
    } else if (id === 'freeradius') {
      if (next.freeradius) {
        next.freeradius.enabled = false;
      }
    } else if (id === 'snmp') {
      if (next.snmp) {
        next.snmp.enabled = false;
      }
    } else if (id === 'nut-ups') {
      if (next.ups) {
        next.ups.enabled = false;
      }
    } else if (id === 'headscale') {
      if (next.headscale) {
        next.headscale.enabled = false;
      }
    } else if (id === 'coroot-ebpf-apm') {
      if (next.observability?.ebpfApm) {
        next.observability.ebpfApm.enabled = false;
      }
    }

    const plugins = next.plugins || [];
    const idx = plugins.findIndex((p) => p.id === id);
    if (idx >= 0) {
      plugins[idx].enabled = false;
    } else {
      plugins.push({ id, enabled: false });
    }
    next.plugins = plugins;
  };

  disableSingle(pluginId, false);
  return { state: next, autoDisabledDependents };
}

