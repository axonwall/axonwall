-- ============================================================================
-- 🛡️ AXONWALL NEOVIM SUPER CONFIGURATOR (/etc/axonwall/nvim/init.lua)
-- Hyperfocused Lua Form & Table TUI with 100% Native Vim Motions in Every Field
-- ============================================================================

local api = vim.api
local fn = vim.fn

-- 1. Strip 100% of traditional Vim chrome so Neovim looks like a dedicated TUI
vim.opt.compatible = false
vim.opt.number = false
vim.opt.relativenumber = false
vim.opt.signcolumn = "no"
vim.opt.foldcolumn = "0"
vim.opt.laststatus = 0
vim.opt.cmdheight = 0
vim.opt.showmode = false
vim.opt.ruler = false
vim.opt.showcmd = false
vim.opt.showtabline = 0
vim.opt.swapfile = false
vim.opt.backup = false
vim.opt.writebackup = false
vim.opt.undofile = false
vim.opt.wrap = false
vim.opt.cursorline = true
vim.opt.termguicolors = true
vim.opt.shortmess:append("IWsWcF")
vim.opt.fillchars = {
  eob = " ",
  vert = "│",
  horiz = "─",
  horizup = "┴",
  horizdown = "┬",
  vertleft = "┤",
  vertright = "├",
  verthoriz = "┼",
}
vim.g.mapleader = " "

-- 2. Cyber-Emerald & Obsidian Highlight Theme
local function setup_highlights()
  local hl = function(name, opts)
    api.nvim_set_hl(0, name, opts)
  end
  hl("Normal", { fg = "#e2e8f0", bg = "#0a0e14" })
  hl("NormalFloat", { fg = "#e2e8f0", bg = "#0d121a" })
  hl("FloatBorder", { fg = "#1e293b", bg = "#0d121a" })
  hl("FloatTitle", { fg = "#10b981", bg = "#0d121a", bold = true })
  hl("CursorLine", { bg = "#162032" })
  hl("Visual", { bg = "#1e3a5f", fg = "#ffffff", bold = true })

  hl("AxonHeaderBg", { fg = "#f8fafc", bg = "#091510" })
  hl("AxonBrand", { fg = "#10b981", bg = "#091510", bold = true })
  hl("AxonHeaderMeta", { fg = "#38bdf8", bg = "#091510", bold = true })
  hl("AxonDirtyBadge", { fg = "#fbbf24", bg = "#091510", bold = true })
  hl("AxonCleanBadge", { fg = "#10b981", bg = "#091510", bold = true })
  hl("AxonCommitWarn", { fg = "#000000", bg = "#fbbf24", bold = true })

  hl("AxonActiveBorder", { fg = "#10b981", bg = "#0d121a", bold = true })
  hl("AxonInactiveBorder", { fg = "#334155", bg = "#0d121a" })

  hl("AxonSidebarActive", { fg = "#10b981", bg = "#132a20", bold = true })
  hl("AxonSidebarItem", { fg = "#94a3b8", bg = "#0d121a" })
  hl("AxonSidebarKey", { fg = "#38bdf8", bold = true })
  hl("AxonSidebarCount", { fg = "#64748b" })

  hl("AxonCardTop", { fg = "#38bdf8", bold = true })
  hl("AxonCardBottom", { fg = "#1e293b" })
  hl("AxonFieldBorder", { fg = "#38bdf8" })
  hl("AxonFieldLabel", { fg = "#94a3b8", bold = true })
  hl("AxonFieldSep", { fg = "#334155" })

  hl("AxonBadgeOn", { fg = "#10b981", bold = true })
  hl("AxonBadgeOff", { fg = "#64748b" })
  hl("AxonBadgeEnum", { fg = "#c084fc", bold = true })
  hl("AxonValid", { fg = "#10b981" })
  hl("AxonInvalid", { fg = "#f43f5e", bold = true })
  hl("AxonHint", { fg = "#64748b", italic = true })

  hl("AxonInspectorTitle", { fg = "#38bdf8", bold = true })
  hl("AxonInspectorKey", { fg = "#10b981", bold = true })
  hl("AxonInspectorVal", { fg = "#e2e8f0" })
  hl("AxonFooterKey", { fg = "#0a0e14", bg = "#10b981", bold = true })
  hl("AxonFooterDesc", { fg = "#cbd5e1", bg = "#111827" })
end

setup_highlights()

-- 3.Namespaces & Global Application State
local ns_form = api.nvim_create_namespace("axonwall_super_form")
local ns_diag = api.nvim_create_namespace("axonwall_super_diag")
local ns_side = api.nvim_create_namespace("axonwall_super_side")
local ns_head = api.nvim_create_namespace("axonwall_super_head")
local ns_insp = api.nvim_create_namespace("axonwall_super_insp")

local App = {
  state = {},
  dirty = false,
  active_domain_idx = 3, -- Default to Firewall Rules
  focused_pane = "form", -- "form" or "sidebar"
  field_map = {},        -- line_nr (1-indexed) -> field descriptor
  validation_errors = {},-- line_nr -> error message
  status_msg = "Welcome to Axonwall Super Configurator — Full Vim motions inside every field!",
  status_hl = "AxonValid",
  pending_confirm = false,
  confirm_remaining = 0,
  wins = {},
  bufs = {},
  updating_buffer = false,
}

-- 4. Domain Definitions (12 Full-Stack Domains)
local DOMAINS = {
  { id = "system",     key = "1", icon = "🖥️ ", label = "System & Capabilities", yaml = "system.yaml" },
  { id = "interfaces", key = "2", icon = "🌐", label = "Interfaces & VLANs",    yaml = "interfaces.yaml" },
  { id = "firewall",   key = "3", icon = "🛡️ ", label = "Firewall Rules",        yaml = "firewall.yaml" },
  { id = "nat",        key = "4", icon = "🔀", label = "NAT & Port Forwards",   yaml = "firewall.yaml" },
  { id = "aliases",    key = "5", icon = "📦", label = "Firewall Aliases",      yaml = "firewall.yaml" },
  { id = "routing",    key = "6", icon = "🧭", label = "Routing, SD-WAN & FRR", yaml = "routing.yaml" },
  { id = "services",   key = "7", icon = "📡", label = "DHCPv4 & Unbound DNS",  yaml = "services.yaml" },
  { id = "vpn",        key = "8", icon = "🔐", label = "WireGuard & PQ-VPN",    yaml = "vpn.yaml" },
  { id = "security",   key = "9", icon = "🚨", label = "IDS/IPS & CrowdSec",    yaml = "security.yaml" },
  { id = "ha",         key = "0", icon = "⚡", label = "High Availability",     yaml = "ha.yaml" },
  { id = "storage",    key = "-", icon = "💾", label = "OpenZFS NAS Storage",   yaml = "storage.yaml" },
  { id = "compute",    key = "=", icon = "☸️ ", label = "K3s, KVM Virt & SOC",   yaml = "k3s.yaml" },
}

-- Resolve axonwallctl binary path
local function resolve_ctl_cmd()
  if vim.env.AXONWALLCTL_BIN and fn.filereadable(vim.env.AXONWALLCTL_BIN) == 1 then
    return { "node", vim.env.AXONWALLCTL_BIN }
  end
  if fn.executable("axonwallctl") == 1 then
    return { "axonwallctl" }
  end
  for _, candidate in ipairs({
    "/opt/axonwall/apps/axonwall-controller/dist/axonwallctl.js",
    fn.getcwd() .. "/apps/axonwall-controller/dist/axonwallctl.js",
    fn.getcwd() .. "/dist/axonwallctl.js",
  }) do
    if fn.filereadable(candidate) == 1 then
      return { "node", candidate }
    end
  end
  return nil
end

local function run_ctl(subargs, stdin_data)
  local cmd = resolve_ctl_cmd()
  if not cmd then
    return "", 127
  end
  for _, a in ipairs(subargs) do
    table.insert(cmd, a)
  end
  local ok, out = pcall(fn.system, cmd, stdin_data)
  if not ok then
    return tostring(out), 1
  end
  return out, vim.v.shell_error
end

-- 5. Default Fallback State & State Loader
local function default_state()
  return {
    version = 1,
    capabilities = {
      firewallEnabled = true,
      nasEnabled = false,
      k3sEnabled = false,
      virtEnabled = false,
      vigilanteEnabled = false,
    },
    system = {
      hostname = "axonwall",
      domain = "local.lan",
      timezone = "UTC",
      dnsServers = { "1.1.1.1", "8.8.8.8" },
      flowtableOffload = true,
      sshEnabled = true,
      sshPort = 22,
      webGuiPort = 2966,
      antiLockout = { enabled = true, interface = "lan", ports = { 80, 443, 22, 2966 } },
    },
    mcp = { enabled = false },
    interfaces = {
      { name = "wan", device = "eth0", type = "dhcp", enabled = true, mtu = 1500, description = "Primary WAN Uplink" },
      { name = "lan", device = "eth1", type = "static", ipv4Address = "192.168.1.1/24", enabled = true, mtu = 1500, description = "Trusted LAN Subnet" },
    },
    vlans = {},
    aliases = {},
    rules = {
      {
        id = "default-lan-pass",
        enabled = true,
        action = "pass",
        direction = "in",
        interface = "lan",
        protocol = "any",
        source = "any",
        sourcePort = "",
        destination = "any",
        destinationPort = "",
        log = false,
        description = "Default Allow LAN to Any",
      },
    },
    nat = {},
    gateways = {},
    routes = {},
    frr = {
      bgp = { enabled = false, asNumber = 65000, routerId = "192.168.1.1", neighbors = {}, networks = {} },
      ospf = { enabled = false, routerId = "192.168.1.1", areas = {} },
    },
    dhcp = { enabled = true, subnets = {} },
    dns = { enabled = true, dnssec = true, dotEnabled = false, dotUpstreams = { "1.1.1.1", "9.9.9.9" }, hostOverrides = {} },
    wireguard = { enabled = false, listenPort = 51820, address = "10.10.0.1/24", peers = {} },
    rosenpass = { enabled = false, listenPort = 9999, wgDevice = "wg0", rekeyIntervalSeconds = 120, failClosedBootGuard = true, peers = {} },
    headscale = { enabled = false, magicDnsDomain = "mesh.axonwall.local" },
    suricata = { enabled = false, mode = "ids", interfaces = { "wan" }, blockOnHighSeverity = true },
    crowdsec = { enabled = false, action = "drop", remediationSetName = "crowdsec_blackhole", logBanned = true },
    geoip = { enabled = false, mode = "block", countries = {} },
    ha = { enabled = false, nodeRole = "master", syncInterface = "lan", peerIp = "", virtualRouterId = 51 },
    nas = { enabled = false, workgroup = "WORKGROUP", serverString = "Axonwall ZFS NAS", pools = {}, datasets = {}, smbShares = {}, nfsExports = {} },
    k3s = { enabled = false, clusterCidr = "10.42.0.0/16", serviceCidr = "10.43.0.0/16", flannelBackend = "wireguard-native", disableTraefik = false },
    vow = { enabled = false, cdRunner = "argocd", domain = "vow.axonwall.local", activePreset = "minimal", localTlsMkcert = true, syncUnboundDns = true, authzEnabled = false },
    virt = { enabled = false, defaultPool = "tank", isoPool = "tank", vms = {}, containers = {} },
    vigilante = { enabled = false, autoBlockCritical = false, defaultBlockTtlSeconds = 3600 },
  }
end

local function load_state()
  local out, code = run_ctl({ "dump-json" })
  if code == 0 and out and #out > 2 then
    local ok, decoded = pcall(fn.json_decode, out)
    if ok and type(decoded) == "table" then
      App.state = decoded
      App.dirty = false
      return
    end
  end
  App.state = default_state()
  App.dirty = false
end

-- 6. Field Validators (Real-Time Schema Feedback)
local function is_valid_ipv4(str)
  local a, b, c, d = str:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
  if not a then return false end
  for _, n in ipairs({ tonumber(a), tonumber(b), tonumber(c), tonumber(d) }) do
    if not n or n < 0 or n > 255 then return false end
  end
  return true
end

local function is_valid_cidr(str)
  local ip, prefix = str:match("^([^/]+)/(%d+)$")
  if not ip or not prefix then return false end
  local p = tonumber(prefix)
  if is_valid_ipv4(ip) then
    return p ~= nil and p >= 0 and p <= 32
  end
  if ip:find(":") then
    return p ~= nil and p >= 0 and p <= 128
  end
  return false
end

local function validate_field_value(field, raw_val)
  local v = vim.trim(raw_val or "")
  local vtype = field.vtype or "string"

  if vtype == "boolean" then
    local low = v:lower()
    if low == "true" or low == "enabled" or low == "on" or low == "yes" or low == "1" then
      return true, true, "✔ Boolean (TRUE)"
    elseif low == "false" or low == "disabled" or low == "off" or low == "no" or low == "0" then
      return true, false, "✔ Boolean (FALSE)"
    end
    return false, nil, "✖ Must be true/false (or press <Space> to toggle)"
  elseif vtype == "enum" then
    for _, opt in ipairs(field.options or {}) do
      if v == opt then
        return true, v, "✔ Allowed (" .. table.concat(field.options, " | ") .. ")"
      end
    end
    return false, nil, "✖ Must be one of: " .. table.concat(field.options or {}, ", ")
  elseif vtype == "int" then
    local n = tonumber(v)
    if not n or math.floor(n) ~= n then
      return false, nil, "✖ Must be a whole integer"
    end
    if field.min and n < field.min then
      return false, nil, string.format("✖ Minimum value is %d", field.min)
    end
    if field.max and n > field.max then
      return false, nil, string.format("✖ Maximum value is %d", field.max)
    end
    return true, n, string.format("✔ Integer (%d..%d)", field.min or 0, field.max or 65535)
  elseif vtype == "cidr" then
    if field.allow_empty and v == "" then
      return true, "", "✔ Optional CIDR"
    end
    if is_valid_cidr(v) then
      return true, v, "✔ Valid CIDR notation"
    end
    return false, nil, "✖ Expected IPv4/v6 CIDR (e.g. 192.168.1.1/24)"
  elseif vtype == "ip" then
    if field.allow_empty and v == "" then
      return true, "", "✔ Optional IP"
    end
    if is_valid_ipv4(v) or v:find(":") then
      return true, v, "✔ Valid IP address"
    end
    return false, nil, "✖ Expected valid IPv4 or IPv6 address"
  elseif vtype == "fw_endpoint" then
    if v == "any" or v == "wan_ip" or v:sub(1, 1) == "$" or is_valid_ipv4(v) or is_valid_cidr(v) or v:find(":") then
      return true, v, "✔ Valid endpoint (any, IP, CIDR, or $alias)"
    end
    return false, nil, "✖ Expected 'any', IP, CIDR, or '$alias_name'"
  elseif vtype == "port" then
    if v == "" or v == "any" or v:sub(1, 1) == "$" then
      return true, v, "✔ Any port / Alias"
    end
    local single = v:match("^(%d+)$")
    if single then
      local p = tonumber(single)
      if p and p >= 1 and p <= 65535 then return true, v, "✔ Port " .. p end
    end
    local p1, p2 = v:match("^(%d+)[:%-](%d+)$")
    if p1 and p2 then
      local n1, n2 = tonumber(p1), tonumber(p2)
      if n1 and n2 and n1 >= 1 and n2 <= 65535 and n1 <= n2 then
        return true, n1 .. ":" .. n2, "✔ Port Range " .. n1 .. ":" .. n2
      end
    end
    return false, nil, "✖ Expected port (1-65535), range (8000:8080), or $alias"
  elseif vtype == "csv" then
    local list = {}
    for item in v:gmatch("[^,%s]+") do
      table.insert(list, item)
    end
    return true, list, string.format("✔ %d item(s)", #list)
  else
    if not field.allow_empty and v == "" then
      return false, nil, "✖ Field cannot be empty"
    end
    return true, v, "✔ Text"
  end
end

-- Helper to get dynamic interface names
local function get_interface_options(include_special)
  local opts = {}
  for _, iface in ipairs(App.state.interfaces or {}) do
    if iface.name and iface.name ~= "" then
      table.insert(opts, iface.name)
    end
  end
  if #opts == 0 then
    opts = { "wan", "lan" }
  end
  if include_special then
    table.insert(opts, "any")
    table.insert(opts, "floating")
  end
  return opts
end

-- 7. Build Field Schema Descriptors for Active Domain
local function build_domain_fields(domain_id)
  local fields = {}
  local st = App.state

  local function add(spec)
    table.insert(fields, spec)
  end

  if domain_id == "system" then
    st.system = st.system or {}
    st.capabilities = st.capabilities or {}
    st.mcp = st.mcp or { enabled = false }

    add({
      card_title = "🖥️  Appliance Identity & Management Plane",
      card_subtitle = "/etc/axonwall/system.yaml",
      label = "Hostname",
      vtype = "string",
      desc = "System hostname broadcast via DHCP, LLDP, and TLS SANs.",
      tip = "Use ciw to change the hostname, or A to append.",
      get = function() return st.system.hostname or "axonwall" end,
      set = function(v) st.system.hostname = v end,
    })
    add({
      label = "Domain Name",
      vtype = "string",
      desc = "Local DNS search domain and OpenLDAP base DN suffix.",
      tip = "Use f. then cw to change the TLD.",
      get = function() return st.system.domain or "local.lan" end,
      set = function(v) st.system.domain = v end,
    })
    add({
      label = "Timezone",
      vtype = "string",
      desc = "IANA timezone identifier (e.g. UTC, America/Chicago).",
      get = function() return st.system.timezone or "UTC" end,
      set = function(v) st.system.timezone = v end,
    })
    add({
      label = "Upstream DNS Servers",
      vtype = "csv",
      desc = "Comma-separated fallback DNS servers for the appliance.",
      tip = "Edit IPs directly with ciw or add comma-separated resolvers.",
      get = function() return table.concat(st.system.dnsServers or { "1.1.1.1", "8.8.8.8" }, ", ") end,
      set = function(v) st.system.dnsServers = v end,
    })
    add({
      label = "Web Console HTTPS Port",
      vtype = "int",
      min = 1,
      max = 65535,
      desc = "Port for the TLS-multiplexed Axonwall Web GUI (default 2966).",
      tip = "Press <C-a> or <C-x> in Normal mode to increment/decrement port.",
      get = function() return tostring(st.system.webGuiPort or 2966) end,
      set = function(v) st.system.webGuiPort = v end,
    })
    add({
      label = "SSH Server Enabled",
      vtype = "boolean",
      desc = "Enable or disable OpenSSH daemon on the appliance.",
      get = function() return tostring(st.system.sshEnabled ~= false) end,
      set = function(v) st.system.sshEnabled = v end,
    })
    add({
      label = "SSH Listen Port",
      vtype = "int",
      min = 1,
      max = 65535,
      desc = "TCP port for OpenSSH administrative access.",
      get = function() return tostring(st.system.sshPort or 22) end,
      set = function(v) st.system.sshPort = v end,
    })
    add({
      label = "Nftables Flowtable Offload",
      vtype = "boolean",
      desc = "Hardware/kernel fastpath flowtable offload for established streams.",
      get = function() return tostring(st.system.flowtableOffload ~= false) end,
      set = function(v) st.system.flowtableOffload = v end,
    })

    add({
      card_title = "🧩 Core Appliance Roles & Security Posture",
      card_subtitle = "Toggle Converged Capabilities & Attack Surface",
      label = "Core Firewall & NGFW",
      vtype = "boolean",
      desc = "Stateful nftables firewall, NAT, SD-WAN, FRR, and VPN concentrator.",
      get = function() return tostring(st.capabilities.firewallEnabled ~= false) end,
      set = function(v) st.capabilities.firewallEnabled = v end,
    })
    add({
      label = "Core OpenZFS NAS",
      vtype = "boolean",
      desc = "TrueNAS-grade ZFS pool manager, snapshots, SMB/NFS/iSCSI shares.",
      get = function() return tostring(Boolean(st.capabilities.nasEnabled)) end,
      set = function(v)
        st.capabilities.nasEnabled = v
        st.nas = st.nas or {}
        st.nas.enabled = v
      end,
    })
    add({
      label = "Core K3s Kubernetes",
      vtype = "boolean",
      desc = "Embedded single/multi-node K3s cluster with OpenEBS ZFS LocalPV.",
      get = function() return tostring(Boolean(st.capabilities.k3sEnabled)) end,
      set = function(v)
        st.capabilities.k3sEnabled = v
        st.k3s = st.k3s or {}
        st.k3s.enabled = v
      end,
    })
    add({
      label = "Core KVM/LXC Hypervisor",
      vtype = "boolean",
      desc = "Libvirt/QEMU virtual machines, VFIO passthrough, and LXC containers.",
      get = function() return tostring(Boolean(st.capabilities.virtEnabled)) end,
      set = function(v)
        st.capabilities.virtEnabled = v
        st.virt = st.virt or {}
        st.virt.enabled = v
      end,
    })
    add({
      label = "Core Vigilante SOC",
      vtype = "boolean",
      desc = "Autonomous threat hunting, IOC correlation, and SOAR auto-blocking.",
      get = function() return tostring(Boolean(st.capabilities.vigilanteEnabled)) end,
      set = function(v)
        st.capabilities.vigilanteEnabled = v
        st.vigilante = st.vigilante or {}
        st.vigilante.enabled = v
      end,
    })
    add({
      label = "MCP Server Master Switch",
      vtype = "boolean",
      desc = "Disabled by default for security. Explicitly enable to allow AI MCP tool calls.",
      get = function() return tostring(Boolean(st.mcp and st.mcp.enabled)) end,
      set = function(v)
        st.mcp = st.mcp or {}
        st.mcp.enabled = v
      end,
    })

  elseif domain_id == "interfaces" then
    st.interfaces = st.interfaces or {}
    for idx, iface in ipairs(st.interfaces) do
      add({
        card_title = string.format("🌐 Interface #%d: %s (%s)", idx, (iface.name or "if"):upper(), iface.device or "eth0"),
        card_subtitle = "Press [n] New Interface · [X] Delete Interface",
        item_kind = "interface",
        item_idx = idx,
        label = "Enabled",
        vtype = "boolean",
        desc = "Bring this network interface up or down.",
        get = function() return tostring(iface.enabled ~= false) end,
        set = function(v) iface.enabled = v end,
      })
      add({
        item_kind = "interface",
        item_idx = idx,
        label = "Logical Name",
        vtype = "string",
        desc = "Logical role name referenced by firewall rules (e.g. wan, lan, dmz).",
        get = function() return iface.name or "" end,
        set = function(v) iface.name = v end,
      })
      add({
        item_kind = "interface",
        item_idx = idx,
        label = "Linux Device",
        vtype = "string",
        desc = "Kernel NIC name (e.g. eth0, enp1s0, br0, bond0).",
        get = function() return iface.device or "eth0" end,
        set = function(v) iface.device = v end,
      })
      add({
        item_kind = "interface",
        item_idx = idx,
        label = "Addressing Mode",
        vtype = "enum",
        options = { "static", "dhcp", "pppoe" },
        desc = "IPv4 configuration method (static CIDR, DHCP client, or PPPoE).",
        get = function() return iface.type or "static" end,
        set = function(v) iface.type = v end,
      })
      add({
        item_kind = "interface",
        item_idx = idx,
        label = "IPv4 Address (CIDR)",
        vtype = "cidr",
        allow_empty = true,
        desc = "Static IPv4 address and subnet mask (e.g. 192.168.1.1/24).",
        tip = "Use f. then ciw to edit an IP octet, or ct/ to change last octet.",
        get = function() return iface.ipv4Address or "" end,
        set = function(v) iface.ipv4Address = v ~= "" and v or nil end,
      })
      add({
        item_kind = "interface",
        item_idx = idx,
        label = "MTU",
        vtype = "int",
        min = 576,
        max = 9216,
        desc = "Maximum Transmission Unit (1500 standard, 9000 jumbo frames).",
        get = function() return tostring(iface.mtu or 1500) end,
        set = function(v) iface.mtu = v end,
      })
      add({
        item_kind = "interface",
        item_idx = idx,
        label = "Description",
        vtype = "string",
        allow_empty = true,
        desc = "Human-readable label shown in Dashboard and TUI.",
        get = function() return iface.description or "" end,
        set = function(v) iface.description = v end,
      })
    end

  elseif domain_id == "firewall" then
    st.rules = st.rules or {}
    local if_opts = get_interface_options(true)
    for idx, rule in ipairs(st.rules) do
      add({
        card_title = string.format("🛡️  Firewall Rule #%d — %s", idx, rule.description ~= "" and rule.description or (rule.id or "Rule")),
        card_subtitle = "Press [n] New Rule · [X] Delete Rule · [J/K] Move Rule",
        item_kind = "rule",
        item_idx = idx,
        label = "Rule Enabled",
        vtype = "boolean",
        desc = "Enable or disable this nftables filter rule.",
        get = function() return tostring(rule.enabled ~= false) end,
        set = function(v) rule.enabled = v end,
      })
      add({
        item_kind = "rule",
        item_idx = idx,
        label = "Action",
        vtype = "enum",
        options = { "pass", "block", "reject" },
        desc = "Verdict: pass (accept), block (silent drop), or reject (TCP RST/ICMP).",
        get = function() return rule.action or "pass" end,
        set = function(v) rule.action = v end,
      })
      add({
        item_kind = "rule",
        item_idx = idx,
        label = "Interface",
        vtype = "enum",
        options = if_opts,
        desc = "Ingress/egress logical interface for this rule.",
        get = function() return rule.interface or "lan" end,
        set = function(v) rule.interface = v end,
      })
      add({
        item_kind = "rule",
        item_idx = idx,
        label = "Direction",
        vtype = "enum",
        options = { "in", "out" },
        desc = "Traffic direction relative to the interface.",
        get = function() return rule.direction or "in" end,
        set = function(v) rule.direction = v end,
      })
      add({
        item_kind = "rule",
        item_idx = idx,
        label = "Protocol",
        vtype = "enum",
        options = { "any", "tcp", "udp", "tcp_udp", "icmp", "ipv6-icmp", "esp", "gre" },
        desc = "Layer-4 protocol to match.",
        get = function() return rule.protocol or "any" end,
        set = function(v) rule.protocol = v end,
      })
      add({
        item_kind = "rule",
        item_idx = idx,
        label = "Source Address",
        vtype = "fw_endpoint",
        desc = "Source match: 'any', IP, CIDR (10.0.0.0/8), or '$alias_name'.",
        tip = "Full Vim motions! Try ciw, f., or :%s/192.168.1/10.80.0/g across all rules.",
        get = function() return rule.source or "any" end,
        set = function(v) rule.source = v end,
      })
      add({
        item_kind = "rule",
        item_idx = idx,
        label = "Source Port",
        vtype = "port",
        allow_empty = true,
        desc = "Optional source port (e.g. 1024:65535) or empty for any.",
        get = function() return rule.sourcePort or "" end,
        set = function(v) rule.sourcePort = v end,
      })
      add({
        item_kind = "rule",
        item_idx = idx,
        label = "Destination Address",
        vtype = "fw_endpoint",
        desc = "Destination match: 'any', IP, CIDR, or '$alias_name'.",
        get = function() return rule.destination or "any" end,
        set = function(v) rule.destination = v end,
      })
      add({
        item_kind = "rule",
        item_idx = idx,
        label = "Destination Port",
        vtype = "port",
        allow_empty = true,
        desc = "Destination port (e.g. 443, 80:443, $web_ports) or empty for any.",
        tip = "Use <C-a>/<C-x> to bump port numbers or ciw to replace.",
        get = function() return rule.destinationPort or "" end,
        set = function(v) rule.destinationPort = v end,
      })
      add({
        item_kind = "rule",
        item_idx = idx,
        label = "Log Matched Packets",
        vtype = "boolean",
        desc = "Emit nflog events for matched packets to telemetry & live log viewer.",
        get = function() return tostring(Boolean(rule.log)) end,
        set = function(v) rule.log = v end,
      })
      add({
        item_kind = "rule",
        item_idx = idx,
        label = "Description",
        vtype = "string",
        allow_empty = true,
        desc = "Comment embedded into the compiled nftables rule.",
        get = function() return rule.description or "" end,
        set = function(v) rule.description = v end,
      })
    end

  elseif domain_id == "nat" then
    st.nat = st.nat or {}
    local if_opts = get_interface_options(false)
    if #st.nat == 0 then
      add({
        card_title = "🔀 NAT & Port Forwards (No custom rules yet — press [n] to create one)",
        card_subtitle = "Automatic WAN Masquerade is active by default",
        label = "Press [n] to add DNAT/SNAT",
        vtype = "string",
        allow_empty = true,
        desc = "Press 'n' in Normal mode to add a Port Forward (DNAT) or Outbound SNAT rule.",
        get = function() return "auto-masquerade" end,
        set = function(_) end,
      })
    end
    for idx, nr in ipairs(st.nat) do
      add({
        card_title = string.format("🔀 NAT Rule #%d (%s) — %s", idx, (nr.type or "dnat"):upper(), nr.description or ""),
        card_subtitle = "Press [n] New NAT Rule · [X] Delete NAT Rule",
        item_kind = "nat",
        item_idx = idx,
        label = "Enabled",
        vtype = "boolean",
        desc = "Enable or disable this NAT translation rule.",
        get = function() return tostring(nr.enabled ~= false) end,
        set = function(v) nr.enabled = v end,
      })
      add({
        item_kind = "nat",
        item_idx = idx,
        label = "NAT Type",
        vtype = "enum",
        options = { "dnat", "snat", "masquerade", "nptv6" },
        desc = "dnat (Port Forward), snat (Static Outbound), masquerade, or nptv6.",
        get = function() return nr.type or "dnat" end,
        set = function(v) nr.type = v end,
      })
      add({
        item_kind = "nat",
        item_idx = idx,
        label = "Interface",
        vtype = "enum",
        options = if_opts,
        desc = "Interface where NAT translation is applied (typically wan).",
        get = function() return nr.interface or "wan" end,
        set = function(v) nr.interface = v end,
      })
      add({
        item_kind = "nat",
        item_idx = idx,
        label = "Protocol",
        vtype = "enum",
        options = { "tcp", "udp", "tcp_udp", "any" },
        desc = "Protocol to translate.",
        get = function() return nr.protocol or "tcp" end,
        set = function(v) nr.protocol = v end,
      })
      add({
        item_kind = "nat",
        item_idx = idx,
        label = "External Dest Port",
        vtype = "port",
        allow_empty = true,
        desc = "External port on WAN IP (e.g. 8443 or 80).",
        get = function() return nr.destinationPort or "" end,
        set = function(v) nr.destinationPort = v end,
      })
      add({
        item_kind = "nat",
        item_idx = idx,
        label = "Internal Target IP",
        vtype = "ip",
        allow_empty = true,
        desc = "Internal LAN host IP to forward traffic to (e.g. 192.168.1.50).",
        get = function() return nr.targetIp or "" end,
        set = function(v) nr.targetIp = v end,
      })
      add({
        item_kind = "nat",
        item_idx = idx,
        label = "Internal Target Port",
        vtype = "port",
        allow_empty = true,
        desc = "Internal target port on the LAN host (e.g. 443).",
        get = function() return nr.targetPort or "" end,
        set = function(v) nr.targetPort = v end,
      })
      add({
        item_kind = "nat",
        item_idx = idx,
        label = "Description",
        vtype = "string",
        allow_empty = true,
        desc = "Human-readable description of this port forward.",
        get = function() return nr.description or "" end,
        set = function(v) nr.description = v end,
      })
    end

  elseif domain_id == "aliases" then
    st.aliases = st.aliases or {}
    if #st.aliases == 0 then
      add({
        card_title = "📦 Firewall Aliases (No aliases yet — press [n] to create one)",
        card_subtitle = "Named nftables sets usable as $alias_name in Firewall & NAT rules",
        label = "Press [n] to create Alias",
        vtype = "string",
        allow_empty = true,
        desc = "Press 'n' in Normal mode to create a new Host, Network, or Port alias.",
        get = function() return "none" end,
        set = function(_) end,
      })
    end
    for idx, al in ipairs(st.aliases) do
      add({
        card_title = string.format("📦 Alias #%d: $%s (%s)", idx, al.name or "alias", (al.type or "host"):upper()),
        card_subtitle = "Press [n] New Alias · [X] Delete Alias",
        item_kind = "alias",
        item_idx = idx,
        label = "Enabled",
        vtype = "boolean",
        desc = "Enable or disable this nftables named set.",
        get = function() return tostring(al.enabled ~= false) end,
        set = function(v) al.enabled = v end,
      })
      add({
        item_kind = "alias",
        item_idx = idx,
        label = "Alias Name",
        vtype = "string",
        desc = "Identifier used as $name in firewall rules (alphanumeric + underscore).",
        get = function() return al.name or "trusted_hosts" end,
        set = function(v) al.name = v end,
      })
      add({
        item_kind = "alias",
        item_idx = idx,
        label = "Alias Type",
        vtype = "enum",
        options = { "host", "network", "port", "url", "geoip" },
        desc = "Type of elements stored in this nftables set.",
        get = function() return al.type or "host" end,
        set = function(v) al.type = v end,
      })
      add({
        item_kind = "alias",
        item_idx = idx,
        label = "Entries (Comma-Separated)",
        vtype = "csv",
        desc = "Comma-separated IPs, CIDRs, or ports belonging to this alias.",
        tip = "Use ciw to edit individual entries or A to append new members.",
        get = function() return table.concat(al.entries or {}, ", ") end,
        set = function(v) al.entries = v end,
      })
      add({
        item_kind = "alias",
        item_idx = idx,
        label = "Description",
        vtype = "string",
        allow_empty = true,
        desc = "Explanation of what this alias groups together.",
        get = function() return al.description or "" end,
        set = function(v) al.description = v end,
      })
    end

  elseif domain_id == "routing" then
    st.routes = st.routes or {}
    st.frr = st.frr or { bgp = { enabled = false, asNumber = 65000, routerId = "192.168.1.1" }, ospf = { enabled = false, routerId = "192.168.1.1" } }
    st.frr.bgp = st.frr.bgp or { enabled = false, asNumber = 65000, routerId = "192.168.1.1" }
    st.frr.ospf = st.frr.ospf or { enabled = false, routerId = "192.168.1.1" }

    for idx, rt in ipairs(st.routes) do
      add({
        card_title = string.format("🧭 Static Route #%d: %s via %s", idx, rt.network or "", rt.gateway or ""),
        card_subtitle = "Press [n] New Static Route · [X] Delete Static Route",
        item_kind = "route",
        item_idx = idx,
        label = "Route Enabled",
        vtype = "boolean",
        desc = "Install this static route into the Linux kernel FIB.",
        get = function() return tostring(rt.enabled ~= false) end,
        set = function(v) rt.enabled = v end,
      })
      add({
        item_kind = "route",
        item_idx = idx,
        label = "Destination Network (CIDR)",
        vtype = "cidr",
        desc = "Destination subnet CIDR (e.g. 10.20.0.0/16).",
        get = function() return rt.network or "10.20.0.0/16" end,
        set = function(v) rt.network = v end,
      })
      add({
        item_kind = "route",
        item_idx = idx,
        label = "Next-Hop Gateway IP",
        vtype = "ip",
        desc = "Next-hop router IP address (e.g. 192.168.1.254).",
        get = function() return rt.gateway or "192.168.1.254" end,
        set = function(v) rt.gateway = v end,
      })
      add({
        item_kind = "route",
        item_idx = idx,
        label = "Interface",
        vtype = "enum",
        options = get_interface_options(false),
        desc = "Outgoing interface for this route.",
        get = function() return rt.interface or "lan" end,
        set = function(v) rt.interface = v end,
      })
      add({
        item_kind = "route",
        item_idx = idx,
        label = "Description",
        vtype = "string",
        allow_empty = true,
        desc = "Description of this static route.",
        get = function() return rt.description or "" end,
        set = function(v) rt.description = v end,
      })
    end

    add({
      card_title = "🌐 FRRouting Dynamic Routing (BGP & OSPF)",
      card_subtitle = "/etc/axonwall/routing.yaml · Press [n] to add a Static Route above",
      label = "BGP Daemon Enabled",
      vtype = "boolean",
      desc = "Enable FRR bgpd dynamic routing protocol.",
      get = function() return tostring(Boolean(st.frr.bgp.enabled)) end,
      set = function(v) st.frr.bgp.enabled = v end,
    })
    add({
      label = "Local BGP ASN",
      vtype = "int",
      min = 1,
      max = 4294967295,
      desc = "Autonomous System Number (e.g. 65000).",
      get = function() return tostring(st.frr.bgp.asNumber or 65000) end,
      set = function(v) st.frr.bgp.asNumber = v end,
    })
    add({
      label = "BGP Router ID",
      vtype = "ip",
      desc = "32-bit dotted-quad BGP router identifier.",
      get = function() return st.frr.bgp.routerId or "192.168.1.1" end,
      set = function(v) st.frr.bgp.routerId = v end,
    })
    add({
      label = "OSPFv2/v3 Enabled",
      vtype = "boolean",
      desc = "Enable FRR ospfd interior gateway protocol.",
      get = function() return tostring(Boolean(st.frr.ospf.enabled)) end,
      set = function(v) st.frr.ospf.enabled = v end,
    })

  elseif domain_id == "services" then
    st.dns = st.dns or { enabled = true, dnssec = true, dotEnabled = false, dotUpstreams = { "1.1.1.1", "9.9.9.9" } }
    st.dhcp = st.dhcp or { enabled = true, subnets = {} }
    st.haproxy = st.haproxy or { enabled = false, mode = "http", frontends = {}, backends = {} }
    st.freeradius = st.freeradius or { enabled = false, authPort = 1812, acctPort = 1813, clients = {}, ldapSync = true }

    add({
      card_title = "📡 Unbound Recursive/Forwarding DNS Resolver",
      card_subtitle = "/etc/axonwall/services.yaml",
      label = "Unbound DNS Enabled",
      vtype = "boolean",
      desc = "Enable local caching DNS resolver with DNSBL sinkhole support.",
      get = function() return tostring(st.dns.enabled ~= false) end,
      set = function(v) st.dns.enabled = v end,
    })
    add({
      label = "DNSSEC Validation",
      vtype = "boolean",
      desc = "Cryptographically validate DNSSEC signatures on responses.",
      get = function() return tostring(st.dns.dnssec ~= false) end,
      set = function(v) st.dns.dnssec = v end,
    })
    add({
      label = "DNS-over-TLS (DoT)",
      vtype = "boolean",
      desc = "Encrypt upstream DNS queries over TLS port 853.",
      get = function() return tostring(Boolean(st.dns.dotEnabled)) end,
      set = function(v) st.dns.dotEnabled = v end,
    })
    add({
      label = "DoT Upstream Resolvers",
      vtype = "csv",
      desc = "Comma-separated upstream DNS-over-TLS servers.",
      get = function() return table.concat(st.dns.dotUpstreams or { "1.1.1.1", "9.9.9.9" }, ", ") end,
      set = function(v) st.dns.dotUpstreams = v end,
    })

    add({
      card_title = "🖧 Kea DHCPv4 Server & Enterprise Ingress Services",
      card_subtitle = "DHCPv4, HAProxy Load Balancer & FreeRADIUS 802.1X",
      label = "Kea DHCPv4 Enabled",
      vtype = "boolean",
      desc = "Enable ISC Kea DHCPv4 server across configured LAN subnets.",
      get = function() return tostring(st.dhcp.enabled ~= false) end,
      set = function(v) st.dhcp.enabled = v end,
    })
    add({
      label = "HAProxy Reverse Proxy",
      vtype = "boolean",
      desc = "Enable HAProxy L4/L7 load balancer and TLS termination.",
      get = function() return tostring(Boolean(st.haproxy.enabled)) end,
      set = function(v) st.haproxy.enabled = v end,
    })
    add({
      label = "HAProxy Default Mode",
      vtype = "enum",
      options = { "http", "tcp" },
      desc = "Default proxy mode (Layer 7 HTTP or Layer 4 TCP).",
      get = function() return st.haproxy.mode or "http" end,
      set = function(v) st.haproxy.mode = v end,
    })
    add({
      label = "FreeRADIUS 802.1X Server",
      vtype = "boolean",
      desc = "Enable FreeRADIUS WPA2/WPA3-Enterprise & VPN authentication.",
      get = function() return tostring(Boolean(st.freeradius.enabled)) end,
      set = function(v) st.freeradius.enabled = v end,
    })
    add({
      label = "FreeRADIUS Auth Port",
      vtype = "int",
      min = 1,
      max = 65535,
      desc = "UDP port for RADIUS authentication requests (default 1812).",
      get = function() return tostring(st.freeradius.authPort or 1812) end,
      set = function(v) st.freeradius.authPort = v end,
    })

  elseif domain_id == "vpn" then
    st.wireguard = st.wireguard or { enabled = false, listenPort = 51820, address = "10.10.0.1/24", peers = {} }
    st.rosenpass = st.rosenpass or { enabled = false, listenPort = 9999, wgDevice = "wg0", rekeyIntervalSeconds = 120, failClosedBootGuard = true, peers = {} }
    st.headscale = st.headscale or { enabled = false, magicDnsDomain = "mesh.axonwall.local" }

    add({
      card_title = "🔐 WireGuard Kernel VPN Tunnel",
      card_subtitle = "/etc/axonwall/vpn.yaml",
      label = "WireGuard Enabled",
      vtype = "boolean",
      desc = "Enable kernel-space WireGuard interface wg0.",
      get = function() return tostring(Boolean(st.wireguard.enabled)) end,
      set = function(v) st.wireguard.enabled = v end,
    })
    add({
      label = "Listen UDP Port",
      vtype = "int",
      min = 1,
      max = 65535,
      desc = "UDP port for incoming WireGuard handshakes (default 51820).",
      get = function() return tostring(st.wireguard.listenPort or 51820) end,
      set = function(v) st.wireguard.listenPort = v end,
    })
    add({
      label = "Tunnel Interface CIDR",
      vtype = "cidr",
      desc = "Tunnel IPv4 address and subnet (e.g. 10.10.0.1/24).",
      get = function() return st.wireguard.address or "10.10.0.1/24" end,
      set = function(v) st.wireguard.address = v end,
    })

    add({
      card_title = "🛡️  Rosenpass Post-Quantum Hybrid KEM (Classic McEliece + ML-KEM)",
      card_subtitle = "Rotates post-quantum pre-shared keys into WireGuard every 2 minutes",
      label = "Rosenpass PQ Enabled",
      vtype = "boolean",
      desc = "Enable post-quantum key exchange daemon alongside WireGuard.",
      get = function() return tostring(Boolean(st.rosenpass.enabled)) end,
      set = function(v) st.rosenpass.enabled = v end,
    })
    add({
      label = "Rosenpass UDP Port",
      vtype = "int",
      min = 1,
      max = 65535,
      desc = "UDP port for post-quantum KEM handshakes (default 9999).",
      get = function() return tostring(st.rosenpass.listenPort or 9999) end,
      set = function(v) st.rosenpass.listenPort = v end,
    })
    add({
      label = "PQ Rekey Interval (sec)",
      vtype = "int",
      min = 30,
      max = 300,
      desc = "Interval in seconds between automatic PSK rotations (30..300).",
      get = function() return tostring(st.rosenpass.rekeyIntervalSeconds or 120) end,
      set = function(v) st.rosenpass.rekeyIntervalSeconds = v end,
    })
    add({
      label = "Fail-Closed Boot Guard",
      vtype = "boolean",
      desc = "Block WireGuard forwarding until post-quantum PSK is negotiated.",
      get = function() return tostring(st.rosenpass.failClosedBootGuard ~= false) end,
      set = function(v) st.rosenpass.failClosedBootGuard = v end,
    })

    add({
      card_title = "🕸️  Headscale Zero-Config Mesh Coordination Server",
      card_subtitle = "Self-hosted Tailscale-compatible control plane & embedded DERP",
      label = "Headscale Server Enabled",
      vtype = "boolean",
      desc = "Run embedded Headscale mesh coordination server.",
      get = function() return tostring(Boolean(st.headscale.enabled)) end,
      set = function(v) st.headscale.enabled = v end,
    })
    add({
      label = "MagicDNS Base Domain",
      vtype = "string",
      desc = "Internal DNS suffix for mesh nodes (e.g. mesh.axonwall.local).",
      get = function() return st.headscale.magicDnsDomain or "mesh.axonwall.local" end,
      set = function(v) st.headscale.magicDnsDomain = v end,
    })

  elseif domain_id == "security" then
    st.suricata = st.suricata or { enabled = false, mode = "ids", interfaces = { "wan" }, blockOnHighSeverity = true }
    st.crowdsec = st.crowdsec or { enabled = false, action = "drop", remediationSetName = "crowdsec_blackhole", logBanned = true }
    st.geoip = st.geoip or { enabled = false, mode = "block", countries = {} }

    add({
      card_title = "🚨 Suricata Multi-Threaded IDS/IPS Engine",
      card_subtitle = "/etc/axonwall/security.yaml",
      label = "Suricata Enabled",
      vtype = "boolean",
      desc = "Enable deep packet inspection and Emerging Threats signature matching.",
      get = function() return tostring(Boolean(st.suricata.enabled)) end,
      set = function(v) st.suricata.enabled = v end,
    })
    add({
      label = "Operating Mode",
      vtype = "enum",
      options = { "ids", "ips" },
      desc = "ids (AF_PACKET passive monitor) or ips (NFQUEUE inline drop).",
      get = function() return st.suricata.mode or "ids" end,
      set = function(v) st.suricata.mode = v end,
    })
    add({
      label = "Inspected Interfaces",
      vtype = "csv",
      desc = "Comma-separated interfaces to inspect (e.g. wan, lan).",
      get = function() return table.concat(st.suricata.interfaces or { "wan" }, ", ") end,
      set = function(v) st.suricata.interfaces = v end,
    })

    add({
      card_title = "🛡️  CrowdSec Threat Intelligence & GeoIP Filtering",
      card_subtitle = "Dynamic nftables blackhole sets (@crowdsec_blackhole)",
      label = "CrowdSec Bouncer Enabled",
      vtype = "boolean",
      desc = "Enforce CrowdSec LAPI ban decisions in kernel nftables.",
      get = function() return tostring(Boolean(st.crowdsec.enabled)) end,
      set = function(v) st.crowdsec.enabled = v end,
    })
    add({
      label = "Remediation Action",
      vtype = "enum",
      options = { "drop", "reject" },
      desc = "Packet disposition for banned IPs.",
      get = function() return st.crowdsec.action or "drop" end,
      set = function(v) st.crowdsec.action = v end,
    })
    add({
      label = "GeoIP Filter Enabled",
      vtype = "boolean",
      desc = "Filter ingress traffic by ISO 3166-1 alpha-2 country codes.",
      get = function() return tostring(Boolean(st.geoip.enabled)) end,
      set = function(v) st.geoip.enabled = v end,
    })
    add({
      label = "GeoIP Country Codes",
      vtype = "csv",
      desc = "Comma-separated 2-letter country codes (e.g. KP, IR, RU, CN).",
      get = function() return table.concat(st.geoip.countries or {}, ", ") end,
      set = function(v) st.geoip.countries = v end,
    })

    st.hostDefense = st.hostDefense or {
      enabled = true,
      rkhunterEnabled = true,
      chkrootkitEnabled = true,
      aideEnabled = true,
      yaraEnabled = true,
      ioUringDisabledMode = "1",
      kernelLockdownMode = "confidentiality",
      bpfLsmGuardEnabled = true,
    }
    add({
      card_title = "👻 Host Malware, Rootkit & Ghost-in-the-Ring Kernel Hunter",
      card_subtitle = "rkhunter, chkrootkit, AIDE, YARA + io_uring SQPOLL & /proc/kcore prog_idr",
      label = "Host Rootkit Hunter Enabled",
      vtype = "boolean",
      desc = "Enable 12-layer host malware, rootkit, io_uring & eBPF Ring-0 defense suite.",
      get = function() return tostring(st.hostDefense.enabled ~= false) end,
      set = function(v) st.hostDefense.enabled = v end,
    })
    add({
      label = "io_uring Lockdown Mode",
      vtype = "enum",
      options = { "0", "1", "2" },
      desc = "kernel.io_uring_disabled: 1 = restrict to GID, 2 = disable system-wide.",
      get = function() return tostring(st.hostDefense.ioUringDisabledMode or "1") end,
      set = function(v) st.hostDefense.ioUringDisabledMode = v end,
    })
    add({
      label = "Kernel Lockdown Mode",
      vtype = "enum",
      options = { "none", "integrity", "confidentiality" },
      desc = "confidentiality blocks bpf_probe_write_user (#36) & bpf_override_return (#58).",
      get = function() return st.hostDefense.kernelLockdownMode or "confidentiality" end,
      set = function(v) st.hostDefense.kernelLockdownMode = v end,
    })
    add({
      label = "Preventive BPF_LSM Guard",
      vtype = "boolean",
      desc = "Enforce SEC('lsm/bpf') inode allowlist and SEC('lsm/uring_sqpoll') -EPERM.",
      get = function() return tostring(st.hostDefense.bpfLsmGuardEnabled ~= false) end,
      set = function(v) st.hostDefense.bpfLsmGuardEnabled = v end,
    })

  elseif domain_id == "ha" then
    st.ha = st.ha or { enabled = false, nodeRole = "master", syncInterface = "lan", peerIp = "", virtualRouterId = 51 }
    add({
      card_title = "⚡ High Availability Active/Passive Cluster (VRRP + Conntrackd)",
      card_subtitle = "/etc/axonwall/ha.yaml · Sub-second stateful failover & mTLS config sync",
      label = "HA Cluster Enabled",
      vtype = "boolean",
      desc = "Enable Keepalived VRRP, conntrackd state sync, and mTLS config replication.",
      get = function() return tostring(Boolean(st.ha.enabled)) end,
      set = function(v) st.ha.enabled = v end,
    })
    add({
      label = "Cluster Node Role",
      vtype = "enum",
      options = { "master", "backup" },
      desc = "Primary active node (master) or hot standby (backup).",
      get = function() return st.ha.nodeRole or "master" end,
      set = function(v) st.ha.nodeRole = v end,
    })
    add({
      label = "Dedicated Sync Interface",
      vtype = "enum",
      options = get_interface_options(false),
      desc = "Interface used for conntrackd state sync and mTLS replication.",
      get = function() return st.ha.syncInterface or "lan" end,
      set = function(v) st.ha.syncInterface = v end,
    })
    add({
      label = "Peer Node IPv4 Address",
      vtype = "ip",
      allow_empty = true,
      desc = "IP address of the partner Axonwall HA appliance.",
      get = function() return st.ha.peerIp or "" end,
      set = function(v) st.ha.peerIp = v end,
    })
    add({
      label = "VRRP Virtual Router ID",
      vtype = "int",
      min = 1,
      max = 255,
      desc = "VRID shared between MASTER and BACKUP nodes (1..255).",
      get = function() return tostring(st.ha.virtualRouterId or 51) end,
      set = function(v) st.ha.virtualRouterId = v end,
    })

  elseif domain_id == "storage" then
    st.nas = st.nas or { enabled = false, workgroup = "WORKGROUP", serverString = "Axonwall ZFS NAS", pools = {}, datasets = {} }
    add({
      card_title = "💾 OpenZFS Enterprise Storage & NAS Engine",
      card_subtitle = "/etc/axonwall/storage.yaml",
      label = "ZFS NAS Role Enabled",
      vtype = "boolean",
      desc = "Enable ZFS pool management, automated snapshots, and SMB/NFS sharing.",
      get = function() return tostring(Boolean(st.nas.enabled)) end,
      set = function(v)
        st.nas.enabled = v
        st.capabilities = st.capabilities or {}
        st.capabilities.nasEnabled = v
      end,
    })
    add({
      label = "SMB Workgroup / Domain",
      vtype = "string",
      desc = "Samba workgroup or Active Directory NetBIOS domain.",
      get = function() return st.nas.workgroup or "WORKGROUP" end,
      set = function(v) st.nas.workgroup = v end,
    })
    add({
      label = "SMB Server Description",
      vtype = "string",
      desc = "Server string announced to SMB/CIFS clients.",
      get = function() return st.nas.serverString or "Axonwall Enterprise ZFS NAS" end,
      set = function(v) st.nas.serverString = v end,
    })

  elseif domain_id == "compute" then
    st.k3s = st.k3s or { enabled = false, clusterCidr = "10.42.0.0/16", serviceCidr = "10.43.0.0/16", flannelBackend = "wireguard-native", disableTraefik = false }
    st.vow = st.vow or { enabled = false, cdRunner = "argocd", domain = "vow.axonwall.local", activePreset = "minimal", localTlsMkcert = true, syncUnboundDns = true, authzEnabled = false }
    st.virt = st.virt or { enabled = false, defaultPool = "tank", isoPool = "tank" }
    st.vigilante = st.vigilante or { enabled = false, autoBlockCritical = false, defaultBlockTtlSeconds = 3600 }

    add({
      card_title = "☸️  Embedded K3s Kubernetes & OpenEBS ZFS-LocalPV",
      card_subtitle = "/etc/axonwall/k3s.yaml",
      label = "K3s Cluster Enabled",
      vtype = "boolean",
      desc = "Run embedded K3s Kubernetes control plane and OpenEBS CSI driver.",
      get = function() return tostring(Boolean(st.k3s.enabled)) end,
      set = function(v)
        st.k3s.enabled = v
        st.capabilities = st.capabilities or {}
        st.capabilities.k3sEnabled = v
        if not v and st.vow then
          st.vow.enabled = false
        end
      end,
    })
    add({
      label = "Pod Cluster CIDR",
      vtype = "cidr",
      desc = "IPv4 CIDR block assigned to Kubernetes pods (default 10.42.0.0/16).",
      get = function() return st.k3s.clusterCidr or "10.42.0.0/16" end,
      set = function(v) st.k3s.clusterCidr = v end,
    })
    add({
      label = "Service Cluster CIDR",
      vtype = "cidr",
      desc = "IPv4 CIDR block assigned to Kubernetes ClusterIP services.",
      get = function() return st.k3s.serviceCidr or "10.43.0.0/16" end,
      set = function(v) st.k3s.serviceCidr = v end,
    })
    add({
      label = "Flannel CNI Backend",
      vtype = "enum",
      options = { "wireguard-native", "vxlan", "host-gw" },
      desc = "Pod network encapsulation backend (wireguard-native recommended).",
      get = function() return st.k3s.flannelBackend or "wireguard-native" end,
      set = function(v) st.k3s.flannelBackend = v end,
    })

    add({
      card_title = "🧇 Vigilant Octo Waffle (VOW) — K8s GitOps & App Platform",
      card_subtitle = "/etc/axonwall/k3s.yaml • Requires plugin dependency: core-k3s",
      label = "VOW Platform Enabled",
      vtype = "boolean",
      desc = "Enable Vigilant Octo Waffle GitOps platform (auto-enables required core-k3s dependency).",
      get = function() return tostring(Boolean(st.vow.enabled and st.k3s.enabled)) end,
      set = function(v)
        st.vow.enabled = v
        if v then
          st.k3s.enabled = true
          st.capabilities = st.capabilities or {}
          st.capabilities.k3sEnabled = true
        end
      end,
    })
    add({
      label = "GitOps CD Runner",
      vtype = "enum",
      options = { "argocd", "flux", "both" },
      desc = "Continuous delivery controller (ArgoCD, FluxCD v2 with Argo-to-Flux synthesis, or both).",
      get = function() return st.vow.cdRunner or "argocd" end,
      set = function(v) st.vow.cdRunner = v end,
    })
    add({
      label = "VOW Ingress Domain",
      vtype = "hostname",
      desc = "Base domain for VOW app subdomains and Unbound DNS local-zone overrides.",
      get = function() return st.vow.domain or "vow.axonwall.local" end,
      set = function(v) st.vow.domain = v end,
    })
    add({
      label = "Deployment Preset",
      vtype = "enum",
      options = { "minimal", "storage", "observability", "ai", "collaboration", "full", "custom" },
      desc = "Curated application stack preset from the 37+ VOW Kubernetes catalog.",
      get = function() return st.vow.activePreset or "minimal" end,
      set = function(v) st.vow.activePreset = v end,
    })
    add({
      label = "Local TLS (mkcert CA)",
      vtype = "boolean",
      desc = "Provision local mkcert CA and Cert-Manager TLS certificates for VOW ingresses.",
      get = function() return tostring(st.vow.localTlsMkcert ~= false) end,
      set = function(v) st.vow.localTlsMkcert = v end,
    })
    add({
      label = "Sync Unbound DNS Zone",
      vtype = "boolean",
      desc = "Automatically publish A records for enabled VOW app subdomains in Unbound DNS.",
      get = function() return tostring(st.vow.syncUnboundDns ~= false) end,
      set = function(v) st.vow.syncUnboundDns = v end,
    })
    add({
      label = "CASL 34-Perm AuthZ Guard",
      vtype = "boolean",
      desc = "Enforce Paperclip/CASL role-based authorization (.vow/authz.yaml).",
      get = function() return tostring(Boolean(st.vow.authzEnabled)) end,
      set = function(v) st.vow.authzEnabled = v end,
    })

    add({
      card_title = " 🖥️  KVM/LXC Virtualization & Vigilante Autonomous SOC",
      card_subtitle = "/etc/axonwall/virt.yaml & /etc/axonwall/vigilante.yaml",
      label = "KVM/LXC Hypervisor Enabled",
      vtype = "boolean",
      desc = "Enable libvirtd QEMU/KVM virtual machines and LXC containers.",
      get = function() return tostring(Boolean(st.virt.enabled)) end,
      set = function(v)
        st.virt.enabled = v
        st.capabilities = st.capabilities or {}
        st.capabilities.virtEnabled = v
      end,
    })
    add({
      label = "Default VM ZFS Pool",
      vtype = "string",
      desc = "Default ZFS pool for VM zvol disks and container rootfs.",
      get = function() return st.virt.defaultPool or "tank" end,
      set = function(v) st.virt.defaultPool = v end,
    })
    add({
      label = "Vigilante SOC Enabled",
      vtype = "boolean",
      desc = "Enable Vigilante autonomous threat hunting and SOAR active response.",
      get = function() return tostring(Boolean(st.vigilante.enabled)) end,
      set = function(v)
        st.vigilante.enabled = v
        st.capabilities = st.capabilities or {}
        st.capabilities.vigilanteEnabled = v
      end,
    })
    add({
      label = "Auto-Block Critical IOCs",
      vtype = "boolean",
      desc = "Automatically quarantine high-confidence attacker IPs in nftables.",
      get = function() return tostring(Boolean(st.vigilante.autoBlockCritical)) end,
      set = function(v) st.vigilante.autoBlockCritical = v end,
    })
  end

  return fields
end

function Boolean(v)
  return v == true or v == "true"
end

-- 8. Render Header, Sidebar, Form Extmarks, Inspector & Footer
local function get_domain_count(domain_id)
  local st = App.state
  if domain_id == "interfaces" then return #(st.interfaces or {}) end
  if domain_id == "firewall" then return #(st.rules or {}) end
  if domain_id == "nat" then return #(st.nat or {}) end
  if domain_id == "aliases" then return #(st.aliases or {}) end
  if domain_id == "routing" then return #(st.routes or {}) end
  return nil
end

local function render_header()
  local buf = App.bufs.header
  if not buf or not api.nvim_buf_is_valid(buf) then return end
  api.nvim_buf_set_option(buf, "modifiable", true)
  local cols = vim.o.columns
  local host = (App.state.system and App.state.system.hostname) or "axonwall"
  local dom = (App.state.system and App.state.system.domain) or "local.lan"
  local state_badge = App.dirty and " ● UNSAVED EDITS (<C-s> Save & Apply) " or " ✔ SYNCED WITH /etc/axonwall/*.yaml "
  local line1 = string.format(
    " 🛡️  AXONWALL NEOVIM SUPER CONFIGURATOR   │   Host: %s.%s   │   %s",
    host,
    dom,
    state_badge
  )
  local line2 = " [Tab] Switch Pane  [1-0/-/=] Domain  [j/k] Field  [i/c/ciw] Vim Edit  [Space] Toggle/Pick  [n] New  [X] Del  [<C-d>] Diff  [<C-y>] Raw YAML  [<C-s>] Save & Apply  [q] Quit"
  if #line1 < cols then line1 = line1 .. string.rep(" ", cols - #line1) end
  if #line2 < cols then line2 = line2 .. string.rep(" ", cols - #line2) end
  api.nvim_buf_set_lines(buf, 0, -1, false, { line1, line2 })
  api.nvim_buf_clear_namespace(buf, ns_head, 0, -1)
  api.nvim_buf_add_highlight(buf, ns_head, "AxonBrand", 0, 0, 42)
  api.nvim_buf_add_highlight(buf, ns_head, App.dirty and "AxonDirtyBadge" or "AxonCleanBadge", 0, 43, -1)
  api.nvim_buf_add_highlight(buf, ns_head, "AxonFooterDesc", 1, 0, -1)
  api.nvim_buf_set_option(buf, "modifiable", false)
end

local function render_sidebar()
  local buf = App.bufs.sidebar
  if not buf or not api.nvim_buf_is_valid(buf) then return end
  api.nvim_buf_set_option(buf, "modifiable", true)
  local lines = {}
  for idx, d in ipairs(DOMAINS) do
    local prefix = (idx == App.active_domain_idx) and "▶ " or "  "
    local cnt = get_domain_count(d.id)
    local cnt_str = cnt and string.format(" (%d)", cnt) or ""
    table.insert(lines, string.format("%s[%s] %s %s%s", prefix, d.key, d.icon, d.label, cnt_str))
  end
  table.insert(lines, "")
  table.insert(lines, " ─── Quick Actions ──────────")
  table.insert(lines, "  [<C-s>] Save & Apply")
  table.insert(lines, "  [<C-d>] Preview nftables")
  table.insert(lines, "  [<C-y>] Raw YAML Buffer")
  table.insert(lines, "  [n]     Add New Card/Rule")
  table.insert(lines, "  [X]     Delete Card/Rule")
  table.insert(lines, "  [q]     Quit Configurator")

  api.nvim_buf_set_lines(buf, 0, -1, false, lines)
  api.nvim_buf_clear_namespace(buf, ns_side, 0, -1)
  for idx = 1, #DOMAINS do
    local hl_group = (idx == App.active_domain_idx) and "AxonSidebarActive" or "AxonSidebarItem"
    api.nvim_buf_add_highlight(buf, ns_side, hl_group, idx - 1, 0, -1)
  end
  for idx = #DOMAINS + 2, #lines do
    api.nvim_buf_add_highlight(buf, ns_side, "AxonHint", idx - 1, 0, -1)
  end
  api.nvim_buf_set_option(buf, "modifiable", false)
end

-- Decorate form lines with inline extmark labels, card borders, and live validation badges
local function decorate_form_extmarks()
  local buf = App.bufs.form
  if not buf or not api.nvim_buf_is_valid(buf) then return end
  api.nvim_buf_clear_namespace(buf, ns_form, 0, -1)
  local diags = {}

  local lines = api.nvim_buf_get_lines(buf, 0, -1, false)
  for lnum, field in ipairs(App.field_map) do
    local row = lnum - 1
    local raw_line = lines[lnum] or ""

    -- 1. Card header virtual lines above the first field of each card
    if field.card_title then
      local virt_above = {}
      if lnum > 1 then
        table.insert(virt_above, { { "  ╰" .. string.rep("─", 66) .. "╯", "AxonCardBottom" } })
        table.insert(virt_above, { { "", "Normal" } })
      end
      local title_bar = string.format("  ╭─ %s ", field.card_title)
      local pad_len = math.max(2, 69 - fn.strdisplaywidth(title_bar))
      title_bar = title_bar .. string.rep("─", pad_len) .. "╮"
      table.insert(virt_above, { { title_bar, "AxonCardTop" } })
      if field.card_subtitle then
        local sub_bar = string.format("  │  %s", field.card_subtitle)
        table.insert(virt_above, { { sub_bar, "AxonHint" } })
      end
      api.nvim_buf_set_extmark(buf, ns_form, row, 0, {
        virt_lines = virt_above,
        virt_lines_above = true,
      })
    end

    -- 2. Inline virtual text label at column 0 (cannot be deleted or corrupted by user!)
    local padded_label = string.format("%-24s", field.label)
    api.nvim_buf_set_extmark(buf, ns_form, row, 0, {
      virt_text = {
        { "  │ ", "AxonFieldBorder" },
        { padded_label, "AxonFieldLabel" },
        { " │ ", "AxonFieldSep" },
      },
      virt_text_pos = "inline",
      right_gravity = true,
    })

    -- 3. Validate current buffer line & render EOL status badge
    local ok, _, badge = validate_field_value(field, raw_line)
    local eol_chunks = {}
    if field.vtype == "boolean" then
      local is_on = vim.trim(raw_line):lower() == "true"
      table.insert(eol_chunks, {
        is_on and "   [● ENABLED] " or "   [○ DISABLED]",
        is_on and "AxonBadgeOn" or "AxonBadgeOff",
      })
      table.insert(eol_chunks, { "  (Space: toggle)", "AxonHint" })
    elseif field.vtype == "enum" then
      table.insert(eol_chunks, { "   ▾ Picker ", "AxonBadgeEnum" })
      table.insert(eol_chunks, { "(" .. table.concat(field.options or {}, " | ") .. ")", "AxonHint" })
    else
      table.insert(eol_chunks, { "   " .. badge, ok and "AxonValid" or "AxonInvalid" })
    end

    api.nvim_buf_set_extmark(buf, ns_form, row, 0, {
      virt_text = eol_chunks,
      virt_text_pos = "eol",
    })

    if not ok then
      App.validation_errors[lnum] = badge
      table.insert(diags, {
        lnum = row,
        col = 0,
        message = badge,
        severity = vim.diagnostic.severity.ERROR,
      })
    else
      App.validation_errors[lnum] = nil
    end

    -- Bottom border on very last field
    if lnum == #App.field_map then
      api.nvim_buf_set_extmark(buf, ns_form, row, 0, {
        virt_lines = {
          { { "  ╰" .. string.rep("─", 66) .. "╯", "AxonCardBottom" } },
        },
        virt_lines_above = false,
      })
    end
  end

  vim.diagnostic.set(ns_diag, buf, diags, { virtual_text = false })
end

local function render_inspector()
  local buf = App.bufs.inspector
  if not buf or not api.nvim_buf_is_valid(buf) then return end
  local win_form = App.wins.form
  local lnum = 1
  if win_form and api.nvim_win_is_valid(win_form) then
    lnum = api.nvim_win_get_cursor(win_form)[1]
  end
  local field = App.field_map[lnum]
  local dom = DOMAINS[App.active_domain_idx]

  local lines = {
    " 🔍 FIELD INSPECTOR",
    " ──────────────────────────────────",
  }
  if field then
    local cur_line = (api.nvim_buf_get_lines(App.bufs.form, lnum - 1, lnum, false)[1]) or ""
    local ok, _, badge = validate_field_value(field, cur_line)
    table.insert(lines, " Domain : " .. dom.label)
    table.insert(lines, " File   : /etc/axonwall/" .. dom.yaml)
    table.insert(lines, " Field  : " .. field.label)
    table.insert(lines, " Type   : " .. (field.vtype or "string"):upper())
    table.insert(lines, " Status : " .. badge)
    table.insert(lines, "")
    table.insert(lines, " 📖 Description:")
    -- Wrap description at 34 chars
    local desc = field.desc or ""
    while #desc > 0 do
      local chunk = desc:sub(1, 34)
      desc = desc:sub(35)
      table.insert(lines, "   " .. chunk)
    end
    if field.options then
      table.insert(lines, "")
      table.insert(lines, " 🎯 Allowed Options (<Space>/<CR>):")
      for _, opt in ipairs(field.options) do
        local mark = (vim.trim(cur_line) == opt) and " ● " or " ○ "
        table.insert(lines, "  " .. mark .. opt)
      end
    end
    table.insert(lines, "")
    table.insert(lines, " ⌨️  Vim Field Superpowers:")
    if field.tip then
      local tip = field.tip
      while #tip > 0 do
        table.insert(lines, "   " .. tip:sub(1, 34))
        tip = tip:sub(35)
      end
    else
      table.insert(lines, "   • ciw / cw : Change word/value")
      table.insert(lines, "   • f. / ct/ : Jump to octet/slash")
      table.insert(lines, "   • <C-a/x>  : Increment number/IP")
      table.insert(lines, "   • :%s/a/b/g: Bulk replace values")
      table.insert(lines, "   • u / <C-r>: Undo / Redo edits")
    end
  end
  table.insert(lines, "")
  table.insert(lines, " ─── Status ───────────────────────")
  local msg = App.status_msg or ""
  while #msg > 0 do
    table.insert(lines, " " .. msg:sub(1, 34))
    msg = msg:sub(35)
  end

  api.nvim_buf_set_option(buf, "modifiable", true)
  api.nvim_buf_set_lines(buf, 0, -1, false, lines)
  api.nvim_buf_clear_namespace(buf, ns_insp, 0, -1)
  api.nvim_buf_add_highlight(buf, ns_insp, "AxonInspectorTitle", 0, 0, -1)
  api.nvim_buf_set_option(buf, "modifiable", false)
end

-- Populate the Form Buffer from the active domain's field descriptors
local function load_domain_into_form(domain_idx, preserve_cursor)
  App.active_domain_idx = domain_idx
  local dom = DOMAINS[domain_idx]
  App.field_map = build_domain_fields(dom.id)
  App.validation_errors = {}

  local buf = App.bufs.form
  if not buf or not api.nvim_buf_is_valid(buf) then return end

  local old_cursor = { 1, 0 }
  if preserve_cursor and App.wins.form and api.nvim_win_is_valid(App.wins.form) then
    old_cursor = api.nvim_win_get_cursor(App.wins.form)
  end

  App.updating_buffer = true
  local lines = {}
  for _, f in ipairs(App.field_map) do
    table.insert(lines, tostring(f.get() or ""))
  end
  api.nvim_buf_set_option(buf, "modifiable", true)
  api.nvim_buf_set_lines(buf, 0, -1, false, lines)
  App.updating_buffer = false

  if App.wins.form and api.nvim_win_is_valid(App.wins.form) then
    if App.focused_pane == "form" then
      pcall(api.nvim_set_current_win, App.wins.form)
    end
    local target_row = math.min(math.max(1, old_cursor[1]), math.max(1, #lines))
    pcall(api.nvim_win_set_cursor, App.wins.form, { target_row, 0 })
    pcall(api.nvim_win_set_config, App.wins.form, {
      title = string.format(" %s %s (/etc/axonwall/%s) — %d Editable Fields ", dom.icon, dom.label, dom.yaml, #lines),
      title_pos = "center",
    })
  end

  decorate_form_extmarks()
  render_sidebar()
  render_header()
  render_inspector()
end

-- Sync any buffer line changes back into App.state
local function sync_form_buffer_to_state()
  if App.updating_buffer then return end
  local buf = App.bufs.form
  if not buf or not api.nvim_buf_is_valid(buf) then return end
  local lines = api.nvim_buf_get_lines(buf, 0, -1, false)

  -- If user accidentally added or deleted a line (e.g. via dd or o), restore line count
  if #lines ~= #App.field_map then
    load_domain_into_form(App.active_domain_idx, true)
    App.status_msg = "Protected form structure: use [n] to add a card or [X] to delete a card."
    render_inspector()
    return
  end

  for lnum, field in ipairs(App.field_map) do
    local raw = lines[lnum] or ""
    local ok, parsed = validate_field_value(field, raw)
    if ok then
      local prev = tostring(field.get() or "")
      if vim.trim(raw) ~= vim.trim(prev) then
        field.set(parsed)
        App.dirty = true
      end
    end
  end

  decorate_form_extmarks()
  render_header()
  render_inspector()
end

-- 9. Interactive Smart Widgets: Boolean Toggle, Floating Enum Picker, Add/Delete Cards
local function open_enum_picker(field, lnum)
  local opts = field.options or {}
  if #opts == 0 then return end

  local pbuf = api.nvim_create_buf(false, true)
  local cur_val = vim.trim((api.nvim_buf_get_lines(App.bufs.form, lnum - 1, lnum, false)[1]) or "")
  local start_idx = 1
  local plines = {}
  for idx, opt in ipairs(opts) do
    if opt == cur_val then start_idx = idx end
    table.insert(plines, string.format(" [%d] %s ", idx, opt))
  end
  api.nvim_buf_set_lines(pbuf, 0, -1, false, plines)
  api.nvim_buf_set_option(pbuf, "modifiable", false)
  api.nvim_buf_set_option(pbuf, "bufhidden", "wipe")

  local width = 34
  for _, l in ipairs(plines) do
    width = math.max(width, #l + 4)
  end
  local pwin = api.nvim_open_win(pbuf, true, {
    relative = "cursor",
    row = 1,
    col = 0,
    width = width,
    height = #plines,
    style = "minimal",
    border = "rounded",
    title = " ▾ Select " .. field.label .. " ",
    title_pos = "center",
  })
  api.nvim_win_set_option(pwin, "cursorline", true)
  api.nvim_win_set_cursor(pwin, { start_idx, 0 })

  local function choose(idx)
    local chosen = opts[idx]
    if api.nvim_win_is_valid(pwin) then
      api.nvim_win_close(pwin, true)
    end
    if chosen then
      App.updating_buffer = true
      api.nvim_buf_set_lines(App.bufs.form, lnum - 1, lnum, false, { chosen })
      App.updating_buffer = false
      field.set(chosen)
      App.dirty = true
      App.status_msg = string.format("Updated %s -> '%s'", field.label, chosen)
      decorate_form_extmarks()
      render_header()
      render_inspector()
    end
  end

  api.nvim_buf_set_keymap(pbuf, "n", "<CR>", "", {
    noremap = true,
    silent = true,
    callback = function()
      local r = api.nvim_win_get_cursor(pwin)[1]
      choose(r)
    end,
  })
  api.nvim_buf_set_keymap(pbuf, "n", "<Space>", "", {
    noremap = true,
    silent = true,
    callback = function()
      local r = api.nvim_win_get_cursor(pwin)[1]
      choose(r)
    end,
  })
  for idx = 1, math.min(9, #opts) do
    api.nvim_buf_set_keymap(pbuf, "n", tostring(idx), "", {
      noremap = true,
      silent = true,
      callback = function() choose(idx) end,
    })
  end
  for _, k in ipairs({ "<Esc>", "q" }) do
    api.nvim_buf_set_keymap(pbuf, "n", k, "", {
      noremap = true,
      silent = true,
      callback = function()
        if api.nvim_win_is_valid(pwin) then api.nvim_win_close(pwin, true) end
      end,
    })
  end
end

local function handle_smart_action_on_field()
  if not App.wins.form or not api.nvim_win_is_valid(App.wins.form) then return end
  local lnum = api.nvim_win_get_cursor(App.wins.form)[1]
  local field = App.field_map[lnum]
  if not field then return end

  if field.vtype == "boolean" then
    local cur = vim.trim((api.nvim_buf_get_lines(App.bufs.form, lnum - 1, lnum, false)[1]) or ""):lower()
    local next_bool = not (cur == "true" or cur == "enabled" or cur == "on" or cur == "1")
    App.updating_buffer = true
    api.nvim_buf_set_lines(App.bufs.form, lnum - 1, lnum, false, { tostring(next_bool) })
    App.updating_buffer = false
    field.set(next_bool)
    App.dirty = true
    App.status_msg = string.format("Toggled %s -> %s", field.label, next_bool and "ENABLED" or "DISABLED")
    decorate_form_extmarks()
    render_header()
    render_inspector()
  elseif field.vtype == "enum" then
    open_enum_picker(field, lnum)
  else
    -- Enter Insert mode at the end of the field value for immediate editing
    vim.cmd("startinsert!")
  end
end

local function add_new_card_item()
  sync_form_buffer_to_state()
  local dom = DOMAINS[App.active_domain_idx]
  local st = App.state
  if dom.id == "firewall" then
    st.rules = st.rules or {}
    table.insert(st.rules, {
      enabled = true,
      action = "pass",
      direction = "in",
      interface = "lan",
      protocol = "tcp",
      source = "any",
      sourcePort = "",
      destination = "any",
      destinationPort = "443",
      log = false,
      description = string.format("Custom Firewall Rule #%d", #st.rules + 1),
    })
    App.status_msg = "Added new Firewall Rule card! Use j/k and ciw to customize."
  elseif dom.id == "interfaces" then
    st.interfaces = st.interfaces or {}
    local n = #st.interfaces + 1
    table.insert(st.interfaces, {
      name = "opt" .. n,
      device = "eth" .. (n - 1),
      type = "static",
      ipv4Address = string.format("192.168.%d.1/24", n),
      mtu = 1500,
      enabled = true,
      description = "Optional Segment " .. n,
    })
    App.status_msg = "Added new Network Interface card!"
  elseif dom.id == "nat" then
    st.nat = st.nat or {}
    table.insert(st.nat, {
      enabled = true,
      type = "dnat",
      interface = "wan",
      protocol = "tcp",
      source = "any",
      destination = "wan_ip",
      destinationPort = "8443",
      targetIp = "192.168.1.50",
      targetPort = "443",
      description = "Port Forward #" .. (#st.nat + 1),
    })
    App.status_msg = "Added new DNAT Port Forward rule!"
  elseif dom.id == "aliases" then
    st.aliases = st.aliases or {}
    table.insert(st.aliases, {
      enabled = true,
      name = "custom_group_" .. (#st.aliases + 1),
      type = "host",
      entries = { "192.168.1.10", "192.168.1.11" },
      description = "Custom Host Group",
    })
    App.status_msg = "Added new Firewall Alias card!"
  elseif dom.id == "routing" then
    st.routes = st.routes or {}
    table.insert(st.routes, {
      enabled = true,
      network = "10.99.0.0/16",
      gateway = "192.168.1.254",
      interface = "lan",
      description = "Remote Branch Subnet",
    })
    App.status_msg = "Added new Static Route card!"
  else
    App.status_msg = "This domain uses singleton configuration cards."
    render_inspector()
    return
  end

  App.dirty = true
  load_domain_into_form(App.active_domain_idx, false)
  -- Jump cursor to the newly added card
  if App.wins.form and api.nvim_win_is_valid(App.wins.form) then
    for lnum = #App.field_map, 1, -1 do
      if App.field_map[lnum].card_title then
        api.nvim_win_set_cursor(App.wins.form, { lnum, 0 })
        break
      end
    end
  end
  render_inspector()
end

local function delete_current_card_item()
  sync_form_buffer_to_state()
  if not App.wins.form or not api.nvim_win_is_valid(App.wins.form) then return end
  local lnum = api.nvim_win_get_cursor(App.wins.form)[1]
  local field = App.field_map[lnum]
  if not field or not field.item_kind or not field.item_idx then
    App.status_msg = "Current card is a singleton system section and cannot be deleted."
    render_inspector()
    return
  end

  local idx = field.item_idx
  if field.item_kind == "rule" and #(App.state.rules or {}) > 1 then
    table.remove(App.state.rules, idx)
    App.status_msg = string.format("Deleted Firewall Rule #%d.", idx)
  elseif field.item_kind == "interface" and #(App.state.interfaces or {}) > 1 then
    table.remove(App.state.interfaces, idx)
    App.status_msg = string.format("Deleted Interface #%d.", idx)
  elseif field.item_kind == "nat" then
    table.remove(App.state.nat, idx)
    App.status_msg = string.format("Deleted NAT Rule #%d.", idx)
  elseif field.item_kind == "alias" then
    table.remove(App.state.aliases, idx)
    App.status_msg = string.format("Deleted Alias #%d.", idx)
  elseif field.item_kind == "route" then
    table.remove(App.state.routes, idx)
    App.status_msg = string.format("Deleted Static Route #%d.", idx)
  else
    App.status_msg = "Cannot delete the last required item in this section."
    render_inspector()
    return
  end

  App.dirty = true
  load_domain_into_form(App.active_domain_idx, true)
end

-- 10. Floating Modal Windows: Live Diff (<C-d>), Raw YAML (<C-y>), Save & Apply (<C-s>)
local function open_floating_modal(title, lines, ft)
  local mbuf = api.nvim_create_buf(false, true)
  api.nvim_buf_set_lines(mbuf, 0, -1, false, lines)
  if ft then api.nvim_buf_set_option(mbuf, "filetype", ft) end
  api.nvim_buf_set_option(mbuf, "modifiable", false)
  api.nvim_buf_set_option(mbuf, "bufhidden", "wipe")

  local w = math.min(vim.o.columns - 8, 108)
  local h = math.min(vim.o.lines - 6, 32)
  local mwin = api.nvim_open_win(mbuf, true, {
    relative = "editor",
    row = math.floor((vim.o.lines - h) / 2),
    col = math.floor((vim.o.columns - w) / 2),
    width = w,
    height = h,
    style = "minimal",
    border = "rounded",
    title = " " .. title .. " (Press [q] or [<Esc>] to close) ",
    title_pos = "center",
  })
  for _, k in ipairs({ "q", "<Esc>" }) do
    api.nvim_buf_set_keymap(mbuf, "n", k, "", {
      noremap = true,
      silent = true,
      callback = function()
        if api.nvim_win_is_valid(mwin) then api.nvim_win_close(mwin, true) end
      end,
    })
  end
end

local function save_state_to_yaml(trigger_apply)
  sync_form_buffer_to_state()
  for lnum, err in pairs(App.validation_errors) do
    if err then
      App.status_msg = string.format("✖ Fix validation error on line %d before saving: %s", lnum, err)
      render_inspector()
      return false
    end
  end

  local payload = fn.json_encode(App.state)
  local out, code = run_ctl({ "save-json", "-" }, payload)
  if code ~= 0 then
    App.status_msg = "✖ Validation failed: " .. vim.trim(out or "")
    render_inspector()
    return false
  end

  App.dirty = false
  if trigger_apply then
    local apply_out, apply_code = run_ctl({ "apply" })
    if apply_code == 0 then
      App.status_msg = "✔ Saved to /etc/axonwall/*.yaml & applied live nftables ruleset!"
    else
      App.status_msg = "✔ Saved to /etc/axonwall/*.yaml (daemon offline; will apply on boot)."
    end
  else
    App.status_msg = "✔ Saved all changes to /etc/axonwall/*.yaml!"
  end

  render_header()
  render_inspector()
  return true
end

local function show_live_diff()
  save_state_to_yaml(false)
  local out, _ = run_ctl({ "diff" })
  local clean = (out or ""):gsub("\27%[[0-9;]*m", "")
  local lines = vim.split(clean, "\n", { plain = true })
  open_floating_modal("🔍 Compiled Linux nftables Ruleset & YAML Diff", lines, "pf")
end

local function open_raw_yaml_drawer()
  save_state_to_yaml(false)
  local dom = DOMAINS[App.active_domain_idx]
  local etc_dir = vim.env.AXONWALL_CONFIG_DIR or "/etc/axonwall"
  local ypath = etc_dir .. "/" .. dom.yaml
  local ylines = {}
  if fn.filereadable(ypath) == 1 then
    ylines = fn.readfile(ypath)
  else
    ylines = { "# " .. dom.label, "# " .. ypath }
  end

  local ybuf = api.nvim_create_buf(false, true)
  api.nvim_buf_set_lines(ybuf, 0, -1, false, ylines)
  api.nvim_buf_set_option(ybuf, "filetype", "yaml")
  api.nvim_buf_set_option(ybuf, "bufhidden", "wipe")

  local w = math.min(vim.o.columns - 8, 104)
  local h = math.min(vim.o.lines - 6, 30)
  local ywin = api.nvim_open_win(ybuf, true, {
    relative = "editor",
    row = math.floor((vim.o.lines - h) / 2),
    col = math.floor((vim.o.columns - w) / 2),
    width = w,
    height = h,
    style = "minimal",
    border = "double",
    title = string.format(" 📄 Raw YAML Power View: %s ([<C-s>] Save & Return  [q/<Esc>] Close) ", ypath),
    title_pos = "center",
  })

  local function save_and_close_yaml()
    local new_lines = api.nvim_buf_get_lines(ybuf, 0, -1, false)
    pcall(fn.writefile, new_lines, ypath)
    if api.nvim_win_is_valid(ywin) then api.nvim_win_close(ywin, true) end
    load_state()
    load_domain_into_form(App.active_domain_idx, true)
    App.status_msg = "✔ Reloaded structured form from modified " .. dom.yaml
    render_inspector()
  end

  api.nvim_buf_set_keymap(ybuf, "n", "<C-s>", "", { noremap = true, silent = true, callback = save_and_close_yaml })
  api.nvim_buf_set_keymap(ybuf, "n", "q", "", {
    noremap = true,
    silent = true,
    callback = function()
      if api.nvim_win_is_valid(ywin) then api.nvim_win_close(ywin, true) end
    end,
  })
end

-- 11. Multi-Window Layout Manager & Keymaps
local function update_focus_borders()
  if App.wins.sidebar and api.nvim_win_is_valid(App.wins.sidebar) then
    api.nvim_win_set_option(
      App.wins.sidebar,
      "winhl",
      "FloatBorder:" .. (App.focused_pane == "sidebar" and "AxonActiveBorder" or "AxonInactiveBorder")
    )
  end
  if App.wins.form and api.nvim_win_is_valid(App.wins.form) then
    api.nvim_win_set_option(
      App.wins.form,
      "winhl",
      "FloatBorder:" .. (App.focused_pane == "form" and "AxonActiveBorder" or "AxonInactiveBorder")
    )
  end
end

local function switch_pane()
  if App.focused_pane == "form" then
    App.focused_pane = "sidebar"
    if App.wins.sidebar and api.nvim_win_is_valid(App.wins.sidebar) then
      api.nvim_set_current_win(App.wins.sidebar)
      api.nvim_win_set_cursor(App.wins.sidebar, { App.active_domain_idx, 0 })
    end
  else
    App.focused_pane = "form"
    if App.wins.form and api.nvim_win_is_valid(App.wins.form) then
      api.nvim_set_current_win(App.wins.form)
    end
  end
  update_focus_borders()
end

local function create_ui_layout()
  local total_cols = math.max(100, vim.o.columns)
  local total_lines = math.max(28, vim.o.lines)

  local header_h = 2
  local body_row = header_h + 2
  local body_h = math.max(16, total_lines - body_row - 2)
  local side_w = 32
  local insp_w = 36
  local form_w = math.max(40, total_cols - side_w - insp_w - 6)

  -- Create scratch buffers
  App.bufs.header = api.nvim_create_buf(false, true)
  App.bufs.sidebar = api.nvim_create_buf(false, true)
  App.bufs.form = api.nvim_create_buf(false, true)
  App.bufs.inspector = api.nvim_create_buf(false, true)

  -- 1. Top Header Window
  App.wins.header = api.nvim_open_win(App.bufs.header, false, {
    relative = "editor",
    row = 0,
    col = 0,
    width = total_cols - 2,
    height = header_h,
    style = "minimal",
    border = "rounded",
    focusable = false,
  })

  -- 2. Left Sidebar Window
  App.wins.sidebar = api.nvim_open_win(App.bufs.sidebar, false, {
    relative = "editor",
    row = body_row,
    col = 0,
    width = side_w,
    height = body_h,
    style = "minimal",
    border = "rounded",
    title = " 🧭 Domains ([1-0/-/=]) ",
    title_pos = "center",
  })
  api.nvim_win_set_option(App.wins.sidebar, "cursorline", true)

  -- 3. Center Form Canvas Window
  App.wins.form = api.nvim_open_win(App.bufs.form, true, {
    relative = "editor",
    row = body_row,
    col = side_w + 2,
    width = form_w,
    height = body_h,
    style = "minimal",
    border = "rounded",
    title = " 🛡️ Firewall Rules ",
    title_pos = "center",
  })
  api.nvim_win_set_option(App.wins.form, "cursorline", true)

  -- 4. Right Inspector Window
  App.wins.inspector = api.nvim_open_win(App.bufs.inspector, false, {
    relative = "editor",
    row = body_row,
    col = side_w + form_w + 4,
    width = insp_w,
    height = body_h,
    style = "minimal",
    border = "rounded",
    title = " 🔍 Field Inspector ",
    title_pos = "center",
    focusable = false,
  })

  update_focus_borders()

  -- Bind global & buffer keymaps on both sidebar and form
  local function bind_common(buf)
    api.nvim_buf_set_keymap(buf, "n", "<Tab>", "", { noremap = true, silent = true, callback = switch_pane })
    api.nvim_buf_set_keymap(buf, "n", "<C-s>", "", {
      noremap = true,
      silent = true,
      callback = function() save_state_to_yaml(true) end,
    })
    api.nvim_buf_set_keymap(buf, "i", "<C-s>", "", {
      noremap = true,
      silent = true,
      callback = function()
        vim.cmd("stopinsert")
        save_state_to_yaml(true)
      end,
    })
    api.nvim_buf_set_keymap(buf, "n", "<C-d>", "", { noremap = true, silent = true, callback = show_live_diff })
    api.nvim_buf_set_keymap(buf, "n", "<C-y>", "", { noremap = true, silent = true, callback = open_raw_yaml_drawer })
    api.nvim_buf_set_keymap(buf, "n", "q", "", {
      noremap = true,
      silent = true,
      callback = function() vim.cmd("qa!") end,
    })
    for idx, d in ipairs(DOMAINS) do
      api.nvim_buf_set_keymap(buf, "n", d.key, "", {
        noremap = true,
        silent = true,
        callback = function()
          sync_form_buffer_to_state()
          load_domain_into_form(idx, false)
        end,
      })
    end
  end

  bind_common(App.bufs.sidebar)
  bind_common(App.bufs.form)

  -- Sidebar specific keymaps
  api.nvim_buf_set_keymap(App.bufs.sidebar, "n", "<CR>", "", {
    noremap = true,
    silent = true,
    callback = function()
      local r = api.nvim_win_get_cursor(App.wins.sidebar)[1]
      if r >= 1 and r <= #DOMAINS then
        sync_form_buffer_to_state()
        load_domain_into_form(r, false)
        switch_pane()
      end
    end,
  })
  api.nvim_buf_set_keymap(App.bufs.sidebar, "n", "<Space>", "", {
    noremap = true,
    silent = true,
    callback = function()
      local r = api.nvim_win_get_cursor(App.wins.sidebar)[1]
      if r >= 1 and r <= #DOMAINS then
        sync_form_buffer_to_state()
        load_domain_into_form(r, false)
      end
    end,
  })

  -- Form specific keymaps (while preserving all native Vim motions: ciw, dw, f., /search, :%s, u, <C-r>, <C-a>, <C-x>!)
  api.nvim_buf_set_keymap(App.bufs.form, "n", "<Space>", "", {
    noremap = true,
    silent = true,
    callback = handle_smart_action_on_field,
  })
  api.nvim_buf_set_keymap(App.bufs.form, "n", "<CR>", "", {
    noremap = true,
    silent = true,
    callback = handle_smart_action_on_field,
  })
  api.nvim_buf_set_keymap(App.bufs.form, "n", "n", "", {
    noremap = true,
    silent = true,
    callback = add_new_card_item,
  })
  api.nvim_buf_set_keymap(App.bufs.form, "n", "X", "", {
    noremap = true,
    silent = true,
    callback = delete_current_card_item,
  })

  -- Autocmds on Form Buffer for live validation & inspector updates
  api.nvim_create_autocmd({ "TextChanged", "TextChangedI" }, {
    buffer = App.bufs.form,
    callback = sync_form_buffer_to_state,
  })
  api.nvim_create_autocmd({ "CursorMoved", "CursorMovedI" }, {
    buffer = App.bufs.form,
    callback = render_inspector,
  })

  -- Intercept :w and :wq so standard Vim muscle memory saves and applies cleanly!
  api.nvim_create_user_command("W", function() save_state_to_yaml(true) end, {})
  api.nvim_create_user_command("AxonSave", function() save_state_to_yaml(false) end, {})
  api.nvim_create_user_command("AxonApply", function() save_state_to_yaml(true) end, {})
end

-- 12. Boot Sequence
local initial_domain_name = (vim.env.AXONWALL_NVIM_DOMAIN or "firewall"):lower()
local start_idx = 3
for idx, d in ipairs(DOMAINS) do
  if d.id == initial_domain_name or d.yaml:gsub("%.yaml$", "") == initial_domain_name then
    start_idx = idx
    break
  end
end

local backdrop_buf = api.nvim_get_current_buf()
load_state()
create_ui_layout()
load_domain_into_form(start_idx, false)

local function enforce_floating_focus()
  local target_win = (App.focused_pane == "sidebar") and App.wins.sidebar or App.wins.form
  if target_win and api.nvim_win_is_valid(target_win) then
    pcall(api.nvim_set_current_win, target_win)
  end
end

api.nvim_create_autocmd({ "BufEnter", "BufWinEnter", "WinEnter", "VimEnter" }, {
  buffer = backdrop_buf,
  callback = enforce_floating_focus,
})
api.nvim_create_autocmd("VimEnter", {
  callback = enforce_floating_focus,
})

-- Expose global test/API table for automated headless verification
_G.AxonwallSuperConfig = {
  App = App,
  DOMAINS = DOMAINS,
  load_domain = function(idx)
    sync_form_buffer_to_state()
    load_domain_into_form(idx, false)
  end,
  sync = sync_form_buffer_to_state,
  save = save_state_to_yaml,
  toggle_current = handle_smart_action_on_field,
  add_card = add_new_card_item,
  delete_card = delete_current_card_item,
}
