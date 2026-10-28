-- Axonwall Initial Schema & RBAC
-- PostgreSQL 17 + Supabase RLS

CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Auth Helpers for RLS
CREATE OR REPLACE FUNCTION auth.jwt_claims()
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SET search_path = public, pg_temp
AS $$
BEGIN
  RETURN COALESCE(NULLIF(current_setting('request.jwt.claims', true), '')::jsonb, '{}'::jsonb);
END;
$$;

CREATE OR REPLACE FUNCTION auth.has_priv(priv text)
RETURNS boolean
LANGUAGE plpgsql
STABLE
SET search_path = public, pg_temp
AS $$
DECLARE
  claims jsonb;
  privs jsonb;
BEGIN
  claims := auth.jwt_claims();
  -- Service role bypasses all RLS checks
  IF claims->>'role' = 'service_role' THEN
    RETURN true;
  END IF;
  
  privs := claims->'app_privs';
  IF privs IS NULL THEN
    RETURN false;
  END IF;

  -- Wildcard admin permission
  IF privs ? '*' THEN
    RETURN true;
  END IF;

  -- Specific privilege check
  RETURN privs ? priv;
END;
$$;

CREATE OR REPLACE FUNCTION auth.has_role(r text)
RETURNS boolean
LANGUAGE plpgsql
STABLE
SET search_path = public, pg_temp
AS $$
DECLARE
  claims jsonb;
  roles jsonb;
BEGIN
  claims := auth.jwt_claims();
  IF claims->>'role' = 'service_role' THEN
    RETURN true;
  END IF;
  roles := claims->'app_roles';
  IF roles IS NULL THEN
    RETURN false;
  END IF;
  RETURN roles ? r;
END;
$$;

-- 1. Nodes Table
CREATE TABLE IF NOT EXISTS public.nodes (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  machine_id text NOT NULL UNIQUE,
  hostname text NOT NULL DEFAULT 'axonwall',
  version text NOT NULL DEFAULT '0.1.0',
  is_local boolean NOT NULL DEFAULT true,
  status text NOT NULL DEFAULT 'online',
  last_heartbeat timestamptz NOT NULL DEFAULT now(),
  created_at timestamptz NOT NULL DEFAULT now()
);

-- 2. RBAC Tables
CREATE TABLE IF NOT EXISTS public.roles (
  id text PRIMARY KEY,
  name text NOT NULL,
  description text NOT NULL DEFAULT '',
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS public.role_privileges (
  role_id text REFERENCES public.roles(id) ON DELETE CASCADE,
  privilege text NOT NULL,
  PRIMARY KEY (role_id, privilege)
);

CREATE TABLE IF NOT EXISTS public.ldap_group_mappings (
  ldap_group text PRIMARY KEY,
  role_id text NOT NULL REFERENCES public.roles(id) ON DELETE CASCADE,
  updated_at timestamptz NOT NULL DEFAULT now()
);

-- 3. Interfaces Table
CREATE TABLE IF NOT EXISTS public.interfaces (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL UNIQUE, -- e.g. wan, lan, opt1
  device text NOT NULL, -- e.g. eth0, eth1
  type text NOT NULL DEFAULT 'static', -- static, dhcp, pppoe, vlan, etc.
  enabled boolean NOT NULL DEFAULT true,
  description text NOT NULL DEFAULT '',
  ipv4_address text,
  ipv4_gateway text,
  ipv6_address text,
  ipv6_gateway text,
  mtu integer NOT NULL DEFAULT 1500,
  mac_address text,
  sort_order integer NOT NULL DEFAULT 100,
  updated_at timestamptz NOT NULL DEFAULT now()
);

-- 4. Aliases Tables
CREATE TABLE IF NOT EXISTS public.fw_aliases (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL UNIQUE,
  type text NOT NULL, -- host, network, port, mac, urltable
  description text NOT NULL DEFAULT '',
  enabled boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS public.fw_alias_entries (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  alias_id uuid NOT NULL REFERENCES public.fw_aliases(id) ON DELETE CASCADE,
  entry text NOT NULL,
  sort_order integer NOT NULL DEFAULT 100
);

-- 5. Firewall Rules Table
CREATE TABLE IF NOT EXISTS public.fw_rules (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  action text NOT NULL DEFAULT 'pass', -- pass, block, reject
  direction text NOT NULL DEFAULT 'in', -- in, out
  interface text NOT NULL DEFAULT 'lan', -- wan, lan, any, floating
  quick boolean NOT NULL DEFAULT true,
  protocol text NOT NULL DEFAULT 'any', -- any, tcp, udp, icmp, etc.
  source text NOT NULL DEFAULT 'any',
  source_port text NOT NULL DEFAULT '',
  destination text NOT NULL DEFAULT 'any',
  destination_port text NOT NULL DEFAULT '',
  gateway text,
  log boolean NOT NULL DEFAULT false,
  enabled boolean NOT NULL DEFAULT true,
  description text NOT NULL DEFAULT '',
  sort_order integer NOT NULL DEFAULT 100,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

-- 6. NAT Rules Table
CREATE TABLE IF NOT EXISTS public.fw_nat_rules (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  type text NOT NULL DEFAULT 'dnat', -- dnat, snat, masquerade, nptv6
  interface text NOT NULL DEFAULT 'wan',
  protocol text NOT NULL DEFAULT 'tcp',
  source text NOT NULL DEFAULT 'any',
  source_port text NOT NULL DEFAULT '',
  destination text NOT NULL DEFAULT 'wan_ip',
  destination_port text NOT NULL DEFAULT '',
  target_ip text,
  target_port text,
  log boolean NOT NULL DEFAULT false,
  enabled boolean NOT NULL DEFAULT true,
  description text NOT NULL DEFAULT '',
  sort_order integer NOT NULL DEFAULT 100,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

-- 7. Gateways Table
CREATE TABLE IF NOT EXISTS public.gateways (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL UNIQUE,
  interface text NOT NULL,
  gateway_ip text NOT NULL,
  monitor_ip text,
  weight integer NOT NULL DEFAULT 1,
  is_default boolean NOT NULL DEFAULT false,
  enabled boolean NOT NULL DEFAULT true,
  description text NOT NULL DEFAULT '',
  updated_at timestamptz NOT NULL DEFAULT now()
);

-- 8. Configuration Revisions & Apply Pipeline (Commit-Confirm)
CREATE TABLE IF NOT EXISTS public.config_revisions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  revision_number serial UNIQUE,
  state_json jsonb NOT NULL,
  patch_diff text,
  author text NOT NULL DEFAULT 'system',
  message text NOT NULL DEFAULT '',
  bundle_hash text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS public.apply_jobs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  revision_id uuid NOT NULL REFERENCES public.config_revisions(id) ON DELETE CASCADE,
  status text NOT NULL DEFAULT 'pending', -- pending, applying, pending_confirm, confirmed, rolled_back, failed
  confirm_deadline timestamptz,
  applied_at timestamptz,
  confirmed_at timestamptz,
  error_message text,
  created_at timestamptz NOT NULL DEFAULT now()
);

-- 9. Audit Log
CREATE TABLE IF NOT EXISTS public.audit_log (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  actor text NOT NULL,
  action text NOT NULL,
  resource text NOT NULL,
  resource_id text,
  details jsonb NOT NULL DEFAULT '{}'::jsonb,
  ip_address text,
  created_at timestamptz NOT NULL DEFAULT now()
);

-- Enable Row Level Security (RLS)
ALTER TABLE public.nodes ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.role_privileges ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.ldap_group_mappings ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.interfaces ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.fw_aliases ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.fw_alias_entries ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.fw_rules ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.fw_nat_rules ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.gateways ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.config_revisions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.apply_jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.audit_log ENABLE ROW LEVEL SECURITY;

-- RLS Policies
-- Nodes
CREATE POLICY "Allow read nodes" ON public.nodes FOR SELECT USING (auth.has_priv('system.status.read'));
CREATE POLICY "Allow write nodes" ON public.nodes FOR ALL USING (auth.has_priv('system.config.write'));

-- Roles & LDAP mappings
CREATE POLICY "Allow read roles" ON public.roles FOR SELECT USING (auth.has_priv('system.users.read'));
CREATE POLICY "Allow write roles" ON public.roles FOR ALL USING (auth.has_priv('system.users.write'));
CREATE POLICY "Allow read role_privileges" ON public.role_privileges FOR SELECT USING (auth.has_priv('system.users.read'));
CREATE POLICY "Allow write role_privileges" ON public.role_privileges FOR ALL USING (auth.has_priv('system.users.write'));
CREATE POLICY "Allow read ldap_group_mappings" ON public.ldap_group_mappings FOR SELECT USING (auth.has_priv('system.users.read'));
CREATE POLICY "Allow write ldap_group_mappings" ON public.ldap_group_mappings FOR ALL USING (auth.has_priv('system.users.write'));

-- Interfaces
CREATE POLICY "Allow read interfaces" ON public.interfaces FOR SELECT USING (auth.has_priv('interfaces.read'));
CREATE POLICY "Allow write interfaces" ON public.interfaces FOR ALL USING (auth.has_priv('interfaces.write'));

-- Aliases
CREATE POLICY "Allow read fw_aliases" ON public.fw_aliases FOR SELECT USING (auth.has_priv('firewall.aliases.read'));
CREATE POLICY "Allow write fw_aliases" ON public.fw_aliases FOR ALL USING (auth.has_priv('firewall.aliases.write'));
CREATE POLICY "Allow read fw_alias_entries" ON public.fw_alias_entries FOR SELECT USING (auth.has_priv('firewall.aliases.read'));
CREATE POLICY "Allow write fw_alias_entries" ON public.fw_alias_entries FOR ALL USING (auth.has_priv('firewall.aliases.write'));

-- Rules
CREATE POLICY "Allow read fw_rules" ON public.fw_rules FOR SELECT USING (auth.has_priv('firewall.rules.read'));
CREATE POLICY "Allow write fw_rules" ON public.fw_rules FOR ALL USING (auth.has_priv('firewall.rules.write'));

-- NAT
CREATE POLICY "Allow read fw_nat_rules" ON public.fw_nat_rules FOR SELECT USING (auth.has_priv('firewall.nat.read'));
CREATE POLICY "Allow write fw_nat_rules" ON public.fw_nat_rules FOR ALL USING (auth.has_priv('firewall.nat.write'));

-- Gateways
CREATE POLICY "Allow read gateways" ON public.gateways FOR SELECT USING (auth.has_priv('routing.read'));
CREATE POLICY "Allow write gateways" ON public.gateways FOR ALL USING (auth.has_priv('routing.write'));

-- Config Revisions & Apply Jobs
CREATE POLICY "Allow read config_revisions" ON public.config_revisions FOR SELECT USING (auth.has_priv('system.config.read'));
CREATE POLICY "Allow write config_revisions" ON public.config_revisions FOR ALL USING (auth.has_priv('system.config.write'));
CREATE POLICY "Allow read apply_jobs" ON public.apply_jobs FOR SELECT USING (auth.has_priv('system.config.read'));
CREATE POLICY "Allow write apply_jobs" ON public.apply_jobs FOR ALL USING (auth.has_priv('firewall.rules.write'));

-- Audit log
CREATE POLICY "Allow read audit_log" ON public.audit_log FOR SELECT USING (auth.has_priv('system.status.read'));
CREATE POLICY "Allow insert audit_log" ON public.audit_log FOR INSERT WITH CHECK ((auth.jwt_claims()->>'role') = 'service_role' OR (auth.jwt_claims()->>'sub') IS NOT NULL);

-- Seed Initial Data
INSERT INTO public.roles (id, name, description) VALUES
  ('admin', 'Administrator', 'Full unconstrained administrative access'),
  ('operator', 'Network Operator', 'Can manage firewall rules, aliases, and execute diagnostics'),
  ('readonly', 'Read Only Auditor', 'Can inspect configuration and status without changes')
ON CONFLICT (id) DO NOTHING;

INSERT INTO public.role_privileges (role_id, privilege) VALUES
  ('admin', '*'),
  ('operator', 'firewall.rules.read'),
  ('operator', 'firewall.rules.write'),
  ('operator', 'firewall.aliases.read'),
  ('operator', 'firewall.aliases.write'),
  ('operator', 'firewall.nat.read'),
  ('operator', 'firewall.nat.write'),
  ('operator', 'interfaces.read'),
  ('operator', 'routing.read'),
  ('operator', 'services.dhcp.read'),
  ('operator', 'services.dns.read'),
  ('operator', 'vpn.wireguard.read'),
  ('operator', 'vpn.wireguard.write'),
  ('operator', 'system.status.read'),
  ('operator', 'system.config.read'),
  ('operator', 'diagnostics.read'),
  ('operator', 'diagnostics.exec'),
  ('readonly', 'firewall.rules.read'),
  ('readonly', 'firewall.aliases.read'),
  ('readonly', 'firewall.nat.read'),
  ('readonly', 'interfaces.read'),
  ('readonly', 'routing.read'),
  ('readonly', 'services.dhcp.read'),
  ('readonly', 'services.dns.read'),
  ('readonly', 'vpn.wireguard.read'),
  ('readonly', 'system.status.read'),
  ('readonly', 'system.config.read'),
  ('readonly', 'diagnostics.read')
ON CONFLICT DO NOTHING;

INSERT INTO public.ldap_group_mappings (ldap_group, role_id) VALUES
  ('admins', 'admin'),
  ('operators', 'operator'),
  ('auditors', 'readonly')
ON CONFLICT DO NOTHING;

-- Initial Interfaces (Default Appliance Setup)
INSERT INTO public.interfaces (name, device, type, enabled, description, ipv4_address, sort_order) VALUES
  ('wan', 'eth0', 'dhcp', true, 'WAN Internet Uplink', '', 10),
  ('lan', 'eth1', 'static', true, 'LAN Internal Network', '192.168.1.1/24', 20)
ON CONFLICT (name) DO NOTHING;

-- Initial Anti-Lockout / Default LAN Rule
INSERT INTO public.fw_rules (action, direction, interface, quick, protocol, source, destination, destination_port, log, enabled, description, sort_order) VALUES
  ('pass', 'in', 'lan', true, 'tcp', 'any', 'any', '22, 80, 443, 3000', false, true, 'Anti-Lockout Rule: Web GUI & SSH', 10),
  ('pass', 'in', 'lan', true, 'any', 'any', 'any', '', false, true, 'Default allow LAN to any', 100)
ON CONFLICT DO NOTHING;

-- Default WAN Masquerade NAT Rule
INSERT INTO public.fw_nat_rules (type, interface, protocol, source, destination, enabled, description, sort_order) VALUES
  ('masquerade', 'wan', 'any', 'any', 'any', true, 'Default Outbound NAT Masquerade', 100)
ON CONFLICT DO NOTHING;
