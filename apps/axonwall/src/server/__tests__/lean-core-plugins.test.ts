import { beforeEach, describe, expect, it, vi } from 'vitest';
import { NextRequest } from 'next/server';
import { DesiredStateSchema } from '@axonwall/lib/schemas';
import { enablePluginWithDependencies } from '@axonwall/lib/plugins';
import type { UserSession } from '@axonwall/lib/rbac';

const hoisted = vi.hoisted(() => {
  const adminSession: UserSession = {
    userId: 'admin-1',
    username: 'admin',
    displayName: 'Administrator',
    roles: ['admin'],
    privileges: ['*'],
    passwordChangeRequired: false,
    source: 'local',
    exp: Math.floor(Date.now() / 1000) + 3600,
  };
  return {
    adminSession,
    getSession: vi.fn<() => Promise<UserSession | null>>(async () => adminSession),
    getDesiredStateInternal: vi.fn(async () => DesiredStateSchema.parse({ version: 1 })),
    callAgentApi: vi.fn(),
    callAgentApiResponse: vi.fn(),
  };
});

vi.mock('../auth', () => ({
  getSession: hoisted.getSession,
}));

vi.mock('../auth-guard', async () => {
  const actual = await vi.importActual<typeof import('../auth-guard')>('../auth-guard');
  return {
    ...actual,
    isPasswordChangeEnforced: vi.fn(() => false),
  };
});

vi.mock('../desired-state-internal', () => ({
  getDesiredStateInternal: hoisted.getDesiredStateInternal,
  invalidateDesiredStateCacheInternal: vi.fn(),
}));

vi.mock('../agent-client', () => ({
  callAgentApi: hoisted.callAgentApi,
  callAgentApiDetailed: vi.fn(),
  callAgentApiResponse: hoisted.callAgentApiResponse,
}));

import { assertPluginEnabled, checkPluginApiGuard } from '../plugin-guard';
import { getOidcConfig } from '../oidc';
import { getKernelStudioTelemetry } from '../kernel-studio';
import {
  getLibreNmsStatusAction,
  getLocalTopologyProbeAction,
  getNetBoxStatusAction,
  getNetFlowStatusAction,
  getThreatHarvesterStatus,
} from '../agent';
import { POST as importPost } from '@/app/api/v1/import/route';
import { GET as directoryGet } from '@/app/api/system/directory/route';
import { GET as usersGet } from '@/app/api/system/users/route';
import { GET as pcapDownloadGet } from '@/app/api/diagnostics/packet-capture/download/route';
import { GET as ebpfOverviewGet } from '@/app/api/v1/ebpf/overview/route';

describe('Lean Core fail-closed UI API & server action plugin gating', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    hoisted.getSession.mockResolvedValue(hoisted.adminSession);
    hoisted.getDesiredStateInternal.mockResolvedValue(DesiredStateSchema.parse({ version: 1 }));
    hoisted.callAgentApi.mockReset();
    hoisted.callAgentApiResponse.mockReset();
  });

  it('assertPluginEnabled and checkPluginApiGuard allow core-firewall and fail closed for disabled plugins', async () => {
    await expect(assertPluginEnabled('core-firewall')).resolves.toBeUndefined();
    expect(await checkPluginApiGuard('core-firewall')).toBeNull();

    await expect(assertPluginEnabled('suricata-ids')).rejects.toThrow(/Forbidden: Plugin 'suricata-ids'/);
    const guardRes = await checkPluginApiGuard('suricata-ids');
    expect(guardRes?.status).toBe(403);
  });

  it('/api/v1/import returns 403 when firewall-importer is disabled and proceeds past guard when enabled', async () => {
    const reqDisabled = new Request('http://localhost/api/v1/import', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({}),
    });
    const resDisabled = await importPost(reqDisabled);
    expect(resDisabled.status).toBe(403);

    const enabledState = enablePluginWithDependencies('firewall-importer', DesiredStateSchema.parse({ version: 1 })).state;
    hoisted.getDesiredStateInternal.mockResolvedValue(enabledState);

    const reqEnabled = new Request('http://localhost/api/v1/import', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({}),
    });
    const resEnabled = await importPost(reqEnabled);
    // Passes plugin guard; empty config triggers 400 validation instead of 403
    expect(resEnabled.status).toBe(400);
  });

  it('/api/system/directory returns 403 when directory-ldap is disabled while /api/system/users keeps POSIX local users active', async () => {
    const dirRes = await directoryGet();
    expect(dirRes.status).toBe(403);

    hoisted.callAgentApi.mockImplementation(async (endpoint: string) => {
      if (endpoint === '/v1/system/users') {
        return {
          users: [
            {
              username: 'localop',
              uid: 1000,
              gid: 1000,
              comment: 'Local Operator',
              homeDir: '/home/localop',
              shell: '/bin/bash',
              role: 'operator',
              groups: ['operator'],
              sshKeys: [],
              passwordLocked: false,
            },
          ],
        };
      }
      if (endpoint === '/v1/system/groups') {
        return { groups: [{ name: 'operator', gid: 1000, members: ['localop'] }] };
      }
      return null;
    });

    const usersRes = await usersGet();
    expect(usersRes.status).toBe(200);
    const payload = await usersRes.json();
    expect(payload.ldapEnabled).toBe(false);
    expect(payload.directoryStatus).toBeNull();
    expect(payload.users).toHaveLength(1);
    expect(payload.groups).toHaveLength(1);
  });

  it('getKernelStudioTelemetry rejects when custom-kernel-studio is disabled', async () => {
    await expect(getKernelStudioTelemetry()).rejects.toThrow(/custom-kernel-studio/);
  });

  it('/api/diagnostics/packet-capture/download returns 403 when packet-diagnostics is disabled', async () => {
    const req = new NextRequest('http://localhost/api/diagnostics/packet-capture/download?id=cap1');
    const res = await pcapDownloadGet(req);
    expect(res.status).toBe(403);
  });

  it('getOidcConfig fails closed when enterprise-sso is disabled and returns config when enabled', async () => {
    const prevIssuer = process.env.OIDC_ISSUER_URL;
    const prevClient = process.env.OIDC_CLIENT_ID;
    delete process.env.OIDC_ISSUER_URL;
    delete process.env.OIDC_CLIENT_ID;
    try {
      expect(await getOidcConfig()).toBeNull();

      const ssoEnabled = DesiredStateSchema.parse({
        version: 1,
        sso: {
          enabled: true,
          provider: 'oidc',
          issuerUrl: 'https://idp.example.com/realms/main',
          clientId: 'axonwall-ui',
        },
      });
      hoisted.getDesiredStateInternal.mockResolvedValue(ssoEnabled);
      const cfg = await getOidcConfig();
      expect(cfg?.issuerUrl).toBe('https://idp.example.com/realms/main');
      expect(cfg?.clientId).toBe('axonwall-ui');
    } finally {
      if (prevIssuer !== undefined) process.env.OIDC_ISSUER_URL = prevIssuer;
      if (prevClient !== undefined) process.env.OIDC_CLIENT_ID = prevClient;
    }
  });

  it('/api/v1/ebpf/overview returns 403 when coroot-ebpf-apm is disabled and 200 when enabled', async () => {
    const disabledRes = await ebpfOverviewGet();
    expect(disabledRes.status).toBe(403);

    const enabledState = enablePluginWithDependencies('coroot-ebpf-apm', DesiredStateSchema.parse({ version: 1 })).state;
    hoisted.getDesiredStateInternal.mockResolvedValue(enabledState);
    hoisted.callAgentApi.mockResolvedValue(null);

    const enabledRes = await ebpfOverviewGet();
    expect(enabledRes.status).toBe(200);
    const body = await enabledRes.json();
    expect(body.status).toBe('ok');
    expect(body.data.daemonDown).toBe(true);
  });

  it('NetFlow, Topology, NetBox, LibreNMS, and ThreatHarvester server actions fail closed when plugins are disabled', async () => {
    await expect(getNetFlowStatusAction()).rejects.toThrow(/Forbidden: Plugin 'netflow-collector'/);
    await expect(getLocalTopologyProbeAction()).rejects.toThrow(/Forbidden: Plugin 'topology-studio'/);
    await expect(getNetBoxStatusAction()).rejects.toThrow(/Forbidden: Plugin 'netbox'/);
    await expect(getLibreNmsStatusAction()).rejects.toThrow(/Forbidden: Plugin 'librenms'/);
    await expect(getThreatHarvesterStatus()).rejects.toThrow(/Forbidden: Plugin 'ebpf-threat-harvester'/);
  });

  it('getOidcConfig fails closed when env vars are set and getDesiredStateInternal throws', async () => {
    const prevIssuer = process.env.OIDC_ISSUER_URL;
    const prevClient = process.env.OIDC_CLIENT_ID;
    process.env.OIDC_ISSUER_URL = 'https://env-idp.example.com/realms/main';
    process.env.OIDC_CLIENT_ID = 'env-client';
    try {
      hoisted.getDesiredStateInternal.mockRejectedValueOnce(new Error('disk unreadable'));
      await expect(getOidcConfig()).resolves.toBeNull();

      hoisted.getDesiredStateInternal.mockResolvedValueOnce(DesiredStateSchema.parse({ version: 1 }));
      await expect(getOidcConfig()).resolves.toBeNull();
    } finally {
      if (prevIssuer === undefined) delete process.env.OIDC_ISSUER_URL;
      else process.env.OIDC_ISSUER_URL = prevIssuer;
      if (prevClient === undefined) delete process.env.OIDC_CLIENT_ID;
      else process.env.OIDC_CLIENT_ID = prevClient;
    }
  });
});
