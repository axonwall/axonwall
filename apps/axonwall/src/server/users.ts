'use server';

import { getSession } from './auth';
import { assertActionPermitted } from './auth-guard';
import { callAgentApi } from './agent-client';
import type {
  LocalUser,
  LocalGroup,
  CreateLocalUserRequest,
  UpdateLocalUserRequest,
} from '@axonwall/lib/schemas';

export async function getLocalUsers(): Promise<LocalUser[]> {
  const session = await getSession();
  assertActionPermitted(session);

  const res = await callAgentApi<{ users: LocalUser[] }>('/v1/system/users', 'GET');
  if (!res || !res.users) {
    return [];
  }
  return res.users;
}

export async function getLocalGroups(): Promise<LocalGroup[]> {
  const session = await getSession();
  assertActionPermitted(session);

  const res = await callAgentApi<{ groups: LocalGroup[] }>('/v1/system/groups', 'GET');
  if (!res || !res.groups) {
    return [];
  }
  return res.groups;
}

export async function createLocalUser(req: CreateLocalUserRequest): Promise<{ success: boolean; message: string }> {
  const session = await getSession();
  assertActionPermitted(session, 'admin');

  const res = await callAgentApi<{ success?: boolean; message?: string }>(
    '/v1/system/users',
    'POST',
    req
  );
  if (!res || !res.success) {
    throw new Error(res?.message || 'Failed to create directory user');
  }
  return { success: true, message: res.message || 'User created successfully' };
}

export async function updateLocalUser(
  username: string,
  req: UpdateLocalUserRequest
): Promise<{ success: boolean; message: string }> {
  const session = await getSession();
  assertActionPermitted(session, 'admin');

  const res = await callAgentApi<{ success?: boolean; message?: string }>(
    `/v1/system/users/${encodeURIComponent(username)}`,
    'PUT',
    req
  );
  if (!res || !res.success) {
    throw new Error(res?.message || 'Failed to update directory user');
  }
  return { success: true, message: res.message || 'User updated successfully' };
}

export async function deleteLocalUser(
  username: string,
  removeHome = false
): Promise<{ success: boolean; message: string }> {
  const session = await getSession();
  assertActionPermitted(session, 'admin');

  const res = await callAgentApi<{ success?: boolean; message?: string }>(
    `/v1/system/users/${encodeURIComponent(username)}?removeHome=${removeHome}`,
    'DELETE'
  );
  if (!res || !res.success) {
    throw new Error(res?.message || 'Failed to delete directory user');
  }
  return { success: true, message: res.message || 'User deleted successfully' };
}

export async function createLocalGroup(name: string): Promise<{ success: boolean; message: string }> {
  const session = await getSession();
  assertActionPermitted(session, 'admin');

  const res = await callAgentApi<{ success?: boolean; message?: string }>(
    '/v1/system/groups',
    'POST',
    { name }
  );
  if (!res || !res.success) {
    throw new Error(res?.message || 'Failed to create directory group');
  }
  return { success: true, message: res.message || 'Group created successfully' };
}

export interface PasswordPolicyConfig {
  minLength: number;
  maxFailures: number;
  lockoutDurationSeconds: number;
  historyCount: number;
  maxAgeDays: number;
  disableRootSshWhenAdminExists: boolean;
}

export interface DirectoryStatus {
  slapdRunning: boolean;
  sssdRunning: boolean;
  baseDn: string;
  serverId: number;
  haSyncEnabled: boolean;
  haRole: string;
  peerUri?: string;
  contextCsn?: string;
  peerContextCsn?: string;
  inSync: boolean;
  clockSkewMs: number;
  rootSshDisabled: boolean;
  totalDirectoryUsers: number;
  adminUsersCount: number;
  unmigratedLocalCount: number;
  passwordPolicy: PasswordPolicyConfig;
}

export async function getDirectoryStatus(): Promise<DirectoryStatus | null> {
  const session = await getSession();
  assertActionPermitted(session);

  const res = await callAgentApi<DirectoryStatus>('/v1/system/directory/status', 'GET');
  return res || null;
}

export async function updateDirectoryPasswordPolicy(
  policy: PasswordPolicyConfig
): Promise<{ success: boolean; message: string; policy: PasswordPolicyConfig }> {
  const session = await getSession();
  assertActionPermitted(session, 'admin');

  const res = await callAgentApi<{ success?: boolean; message?: string; policy?: PasswordPolicyConfig }>(
    '/v1/system/directory/policy',
    'PUT',
    policy
  );
  if (!res || !res.success) {
    throw new Error(res?.message || 'Failed to update OpenLDAP password policy');
  }
  return {
    success: true,
    message: res.message || 'Password policy updated successfully',
    policy: res.policy || policy,
  };
}

export async function migrateLocalUsersToLdap(): Promise<{
  success: boolean;
  migrated: string[];
  message: string;
}> {
  const session = await getSession();
  assertActionPermitted(session, 'admin');

  const res = await callAgentApi<{ success?: boolean; migrated?: string[]; message?: string }>(
    '/v1/system/directory/migrate',
    'POST',
    {}
  );
  if (!res || !res.success) {
    throw new Error(res?.message || 'Failed to migrate local users into OpenLDAP');
  }
  return {
    success: true,
    migrated: res.migrated || [],
    message: res.message || 'Local users migrated successfully',
  };
}

