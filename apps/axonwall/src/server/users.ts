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
    throw new Error(res?.message || 'Failed to create local user');
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
    throw new Error(res?.message || 'Failed to update local user');
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
    throw new Error(res?.message || 'Failed to delete local user');
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
    throw new Error(res?.message || 'Failed to create group');
  }
  return { success: true, message: res.message || 'Group created successfully' };
}
