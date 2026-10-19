'use client';

import { useState, useEffect, useMemo } from 'react';
import {
  Users,
  Shield,
  ShieldAlert,
  Key,
  Plus,
  Trash2,
  Edit2,
  RefreshCw,
  Search,
  Lock,
  Unlock,
  Check,
  AlertCircle,
  Terminal,
  UserCheck,
  FileCode,
  Layers,
  Info,
  X,
  ExternalLink,
} from 'lucide-react';
import type { LocalUser, LocalGroup, ApplianceRole } from '@axonwall/lib/schemas';
import Link from 'next/link';

export default function LocalUsersPage() {
  const [users, setUsers] = useState<LocalUser[]>([]);
  const [groups, setGroups] = useState<LocalGroup[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [activeTab, setActiveTab] = useState<'human' | 'system' | 'groups'>('human');

  // Modal states
  const [isUserModalOpen, setIsUserModalOpen] = useState(false);
  const [isGroupModalOpen, setIsGroupModalOpen] = useState(false);
  const [editingUser, setEditingUser] = useState<LocalUser | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  // Form states
  const [formUsername, setFormUsername] = useState('');
  const [formComment, setFormComment] = useState('');
  const [formPassword, setFormPassword] = useState('');
  const [formShell, setFormShell] = useState('/bin/bash');
  const [formRole, setFormRole] = useState<ApplianceRole>('operator');
  const [formGroups, setFormGroups] = useState<string[]>([]);
  const [formSSHKeys, setFormSSHKeys] = useState('');
  const [formPasswordLocked, setFormPasswordLocked] = useState(false);

  const [newGroupName, setNewGroupName] = useState('');

  const loadData = async () => {
    setIsLoading(true);
    setError(null);
    try {
      const res = await fetch('/api/system/users');
      if (!res.ok) {
        const errJson = await res.json().catch(() => ({}));
        throw new Error(errJson.error || `HTTP ${res.status}`);
      }
      const data = await res.json();
      setUsers(data.users || []);
      setGroups(data.groups || []);
    } catch (err: any) {
      setError(err.message || 'Failed to fetch local users and groups');
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const openCreateUserModal = () => {
    setEditingUser(null);
    setFormUsername('');
    setFormComment('');
    setFormPassword('');
    setFormShell('/bin/bash');
    setFormRole('operator');
    setFormGroups([]);
    setFormSSHKeys('');
    setFormPasswordLocked(false);
    setIsUserModalOpen(true);
  };

  const openEditUserModal = (user: LocalUser) => {
    setEditingUser(user);
    setFormUsername(user.username);
    setFormComment(user.comment || '');
    setFormPassword('');
    setFormShell(user.shell || '/bin/bash');
    setFormRole(user.applianceRole || 'os_only');
    setFormGroups(user.groups || []);
    setFormSSHKeys((user.sshKeys || []).join('\n'));
    setFormPasswordLocked(user.passwordLocked);
    setIsUserModalOpen(true);
  };

  const handleSaveUser = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSubmitting(true);
    setError(null);
    setSuccessMsg(null);

    const parsedSSHKeys = formSSHKeys
      .split('\n')
      .map((k) => k.trim())
      .filter((k) => k && !k.startsWith('#'));

    try {
      if (editingUser) {
        // Update user
        const updatePayload: any = {
          comment: formComment,
          shell: formShell,
          applianceRole: formRole,
          groups: formGroups,
          sshKeys: parsedSSHKeys,
          passwordLocked: formPasswordLocked,
        };
        if (formPassword.trim()) {
          updatePayload.password = formPassword.trim();
        }

        const res = await fetch(`/api/system/users/${encodeURIComponent(editingUser.username)}`, {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(updatePayload),
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || 'Failed to update user');
        setSuccessMsg(`User ${editingUser.username} updated successfully`);
      } else {
        // Create user
        const createPayload = {
          username: formUsername.trim(),
          comment: formComment.trim(),
          password: formPassword.trim(),
          shell: formShell.trim(),
          applianceRole: formRole,
          groups: formGroups,
          sshKeys: parsedSSHKeys,
        };

        const res = await fetch('/api/system/users', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(createPayload),
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || 'Failed to create user');
        setSuccessMsg(`User ${formUsername.trim()} created successfully`);
      }

      setIsUserModalOpen(false);
      await loadData();
    } catch (err: any) {
      setError(err.message || 'Error saving user');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleDeleteUser = async (username: string) => {
    if (!confirm(`Are you sure you want to delete user '${username}'? This will also remove the user's home directory.`)) {
      return;
    }
    setError(null);
    setSuccessMsg(null);
    try {
      const res = await fetch(`/api/system/users/${encodeURIComponent(username)}?removeHome=true`, {
        method: 'DELETE',
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Failed to delete user');
      setSuccessMsg(`User ${username} deleted successfully`);
      await loadData();
    } catch (err: any) {
      setError(err.message || 'Error deleting user');
    }
  };

  const handleCreateGroup = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newGroupName.trim()) return;
    setIsSubmitting(true);
    setError(null);
    setSuccessMsg(null);
    try {
      const res = await fetch('/api/system/groups', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: newGroupName.trim() }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Failed to create group');
      setSuccessMsg(`Group ${newGroupName.trim()} created successfully`);
      setNewGroupName('');
      setIsGroupModalOpen(false);
      await loadData();
    } catch (err: any) {
      setError(err.message || 'Error creating group');
    } finally {
      setIsSubmitting(false);
    }
  };

  const toggleGroupSelection = (groupName: string) => {
    setFormGroups((prev) =>
      prev.includes(groupName) ? prev.filter((g) => g !== groupName) : [...prev, groupName]
    );
  };

  // Filtered lists
  const humanUsers = useMemo(() => {
    return users.filter((u) => !u.isSystem);
  }, [users]);

  const systemUsers = useMemo(() => {
    return users.filter((u) => u.isSystem);
  }, [users]);

  const filteredHumanUsers = useMemo(() => {
    const q = searchQuery.toLowerCase().trim();
    if (!q) return humanUsers;
    return humanUsers.filter(
      (u) =>
        u.username.toLowerCase().includes(q) ||
        (u.comment && u.comment.toLowerCase().includes(q)) ||
        u.applianceRole.toLowerCase().includes(q) ||
        u.groups.some((g) => g.toLowerCase().includes(q))
    );
  }, [humanUsers, searchQuery]);

  const filteredSystemUsers = useMemo(() => {
    const q = searchQuery.toLowerCase().trim();
    if (!q) return systemUsers;
    return systemUsers.filter(
      (u) =>
        u.username.toLowerCase().includes(q) ||
        (u.comment && u.comment.toLowerCase().includes(q)) ||
        u.shell.toLowerCase().includes(q)
    );
  }, [systemUsers, searchQuery]);

  const filteredGroups = useMemo(() => {
    const q = searchQuery.toLowerCase().trim();
    if (!q) return groups;
    return groups.filter(
      (g) =>
        g.name.toLowerCase().includes(q) ||
        g.members.some((m) => m.toLowerCase().includes(q))
    );
  }, [groups, searchQuery]);

  // Statistics
  const adminCount = humanUsers.filter((u) => u.applianceRole === 'admin').length;
  const operatorCount = humanUsers.filter((u) => u.applianceRole === 'operator').length;
  const sshKeyUsersCount = humanUsers.filter((u) => u.hasSSHKeys).length;

  return (
    <div className="space-y-6 max-w-7xl mx-auto pb-16">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <div className="p-2 rounded-lg bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
              <Users className="w-5 h-5" />
            </div>
            <h1 className="text-2xl font-bold tracking-tight text-white">Local Users & POSIX Groups</h1>
          </div>
          <p className="text-sm text-slate-400 mt-1">
            Manage appliance Linux OS user accounts, POSIX group memberships, appliance administrative roles, and authorized SSH keys.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <Link
            href="/system/sso"
            className="inline-flex items-center gap-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 text-sm font-medium px-3 py-2 rounded-lg border border-slate-700 transition"
          >
            <Shield className="w-4 h-4 text-emerald-400" />
            <span>Enterprise SSO</span>
          </Link>
          <button
            type="button"
            onClick={loadData}
            disabled={isLoading}
            className="inline-flex items-center gap-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 text-sm font-medium px-3 py-2 rounded-lg border border-slate-700 transition cursor-pointer disabled:opacity-50"
            title="Refresh Users & Groups"
          >
            <RefreshCw className={`w-4 h-4 ${isLoading ? 'animate-spin' : ''}`} />
            <span>Refresh</span>
          </button>
          <button
            type="button"
            onClick={() => setIsGroupModalOpen(true)}
            className="inline-flex items-center gap-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 text-sm font-medium px-3 py-2 rounded-lg border border-slate-700 transition cursor-pointer"
          >
            <Plus className="w-4 h-4" />
            <span>Add Group</span>
          </button>
          <button
            type="button"
            onClick={openCreateUserModal}
            className="inline-flex items-center gap-1.5 bg-cyan-600 hover:bg-cyan-500 text-white text-sm font-medium px-4 py-2 rounded-lg shadow-sm transition cursor-pointer"
          >
            <Plus className="w-4 h-4" />
            <span>Add User</span>
          </button>
        </div>
      </div>

      {/* Alerts */}
      {error && (
        <div className="flex items-center gap-3 p-4 bg-red-950/40 border border-red-800/60 rounded-xl text-red-200 text-sm">
          <AlertCircle className="w-5 h-5 text-red-400 shrink-0" />
          <p className="flex-1">{error}</p>
          <button onClick={() => setError(null)} className="text-red-400 hover:text-red-200">
            <X className="w-4 h-4" />
          </button>
        </div>
      )}
      {successMsg && (
        <div className="flex items-center gap-3 p-4 bg-emerald-950/40 border border-emerald-800/60 rounded-xl text-emerald-200 text-sm">
          <Check className="w-5 h-5 text-emerald-400 shrink-0" />
          <p className="flex-1">{successMsg}</p>
          <button onClick={() => setSuccessMsg(null)} className="text-emerald-400 hover:text-emerald-200">
            <X className="w-4 h-4" />
          </button>
        </div>
      )}

      {/* Metrics Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-slate-900/60 border border-slate-800 p-4 rounded-xl flex items-center gap-3.5">
          <div className="p-2.5 rounded-lg bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
            <UserCheck className="w-5 h-5" />
          </div>
          <div>
            <div className="text-2xl font-bold text-white">{humanUsers.length}</div>
            <div className="text-xs text-slate-400 font-medium">Human User Accounts</div>
          </div>
        </div>
        <div className="bg-slate-900/60 border border-slate-800 p-4 rounded-xl flex items-center gap-3.5">
          <div className="p-2.5 rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
            <Shield className="w-5 h-5" />
          </div>
          <div>
            <div className="text-2xl font-bold text-white">{adminCount}</div>
            <div className="text-xs text-slate-400 font-medium">Administrators (sudo)</div>
          </div>
        </div>
        <div className="bg-slate-900/60 border border-slate-800 p-4 rounded-xl flex items-center gap-3.5">
          <div className="p-2.5 rounded-lg bg-indigo-500/10 text-indigo-400 border border-indigo-500/20">
            <Key className="w-5 h-5" />
          </div>
          <div>
            <div className="text-2xl font-bold text-white">{sshKeyUsersCount}</div>
            <div className="text-xs text-slate-400 font-medium">SSH Public Keys Enrolled</div>
          </div>
        </div>
        <div className="bg-slate-900/60 border border-slate-800 p-4 rounded-xl flex items-center gap-3.5">
          <div className="p-2.5 rounded-lg bg-slate-500/10 text-slate-400 border border-slate-500/20">
            <Terminal className="w-5 h-5" />
          </div>
          <div>
            <div className="text-2xl font-bold text-white">{systemUsers.length}</div>
            <div className="text-xs text-slate-400 font-medium">System / Daemon Accounts</div>
          </div>
        </div>
      </div>

      {/* Navigation Tabs & Search */}
      <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-4 border-b border-slate-800 pb-3">
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => setActiveTab('human')}
            className={`px-4 py-2 rounded-lg text-sm font-medium transition cursor-pointer flex items-center gap-2 ${
              activeTab === 'human'
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
            }`}
          >
            <Users className="w-4 h-4" />
            <span>Local Human Users</span>
            <span className="px-1.5 py-0.5 rounded-full text-xs bg-slate-800 text-slate-300">
              {humanUsers.length}
            </span>
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('system')}
            className={`px-4 py-2 rounded-lg text-sm font-medium transition cursor-pointer flex items-center gap-2 ${
              activeTab === 'system'
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
            }`}
          >
            <Terminal className="w-4 h-4" />
            <span>System & Daemons</span>
            <span className="px-1.5 py-0.5 rounded-full text-xs bg-slate-800 text-slate-300">
              {systemUsers.length}
            </span>
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('groups')}
            className={`px-4 py-2 rounded-lg text-sm font-medium transition cursor-pointer flex items-center gap-2 ${
              activeTab === 'groups'
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
            }`}
          >
            <Layers className="w-4 h-4" />
            <span>POSIX Groups</span>
            <span className="px-1.5 py-0.5 rounded-full text-xs bg-slate-800 text-slate-300">
              {groups.length}
            </span>
          </button>
        </div>

        <div className="relative w-full sm:w-72">
          <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
          <input
            type="text"
            placeholder="Search users or groups..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-9 pr-4 py-1.5 bg-slate-900/80 border border-slate-800 rounded-lg text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:ring-1 focus:ring-cyan-500 focus:border-cyan-500"
          />
        </div>
      </div>

      {/* Tab 1: Human Users */}
      {activeTab === 'human' && (
        <div className="bg-slate-900/50 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm text-slate-300">
              <thead className="bg-slate-950/60 text-xs uppercase text-slate-400 tracking-wider border-b border-slate-800">
                <tr>
                  <th className="py-3.5 px-4 font-semibold">User</th>
                  <th className="py-3.5 px-4 font-semibold">Role</th>
                  <th className="py-3.5 px-4 font-semibold">POSIX Groups</th>
                  <th className="py-3.5 px-4 font-semibold">Home & Shell</th>
                  <th className="py-3.5 px-4 font-semibold">Credentials</th>
                  <th className="py-3.5 px-4 font-semibold text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {filteredHumanUsers.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="py-8 text-center text-slate-500">
                      No human user accounts found.
                    </td>
                  </tr>
                ) : (
                  filteredHumanUsers.map((u) => {
                    const isRoot = u.username === 'root';
                    return (
                      <tr key={u.username} className="hover:bg-slate-800/30 transition">
                        <td className="py-3 px-4">
                          <div className="flex items-center gap-2.5">
                            <div className="w-8 h-8 rounded-full bg-slate-800 border border-slate-700 flex items-center justify-center font-bold text-xs text-cyan-400 uppercase">
                              {u.username.substring(0, 2)}
                            </div>
                            <div>
                              <div className="font-medium text-white flex items-center gap-2">
                                <span>{u.username}</span>
                                {isRoot && (
                                  <span className="text-[10px] uppercase font-bold tracking-wider px-1.5 py-0.5 rounded bg-amber-500/20 text-amber-300 border border-amber-500/30">
                                    Root
                                  </span>
                                )}
                              </div>
                              <div className="text-xs text-slate-400">
                                {u.comment || `UID: ${u.uid}, GID: ${u.gid}`}
                              </div>
                            </div>
                          </div>
                        </td>
                        <td className="py-3 px-4">
                          {u.applianceRole === 'admin' ? (
                            <span className="inline-flex items-center gap-1 text-xs font-semibold px-2.5 py-0.5 rounded-full bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
                              <Shield className="w-3 h-3" />
                              Administrator
                            </span>
                          ) : u.applianceRole === 'operator' ? (
                            <span className="inline-flex items-center gap-1 text-xs font-semibold px-2.5 py-0.5 rounded-full bg-blue-500/20 text-blue-400 border border-blue-500/30">
                              <Shield className="w-3 h-3" />
                              Operator
                            </span>
                          ) : u.applianceRole === 'readonly' ? (
                            <span className="inline-flex items-center gap-1 text-xs font-semibold px-2.5 py-0.5 rounded-full bg-amber-500/20 text-amber-400 border border-amber-500/30">
                              <Shield className="w-3 h-3" />
                              Read-Only
                            </span>
                          ) : (
                            <span className="inline-flex items-center gap-1 text-xs font-medium px-2.5 py-0.5 rounded-full bg-slate-800 text-slate-400 border border-slate-700">
                              OS Only
                            </span>
                          )}
                        </td>
                        <td className="py-3 px-4">
                          <div className="flex flex-wrap gap-1 max-w-xs">
                            {u.groups.slice(0, 4).map((g) => (
                              <span
                                key={g}
                                className="text-[11px] px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700/60 font-mono"
                              >
                                {g}
                              </span>
                            ))}
                            {u.groups.length > 4 && (
                              <span className="text-[11px] px-1.5 py-0.5 rounded bg-slate-800/60 text-slate-400 font-mono">
                                +{u.groups.length - 4}
                              </span>
                            )}
                          </div>
                        </td>
                        <td className="py-3 px-4 text-xs font-mono text-slate-400">
                          <div>{u.homeDir}</div>
                          <div className="text-slate-500">{u.shell}</div>
                        </td>
                        <td className="py-3 px-4">
                          <div className="flex items-center gap-3">
                            <span
                              className={`flex items-center gap-1 text-xs ${
                                u.hasSSHKeys ? 'text-indigo-400' : 'text-slate-500'
                              }`}
                              title={u.hasSSHKeys ? `${u.sshKeysCount} SSH Key(s)` : 'No SSH Keys'}
                            >
                              <Key className="w-3.5 h-3.5" />
                              <span>{u.hasSSHKeys ? `${u.sshKeysCount}` : 'None'}</span>
                            </span>
                            <span
                              className={`flex items-center gap-1 text-xs ${
                                u.hasPassword && !u.passwordLocked
                                  ? 'text-emerald-400'
                                  : 'text-amber-500/80'
                              }`}
                              title={
                                u.passwordLocked
                                  ? 'Password Locked / Disabled'
                                  : u.hasPassword
                                  ? 'Password Active'
                                  : 'No Password'
                              }
                            >
                              {u.passwordLocked ? (
                                <Lock className="w-3.5 h-3.5" />
                              ) : (
                                <Unlock className="w-3.5 h-3.5" />
                              )}
                              <span>
                                {u.passwordLocked ? 'Locked' : u.hasPassword ? 'Active' : 'Unset'}
                              </span>
                            </span>
                          </div>
                        </td>
                        <td className="py-3 px-4 text-right">
                          <div className="inline-flex items-center gap-2">
                            <button
                              type="button"
                              onClick={() => openEditUserModal(u)}
                              className="p-1.5 hover:bg-slate-800 rounded-lg text-slate-300 hover:text-white transition cursor-pointer"
                              title="Edit User"
                            >
                              <Edit2 className="w-4 h-4" />
                            </button>
                            <button
                              type="button"
                              onClick={() => handleDeleteUser(u.username)}
                              disabled={u.protected || isRoot}
                              className={`p-1.5 rounded-lg transition ${
                                u.protected || isRoot
                                  ? 'text-slate-600 cursor-not-allowed'
                                  : 'hover:bg-red-500/10 text-red-400 hover:text-red-300 cursor-pointer'
                              }`}
                              title={
                                u.protected || isRoot
                                  ? 'Protected account cannot be deleted'
                                  : 'Delete User'
                              }
                            >
                              <Trash2 className="w-4 h-4" />
                            </button>
                          </div>
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Tab 2: System / Daemon Accounts */}
      {activeTab === 'system' && (
        <div className="space-y-4">
          <div className="p-4 bg-slate-900/60 border border-slate-800 rounded-xl flex items-start gap-3">
            <Info className="w-5 h-5 text-cyan-400 shrink-0 mt-0.5" />
            <div className="text-sm text-slate-300">
              <span className="font-semibold text-white">System & Service Daemon Protection: </span>
              These accounts are reserved for underlying Linux network services (such as{' '}
              <code className="text-cyan-300 font-mono text-xs">axonwall</code>,{' '}
              <code className="text-cyan-300 font-mono text-xs">sshd</code>,{' '}
              <code className="text-cyan-300 font-mono text-xs">unbound</code>,{' '}
              <code className="text-cyan-300 font-mono text-xs">suricata</code>,{' '}
              <code className="text-cyan-300 font-mono text-xs">kea</code>, and{' '}
              <code className="text-cyan-300 font-mono text-xs">frr</code>). They are read-only in the
              web console to prevent system integrity corruption or lockouts.
            </div>
          </div>

          <div className="bg-slate-900/50 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-sm text-slate-300">
                <thead className="bg-slate-950/60 text-xs uppercase text-slate-400 tracking-wider border-b border-slate-800">
                  <tr>
                    <th className="py-3.5 px-4 font-semibold">Daemon / Service</th>
                    <th className="py-3.5 px-4 font-semibold">UID / GID</th>
                    <th className="py-3.5 px-4 font-semibold">Description</th>
                    <th className="py-3.5 px-4 font-semibold">Home Directory</th>
                    <th className="py-3.5 px-4 font-semibold">Login Shell</th>
                    <th className="py-3.5 px-4 font-semibold">Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {filteredSystemUsers.map((u) => (
                    <tr key={u.username} className="hover:bg-slate-800/30 transition">
                      <td className="py-3 px-4 font-mono font-medium text-white">{u.username}</td>
                      <td className="py-3 px-4 text-xs font-mono text-slate-400">
                        {u.uid} : {u.gid}
                      </td>
                      <td className="py-3 px-4 text-xs text-slate-400">{u.comment || '—'}</td>
                      <td className="py-3 px-4 text-xs font-mono text-slate-400">{u.homeDir}</td>
                      <td className="py-3 px-4 text-xs font-mono text-slate-500">{u.shell}</td>
                      <td className="py-3 px-4">
                        <span className="inline-flex items-center gap-1 text-[11px] font-semibold px-2 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700">
                          <Lock className="w-3 h-3 text-slate-500" />
                          System Protected
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* Tab 3: POSIX Groups */}
      {activeTab === 'groups' && (
        <div className="bg-slate-900/50 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm text-slate-300">
              <thead className="bg-slate-950/60 text-xs uppercase text-slate-400 tracking-wider border-b border-slate-800">
                <tr>
                  <th className="py-3.5 px-4 font-semibold">Group Name</th>
                  <th className="py-3.5 px-4 font-semibold">GID</th>
                  <th className="py-3.5 px-4 font-semibold">Type</th>
                  <th className="py-3.5 px-4 font-semibold">Members</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {filteredGroups.map((g) => (
                  <tr key={g.name} className="hover:bg-slate-800/30 transition">
                    <td className="py-3 px-4 font-mono font-medium text-white flex items-center gap-2">
                      <span>{g.name}</span>
                      {g.name === 'axonwall-admin' && (
                        <span className="text-[10px] px-1.5 py-0.5 rounded bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
                          Admin Role
                        </span>
                      )}
                      {g.name === 'axonwall-operator' && (
                        <span className="text-[10px] px-1.5 py-0.5 rounded bg-blue-500/20 text-blue-400 border border-blue-500/30">
                          Operator Role
                        </span>
                      )}
                      {g.name === 'axonwall-readonly' && (
                        <span className="text-[10px] px-1.5 py-0.5 rounded bg-amber-500/20 text-amber-400 border border-amber-500/30">
                          Read-Only Role
                        </span>
                      )}
                    </td>
                    <td className="py-3 px-4 text-xs font-mono text-slate-400">{g.gid}</td>
                    <td className="py-3 px-4 text-xs">
                      {g.isSystem ? (
                        <span className="text-slate-500 font-medium">System Builtin</span>
                      ) : (
                        <span className="text-cyan-400 font-medium">Custom POSIX</span>
                      )}
                    </td>
                    <td className="py-3 px-4">
                      <div className="flex flex-wrap gap-1">
                        {g.members.length === 0 ? (
                          <span className="text-xs text-slate-500 italic">No members</span>
                        ) : (
                          g.members.map((m) => (
                            <span
                              key={m}
                              className="text-[11px] px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-mono border border-slate-700/60"
                            >
                              {m}
                            </span>
                          ))
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Modal: Create / Edit User */}
      {isUserModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-xs">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl w-full max-w-2xl max-h-[90vh] overflow-y-auto shadow-2xl p-6 space-y-6">
            <div className="flex items-center justify-between border-b border-slate-800 pb-4">
              <div className="flex items-center gap-2.5">
                <div className="p-2 rounded-lg bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                  <Users className="w-5 h-5" />
                </div>
                <div>
                  <h3 className="text-lg font-bold text-white">
                    {editingUser ? `Edit User: ${editingUser.username}` : 'Add Local Linux User'}
                  </h3>
                  <p className="text-xs text-slate-400">
                    Provision Linux OS credentials and assign Axonwall administrative privileges.
                  </p>
                </div>
              </div>
              <button
                type="button"
                onClick={() => setIsUserModalOpen(false)}
                className="text-slate-400 hover:text-white transition"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <form onSubmit={handleSaveUser} className="space-y-4">
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs font-semibold uppercase text-slate-300 mb-1.5">
                    Username *
                  </label>
                  <input
                    type="text"
                    required
                    disabled={!!editingUser}
                    value={formUsername}
                    onChange={(e) => setFormUsername(e.target.value.toLowerCase())}
                    placeholder="e.g. netadmin, secops"
                    pattern="[a-z_][a-z0-9_-]{0,31}"
                    className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-sm text-white focus:outline-none focus:ring-1 focus:ring-cyan-500 disabled:opacity-60 disabled:cursor-not-allowed font-mono"
                  />
                  <p className="text-[11px] text-slate-500 mt-1">
                    Lowercase alphanumeric, 1-32 characters.
                  </p>
                </div>

                <div>
                  <label className="block text-xs font-semibold uppercase text-slate-300 mb-1.5">
                    Full Name / Comment
                  </label>
                  <input
                    type="text"
                    value={formComment}
                    onChange={(e) => setFormComment(e.target.value)}
                    placeholder="e.g. Alice Smith - Security Ops"
                    className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-sm text-white focus:outline-none focus:ring-1 focus:ring-cyan-500"
                  />
                </div>
              </div>

              {/* Appliance Role */}
              <div>
                <label className="block text-xs font-semibold uppercase text-slate-300 mb-1.5">
                  Appliance Administrative Role *
                </label>
                <div className="grid grid-cols-1 sm:grid-cols-4 gap-2.5">
                  <label
                    className={`flex flex-col p-3 rounded-xl border cursor-pointer transition ${
                      formRole === 'admin'
                        ? 'bg-emerald-500/10 border-emerald-500 text-white'
                        : 'bg-slate-950 border-slate-800 text-slate-400 hover:border-slate-700'
                    }`}
                  >
                    <input
                      type="radio"
                      name="applianceRole"
                      value="admin"
                      checked={formRole === 'admin'}
                      onChange={() => setFormRole('admin')}
                      className="sr-only"
                    />
                    <div className="flex items-center gap-1.5 font-bold text-xs text-emerald-400">
                      <Shield className="w-3.5 h-3.5" />
                      <span>Administrator</span>
                    </div>
                    <p className="text-[11px] text-slate-400 mt-1 leading-snug">
                      Full access + sudo/wheel POSIX rights.
                    </p>
                  </label>

                  <label
                    className={`flex flex-col p-3 rounded-xl border cursor-pointer transition ${
                      formRole === 'operator'
                        ? 'bg-blue-500/10 border-blue-500 text-white'
                        : 'bg-slate-950 border-slate-800 text-slate-400 hover:border-slate-700'
                    }`}
                  >
                    <input
                      type="radio"
                      name="applianceRole"
                      value="operator"
                      checked={formRole === 'operator'}
                      onChange={() => setFormRole('operator')}
                      className="sr-only"
                    />
                    <div className="flex items-center gap-1.5 font-bold text-xs text-blue-400">
                      <Shield className="w-3.5 h-3.5" />
                      <span>Operator</span>
                    </div>
                    <p className="text-[11px] text-slate-400 mt-1 leading-snug">
                      Network, firewall, VPN management.
                    </p>
                  </label>

                  <label
                    className={`flex flex-col p-3 rounded-xl border cursor-pointer transition ${
                      formRole === 'readonly'
                        ? 'bg-amber-500/10 border-amber-500 text-white'
                        : 'bg-slate-950 border-slate-800 text-slate-400 hover:border-slate-700'
                    }`}
                  >
                    <input
                      type="radio"
                      name="applianceRole"
                      value="readonly"
                      checked={formRole === 'readonly'}
                      onChange={() => setFormRole('readonly')}
                      className="sr-only"
                    />
                    <div className="flex items-center gap-1.5 font-bold text-xs text-amber-400">
                      <Shield className="w-3.5 h-3.5" />
                      <span>Read-Only</span>
                    </div>
                    <p className="text-[11px] text-slate-400 mt-1 leading-snug">
                      View status, logs & telemetry only.
                    </p>
                  </label>

                  <label
                    className={`flex flex-col p-3 rounded-xl border cursor-pointer transition ${
                      formRole === 'os_only'
                        ? 'bg-slate-800 border-slate-600 text-white'
                        : 'bg-slate-950 border-slate-800 text-slate-400 hover:border-slate-700'
                    }`}
                  >
                    <input
                      type="radio"
                      name="applianceRole"
                      value="os_only"
                      checked={formRole === 'os_only'}
                      onChange={() => setFormRole('os_only')}
                      className="sr-only"
                    />
                    <div className="flex items-center gap-1.5 font-bold text-xs text-slate-300">
                      <Terminal className="w-3.5 h-3.5" />
                      <span>OS Shell Only</span>
                    </div>
                    <p className="text-[11px] text-slate-400 mt-1 leading-snug">
                      No web console login permission.
                    </p>
                  </label>
                </div>
              </div>

              {/* Password & Shell */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs font-semibold uppercase text-slate-300 mb-1.5">
                    {editingUser ? 'New Password (leave blank to keep)' : 'Initial Password'}
                  </label>
                  <input
                    type="password"
                    value={formPassword}
                    onChange={(e) => setFormPassword(e.target.value)}
                    placeholder="••••••••••••"
                    className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-sm text-white focus:outline-none focus:ring-1 focus:ring-cyan-500 font-mono"
                  />
                  {editingUser && (
                    <div className="mt-2 flex items-center gap-2">
                      <input
                        type="checkbox"
                        id="pwdLock"
                        checked={formPasswordLocked}
                        onChange={(e) => setFormPasswordLocked(e.target.checked)}
                        className="rounded border-slate-800 bg-slate-950 text-cyan-500 focus:ring-cyan-500"
                      />
                      <label htmlFor="pwdLock" className="text-xs text-slate-400 cursor-pointer">
                        Lock password (require SSH key authentication only)
                      </label>
                    </div>
                  )}
                </div>

                <div>
                  <label className="block text-xs font-semibold uppercase text-slate-300 mb-1.5">
                    Login Shell
                  </label>
                  <select
                    value={formShell}
                    onChange={(e) => setFormShell(e.target.value)}
                    className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-sm text-white focus:outline-none focus:ring-1 focus:ring-cyan-500 font-mono"
                  >
                    <option value="/bin/bash">/bin/bash (Default interactive)</option>
                    <option value="/bin/sh">/bin/sh (POSIX standard)</option>
                    <option value="/usr/sbin/nologin">/usr/sbin/nologin (Disabled shell)</option>
                    <option value="/bin/false">/bin/false (Disabled shell)</option>
                  </select>
                </div>
              </div>

              {/* Supplementary Groups */}
              <div>
                <label className="block text-xs font-semibold uppercase text-slate-300 mb-1.5">
                  Supplementary POSIX Groups
                </label>
                <div className="flex flex-wrap gap-1.5 max-h-32 overflow-y-auto p-2 bg-slate-950 border border-slate-800 rounded-lg">
                  {groups
                    .filter((g) => !['axonwall-admin', 'axonwall-operator', 'axonwall-readonly'].includes(g.name))
                    .map((g) => {
                      const isSelected = formGroups.includes(g.name);
                      return (
                        <button
                          key={g.name}
                          type="button"
                          onClick={() => toggleGroupSelection(g.name)}
                          className={`px-2 py-1 rounded text-xs font-mono transition cursor-pointer flex items-center gap-1 ${
                            isSelected
                              ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                              : 'bg-slate-900 text-slate-400 border border-slate-800 hover:text-slate-200'
                          }`}
                        >
                          {isSelected && <Check className="w-3 h-3" />}
                          <span>{g.name}</span>
                        </button>
                      );
                    })}
                </div>
                <p className="text-[11px] text-slate-500 mt-1">
                  Click to attach custom supplementary groups (role groups like axonwall-admin and sudo are attached automatically based on role).
                </p>
              </div>

              {/* Authorized SSH Public Keys */}
              <div>
                <label className="block text-xs font-semibold uppercase text-slate-300 mb-1.5">
                  Authorized SSH Public Keys (~/.ssh/authorized_keys)
                </label>
                <textarea
                  rows={3}
                  value={formSSHKeys}
                  onChange={(e) => setFormSSHKeys(e.target.value)}
                  placeholder="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... admin@workstation"
                  className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-xs font-mono text-slate-200 focus:outline-none focus:ring-1 focus:ring-cyan-500"
                />
                <p className="text-[11px] text-slate-500 mt-1">
                  One OpenSSH public key per line. Axonwall enforces strict SSH key security permissions.
                </p>
              </div>

              {/* Buttons */}
              <div className="flex items-center justify-end gap-3 pt-4 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setIsUserModalOpen(false)}
                  className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 text-sm font-medium rounded-lg transition cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={isSubmitting}
                  className="px-5 py-2 bg-cyan-600 hover:bg-cyan-500 text-white text-sm font-semibold rounded-lg shadow-sm transition cursor-pointer disabled:opacity-50"
                >
                  {isSubmitting ? 'Saving...' : editingUser ? 'Update User' : 'Create User'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Modal: Create POSIX Group */}
      {isGroupModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-xs">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl w-full max-w-md shadow-2xl p-6 space-y-5">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2">
                <div className="p-2 rounded-lg bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                  <Layers className="w-5 h-5" />
                </div>
                <h3 className="text-lg font-bold text-white">Create POSIX Group</h3>
              </div>
              <button
                type="button"
                onClick={() => setIsGroupModalOpen(false)}
                className="text-slate-400 hover:text-white transition"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <form onSubmit={handleCreateGroup} className="space-y-4">
              <div>
                <label className="block text-xs font-semibold uppercase text-slate-300 mb-1.5">
                  Group Name *
                </label>
                <input
                  type="text"
                  required
                  value={newGroupName}
                  onChange={(e) => setNewGroupName(e.target.value.toLowerCase())}
                  placeholder="e.g. netops, secengineers, auditteam"
                  pattern="[a-z_][a-z0-9_-]{0,31}"
                  className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-sm text-white focus:outline-none focus:ring-1 focus:ring-cyan-500 font-mono"
                />
                <p className="text-[11px] text-slate-500 mt-1">
                  Lowercase alphanumeric string, 1-32 characters.
                </p>
              </div>

              <div className="flex items-center justify-end gap-3 pt-3 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setIsGroupModalOpen(false)}
                  className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 text-sm font-medium rounded-lg transition cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={isSubmitting}
                  className="px-5 py-2 bg-cyan-600 hover:bg-cyan-500 text-white text-sm font-semibold rounded-lg shadow-sm transition cursor-pointer disabled:opacity-50"
                >
                  {isSubmitting ? 'Creating...' : 'Create Group'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
