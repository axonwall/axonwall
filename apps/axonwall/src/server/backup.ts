import crypto from 'crypto';
import type { DesiredState } from '@axonwall/lib/schemas';
import { getSession } from './auth';

const BACKUP_MAGIC = Buffer.from('AXB1'); // Axonwall Encrypted Backup Version 1 (PBKDF2 100k)
const BACKUP_MAGIC_V2 = Buffer.from('AXB2'); // Version 2 (PBKDF2 600k, current OWASP guidance)
const PBKDF2_ITERATIONS_V1 = 100000;
const PBKDF2_ITERATIONS = 600000;

export interface BackupMetadata {
  id: string;
  timestamp: string;
  version: number;
  hostname: string;
  rulesCount: number;
  interfacesCount: number;
  encrypted: boolean;
}

/**
 * Creates an enterprise-grade AES-256-GCM encrypted backup archive of the firewall configuration.
 */
export async function createEncryptedBackup(
  state: DesiredState,
  passphrase: string
): Promise<{ id: string; buffer: Buffer; metadata: BackupMetadata }> {
  const session = await getSession();
  if (!session || !session.roles.includes('admin')) {
    throw new Error('Unauthorized: Admin privileges required for configuration backups');
  }

  if (!passphrase || passphrase.length < 8) {
    throw new Error('Passphrase must be at least 8 characters long for AES-256-GCM encryption');
  }

  const backupId = `axonwall-backup-${new Date().toISOString().replace(/[:.]/g, '-')}`;
  const metadata: BackupMetadata = {
    id: backupId,
    timestamp: new Date().toISOString(),
    version: state.version,
    hostname: state.system.hostname,
    rulesCount: state.rules.length,
    interfacesCount: state.interfaces.length,
    encrypted: true,
  };

  const payload = JSON.stringify({ metadata, state }, null, 2);

  // Derive 256-bit key from passphrase using PBKDF2 with 600,000
  // iterations (audit B-16; version 1 backups used 100,000, see the
  // magic-based dispatch in restoreEncryptedBackup).
  const salt = crypto.randomBytes(16);
  const key = crypto.pbkdf2Sync(passphrase, salt, PBKDF2_ITERATIONS, 32, 'sha256');
  const iv = crypto.randomBytes(12);

  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(payload, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();

  // File Layout: [MAGIC: 4B][SALT: 16B][IV: 12B][TAG: 16B][CIPHERTEXT: N B]
  const buffer = Buffer.concat([BACKUP_MAGIC_V2, salt, iv, tag, encrypted]);

  return { id: backupId, buffer, metadata };
}

/**
 * Decrypts and verifies an AES-256-GCM encrypted backup archive.
 */
export async function restoreEncryptedBackup(
  buffer: Buffer,
  passphrase: string
): Promise<{ metadata: BackupMetadata; state: DesiredState }> {
  const session = await getSession();
  if (!session || !session.roles.includes('admin')) {
    throw new Error('Unauthorized: Admin privileges required to restore configuration');
  }

  if (buffer.length < 48) {
    throw new Error('Invalid backup file: file truncated or too small');
  }

  const magic = buffer.subarray(0, 4);
  let iterations: number;
  if (magic.equals(BACKUP_MAGIC_V2)) {
    iterations = PBKDF2_ITERATIONS;
  } else if (magic.equals(BACKUP_MAGIC)) {
    iterations = PBKDF2_ITERATIONS_V1;
  } else {
    throw new Error('Invalid backup header: unrecognized magic bytes. Expected AXB1 or AXB2.');
  }

  const salt = buffer.subarray(4, 20);
  const iv = buffer.subarray(20, 32);
  const tag = buffer.subarray(32, 48);
  const ciphertext = buffer.subarray(48);

  const key = crypto.pbkdf2Sync(passphrase, salt, iterations, 32, 'sha256');

  try {
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(tag);
    const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    const parsed = JSON.parse(decrypted.toString('utf8'));
    return {
      metadata: parsed.metadata,
      state: parsed.state,
    };
  } catch (err: any) {
    throw new Error('Decryption failed: incorrect passphrase or corrupted backup archive');
  }
}

/**
 * Formats a clean human-readable GitOps YAML snapshot for automated version control.
 */
export function generateGitOpsSnapshot(state: DesiredState): { filename: string; content: string } {
  const timestamp = new Date().toISOString();
  const content = `# Axonwall GitOps Firewall State Snapshot
# Generated: ${timestamp}
# Hostname: ${state.system.hostname}.${state.system.domain}
# Version: ${state.version}

${JSON.stringify(state, null, 2)}
`;
  return {
    filename: `axonwall-state-${state.system.hostname}.json`,
    content,
  };
}
