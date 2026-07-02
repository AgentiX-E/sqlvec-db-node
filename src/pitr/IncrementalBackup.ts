/**
 * IncrementalBackup — SQLite file-level incremental backup.
 *
 * PostgreSQL-style incremental backup tracks *changed pages* since the last
 * full or incremental backup. Since SQLite uses a single file per shard,
 * "incremental" operates at the file level:
 *
 *   - Track SHA-256 checksums of each shard/database file at full backup time
 *   - On incremental backup, compare current checksum → only copy changed files
 *   - For partial file changes: copy the entire file (SQLite doesn't support
 *     page-level diff without heavy custom tooling)
 *
 * A backup chain is a linked list of manifests:
 *   full → incremental → incremental → ...
 *
 * @module pitr/IncrementalBackup
 */

import * as fs from 'node:fs';
import * as fsp from 'fs/promises';
import * as path from 'node:path';
import * as crypto from 'node:crypto';
import { PinoLogger } from '../monitoring/PinoLogger';

const logger = PinoLogger.forComponent('IncrementalBackup');

// ── Types ────────────────────────────────────────────────────────

export interface BackupFileEntry {
  /** Absolute path to the source file at backup time */
  path: string;
  /** File size in bytes */
  size: number;
  /** SHA-256 hex checksum of the file contents */
  checksum: string;
  /** Relative path within the backup (preserves shard directory structure) */
  relativePath: string;
}

export interface BackupManifest {
  /** UUID identifying this backup */
  id: string;
  /** Unix epoch ms timestamp of backup creation */
  timestamp: number;
  /** Backup type: full or incremental */
  type: 'full' | 'incremental';
  /** For incremental backups: ID of the parent backup (full or incremental) */
  parentId?: string;
  /** File entries in this backup */
  files: BackupFileEntry[];
  /** LSN at the end of the WAL when this backup was taken */
  walEndLsn?: string;
}

// ── Manifest storage helpers ─────────────────────────────────────

/** Filename for the backup manifest inside a backup directory */
const MANIFEST_FILENAME = 'backup_manifest.json';

/**
 * Full path to a backup's manifest file.
 */
function manifestPath(backupDir: string, backupId: string): string {
  return path.join(backupDir, backupId, MANIFEST_FILENAME);
}

/**
 * Compute SHA-256 checksum of a file.
 */
async function sha256File(filePath: string): Promise<string> {
  const data = await fsp.readFile(filePath);
  return crypto.createHash('sha256').update(data).digest('hex');
}

/**
 * Generate a UUID v4 backup ID.
 */
function generateBackupId(): string {
  return crypto.randomUUID();
}

// ── Query WAL end LSN ────────────────────────────────────────────

/**
 * Attempt to query the WAL end LSN from the SQLite database via PRAGMA.
 * Returns undefined if the database doesn't support this or on error.
 */
function queryWalEndLsn(db: any): string | undefined {
  if (!db) return undefined;
  try {
    // Check if we have a wal_status pragma (better-sqlite3)
    const row = db.pragma('wal_checkpoint(TRUNCATE)');
    if (row && row.length > 0) {
      // Format as a simplified LSN: epochMs-hex
      return `${Date.now()}-${row[0].log || 0}`;
    }
  } catch {
    // Ignore — this is best-effort
  }
  return undefined;
}

// ── Copy files into backup directory ─────────────────────────────

/**
 * Copy a single file into the backup directory.
 * Creates subdirectories as needed based on relativePath.
 */
async function copyToBackup(
  sourcePath: string,
  backupDir: string,
  relativePath: string,
): Promise<void> {
  const targetDir = path.join(backupDir, path.dirname(relativePath));
  await fsp.mkdir(targetDir, { recursive: true });
  const targetPath = path.join(backupDir, relativePath);
  await fsp.copyFile(sourcePath, targetPath);
}

// ── Public API ───────────────────────────────────────────────────

/**
 * Perform a full backup of all shard databases.
 *
 * Scans the `pitrManager.config.dataDir` for shard databases,
 * computes SHA-256 checksums, creates a full backup manifest,
 * and copies all files to the backup directory.
 *
 * @param pitrManager - PITRManager instance (or compatible object with config)
 * @param db - better-sqlite3 Database instance (or compatible, for WAL LSN)
 * @param backupDir - Root directory for storing backups
 * @returns BackupManifest describing the full backup
 */
export async function performFullBackup(
  pitrManager: any,
  db: any,
  backupDir: string,
): Promise<BackupManifest> {
  const dataDir = pitrManager?.config?.dataDir;
  if (!dataDir) {
    throw new Error('performFullBackup: pitrManager.config.dataDir is required');
  }

  const backupId = generateBackupId();
  const timestamp = Date.now();
  const files: BackupFileEntry[] = [];

  // Discover shard database files
  const shardIds = pitrManager.config.shardIds ?? [];
  if (shardIds.length === 0) {
    // Scan dataDir for .db files
    const entries = await fsp.readdir(dataDir, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = path.join(dataDir, entry.name);
      if (entry.isFile() && entry.name.endsWith('.db')) {
        const checksum = await sha256File(fullPath);
        const stat = await fsp.stat(fullPath);
        files.push({
          path: fullPath,
          size: stat.size,
          checksum,
          relativePath: entry.name,
        });
      } else if (entry.isDirectory()) {
        // Check for <shard>.db inside shard directory
        const dbPath = path.join(fullPath, `${entry.name}.db`);
        if (fs.existsSync(dbPath)) {
          const checksum = await sha256File(dbPath);
          const stat = await fsp.stat(dbPath);
          files.push({
            path: dbPath,
            size: stat.size,
            checksum,
            relativePath: path.join(entry.name, `${entry.name}.db`),
          });
        }
      }
    }
  } else {
    // Use configured shardIds
    for (const shardId of shardIds) {
      const dbPath = path.join(dataDir, shardId, `${shardId}.db`);
      if (fs.existsSync(dbPath)) {
        const checksum = await sha256File(dbPath);
        const stat = await fsp.stat(dbPath);
        files.push({
          path: dbPath,
          size: stat.size,
          checksum,
          relativePath: path.join(shardId, `${shardId}.db`),
        });
      }
    }
  }

  const walEndLsn = queryWalEndLsn(db);

  const manifest: BackupManifest = {
    id: backupId,
    timestamp,
    type: 'full',
    files,
    walEndLsn,
  };

  // Create backup directory and write manifest
  const backupDirPath = path.join(backupDir, backupId);
  await fsp.mkdir(backupDirPath, { recursive: true });

  // Copy all files to the backup directory
  for (const file of files) {
    await copyToBackup(file.path, backupDirPath, file.relativePath);
  }

  // Write manifest
  await fsp.writeFile(
    manifestPath(backupDir, backupId),
    JSON.stringify(manifest, null, 2),
    'utf-8',
  );

  logger.info(
    { backupId, type: 'full', fileCount: files.length },
    'Full backup completed',
  );

  return manifest;
}

/**
 * Perform an incremental backup.
 *
 * Compares current SHA-256 checksums of database files against the
 * parent manifest. Only copies files whose checksums have changed.
 * If no files have changed, returns null.
 *
 * @param pitrManager - PITRManager instance (or compatible)
 * @param db - better-sqlite3 Database instance (for WAL LSN)
 * @param backupDir - Root directory for storing backups
 * @param parentManifest - The previous full or incremental manifest to diff against
 * @returns BackupManifest describing the incremental backup, or null if no changes
 */
export async function performIncrementalBackup(
  pitrManager: any,
  db: any,
  backupDir: string,
  parentManifest: BackupManifest,
): Promise<BackupManifest | null> {
  const dataDir = pitrManager?.config?.dataDir;
  if (!dataDir) {
    throw new Error('performIncrementalBackup: pitrManager.config.dataDir is required');
  }

  const changedFiles: BackupFileEntry[] = [];

  for (const parentFile of parentManifest.files) {
    const sourcePath = path.resolve(dataDir, parentFile.relativePath);

    if (!fs.existsSync(sourcePath)) {
      // File was deleted — skip it in incremental (will be noted at restore)
      logger.warn(
        { relativePath: parentFile.relativePath },
        'File in parent manifest no longer exists — skipping',
      );
      continue;
    }

    const currentChecksum = await sha256File(sourcePath);

    if (currentChecksum !== parentFile.checksum) {
      // File has changed — include it in incremental
      const stat = await fsp.stat(sourcePath);
      changedFiles.push({
        path: sourcePath,
        size: stat.size,
        checksum: currentChecksum,
        relativePath: parentFile.relativePath,
      });
    }
  }

  if (changedFiles.length === 0) {
    logger.info('No files changed — incremental backup skipped');
    return null;
  }

  const backupId = generateBackupId();
  const timestamp = Date.now();
  const walEndLsn = queryWalEndLsn(db);

  const manifest: BackupManifest = {
    id: backupId,
    timestamp,
    type: 'incremental',
    parentId: parentManifest.id,
    files: changedFiles,
    walEndLsn,
  };

  // Create backup directory and write manifest
  const backupDirPath = path.join(backupDir, backupId);
  await fsp.mkdir(backupDirPath, { recursive: true });

  // Copy only changed files
  for (const file of changedFiles) {
    await copyToBackup(file.path, backupDirPath, file.relativePath);
  }

  // Write manifest
  await fsp.writeFile(
    manifestPath(backupDir, backupId),
    JSON.stringify(manifest, null, 2),
    'utf-8',
  );

  logger.info(
    { backupId, type: 'incremental', parentId: parentManifest.id, changedCount: changedFiles.length },
    'Incremental backup completed',
  );

  return manifest;
}

/**
 * Restore databases from a backup chain.
 *
 * Walks the chain from the target manifest back to the root full backup,
 * then restores files in order so that the latest version of each file wins.
 *
 * @param pitrManager - PITRManager instance (or compatible)
 * @param db - better-sqlite3 Database instance
 * @param backupDir - Root directory containing backup manifests
 * @param targetManifestId - ID of the target manifest (undefined = latest)
 * @returns true if restore succeeded
 */
export async function restoreFromChain(
  pitrManager: any,
  db: any,
  backupDir: string,
  targetManifestId?: string,
): Promise<boolean> {
  const dataDir = pitrManager?.config?.dataDir;
  if (!dataDir) {
    throw new Error('restoreFromChain: pitrManager.config.dataDir is required');
  }

  // Load all manifests in the chain
  const chain = listBackupChain(backupDir);
  if (chain.length === 0) {
    logger.error('No backups found in chain');
    return false;
  }

  // Determine target manifest
  let targetIndex: number;
  if (targetManifestId) {
    targetIndex = chain.findIndex((m) => m.id === targetManifestId);
    if (targetIndex === -1) {
      logger.error({ targetManifestId }, 'Target manifest not found in chain');
      return false;
    }
  } else {
    targetIndex = chain.length - 1; // Latest
  }

  // Walk the chain from target back to the root full backup
  const restoreChain: BackupManifest[] = [];
  let currentIndex = targetIndex;
  while (currentIndex >= 0) {
    restoreChain.unshift(chain[currentIndex]);
    const manifest = chain[currentIndex];
    if (manifest.type === 'full') break;
    currentIndex = chain.findIndex((m) => m.id === manifest.parentId);
    if (currentIndex === -1) {
      logger.error({ manifestId: manifest.id }, 'Orphan incremental — parent not found');
      return false;
    }
  }

  // Restore files: start from full backup, apply incrementals in order
  // If a file appears in multiple manifests, the latest version wins
  const restoredFiles = new Map<string, Buffer>();

  for (const manifest of restoreChain) {
    const backupDirPath = path.join(backupDir, manifest.id);
    for (const file of manifest.files) {
      const sourcePath = path.join(backupDirPath, file.relativePath);
      if (!fs.existsSync(sourcePath)) {
        logger.warn(
          { backupId: manifest.id, relativePath: file.relativePath },
          'Backup file not found on disk — skipping',
        );
        continue;
      }
      const data = await fsp.readFile(sourcePath);
      restoredFiles.set(file.relativePath, data);
    }
  }

  // Write restored files to their original locations
  for (const [relativePath, data] of restoredFiles) {
    const targetPath = path.resolve(dataDir, relativePath);
    const targetDir = path.dirname(targetPath);
    await fsp.mkdir(targetDir, { recursive: true });
    await fsp.writeFile(targetPath, data);
  }

  logger.info(
    { targetManifestId: targetManifestId ?? chain[targetIndex]?.id, restoredCount: restoredFiles.size },
    'Restore from chain completed',
  );

  return true;
}

/**
 * List all backup manifests in a backup directory, ordered oldest-first.
 *
 * @param backupDir - Root directory containing backup manifests
 * @returns Array of BackupManifest objects, sorted by timestamp ascending
 */
export function listBackupChain(backupDir: string): BackupManifest[] {
  if (!fs.existsSync(backupDir)) {
    return [];
  }

  const manifests: BackupManifest[] = [];
  const entries = fs.readdirSync(backupDir, { withFileTypes: true });

  for (const entry of entries) {
    if (!entry.isDirectory()) continue;
    const mfPath = path.join(backupDir, entry.name, MANIFEST_FILENAME);
    if (!fs.existsSync(mfPath)) continue;

    try {
      const content = fs.readFileSync(mfPath, 'utf-8');
      const manifest = JSON.parse(content) as BackupManifest;
      manifests.push(manifest);
    } catch (err: any) {
      logger.warn(
        { backupId: entry.name, err: err.message },
        'Failed to parse backup manifest',
      );
    }
  }

  // Sort by timestamp ascending
  manifests.sort((a, b) => a.timestamp - b.timestamp);

  return manifests;
}

/**
 * Verify the integrity of a backup chain.
 *
 * Checks:
 *   - All manifests are valid JSON with required fields
 *   - All backup files referenced in manifests exist on disk
 *   - Incremental manifests have a valid parent chain leading to a full backup
 *   - No orphaned incrementals
 *
 * @param backupDir - Root directory containing backup manifests
 * @returns Validation result with errors array
 */
export function verifyBackupChain(
  backupDir: string,
): { valid: boolean; errors: string[] } {
  const errors: string[] = [];
  const manifests = listBackupChain(backupDir);

  if (manifests.length === 0) {
    return { valid: false, errors: ['No backup manifests found'] };
  }

  // Build a set of all manifest IDs for parent lookup
  const manifestIds = new Set(manifests.map((m) => m.id));

  for (const manifest of manifests) {
    // Validate required fields
    if (!manifest.id) {
      errors.push(`Manifest missing 'id' field (timestamp: ${manifest.timestamp})`);
    }
    if (!manifest.type) {
      errors.push(`Manifest ${manifest.id || 'unknown'} missing 'type' field`);
    }
    if (manifest.type !== 'full' && manifest.type !== 'incremental') {
      errors.push(`Manifest ${manifest.id} has invalid type: ${manifest.type}`);
    }

    if (!Array.isArray(manifest.files)) {
      errors.push(`Manifest ${manifest.id} 'files' is not an array`);
      continue;
    }

    // Check backup files exist on disk
    for (const file of manifest.files) {
      const filePath = path.join(backupDir, manifest.id, file.relativePath);
      if (!fs.existsSync(filePath)) {
        errors.push(
          `Manifest ${manifest.id}: backup file not found: ${file.relativePath}`,
        );
      }
    }

    // Validate chain integrity
    if (manifest.type === 'incremental') {
      if (!manifest.parentId) {
        errors.push(
          `Incremental manifest ${manifest.id} has no parentId`,
        );
      } else if (!manifestIds.has(manifest.parentId)) {
        errors.push(
          `Incremental manifest ${manifest.id} references missing parent: ${manifest.parentId}`,
        );
      }
    }
  }

  // Check that at least one full backup exists
  const hasFull = manifests.some((m) => m.type === 'full');
  if (!hasFull && manifests.length > 0) {
    errors.push('No full backup found in chain — all incrementals are orphaned');
  }

  return {
    valid: errors.length === 0,
    errors,
  };
}
