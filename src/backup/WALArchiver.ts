import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import * as crypto from 'node:crypto';
import * as zlib from 'zlib';
import { promisify } from 'util';
import { PinoLogger } from '../monitoring/PinoLogger';
import { BackupManager } from './BackupManager';
import { WALEncryptionManager } from '../security/WALEncryptionManager';

const gunzipAsync = promisify(zlib.gunzip);

const logger = PinoLogger.forComponent('wal-archiver');

/**
 * WALArchiver — SQLite WAL file archiving and Point-In-Time Recovery (PITR).
 *
 * SQLite uses a Write-Ahead Log (WAL) for concurrent read transactions.
 * This archiver periodically copies WAL files to an archive directory,
 * enabling point-in-time recovery to any archived WAL state.
 *
 * Architecture:
 *   - WAL files are archived alongside full backups
 *   - Each archive entry stores: WAL file, shard ID, timestamp, checksum
 *   - Restore replaces the current WAL with an archived version + the
 *     corresponding database file from the closest BackupManager backup
 *
 * Usage:
 *   const archiver = new WALArchiver('/tmp/wal-archive', backupManager);
 *   await archiver.archiveWAL('shard_0', '/data/shard_0/sqlite.db-wal');
 *   await archiver.restoreToTime('shard_0', new Date('2026-05-28T12:00:00Z'));
 */

export interface WALArchiveEntry {
  shardId: string;
  timestamp: number;
  sourcePath: string;
  archivePath: string;
  checksum: string;
  size: number;
  restorePointName?: string;
}

/**
 * PITR restore manifest — links a full backup with a target WAL archive position.
 * Used to validate consistency before performing a point-in-time recovery.
 */
export interface PITRRestoreManifest {
  /** Path to the full backup directory (containing manifest.json) */
  backup_path: string;
  /** SHA-256 hex digest of the backup manifest.json content */
  backup_checksum: string;
  /** WAL sequence number marking the start of the replay range */
  wal_start_seq: number;
  /** WAL sequence number at the restore point (inclusive end) */
  wal_end_seq: number;
  /** Target recovery timestamp (ms since epoch) */
  restore_time: number;
  /** When this manifest was created (ms since epoch) */
  createdAt: number;
}

export interface ArchiverConfig {
  /** Archive root directory */
  archiveDir: string;
  /** Maximum number of archived WALs to retain per shard (default: 50) */
  retentionCount: number;
  /** Optional WAL encryption manager for at-rest encryption of archived segments */
  encryptionManager?: WALEncryptionManager;
}

const DEFAULT_CONFIG: ArchiverConfig = {
  archiveDir: './wal-archive',
  retentionCount: 50,
};

export class WALArchiver {
  private config: ArchiverConfig;
  private backupManager?: BackupManager;

  constructor(config: Partial<ArchiverConfig>, backupManager?: BackupManager) {
    this.config = { ...DEFAULT_CONFIG, ...config };
    this.backupManager = backupManager;

    if (!fs.existsSync(this.config.archiveDir)) {
      fs.mkdirSync(this.config.archiveDir, { recursive: true });
    }
  }

  /**
   * Archive a WAL file.
   *
   * @param shardId    Shard identifier (e.g. "shard_0")
   * @param walPath    Path to the current WAL file
   * @param pointName  Optional human-readable restore point name
   * @returns          Archive entry describing the archived WAL
   */
  async archiveWAL(shardId: string, walPath: string, pointName?: string): Promise<WALArchiveEntry> {
    if (!fs.existsSync(walPath)) {
      throw new Error(`WAL file not found: ${walPath}`);
    }

    const timestamp = Date.now();
    const dateStr = new Date(timestamp).toISOString().replace(/[:.]/g, '-');

    // Create archive path: archiveDir/shardId/YYYY-MM-DDTHH-mm-ss/
    const shardDir = path.join(this.config.archiveDir, shardId);
    const archiveSubDir = path.join(shardDir, dateStr);
    fs.mkdirSync(archiveSubDir, { recursive: true });

    // Read and optionally encrypt WAL file for at-rest storage
    const walContent = fs.readFileSync(walPath);
    const checksum = crypto.createHash('sha256').update(walContent).digest('hex');

    const archiveFileName = path.basename(walPath);
    const archiveFilePath = path.join(archiveSubDir, archiveFileName);

    // Encrypt before writing to archive (AES-256-GCM)
    const archiveData = this.config.encryptionManager
      ? this.config.encryptionManager.encrypt(walContent)
      : walContent;
    fs.writeFileSync(archiveFilePath, archiveData);

    // Create SQLite .wal file is often named <db>.wal, but SQLite also uses
    // <db>-wal. We store the actual filename to be safe.

    // Write manifest
    const entry: WALArchiveEntry = {
      shardId,
      timestamp,
      sourcePath: walPath,
      archivePath: archiveFilePath,
      checksum,
      size: walContent.length,
      restorePointName: pointName,
    };

    const manifestPath = path.join(archiveSubDir, 'wal-manifest.json');
    fs.writeFileSync(manifestPath, JSON.stringify(entry, null, 2));

    // Enforce retention
    await this.enforceRetention(shardId);

    logger.info({ shardId, archivePath: archiveFilePath, size: walContent.length }, 'WAL archived');
    return entry;
  }

  /**
   * List all archived WAL entries for a shard, sorted newest-first.
   */
  async listArchives(shardId: string): Promise<WALArchiveEntry[]> {
    const shardDir = path.join(this.config.archiveDir, shardId);

    if (!fs.existsSync(shardDir)) {
      return [];
    }

    const entries: WALArchiveEntry[] = [];
    const dirs = fs.readdirSync(shardDir, { withFileTypes: true });

    for (const dir of dirs) {
      if (!dir.isDirectory()) continue;
      const manifestPath = path.join(shardDir, dir.name, 'wal-manifest.json');
      if (!fs.existsSync(manifestPath)) continue;

      try {
        const content = fs.readFileSync(manifestPath, 'utf-8');
        const entry = JSON.parse(content) as WALArchiveEntry;
        entries.push(entry);
      } catch {
        // Skip corrupted manifests
        continue;
      }
    }

    entries.sort((a, b) => b.timestamp - a.timestamp);
    return entries;
  }

  /**
   * Restore a WAL file to its original location.
   *
   * @param entry The archive entry to restore from
   */
  async restoreWAL(entry: WALArchiveEntry): Promise<void> {
    if (!fs.existsSync(entry.archivePath)) {
      throw new Error(`Archived WAL not found: ${entry.archivePath}`);
    }

    // Read and optionally decrypt archived content
    const content = fs.readFileSync(entry.archivePath);
    const plaintext = this.config.encryptionManager
      ? this.config.encryptionManager.decrypt(content)
      : content;

    if (plaintext === null) {
      throw new Error(
        `Failed to decrypt WAL segment: ${entry.archivePath}. ` +
        'Check WAL encryption key configuration.',
      );
    }

    // Verify checksum against the original plaintext
    const actualChecksum = crypto.createHash('sha256').update(plaintext).digest('hex');
    if (actualChecksum !== entry.checksum) {
      throw new Error(
        `WAL checksum mismatch for ${entry.archivePath}: ` +
        `expected ${entry.checksum}, got ${actualChecksum}`,
      );
    }

    // Ensure target directory exists
    const targetDir = path.dirname(entry.sourcePath);
    if (!fs.existsSync(targetDir)) {
      fs.mkdirSync(targetDir, { recursive: true });
    }

    // Write decrypted WAL back to source location
    fs.writeFileSync(entry.sourcePath, plaintext);
    logger.info({ shardId: entry.shardId, source: entry.sourcePath }, 'WAL restored');
  }

  /**
   * Restore a shard to a point in time (PITR) — atomic version.
   *
   * All source data (backup files + WAL) is validated before any writes.
   * A temp directory is used for intermediate storage; on success files are
   * moved to their final locations. On failure the temp dir is cleaned up
   * and the original files remain untouched.
   *
   * @param shardId   Shard identifier
   * @param timestamp Target timestamp (ms since epoch)
   */
  async restoreToTime(shardId: string, timestamp: number): Promise<void> {
    // ── 1. Find target WAL archive ──────────────────────────
    const archives = await this.listArchives(shardId);
    const target = archives.find(a => a.timestamp <= timestamp);
    if (!target) {
      throw new Error(
        `No archived WAL found for shard "${shardId}" at or before ${new Date(timestamp).toISOString()}`,
      );
    }

    // ── 2. Pre-validate WAL checksum (decrypt if needed) ───────────
    if (!fs.existsSync(target.archivePath)) {
      throw new Error(`Archived WAL not found: ${target.archivePath}`);
    }
    const rawWalContent = fs.readFileSync(target.archivePath);
    const walContent = this.config.encryptionManager
      ? this.config.encryptionManager.decrypt(rawWalContent)
      : rawWalContent;

    if (walContent === null) {
      throw new Error(
        `Failed to decrypt WAL segment: ${target.archivePath}. ` +
        'Check WAL encryption key configuration.',
      );
    }

    const walChecksum = crypto.createHash('sha256').update(walContent).digest('hex');
    if (walChecksum !== target.checksum) {
      throw new Error(
        `WAL checksum mismatch for ${target.archivePath}: ` +
        `expected ${target.checksum}, got ${walChecksum}`,
      );
    }

    // ── 3. Pre-validate backup files ────────────────────────
    interface BackupRestoreEntry {
      sourcePath: string;
      targetPath: string;
      compressed: boolean;
    }
    const backupOps: BackupRestoreEntry[] = [];

    if (this.backupManager) {
      const backups = await this.backupManager.listBackups();
      const nearestBackup = backups.find(b => b.timestamp <= timestamp);
      if (nearestBackup) {
        const backupDir = this.backupManager.getConfig().backupDir;
        for (const entry of nearestBackup.shards) {
          const srcPath = path.join(backupDir, entry.path);
          if (!fs.existsSync(srcPath)) {
            throw new Error(`Backup file missing: ${srcPath}`);
          }

          // Read and verify checksum (decompress if needed)
          const raw = fs.readFileSync(srcPath);
          const data = entry.compressed ? await gunzipAsync(raw) : raw;
          const checksum = crypto.createHash('sha256').update(data).digest('hex');
          if (checksum !== entry.checksum) {
            throw new Error(
              `Backup checksum mismatch for shard ${entry.shardId}: ` +
              `expected ${entry.checksum}, got ${checksum}`,
            );
          }

          backupOps.push({
            sourcePath: srcPath,
            targetPath: entry.originalPath,
            compressed: entry.compressed,
          });
        }
      }
    }

    logger.info({
      shardId,
      targetTimestamp: new Date(timestamp).toISOString(),
      archiveTimestamp: new Date(target.timestamp).toISOString(),
    }, 'PITR: all source data validated, proceeding with atomic restore');

    // ── 4. Atomic restore: temp directory → move ──────────
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pitr-restore-'));
    try {
      type TempEntry = { tempPath: string; targetPath: string };

      // Decompress & copy backup files to temp directory
      const backupTempFiles: TempEntry[] = [];
      for (const op of backupOps) {
        const raw = fs.readFileSync(op.sourcePath);
        const data = op.compressed ? await gunzipAsync(raw) : raw;
        const tempPath = path.join(tempDir, path.basename(op.targetPath));
        fs.writeFileSync(tempPath, data);
        backupTempFiles.push({ tempPath, targetPath: op.targetPath });
      }

      // Copy WAL to temp directory
      const walTempPath = path.join(tempDir, path.basename(target.sourcePath));
      fs.writeFileSync(walTempPath, walContent);

      // Move backup files from temp to final locations
      for (const tf of backupTempFiles) {
        fs.mkdirSync(path.dirname(tf.targetPath), { recursive: true });
        fs.renameSync(tf.tempPath, tf.targetPath);
      }

      // Move WAL from temp to final location
      fs.mkdirSync(path.dirname(target.sourcePath), { recursive: true });
      fs.renameSync(walTempPath, target.sourcePath);

      logger.info({
        shardId,
        backupFiles: backupOps.length,
        walFile: target.sourcePath,
      }, 'PITR: atomic restore completed successfully');
    } catch (restoreErr) {
      // Clean up any partial writes in temp (original files untouched)
      logger.error({ err: restoreErr, shardId }, 'PITR: atomic restore failed, temp directory cleaned up');
      throw restoreErr;
    } finally {
      // Always clean up temp directory
      try {
        fs.rmSync(tempDir, { recursive: true, force: true });
      } catch (cleanupErr) {
        logger.warn({ err: cleanupErr, tempDir }, 'Failed to clean up temp restore directory');
      }
    }
  }

  /**
   * Create a PITR restore manifest linking a full backup with a WAL archive position.
   * The manifest includes a SHA-256 checksum of the backup manifest for later validation.
   *
   * The output manifest is written to:
   *   <archiveDir>/pitr-restore-manifest-<timestamp>.json
   *
   * @param backupPath  Path to the full backup directory (must contain manifest.json)
   * @param walSeq      WAL sequence number at the restore point
   * @param timestamp   Target recovery timestamp (ms since epoch)
   */
  createRestoreManifest(backupPath: string, walSeq: number, timestamp: number): void {
    const backupManifestPath = path.join(backupPath, 'manifest.json');
    if (!fs.existsSync(backupManifestPath)) {
      throw new Error(`Backup manifest not found: ${backupManifestPath}`);
    }

    // Compute SHA-256 of the backup manifest content
    const backupManifestContent = fs.readFileSync(backupManifestPath);
    const backupChecksum = crypto.createHash('sha256').update(backupManifestContent).digest('hex');

    const restoreTime = timestamp || Date.now();
    const manifest: PITRRestoreManifest = {
      backup_path: backupPath,
      backup_checksum: backupChecksum,
      wal_start_seq: 0,
      wal_end_seq: walSeq,
      restore_time: restoreTime,
      createdAt: Date.now(),
    };

    // Write manifest to archive directory with timestamped name
    const outputName = `pitr-restore-manifest-${restoreTime}.json`;
    const outputPath = path.join(this.config.archiveDir, outputName);
    fs.writeFileSync(outputPath, JSON.stringify(manifest, null, 2));

    logger.info({ outputPath, backupPath, walSeq, restoreTime }, 'PITR restore manifest created');
  }

  /**
   * Validate a PITR restore manifest object for structural completeness.
   *
   * Checks that all required fields are present with correct types:
   *   - backup_path (string, non-empty)
   *   - backup_checksum (string, 64 hex chars)
   *   - wal_start_seq / wal_end_seq (finite numbers)
   *   - restore_time (finite number)
   *
   * @param manifest  Parsed manifest object (or any value)
   * @returns true if the manifest has valid structure
   */
  validateManifest(manifest: any): boolean {
    if (!manifest || typeof manifest !== 'object') return false;
    return (
      typeof manifest.backup_path === 'string' &&
      manifest.backup_path.length > 0 &&
      typeof manifest.backup_checksum === 'string' &&
      manifest.backup_checksum.length === 64 &&
      typeof manifest.wal_start_seq === 'number' &&
      Number.isFinite(manifest.wal_start_seq) &&
      manifest.wal_start_seq >= 0 &&
      typeof manifest.wal_end_seq === 'number' &&
      Number.isFinite(manifest.wal_end_seq) &&
      manifest.wal_end_seq >= 0 &&
      typeof manifest.restore_time === 'number' &&
      Number.isFinite(manifest.restore_time) &&
      manifest.restore_time > 0
    );
  }

  /**
   * Validate a PITR restore point by loading and checking the manifest file.
   *
   * Performs three checks:
   *  1. Manifest file exists and is valid JSON
   *  2. Manifest structure is valid (via validateManifest)
   *  3. Backup manifest content checksum matches (data integrity)
   *  4. Restore time is not after the target time
   *
   * @param manifestPath  Path to the PITR restore manifest JSON file
   * @param targetTime    Target recovery timestamp (ms since epoch)
   * @returns             Object with valid flag and optional reason
   */
  validateRestorePoint(manifestPath: string, targetTime: number): { valid: boolean; reason?: string } {
    try {
      // Check file exists
      if (!fs.existsSync(manifestPath)) {
        return { valid: false, reason: `Manifest file not found: ${manifestPath}` };
      }

      // Parse JSON
      let manifest: any;
      try {
        const content = fs.readFileSync(manifestPath, 'utf-8');
        manifest = JSON.parse(content);
      } catch {
        return { valid: false, reason: 'Manifest file is not valid JSON' };
      }

      // Validate structure
      if (!this.validateManifest(manifest)) {
        return { valid: false, reason: 'Manifest missing required fields or has invalid types' };
      }

      // Check restore time is not after target time
      if (manifest.restore_time > targetTime) {
        return {
          valid: false,
          reason: `Restore time (${new Date(manifest.restore_time).toISOString()}) is after target time (${new Date(targetTime).toISOString()})`,
        };
      }

      // Verify backup checksum
      const backupManifestPath = path.join(manifest.backup_path, 'manifest.json');
      if (!fs.existsSync(backupManifestPath)) {
        return {
          valid: false,
          reason: `Backup manifest not found at: ${backupManifestPath}`,
        };
      }

      const backupManifestContent = fs.readFileSync(backupManifestPath);
      const actualChecksum = crypto.createHash('sha256').update(backupManifestContent).digest('hex');
      if (actualChecksum !== manifest.backup_checksum) {
        return {
          valid: false,
          reason: `Backup checksum mismatch: expected ${manifest.backup_checksum}, got ${actualChecksum}`,
        };
      }

      return { valid: true };
    } catch (err: any) {
      return { valid: false, reason: `Validation error: ${err.message}` };
    }
  }

  /**
   * Create a named restore point and archive the current WAL.
   *
   * @param shardId Shard identifier
   * @param walPath Path to the WAL file
   * @param name    Human-readable restore point name
   */
  async createRestorePoint(shardId: string, walPath: string, name: string): Promise<WALArchiveEntry> {
    return this.archiveWAL(shardId, walPath, name);
  }

  /**
   * Enforce retention policy for a shard.
   */
  private async enforceRetention(shardId: string): Promise<void> {
    const archives = await this.listArchives(shardId);
    if (archives.length <= this.config.retentionCount) return;

    const toDelete = archives.slice(this.config.retentionCount);
    for (const entry of toDelete) {
      const archiveDir = path.dirname(entry.archivePath);
      try {
        // Remove the archive directory (contains WAL + manifest)
        const shardDir = path.join(this.config.archiveDir, shardId);
        const dirs = fs.readdirSync(shardDir, { withFileTypes: true });

        for (const dir of dirs) {
          if (!dir.isDirectory()) continue;
          const manifestPath = path.join(shardDir, dir.name, 'wal-manifest.json');
          if (!fs.existsSync(manifestPath)) continue;

          try {
            const content = fs.readFileSync(manifestPath, 'utf-8');
            const m = JSON.parse(content) as WALArchiveEntry;
            if (m.checksum === entry.checksum) {
              fs.rmSync(path.join(shardDir, dir.name), { recursive: true, force: true });
            }
          } catch {
            continue;
          }
        }
      } catch (err) {
        logger.error({ err, shardId }, 'Failed to delete old WAL archive');
      }
    }
  }
}
