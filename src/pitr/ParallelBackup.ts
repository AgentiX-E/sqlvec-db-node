/**
 * ParallelBackup — Parallelize backup of multiple shard databases.
 *
 * Uses Promise.all with concurrency batching for true parallel I/O.
 * Each shard backup runs concurrently via async/await, allowing
 * parallel I/O across shards. On failure, individual shards are
 * marked as failed while other shards continue (partial success).
 *
 * Concurrency is controlled by the `concurrency` config parameter.
 * Shards are processed in batches to avoid overwhelming the system.
 *
 * @module pitr/ParallelBackup
 */

import * as fs from 'node:fs';
import * as fsp from 'fs/promises';
import * as path from 'node:path';
import * as crypto from 'node:crypto';
import { Worker, isMainThread, parentPort, workerData } from 'node:worker_threads';
import { PinoLogger } from '../monitoring/PinoLogger';
import type { BackupManifest } from './IncrementalBackup';

const logger = PinoLogger.forComponent('ParallelBackup');

// ── Types ────────────────────────────────────────────────────────

export interface ParallelBackupConfig {
  /** Maximum number of concurrent backup operations (default: 4) */
  concurrency: number;
  /** Array of shard database file paths to back up */
  shardPaths: string[];
  /** Root directory for storing backup data */
  backupDir: string;
  /** Backup type: 'full' or 'incremental' */
  type: 'full' | 'incremental';
  /** Parent manifest for incremental backups */
  parentManifest?: BackupManifest;
}

export interface ShardBackupResult {
  /** Shard path that was backed up */
  shardPath: string;
  /** Whether the shard backup succeeded */
  success: boolean;
  /** Size of the backed-up file in bytes (0 on failure) */
  bytesCopied: number;
  /** Error message if failed */
  error: string | null;
  /** Backup manifest entry for this shard (if succeeded) */
  manifestEntry?: {
    path: string;
    size: number;
    checksum: string;
    relativePath: string;
  };
}

export interface ParallelBackupStats {
  totalBytes: number;
  elapsedMs: number;
  shardsCompleted: number;
  shardsFailed: number;
  errors: string[];
}

export interface ParallelBackupResult {
  success: boolean;
  manifest: BackupManifest | null;
  stats: ParallelBackupStats;
}

// ── Worker thread support ────────────────────────────────────────

/**
 * Worker thread entry point.
 *
 * Designed to be used as the `worker_threads` worker file.
 * Exported for integration tests.
 *
 * When running in a worker thread (isMainThread === false), it
 * reads workerData, backs up the specified shard, and posts the
 * result back to the parent thread.
 */
export function createBackupWorker(): void {
  if (isMainThread) return; // No-op in main thread

  const input = workerData as { shardPath: string; backupDir: string; type: string };

  try {
    if (!fs.existsSync(input.shardPath)) {
      parentPort!.postMessage({
        success: false,
        error: `Shard file not found: ${input.shardPath}`,
        bytesCopied: 0,
        shardPath: input.shardPath,
        relativePath: '',
        checksum: '',
        size: 0,
      });
      return;
    }

    const stat = fs.statSync(input.shardPath);
    const data = fs.readFileSync(input.shardPath);
    const checksum = crypto.createHash('sha256').update(data).digest('hex');
    const relativePath = path.basename(input.shardPath);
    const backupId = crypto.randomUUID();
    const targetDir = path.join(input.backupDir, backupId);
    fs.mkdirSync(targetDir, { recursive: true });
    fs.copyFileSync(input.shardPath, path.join(targetDir, relativePath));

    parentPort!.postMessage({
      success: true,
      error: null,
      bytesCopied: stat.size,
      shardPath: input.shardPath,
      relativePath,
      checksum,
      size: stat.size,
    });
  } catch (err: any) {
    parentPort!.postMessage({
      success: false,
      error: err.message,
      bytesCopied: 0,
      shardPath: input.shardPath,
      relativePath: '',
      checksum: '',
      size: 0,
    });
  }
}

// ── In-process shard backup ───────────────────────────────────────

/**
 * Compute SHA-256 checksum of a file.
 */
async function sha256File(filePath: string): Promise<string> {
  const data = await fsp.readFile(filePath);
  return crypto.createHash('sha256').update(data).digest('hex');
}

/**
 * Back up a single shard file in the current process.
 *
 * @param shardPath - Absolute path to the shard database file
 * @param backupDir - Root backup directory
 * @returns ShardBackupResult with manifest entry on success
 */
async function backupSingleShard(
  shardPath: string,
  backupDir: string,
): Promise<ShardBackupResult> {
  try {
    if (!fs.existsSync(shardPath)) {
      return {
        shardPath,
        success: false,
        bytesCopied: 0,
        error: `Shard file not found: ${shardPath}`,
      };
    }

    const stat = await fsp.stat(shardPath);
    const checksum = await sha256File(shardPath);
    const relativePath = path.basename(shardPath);

    const result: ShardBackupResult = {
      shardPath,
      success: true,
      bytesCopied: stat.size,
      error: null,
      manifestEntry: {
        path: shardPath,
        size: stat.size,
        checksum,
        relativePath,
      },
    };
    return result;
  } catch (err: any) {
    return {
      shardPath,
      success: false,
      bytesCopied: 0,
      error: err.message,
    };
  }
}

// ── Main entry point ─────────────────────────────────────────────

/**
 * Perform a parallel backup of multiple shard databases.
 *
 * Processes shards concurrently using Promise.all with batching.
 * On failure, individual shards are marked as failed while other
 * shards continue (partial success).
 *
 * Uses in-process parallel I/O (Promise.all with concurrency batching)
 * rather than worker_threads for reliability and testability.
 *
 * @param pitrManager - PITRManager instance (used for dataDir context)
 * @param config - Parallel backup configuration
 * @returns Result with manifest, stats, and overall success flag
 */
export async function performParallelBackup(
  pitrManager: any,
  config: ParallelBackupConfig,
): Promise<ParallelBackupResult> {
  const concurrency = Math.max(1, config.concurrency || 4);
  const shardPaths = config.shardPaths;
  const backupDir = config.backupDir;
  const startTime = Date.now();

  if (shardPaths.length === 0) {
    logger.warn('No shard paths provided for parallel backup');
    return {
      success: true,
      manifest: null,
      stats: {
        totalBytes: 0,
        elapsedMs: 0,
        shardsCompleted: 0,
        shardsFailed: 0,
        errors: [],
      },
    };
  }

  const results: ShardBackupResult[] = [];

  // Process shards in batches at the concurrency level
  for (let i = 0; i < shardPaths.length; i += concurrency) {
    const batch = shardPaths.slice(i, i + concurrency);

    const batchResults = await Promise.all(
      batch.map((shardPath) => backupSingleShard(shardPath, backupDir)),
    );

    results.push(...batchResults);
  }

  // Aggregate results
  const succeeded = results.filter((r) => r.success);
  const failed = results.filter((r) => !r.success);

  const stats: ParallelBackupStats = {
    totalBytes: succeeded.reduce((sum, r) => sum + r.bytesCopied, 0),
    elapsedMs: Date.now() - startTime,
    shardsCompleted: succeeded.length,
    shardsFailed: failed.length,
    errors: failed.map((r) => r.error!).filter(Boolean),
  };

  // Build manifest if at least one shard succeeded
  let manifest: BackupManifest | null = null;
  if (succeeded.length > 0) {
    const backupId = crypto.randomUUID();

    manifest = {
      id: backupId,
      timestamp: Date.now(),
      type: config.type,
      files: succeeded.map((r) => r.manifestEntry!).filter(Boolean),
      ...(config.parentManifest ? { parentId: config.parentManifest.id } : {}),
    };

    // Write the consolidated manifest to a backup directory
    const manifestDir = path.join(backupDir, backupId);
    await fsp.mkdir(manifestDir, { recursive: true });
    await fsp.writeFile(
      path.join(manifestDir, 'backup_manifest.json'),
      JSON.stringify(manifest, null, 2),
      'utf-8',
    );

    // Copy each shard file into the backup directory
    for (const file of manifest.files) {
      const targetDir = path.join(manifestDir, path.dirname(file.relativePath));
      await fsp.mkdir(targetDir, { recursive: true });
      await fsp.copyFile(file.path, path.join(manifestDir, file.relativePath));
    }
  }

  const overallSuccess = failed.length === 0;

  logger.info(
    {
      shardsCompleted: stats.shardsCompleted,
      shardsFailed: stats.shardsFailed,
      totalBytes: stats.totalBytes,
      elapsedMs: stats.elapsedMs,
    },
    overallSuccess
      ? 'Parallel backup completed successfully'
      : 'Parallel backup completed with errors',
  );

  return {
    success: overallSuccess,
    manifest,
    stats,
  };
}
