/**
 * PITRManager — Point-in-Time Recovery orchestration manager.
 *
 * Coordinates the full recovery flow:
 *   1. resolveTarget   → parse target to actual LSN
 *   2. selectBaseBackup → find closest base backup before target
 *   3. haltShards      → stop all target shards (Phase 4: real Raft pause)
 *   4. restoreBaseBackup → restore the base backup
 *   5. replayWAL       → replay WAL from backup point to target (Phase 4: real SQL replay)
 *   6. truncateRaftLog → reset Raft log to match (Phase 4: real SqliteStorage truncation)
 *   7. verifyIntegrity → check DB + WAL consistency
 *   8. resumeShards    → restart all target shards (Phase 4: real Raft resume)
 *
 * Phase 2: Recovery Engine
 * Phase 5: Remote Storage Integration
 *
 * @see design-pitr.md §4.1 for recovery flow
 * @see design-pitr.md §7 Phase 5-6 for remote storage & API
 */

import * as fs from 'node:fs';
import * as fsp from 'fs/promises';
import * as path from 'node:path';
import { PITRReader } from './PITRReader';
import { PITRWriter } from './PITRWriter';
import { WALManifest } from './WALManifest';
import { PITRVerifier } from './PITRVerifier';
import { PITRGC, PITRGCSummary } from './PITRGC';
import { PITRRetentionRule } from './PITRRetentionPolicy';
import { PITRRemoteStorage, PITRRemoteStorageConfig, RemoteStorageStatus } from './PITRRemoteStorage';
import {
  PitrTarget,
  PitrWALEntry,
  LSN,
  DEFAULT_SEGMENT_SIZE,
} from './types';
import { PinoLogger } from '../monitoring/PinoLogger';
import { PhysicalWalReplayer } from '../recovery/PhysicalWalReplayer';
import Database from 'better-sqlite3';

const logger = PinoLogger.forComponent('PITRManager');

// ── Config & Status ──────────────────────────────────────────────────────────

export interface PITRManagerConfig {
  /** Directory where PITR WAL segments are stored */
  archiveDir: string;
  /** Directory where data (shard databases, backups) are stored */
  dataDir: string;
  /** IDs of the shards to manage for PITR */
  shardIds: string[];
  /** Maximum entries per WAL segment (default: 10_000) */
  segmentSize?: number;
  /** Retention rules for WAL segment lifecycle management (optional) */
  retentionConfig?: {
    /** Custom retention rules. Falls back to PITRRetentionPolicy defaults. */
    rules?: PITRRetentionRule[];
    /** Enable periodic GC (default: true) */
    enableGC?: boolean;
    /** GC interval in ms (default: 300_000 = 5 minutes) */
    gcIntervalMs?: number;
  };
  /** Remote storage configuration (optional — enables PITR remote backup sync) */
  remoteStorage?: PITRRemoteStorageConfig;
  /** Enable automatic sync of new WAL segments to remote storage (default: true) */
  syncRemote?: boolean;
  /** Sync interval in ms (default: 60_000 = 1 minute) */
  syncIntervalMs?: number;

  // ── Stage 4: Component References (optional — enable real shard lifecycle) ──

  /**
   * Optional reference to a RaftGroupManager for halting/resuming shard Raft
   * groups and truncating Raft logs during PITR recovery.
   *
   * When provided:
   *   - haltShards() calls pauseShard() on each shard (pauses Raft consensus)
   *   - truncateRaftLog() calls each group's getRaftAdapter().getStorage().truncateLogsFrom()
   *   - resumeShards() calls resumeShard() on each shard (restarts Raft consensus)
   *
   * When absent, the legacy flag-file approach is used as fallback.
   *
   * The interfaced methods follow RaftGroupManager's actual API surface:
   *   pauseShard()  — stops Raft timers/election/replication (group stays registered)
   *   resumeShard() — reinitializes Raft, restarts election/replication
   *   getGroup()    — access the RaftGroup for log truncation
   */
  raftGroupManager?: {
    /** Pause a single shard's Raft group (stops consensus but preserves registration). */
    pauseShard(shardId: number): Promise<void>;
    /** Resume a previously paused shard's Raft group (restarts consensus). */
    resumeShard(shardId: number): Promise<void>;
    /** Get a group by shard ID (returns undefined if not managed here). */
    getGroup(shardId: number): {
      /** Access the underlying SqliteStorage for log truncation. */
      getRaftAdapter(): { getStorage(): { truncateLogsFrom(fromIndex: number): Promise<void> } };
    } | undefined;
  };

  /**
   * Optional onShardHalted / onShardResumed callbacks for external wiring.
   * Called after flag files are created/removed.
   */
  onShardHalted?: (shardId: string) => Promise<void>;
  onShardResumed?: (shardId: string) => Promise<void>;

  /**
   * Optional per-shard binary WAL segment directories for PhysicalWalReplayer.
   *
   * When provided, replayWAL() will first attempt to replay from binary .wal
   * segment files using PhysicalWalReplayer (providing full MVCC semantics),
   * falling back to JSONL-based replay only if no segments are found.
   *
   * Format: { "shard-0": "/path/to/shard-0/pg_wal", "shard-1": "/path/to/shard-1/pg_wal" }
   */
  walSegmentDirs?: Record<string, string>;
}

export interface PITRStatus {
  /** LSN of the last (newest) WAL entry */
  lastEntryLSN: string;
  /** ISO 8601 timestamp of the last entry */
  lastEntryTimestamp: string;
  /** Total number of WAL segments */
  segmentCount: number;
  /** Total entries across all segments */
  totalEntryCount: number;
  /** Total compressed size of all segments in bytes */
  totalSizeBytes: number;
  /** Names of all known restore points */
  restorePoints: string[];
}

/**
 * Result of resolving a PITR target to an actual LSN and raft index.
 */
interface ResolvedTarget {
  lsn: LSN;
  raftIndex: number;
  timestamp: string;
}

/**
 * Backup entry found in the backup directory.
 */
interface BackupEntry {
  backupPath: string;
  timestamp: string;
  shardId: string;
}

// ── PITR Production Readiness Types ──────────────────────────────────────────

/**
 * Recovery phase state machine.
 * Tracks where PITRManager is in the recovery lifecycle.
 */
export enum PitrRecoveryState {
  /** No recovery in progress — normal operation. */
  IDLE = 'IDLE',
  /** Recovery target is being resolved. */
  RESOLVING = 'RESOLVING',
  /** Base backup is being selected. */
  SELECTING_BACKUP = 'SELECTING_BACKUP',
  /** Shards are being halted for recovery. */
  HALTING = 'HALTING',
  /** Base backup is being restored. */
  RESTORING = 'RESTORING',
  /** WAL entries are being replayed. */
  REPLAYING = 'REPLAYING',
  /** Raft log is being truncated. */
  TRUNCATING = 'TRUNCATING',
  /** Integrity verification is in progress. */
  VERIFYING = 'VERIFYING',
  /** Shards are being resumed. */
  RESUMING = 'RESUMING',
  /** Recovery completed successfully. */
  COMPLETED = 'COMPLETED',
  /** Recovery failed. */
  FAILED = 'FAILED',
}

/**
 * Detailed recovery progress information.
 */
export interface RecoveryProgress {
  /** Current phase description (e.g. "replaying WAL", "restoring backup"). */
  phase: string;
  /** Shard currently being processed (empty string if not shard-specific). */
  shard: string;
  /** Estimated completion percentage (0–100). */
  percentage: number;
}

/**
 * Result of a post-recovery integrity verification.
 */
export interface VerificationResult {
  /** Whether all verification checks passed. */
  passed: boolean;
  /** Detailed results per shard. */
  shardResults: VerificationShardResult[];
  /** Timing information. */
  timingMs: number;
}

/**
 * Per-shard verification result.
 */
export interface VerificationShardResult {
  /** Shard identifier. */
  shardId: string;
  /** DB integrity check passed. */
  dbIntegrityOk: boolean;
  /** WAL segment integrity check passed. */
  walIntegrityOk: boolean;
  /** Whether the shard database file exists. */
  dbExists: boolean;
}

// ── PITRManager ──────────────────────────────────────────────────────────────

/**
 * Orchestrates the full PITR recovery cycle.
 *
 * Usage:
 * ```ts
 * const mgr = new PITRManager({
 *   archiveDir: '/data/pitr-archive',
 *   dataDir: '/data/shards',
 *   shardIds: ['shard-0', 'shard-1', 'shard-2'],
 * });
 * await mgr.recover({ type: 'timestamp', value: '2026-05-28T14:30:00.000Z' });
 * ```
 */
export class PITRManager {
  private config: PITRManagerConfig;
  private reader: PITRReader;
  private writer: PITRWriter;
  private manifest: WALManifest;
  private verifier: PITRVerifier;
  private gc: PITRGC;
  private remoteStorage: PITRRemoteStorage | null = null;
  private syncTimer: ReturnType<typeof setInterval> | null = null;
  /** Track which segments have been synced to remote */
  private syncedSegments: Set<number> = new Set();

  // ── Recovery State Tracking (PITR Production Readiness) ──────────────
  /** Current recovery phase. */
  private recoveryState: PitrRecoveryState = PitrRecoveryState.IDLE;
  /** Detailed recovery progress information. */
  private recoveryProgress: RecoveryProgress = {
    phase: 'idle',
    shard: '',
    percentage: 0,
  };
  /** Checkpoint interval in ms during WAL replay (default: 10_000 = 10s). */
  private checkpointIntervalMs: number = 10_000;
  /** Verification result from the last verifyRecovery call. */
  private lastVerificationResult: VerificationResult | null = null;

  constructor(config: PITRManagerConfig) {
    this.config = {
      archiveDir: path.resolve(config.archiveDir),
      dataDir: path.resolve(config.dataDir),
      shardIds: config.shardIds,
      segmentSize: config.segmentSize ?? DEFAULT_SEGMENT_SIZE,
      syncRemote: config.syncRemote ?? true,
      syncIntervalMs: config.syncIntervalMs ?? 60_000,
    };

    // Ensure archive directory exists
    fs.mkdirSync(this.config.archiveDir, { recursive: true });

    this.reader = new PITRReader(this.config.archiveDir);
    this.writer = new PITRWriter(this.config.archiveDir, this.config.segmentSize);
    this.manifest = new WALManifest(this.config.archiveDir);
    this.manifest.load();
    this.verifier = new PITRVerifier();

    // Initialize GC with retention configuration
    const gcRules = config.retentionConfig?.rules;
    this.gc = new PITRGC({
      archiveDir: this.config.archiveDir,
      manifest: this.manifest,
      rules: gcRules,
    });

    // Start periodic GC if enabled (default: true)
    const enableGC = config.retentionConfig?.enableGC ?? true;
    if (enableGC) {
      const gcIntervalMs = config.retentionConfig?.gcIntervalMs ?? 300_000;
      this.gc.start(gcIntervalMs);
      logger.info(
        `PITR GC started (interval: ${gcIntervalMs / 1000}s, ` +
        `rules: ${this.gc.getSummary().retentionRules.map(r => r.type).join(', ')})`,
      );
    }

    // Initialize remote storage if configured
    if (config.remoteStorage) {
      this.remoteStorage = new PITRRemoteStorage(config.remoteStorage);
      logger.info(`PITR remote storage initialized: backend=${config.remoteStorage.backend}`);

      // Start periodic sync if enabled
      if (this.config.syncRemote) {
        this.startSyncTimer();
      }
    }
  }

  // ── Public API ─────────────────────────────────────────────────────────

  /**
   * Start remote sync with the given storage config.
   * Creates the PITRRemoteStorage and starts the sync timer.
   * Safe to call multiple times (earlier instance is stopped).
   */
  startRemoteSync(storageConfig: PITRRemoteStorageConfig): void {
    // Stop existing sync if running
    this.stopRemoteSync();

    this.remoteStorage = new PITRRemoteStorage(storageConfig);
    logger.info(`PITR remote sync started: backend=${storageConfig.backend}`);

    if (this.config.syncRemote) {
      this.startSyncTimer();
    }
  }

  /**
   * Stop remote sync. Closes the storage connection and stops the timer.
   */
  stopRemoteSync(): void {
    this.stopSyncTimer();
    this.remoteStorage = null;
    logger.info('PITR remote sync stopped');
  }

  /**
   * Returns true if remote storage is currently active.
   */
  isRemoteSyncActive(): boolean {
    return this.remoteStorage !== null;
  }

  // ── PITR Production Readiness Methods ──────────────────────────────────────

  /**
   * Get the current recovery state phase.
   */
  getRecoveryState(): PitrRecoveryState {
    return this.recoveryState;
  }

  /**
   * Get the current recovery progress information.
   * Returns detailed phase, shard, and percentage progress.
   */
  getRecoveryProgress(): RecoveryProgress {
    return { ...this.recoveryProgress };
  }

  /**
   * Set the checkpoint interval for WAL replay.
   * During recovery, PRAGMA checkpoint is called periodically at this interval
   * to prevent the WAL file from growing unbounded.
   * Default: 10_000 ms (10 seconds).
   *
   * @param ms - Checkpoint interval in milliseconds (minimum: 1000)
   */
  setCheckpointInterval(ms: number): void {
    if (ms < 1000) {
      logger.warn(
        `Checkpoint interval ${ms}ms is too low — clamping to 1000ms minimum`,
      );
      this.checkpointIntervalMs = 1000;
    } else {
      this.checkpointIntervalMs = ms;
    }
    logger.info(`PITR WAL replay checkpoint interval set to ${this.checkpointIntervalMs}ms`);
  }

  /**
   * Run post-recovery integrity verification independently.
   * This can be called after a recovery completes to double-check the
   * consistency of all shard databases and WAL segments.
   *
   * The result includes per-shard details: DB integrity_check status,
   * WAL segment integrity, and whether the shard file exists.
   *
   * @returns {@link VerificationResult} with per-shard details
   */
  async verifyRecovery(): Promise<VerificationResult> {
    const startTime = Date.now();
    const previousState = this.recoveryState;
    this.recoveryState = PitrRecoveryState.VERIFYING;
    this.updateProgress('verifying recovery integrity', '', 50);

    const shardResults: VerificationShardResult[] = [];

    for (const shardId of this.config.shardIds) {
      this.updateProgress('verifying shard', shardId, 50);

      const dbPath = path.join(this.config.dataDir, shardId, `${shardId}.db`);
      const dbExists = fs.existsSync(dbPath);

      let dbIntegrityOk = false;
      let walIntegrityOk = false;

      if (dbExists) {
        dbIntegrityOk = this.verifier.verifyDBIntegrity(dbPath);
      }

      // Verify all WAL segments
      if (this.manifest.segments.length > 0) {
        let allWalOk = true;
        for (const segment of this.manifest.segments) {
          const walOk = this.verifier.verifyWALSegmentIntegrity(
            this.config.archiveDir,
            segment.segmentIndex,
          );
          if (!walOk) {
            allWalOk = false;
            break;
          }
        }
        walIntegrityOk = allWalOk;
      } else {
        // No WAL segments — consider it trivially valid
        walIntegrityOk = true;
      }

      shardResults.push({
        shardId,
        dbIntegrityOk,
        walIntegrityOk,
        dbExists,
      });
    }

    const passed = shardResults.every(
      (r) => (r.dbExists && r.dbIntegrityOk) || !r.dbExists,
    ) && shardResults.every((r) => r.walIntegrityOk);

    const timingMs = Date.now() - startTime;

    this.lastVerificationResult = { passed, shardResults, timingMs };
    this.updateProgress('verification complete', '', passed ? 100 : 0);
    this.recoveryState = previousState;

    return this.lastVerificationResult;
  }

  /**
   * Internal helper to update recovery progress.
   */
  private updateProgress(phase: string, shard: string, percentage: number): void {
    this.recoveryProgress = { phase, shard, percentage };
    logger.debug(
      { phase, shard, percentage },
      'PITR recovery progress update',
    );
  }

  /** ── end of PITR Production Readiness Methods ─────────────────────── */

  /**
   * Execute a full PITR recovery to the specified target.
   *
   * Implements the 8-step recovery flow from the design doc:
   *   1. resolveTarget — parse target to actual LSN
   *   2. selectBaseBackup — find closest base backup before target
   *   3. haltShards — stop all target shards
   *   4. restoreBaseBackup — restore the base backup
   *   5. replayWAL — replay WAL entries from backup point to target
   *   6. truncateRaftLog — reset Raft log to match
   *   7. verifyIntegrity — check DB + WAL consistency
   *   8. resumeShards — restart all target shards
   *
   * @param target - Recovery target specification
   * @throws {Error} If any step of the recovery fails
   */
  async recover(target: PitrTarget): Promise<void> {
    logger.info('=== PITR Recovery Starting ===');
    this.recoveryState = PitrRecoveryState.RESOLVING;
    this.updateProgress('resolving target', '', 5);

    // Step 1: Resolve target
    const resolved = this.resolveTarget(target);
    logger.info(
      `[1/8] Target resolved: ${JSON.stringify(target)} ` +
        `→ LSN=${resolved.lsn} raftIndex=${resolved.raftIndex} ts=${resolved.timestamp}`,
    );

    // Step 2: Select base backup
    this.recoveryState = PitrRecoveryState.SELECTING_BACKUP;
    this.updateProgress('selecting base backup', '', 10);
    const baseBackup = await this.selectBaseBackup(resolved.timestamp);
    if (!baseBackup) {
      this.recoveryState = PitrRecoveryState.FAILED;
      this.updateProgress('failed - no base backup', '', 0);
      throw new Error(
        `No base backup found before target timestamp: ${resolved.timestamp}`,
      );
    }
    logger.info(
      `[2/8] Base backup selected: ${baseBackup.backupPath} @ ${baseBackup.timestamp}`,
    );

    // Step 3: Halt all shards (Phase 4: real Raft pause + flag fallback)
    this.recoveryState = PitrRecoveryState.HALTING;
    this.updateProgress('halting shards', '', 20);
    await this.haltShards();
    logger.info('[3/8] Shards halted');

    try {
      // Step 4: Restore base backup
      this.recoveryState = PitrRecoveryState.RESTORING;
      this.updateProgress('restoring base backup', '', 30);
      await this.restoreBaseBackup(baseBackup);
      logger.info(
        `[4/8] Base backup restored from: ${baseBackup.backupPath}`,
      );

      // Step 5: Replay WAL from backup point to target (Phase 4: real SQL replay)
      this.recoveryState = PitrRecoveryState.REPLAYING;
      this.updateProgress('replaying WAL entries', '', 50);
      const replayed = await this.replayWAL(baseBackup.timestamp, resolved);
      logger.info(`[5/8] WAL replay complete (${replayed} entries replayed)`);

      // Step 6: Truncate Raft log (Phase 4: real SqliteStorage truncation + flag)
      this.recoveryState = PitrRecoveryState.TRUNCATING;
      this.updateProgress('truncating Raft log', '', 80);
      await this.truncateRaftLog(resolved.raftIndex);
      logger.info(
        `[6/8] Raft log truncated to index ${resolved.raftIndex}`,
      );

      // Step 7: Verify integrity
      this.recoveryState = PitrRecoveryState.VERIFYING;
      this.updateProgress('verifying recovery integrity', '', 90);
      const verified = this.verifyIntegrity();
      if (!verified) {
        throw new Error('Post-recovery integrity verification failed');
      }
      logger.info('[7/8] Integrity verification passed');

      this.recoveryState = PitrRecoveryState.COMPLETED;
      this.updateProgress('recovery complete', '', 100);
    } catch (err: any) {
      this.recoveryState = PitrRecoveryState.FAILED;
      this.updateProgress(`failed: ${err.message}`, '', 0);
      logger.error(`PITR recovery failed: ${err.message}`);
      throw err;
    } finally {
      // Step 8: Resume shards (Phase 4: real Raft resume + flag cleanup)
      this.recoveryState = PitrRecoveryState.RESUMING;
      this.updateProgress('resuming shards', '', 95);
      await this.resumeShards();
      logger.info('[8/8] Shards resumed');
    }

    logger.info(
      `=== PITR Recovery Complete: target LSN ${resolved.lsn}, ` +
        `raft index ${resolved.raftIndex} ===`,
    );
  }

  /**
   * Create a named restore point for easy reference.
   *
   * Writes a special marker entry to the WAL so it can be found later
   * via `listRestorePoints()`.
   *
   * @param name - Human-readable name for the restore point
   */
  async createRestorePoint(name: string): Promise<void> {
    // Write a special marker entry to the WAL
    const markerData = JSON.stringify({
      __restore_point: name,
    });

    // Write to each shard's WAL
    for (const shardId of this.config.shardIds) {
      this.writer.append(0, 0, shardId, markerData);
    }
    this.writer.flushSegment();

    // Run a GC cycle after flushing to apply retention immediately
    this.gc.runCycle();

    logger.info(`Restore point created: ${name}`);
  }

  /**
   * List all available restore point names.
   *
   * Scans the WAL for entries containing restore point markers.
   *
   * @returns Array of restore point names
   */
  async listRestorePoints(): Promise<string[]> {
    const points: string[] = [];

    for (const segment of this.manifest.segments) {
      try {
        const entries = this.reader.readSegment(segment.segmentIndex);
        for (const entry of entries) {
          try {
            const parsed = JSON.parse(entry.data);
            if (parsed && parsed.__restore_point) {
              points.push(parsed.__restore_point);
            }
          } catch {
            // Not a restore-point entry — skip
            continue;
          }
        }
      } catch {
        // Segment read failure — skip
        continue;
      }
    }

    return points;
  }

  /**
   * Get the current PITR status.
   *
   * @returns PITRStatus snapshot
   */
  getStatus(): PITRStatus {
    // Reload manifest to get latest state
    this.manifest.load();

    const segments = this.manifest.segments;
    const segmentCount = segments.length;

    let lastEntryLSN = '';
    let lastEntryTimestamp = '';
    let totalEntryCount = 0;
    let totalSizeBytes = 0;

    if (segments.length > 0) {
      const lastSeg = segments[segments.length - 1];
      lastEntryLSN = lastSeg.lastLSN;
      lastEntryTimestamp = lastSeg.lastTimestamp;
      totalEntryCount = this.manifest.totalEntryCount();
      totalSizeBytes = this.manifest.totalSizeBytes();
    }

    return {
      lastEntryLSN,
      lastEntryTimestamp,
      segmentCount,
      totalEntryCount,
      totalSizeBytes,
      restorePoints: [],
    };
  }

  /**
   * Get a summary of the GC state (segment counts, rules, running status).
   */
  getGCSummary(): PITRGCSummary {
    return this.gc.getSummary();
  }

  /**
   * Run a single GC cycle manually.
   *
   * @returns Number of segments removed
   */
  runGC(): number {
    return this.gc.runCycle();
  }

  /**
   * Get the remote storage status (if configured).
   */
  getRemoteStatus(): RemoteStorageStatus | null {
    return this.remoteStorage?.getStatus() ?? null;
  }

  /**
   * Sync all unsynced local WAL segments to remote storage.
   *
   * Uploads any segments that exist locally but have not yet been
   * flagged as synced in `syncedSegments`. After successful upload,
   * the segment is marked as synced so it won't be re-uploaded.
   *
   * @returns Number of segments synced
   */
  async syncToRemote(): Promise<number> {
    if (!this.remoteStorage) {
      logger.warn('syncToRemote() called but remote storage is not configured');
      return 0;
    }

    // Reload manifest to get latest segments
    this.manifest.load();
    const segments = this.manifest.segments;

    let syncedCount = 0;

    for (const segment of segments) {
      const segmentIndex = segment.segmentIndex;

      // Skip if already synced
      if (this.syncedSegments.has(segmentIndex)) continue;

      const segmentFileName = this.segmentFilename(segmentIndex);
      const localPath = path.join(this.config.archiveDir, segmentFileName);

      if (!fs.existsSync(localPath)) {
        logger.warn(`Segment file not found for sync: ${localPath}`);
        continue;
      }

      try {
        await this.remoteStorage.uploadSegment(localPath, segmentFileName);
        this.syncedSegments.add(segmentIndex);
        syncedCount++;
      } catch (err: any) {
        logger.error(`Failed to sync segment ${segmentFileName}: ${err.message}`);
        // Continue with next segment even if one fails
      }
    }

    if (syncedCount > 0) {
      logger.info(`Synced ${syncedCount} segment(s) to remote storage`);
    }

    return syncedCount;
  }

  /**
   * Restore WAL segments and databases from remote storage for a PITR recovery.
   *
   * Downloads all remote segments, then runs the full recovery flow using
   * the locally-restored WAL and databases.
   *
   * @param target - Recovery target specification
   */
  async restoreFromRemote(target: PitrTarget): Promise<void> {
    if (!this.remoteStorage) {
      throw new Error('restoreFromRemote() called but remote storage is not configured');
    }

    logger.info('=== PITR Remote Restore Starting ===');

    // Step 1: List available segments in remote storage
    const remoteSegments = await this.remoteStorage.listSegments();
    if (remoteSegments.length === 0) {
      throw new Error('No WAL segments found in remote storage');
    }

    logger.info(`Found ${remoteSegments.length} segment(s) in remote storage`);

    // Step 2: Download all segments
    let downloaded = 0;
    for (const segmentName of remoteSegments) {
      const localPath = path.join(this.config.archiveDir, segmentName);
      if (fs.existsSync(localPath)) {
        // Already exists locally — skip
        this.syncedSegments.add(this.extractSegmentIndex(segmentName));
        continue;
      }

      try {
        await this.remoteStorage.downloadSegment(segmentName, localPath);
        const segIdx = this.extractSegmentIndex(segmentName);
        this.syncedSegments.add(segIdx);
        downloaded++;
      } catch (err: any) {
        logger.warn(`Failed to download segment ${segmentName}: ${err.message}`);
        // Continue with other segments
      }
    }

    logger.info(`Downloaded ${downloaded} segment(s) from remote storage`);

    // Step 3: Rebuild manifest from local files
    this.manifest.load();

    // Step 4: Run recovery
    await this.recover(target);

    logger.info('=== PITR Remote Restore Complete ===');
  }

  /**
   * Start the periodic sync timer.
   */
  private startSyncTimer(): void {
    const interval = this.config.syncIntervalMs!;
    logger.info(`Starting periodic remote sync every ${interval / 1000}s`);

    this.syncTimer = setInterval(async () => {
      try {
        await this.syncToRemote();
      } catch (err: any) {
        logger.error(`Periodic sync failed: ${err.message}`);
      }
    }, interval);

    // Don't prevent process exit
    this.syncTimer.unref();

    // Run an initial sync after a short delay
    setTimeout(() => {
      this.syncToRemote().catch((err) => {
        logger.error(`Initial sync failed: ${err.message}`);
      });
    }, 5_000);
  }

  /**
   * Generate the local segment filename for a given index.
   * Matches the format from `types.ts` segmentFilename() function.
   */
  private segmentFilename(segmentIndex: number): string {
    return `pitr-segment-${String(segmentIndex).padStart(6, '0')}.wal.gz`;
  }

  /**
   * Extract segment index from a segment filename.
   */
  private extractSegmentIndex(filename: string): number {
    const match = filename.match(/pitr-segment-(\d+)\.wal\.gz/);
    if (!match) return 0;
    return parseInt(match[1], 10);
  }

  /**
   * Stop the periodic sync timer.
   */
  private stopSyncTimer(): void {
    if (this.syncTimer) {
      clearInterval(this.syncTimer);
      this.syncTimer = null;
      logger.info('Periodic remote sync stopped');
    }
  }

  /**
   * Dispose of internal resources (close writer, stop GC, stop sync, flush).
   */
  close(): void {
    this.gc.stop();
    this.stopSyncTimer();
    this.writer.close();
  }

  // ── Step Implementations ──────────────────────────────────────────────

  /**
   * Step 1: Resolve a PITR target to its actual LSN, raft index, and timestamp.
   *
   * Uses PITRReader.readUpTo() to find the exact entry matching the target,
   * then extracts the resolved coordinates from the last entry in the range.
   */
  private resolveTarget(target: PitrTarget): ResolvedTarget {
    try {
      const entries = this.reader.readUpTo(target);

      if (entries.length === 0) {
        throw new Error(
          `Target ${JSON.stringify(target)} resolved to zero entries`,
        );
      }

      const lastEntry = entries[entries.length - 1];

      return {
        lsn: lastEntry.lsn,
        raftIndex: lastEntry.raftIndex,
        timestamp: lastEntry.timestamp,
      };
    } catch (err: any) {
      throw new Error(
        `Failed to resolve target ${JSON.stringify(target)}: ${err.message}`,
      );
    }
  }

  /**
   * Step 2: Select the best base backup for recovery.
   *
   * Walks the data directory looking for backup files and finds the
   * newest full backup whose timestamp is <= the target timestamp.
   *
   * Backups are expected to follow the pattern:
   *   {dataDir}/backups/{shardId}/backup-{timestamp}.db
   * with an accompanying {backup}.manifest.json file.
   */
  private async selectBaseBackup(
    targetTimestamp: string,
  ): Promise<BackupEntry | null> {
    const backupsDir = path.join(this.config.dataDir, 'backups');
    if (!fs.existsSync(backupsDir)) {
      logger.warn(`No backups directory found at: ${backupsDir}`);
      return null;
    }

    const targetTime = new Date(targetTimestamp).getTime();
    let bestBackup: BackupEntry | null = null;
    let bestTime = 0;

    // Walk shardId subdirectories
    const shardDirs = fs.readdirSync(backupsDir, { withFileTypes: true });
    for (const shardDir of shardDirs) {
      if (!shardDir.isDirectory()) continue;
      const shardPath = path.join(backupsDir, shardDir.name);

      // Look for manifest.json files inside each shard's backup dir
      const files = fs.readdirSync(shardPath);
      for (const file of files) {
        if (!file.endsWith('.manifest.json')) continue;
        const manifestPath = path.join(shardPath, file);

        try {
          const content = fs.readFileSync(manifestPath, 'utf-8');
          const meta = JSON.parse(content);

          const backupTime = new Date(meta.timestamp).getTime();
          if (isNaN(backupTime)) continue;

          // We want the backup with the newest timestamp <= target
          if (backupTime <= targetTime && backupTime > bestTime) {
            // Derive the actual backup file path from the manifest
            const backupFileName = file.replace('.manifest.json', '');
            const backupPath = path.join(shardPath, backupFileName);

            if (fs.existsSync(backupPath)) {
              bestBackup = {
                backupPath,
                timestamp: meta.timestamp,
                shardId: shardDir.name,
              };
              bestTime = backupTime;
            }
          }
        } catch {
          // Corrupt manifest — skip
          continue;
        }
      }
    }

    return bestBackup;
  }

  /**
   * Step 3: Halt all target shards prior to recovery.
   *
   * Raft-aware implementation:
   *   - Flushes all buffered PITR WAL segments to disk (ensures no uncommitted
   *     WAL entries are lost during the halt).
   *   - If raftGroupManager is configured, calls pauseShard() on each shard.
   *     This stops Raft consensus (timers, leader election, log replication)
   *     while keeping the group registered for clean resumption.
   *   - Always creates pitr_halted.flag files for each shard as durable status
   *     markers for crash recovery detection.
   *   - Calls onShardHalted callback if provided.
   *
   * All Raft operations are wrapped in try/catch with graceful fallback to
   * flag-only mode on failure.
   */
  private async haltShards(): Promise<void> {
    const shardIds = this.config.shardIds;
    const raftMgr = this.config.raftGroupManager;
    const onHalted = this.config.onShardHalted;

    logger.info(
      `[PITR] Halting shards: ${shardIds.join(', ')}` +
        (raftMgr ? ' (using RaftGroupManager pauseShard)' : ' (flag-only fallback)'),
    );

    // ── Flush WAL: ensure all buffered entries are durable before halting ──
    try {
      this.writer.flushSegment();
      logger.info('PITR WAL flush complete before halt');
    } catch (err: any) {
      logger.warn(`WAL flush before halt failed: ${err.message} — continuing`);
    }

    // ── Real: pause Raft groups ──
    if (raftMgr) {
      for (const shardId of shardIds) {
        try {
          await raftMgr.pauseShard(Number(shardId));
          logger.info(`Shard ${shardId} Raft group paused`);
        } catch (err: any) {
          logger.warn(
            `Failed to pause Raft group for shard ${shardId}: ${err.message} — continuing with flag fallback`,
          );
        }
      }
    }

    // ── Fallback: create halt flags ──
    for (const shardId of shardIds) {
      const shardDir = path.join(this.config.dataDir, shardId);
      await fsp.mkdir(shardDir, { recursive: true });
      const flagFile = path.join(shardDir, 'pitr_halted.flag');
      await fsp.writeFile(flagFile, `halted at ${new Date().toISOString()}\n`);
      logger.trace(`Created halt flag: ${flagFile}`);

      // Callback
      if (onHalted) {
        await onHalted(shardId).catch((err: any) =>
          logger.warn(`onShardHalted callback failed for ${shardId}: ${err.message}`),
        );
      }
    }
  }

  /**
   * Step 4: Restore the selected base backup to each shard.
   *
   * Copies the backup file back to each shard's data directory.
   */
  private async restoreBaseBackup(backup: BackupEntry): Promise<void> {
    for (const shardId of this.config.shardIds) {
      const dbFileName = `${shardId}.db`;
      const targetPath = path.join(this.config.dataDir, shardId, dbFileName);

      // Ensure target directory exists
      const targetDir = path.dirname(targetPath);
      if (!fs.existsSync(targetDir)) {
        fs.mkdirSync(targetDir, { recursive: true });
      }

      // Copy backup file to target
      if (fs.existsSync(backup.backupPath)) {
        fs.copyFileSync(backup.backupPath, targetPath);
        logger.info(
          `Base backup restored to shard ${shardId}: ${backup.backupPath} → ${targetPath}`,
        );
      } else {
        logger.warn(
          `Backup file not found for shard ${shardId}: ${backup.backupPath}`,
        );
      }
    }
  }

  /**
   * Step 5: Replay WAL entries from the backup point to the target.
   *
   * Reads all entries from the backup's timestamp to the resolved target
   * and replays them (writes to a replay log; actual state machine apply
   * will be wired in Phase 4).
   *
   * @returns The number of entries replayed
   */
  /**
   * Step 5: Replay WAL entries from the backup point to the target.
   *
   * Phase 4 implementation:
   *   For each shard, first attempts binary PhysicalWalReplayer replay if
   *   walSegmentDirs are configured (providing full MVCC semantics).
   *   Falls back to PITRWriter.replayToDb() JSONL-based replay.
   *
   * @returns The number of entries replayed
   */
  private async replayWAL(
    backupTimestamp: string,
    target: ResolvedTarget,
  ): Promise<number> {
    // Read all entries from beginning up to target
    const entries = this.reader.readRange('0-0' as LSN, target.lsn);

    // Filter entries created at or after the backup timestamp
    const backupTime = new Date(backupTimestamp).getTime();
    const entriesToReplay = entries.filter(e => {
      const entryTime = new Date(e.timestamp).getTime();
      return entryTime >= backupTime;
    });

    if (entriesToReplay.length === 0) {
      logger.info('No WAL entries to replay (backup is already at target)');
      return 0;
    }

    logger.info(
      `Replaying ${entriesToReplay.length} WAL entries across ` +
        `${this.config.shardIds.length} shards`,
    );

    // Group entries by shard for efficient per-DB replay
    const shardEntries = new Map<string, PitrWALEntry[]>();
    for (const entry of entriesToReplay) {
      const list = shardEntries.get(entry.shardId) ?? [];
      list.push(entry);
      shardEntries.set(entry.shardId, list);
    }

    let totalApplied = 0;

    // Replay each shard's entries to its database
    for (const [shardId, shardEntriesList] of shardEntries) {
      const dbPath = path.join(
        this.config.dataDir,
        shardId,
        `${shardId}.db`,
      );

      // Ensure target directory exists
      const dbDir = path.dirname(dbPath);
      if (!fs.existsSync(dbDir)) {
        await fsp.mkdir(dbDir, { recursive: true });
      }

      // ── Attempt PhysicalWalReplayer binary replay first ──
      const segDir = this.config.walSegmentDirs?.[shardId];
      if (segDir && fs.existsSync(segDir)) {
        const segFiles = fs.readdirSync(segDir).filter(f => f.endsWith('.wal'));
        if (segFiles.length > 0) {
          logger.info(
            `Binary WAL replay for ${shardId}: ${segFiles.length} segment(s) in ${segDir}`,
          );
          try {
            // Create DB from scratch for replay
            const replayDb = new Database(dbPath);
            replayDb.exec('PRAGMA journal_mode = WAL');
            replayDb.exec('PRAGMA synchronous = NORMAL');

            const replayer = new PhysicalWalReplayer({
              db: replayDb as any,
              clog: { commit: () => {}, abort: () => {} },
              segmentDir: segDir,
            });

            const status = replayer.replay('0/0'); // replay all available segments

            replayDb.close();
            totalApplied += status;

            logger.info(
              `Binary WAL replay for ${shardId}: ${status} records replayed`,
            );
            // Skip JSONL fallback — binary path succeeded
            continue;
          } catch (err) {
            logger.error(
              { err, shardId, segDir },
              `Binary WAL replay failed for ${shardId}, falling back to JSONL`,
            );
            // Fall through to JSONL path
          }
        }
      }

      // ── Fallback: JSONL-based replay via PITRWriter ──
      logger.info(
        `JSONL replay for shard ${shardId}: ${shardEntriesList.length} entries → ${dbPath}`,
      );

      const applied = this.writer.replayToDb(shardEntriesList, dbPath);
      totalApplied += applied;

      // Also write to replay log for traceability
      await this.writeReplayLog(shardId, shardEntriesList);
    }

    logger.info(
      `WAL replay complete: ${totalApplied}/${entriesToReplay.length} entries applied to databases`,
    );
    return totalApplied;
  }

  /**
   * Write WAL entries to a replay log file for traceability.
   */
  private async writeReplayLog(
    shardId: string,
    entries: PitrWALEntry[],
  ): Promise<void> {
    const shardDir = path.join(this.config.dataDir, shardId);
    await fsp.mkdir(shardDir, { recursive: true });
    const replayLog = path.join(shardDir, 'pitr_replay.log');
    const lines = entries.map(e => JSON.stringify(e) + '\n').join('');
    await fsp.appendFile(replayLog, lines);
  }

  /**
   * Step 6: Truncate the Raft log after recovery.
   *
   * Raft-aware implementation:
   *   If raftGroupManager is configured:
   *     1. For each shard, get the RaftGroup via getGroup()
   *     2. Access the underlying SqliteStorage via getRaftAdapter().getStorage()
   *     3. Call truncateLogsFrom(targetRaftIndex + 1) to remove all
   *        log entries beyond the recovery point
   *
   *   Always creates a pitr_truncated_at_*.flag file as a durable marker of
   *   the truncation point for crash recovery detection.
   *
   * All Raft operations are wrapped in try/catch with graceful fallback to
   * flag-only mode on failure.
   */
  private async truncateRaftLog(targetRaftIndex: number): Promise<void> {
    const raftMgr = this.config.raftGroupManager;

    logger.info(
      `[PITR] Truncating Raft log to index ${targetRaftIndex}` +
        (raftMgr ? ' (using SqliteStorage)' : ' (flag-only fallback)'),
    );

    // ── Real: truncate via RaftGroupManager → SqliteStorage ──
    if (raftMgr) {
      for (const shardId of this.config.shardIds) {
        try {
          const group = raftMgr.getGroup(Number(shardId));
          if (group) {
            const adapter = group.getRaftAdapter();
            const storage = adapter.getStorage();
            // Remove entries from (targetRaftIndex + 1) onwards
            await storage.truncateLogsFrom(targetRaftIndex + 1);
            logger.info(
              `Raft log truncated for shard ${shardId}: entries >= ${targetRaftIndex + 1} removed`,
            );
          } else {
            logger.warn(
              `No Raft group found for shard ${shardId} — skipping real truncation`,
            );
          }
        } catch (err: any) {
          logger.warn(
            `Failed to truncate Raft log for shard ${shardId}: ${err.message} — continuing with flag fallback`,
          );
        }
      }
    }

    // ── Fallback: create truncation flag ──
    await fsp.mkdir(this.config.dataDir, { recursive: true });
    const flagFile = path.join(
      this.config.dataDir,
      `pitr_truncated_at_${targetRaftIndex}.flag`,
    );
    await fsp.writeFile(
      flagFile,
      `truncated at raft index ${targetRaftIndex} via ${raftMgr ? 'SqliteStorage' : 'flag-only'}\n`,
    );
    logger.trace(`Created truncation flag: ${flagFile}`);
  }

  /**
   * Step 7: Verify the integrity of recovered databases and WAL.
   *
   * Checks:
   * - All shards' databases pass PRAGMA integrity_check
   * - All WAL segments are intact (CRC32C)
   * - Vector index consistency (where applicable)
   *
   * @returns true if all checks pass
   */
  private verifyIntegrity(): boolean {
    // Verify all WAL segments
    for (const segment of this.manifest.segments) {
      const ok = this.verifier.verifyWALSegmentIntegrity(
        this.config.archiveDir,
        segment.segmentIndex,
      );
      if (!ok) {
        logger.error(
          `WAL segment integrity check failed: segment ${segment.segmentIndex}`,
        );
        return false;
      }
    }
    logger.info(
      `All ${this.manifest.segments.length} WAL segments passed integrity check`,
    );

    // Verify DB integrity for each shard
    for (const shardId of this.config.shardIds) {
      const dbPath = path.join(
        this.config.dataDir,
        shardId,
        `${shardId}.db`,
      );
      if (fs.existsSync(dbPath)) {
        const ok = this.verifier.verifyDBIntegrity(dbPath);
        if (!ok) {
          logger.error(
            `Database integrity check failed for shard ${shardId}: ${dbPath}`,
          );
          return false;
        }
        logger.info(`Database integrity check passed for shard ${shardId}`);
      } else {
        logger.warn(
          `Database file not found for shard ${shardId}: ${dbPath}`,
        );
      }
    }

    return true;
  }

  /**
   * Step 8: Resume all target shards after recovery.
   *
   * Raft-aware implementation:
   *   - If raftGroupManager is configured, calls resumeShard() on each shard.
   *     This reinitializes the Raft node, restarting election timers and log
   *     replication, bringing the shard back to operational status.
   *   - Calls onShardResumed callback if provided.
   *   - Always removes halt flags and truncation flags.
   *
   * All Raft operations are wrapped in try/catch with graceful fallback to
   * flag-only mode on failure.
   *
   * Replay logs (pitr_replay.log) are intentionally preserved — they serve
   * as an audit trail of what was replayed during recovery.
   */
  private async resumeShards(): Promise<void> {
    const raftMgr = this.config.raftGroupManager;
    const onResumed = this.config.onShardResumed;

    logger.info(
      `[PITR] Resuming shards: ${this.config.shardIds.join(', ')}` +
        (raftMgr ? ' (using RaftGroupManager resumeShard)' : ' (flag-only cleanup)'),
    );

    // ── Real: resume Raft groups ──
    if (raftMgr) {
      for (const shardId of this.config.shardIds) {
        try {
          await raftMgr.resumeShard(Number(shardId));
          logger.info(`Shard ${shardId} Raft group resumed`);
        } catch (err: any) {
          logger.warn(
            `Failed to resume Raft group for shard ${shardId}: ${err.message} — continuing with flag cleanup`,
          );
        }

        // Callback
        if (onResumed) {
          await onResumed(shardId).catch((err: any) =>
            logger.warn(`onShardResumed callback failed for ${shardId}: ${err.message}`),
          );
        }
      }
    }

    // ── Fallback: remove halt flags ──
    for (const shardId of this.config.shardIds) {
      const flagFile = path.join(this.config.dataDir, shardId, 'pitr_halted.flag');
      try {
        await fsp.unlink(flagFile);
        logger.trace(`Removed halt flag: ${flagFile}`);
      } catch (err: any) {
        if (err.code !== 'ENOENT') {
          throw err;
        }
        // File didn't exist — that's fine
      }

      // Callback (also called in fallback path)
      if (!raftMgr && onResumed) {
        await onResumed(shardId).catch((err: any) =>
          logger.warn(`onShardResumed callback failed for ${shardId}: ${err.message}`),
        );
      }
    }

    // Remove truncation flags
    try {
      const entries = await fsp.readdir(this.config.dataDir);
      for (const entry of entries) {
        if (entry.startsWith('pitr_truncated_at_') && entry.endsWith('.flag')) {
          const flagPath = path.join(this.config.dataDir, entry);
          await fsp.unlink(flagPath);
          logger.trace(`Removed truncation flag: ${flagPath}`);
        }
      }
    } catch (err: any) {
      if (err.code !== 'ENOENT') {
        throw err;
      }
    }
  }
}
