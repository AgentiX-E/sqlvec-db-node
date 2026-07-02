/**
 * pgStatBgwriter — PostgreSQL pg_stat_bgwriter view compatibility.
 *
 * Tracks background writer and checkpointer statistics:
 *   - buffers_clean: Buffers written by background writer
 *   - buffers_backend: Buffers written by backends
 *   - maxwritten_clean: Number of times bgwriter stopped cleaning
 *   - buffers_alloc: Total buffers allocated
 *   - checkpoints_timed: Number of scheduled checkpoints
 *   - checkpoints_req: Number of requested checkpoints
 *
 * Exposed via pg_stat_bgwriter view.
 */

import { PinoLogger } from '../monitoring/PinoLogger';

const logger = PinoLogger.forComponent('pg-stat-bgwriter');

export interface PgStatBgwriterRow {
  checkpoints_timed: number;
  checkpoints_req: number;
  buffers_checkpoint: number;
  buffers_clean: number;
  buffers_backend: number;
  buffers_backend_fsync: number;
  buffers_alloc: number;
  maxwritten_clean: number;
  stats_reset: string;
}

export class PgStatBgwriter {
  private checkpointsTimed = 0;
  private checkpointsReq = 0;
  private buffersCheckpoint = 0;
  private buffersClean = 0;
  private buffersBackend = 0;
  private buffersBackendFsync = 0;
  private buffersAlloc = 0;
  private maxwrittenClean = 0;
  private lastReset: Date = new Date();

  // ── Counter Increments ────────────────────────────────────────

  recordTimedCheckpoint(buffers: number): void {
    this.checkpointsTimed++;
    this.buffersCheckpoint += buffers;
  }

  recordRequestedCheckpoint(buffers: number): void {
    this.checkpointsReq++;
    this.buffersCheckpoint += buffers;
  }

  recordCleanBuffer(): void {
    this.buffersClean++;
  }

  recordMaxwrittenClean(): void {
    this.maxwrittenClean++;
  }

  recordBackendBuffer(fsyncRequired: boolean): void {
    this.buffersBackend++;
    if (fsyncRequired) {
      this.buffersBackendFsync++;
    }
  }

  recordAlloc(count: number = 1): void {
    this.buffersAlloc += count;
  }

  // ── View Query ────────────────────────────────────────────────

  /** Return a snapshot matching pg_stat_bgwriter schema. */
  snapshot(): PgStatBgwriterRow {
    return {
      checkpoints_timed: this.checkpointsTimed,
      checkpoints_req: this.checkpointsReq,
      buffers_checkpoint: this.buffersCheckpoint,
      buffers_clean: this.buffersClean,
      buffers_backend: this.buffersBackend,
      buffers_backend_fsync: this.buffersBackendFsync,
      buffers_alloc: this.buffersAlloc,
      maxwritten_clean: this.maxwrittenClean,
      stats_reset: this.lastReset.toISOString(),
    };
  }

  /** Reset all counters. */
  reset(): void {
    this.checkpointsTimed = 0;
    this.checkpointsReq = 0;
    this.buffersCheckpoint = 0;
    this.buffersClean = 0;
    this.buffersBackend = 0;
    this.buffersBackendFsync = 0;
    this.buffersAlloc = 0;
    this.maxwrittenClean = 0;
    this.lastReset = new Date();
    logger.info('pg_stat_bgwriter stats reset');
  }
}
