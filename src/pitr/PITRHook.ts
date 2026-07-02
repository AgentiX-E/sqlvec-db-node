/**
 * PITRHook — Raft apply callback integration for PITR WAL capture.
 *
 * Intercepts the RaftGroup's apply callback to capture every committed
 * entry into the PITR WAL before (or concurrently with) state machine
 * application. This ensures the PITR WAL is always ahead of or in sync
 * with the actual database state.
 *
 * Phase 1: Core Infrastructure
 *
 * @see design-pitr.md §5.2 for interception point rationale
 */

import { PITRWriter } from './PITRWriter';
import { PinoLogger } from '../monitoring/PinoLogger';

const logger = PinoLogger.forComponent('PITRHook');

/**
 * Integration hook between RaftGroup's apply callback and the PITR WAL.
 *
 * Usage:
 *   const hook = new PITRHook('/path/to/pitr-archive');
 *   // In RaftGroup's applyHandler:
 *   hook.onApply(shardId, raftIndex, raftTerm, data);
 *   // State machine apply happens here
 *   hook.flush(); // On shutdown or snapshot
 */
export class PITRHook {
  private writer: PITRWriter;
  private _enabled = true;

  constructor(archiveDir: string) {
    this.writer = new PITRWriter(archiveDir);
    logger.info('PITRHook initialized');
  }

  /**
   * Called by RaftGroup's applyHandler after each committed entry.
   *
   * Captures the entry data into the PITR WAL. The WAL entry is written
   * before the state machine apply to ensure no committed entry is lost
   * in case of a crash.
   *
   * @param shardId  - Shard/partition identifier
   * @param raftIndex - Raft log index of the committed entry
   * @param raftTerm  - Raft term at the time of commitment
   * @param data      - Raw JSON string of the applied entry
   */
  onApply(
    shardId: string,
    raftIndex: number,
    raftTerm: number,
    data: string,
  ): void {
    if (!this._enabled) return;
    this.writer.append(raftIndex, raftTerm, shardId, data);
  }

  /**
   * Force-flush the current WAL segment buffer to disk.
   * Should be called before Raft snapshots to ensure all entries
   * up to the snapshot index are durable.
   */
  flush(): void {
    this.writer.flushSegment();
    logger.info('PITRHook flushed');
  }

  /**
   * Close the hook, flushing all buffered entries and releasing resources.
   * After close(), the hook should not be used further.
   */
  close(): void {
    this.writer.close();
    this._enabled = false;
    logger.info('PITRHook closed');
  }

  /**
   * Enable WAL capture.
   */
  enable(): void {
    this._enabled = true;
  }

  /**
   * Disable WAL capture.
   * While disabled, onApply() calls are silently ignored.
   */
  disable(): void {
    this._enabled = false;
  }

  /**
   * Check if the hook is currently enabled.
   */
  get enabled(): boolean {
    return this._enabled;
  }

  /**
   * Get the underlying PITRWriter (for direct access if needed).
   */
  getWriter(): PITRWriter {
    return this.writer;
  }
}
