/**
 * PITRRaftSync — Post-restore Raft state synchronization.
 *
 * After a PITR recovery restores a shard's database to a specific
 * point in time, the Raft log must be reset to match. This prevents
 * Raft from replaying old entries that are now part of the PITR WAL
 * and ensures the Raft group stays consistent with the restored
 * database state.
 *
 * Phase 4: Raft Integration & Safety
 *
 * @see design-pitr.md §7 Phase 4 Task 4.3
 * @see design-pitr.md §5.6 for recovery completeness invariant
 */

import { PinoLogger } from '../monitoring/PinoLogger';

const logger = PinoLogger.forComponent('PITRRaftSync');

/**
 * Interface for the subset of SqliteStorage operations needed for
 * Raft state reset. This keeps the coupling loose and testable.
 */
export interface RaftStorageForReset {
  /** Delete all raft log entries. */
  truncateAll(): Promise<void>;
  /** Persist a new Raft hard state (term, vote, commit). */
  setHardState(state: { currentTerm: number; votedFor: string | null; commit: number }): Promise<void>;
}

/**
 * Handles post-PITR-restore Raft synchronization.
 *
 * After the shard's database has been restored to a target raft index,
 * this class resets the Raft log state so the node can safely rejoin
 * the cluster as a follower without replaying already-applied entries.
 *
 * Usage:
 * ```ts
 * const raftSync = new PITRRaftSync();
 * await raftSync.resetRaftState(
 *   sqliteStorage,
 *   targetRaftIndex,  // the index at which the restore happened
 *   targetRaftTerm,   // the term at which the restore happened
 * );
 * ```
 */
export class PITRRaftSync {
  private logger = PinoLogger.forComponent('PITRRaftSync');

  /**
   * After a PITR restore, reset Raft hard state to match the restored point.
   *
   * This performs two critical operations:
   *   1. Clears all raft log entries — they are either already applied
   *      to the state machine (from the restore) or superseded by the
   *      restored state.
   *   2. Sets the hard state (current_term, voted_for, commit) to reflect
   *      the restored point, so Raft knows not to replay entries ≤ commit.
   *
   * After this method, the node should start as a follower and catch up
   * from the leader for any entries after the restore point.
   *
   * @param sqliteStorage   - The Raft storage backend to reset
   * @param targetRaftIndex - The raft index at which the PITR restore occurred
   * @param targetRaftTerm  - The raft term at which the PITR restore occurred
   */
  async resetRaftState(
    sqliteStorage: RaftStorageForReset,
    targetRaftIndex: number,
    targetRaftTerm: number,
  ): Promise<void> {
    // 1. Clear all raft log entries — they are reflected in the restored DB
    await sqliteStorage.truncateAll();

    // 2. Set the hard state to match (current_term, voted_for, commit)
    //    - currentTerm matches the restore point's term
    //    - votedFor is cleared (follower starts fresh)
    //    - commit matches the restore point, so Raft won't re-apply ≤ this
    await sqliteStorage.setHardState({
      currentTerm: targetRaftTerm,
      votedFor: null,
      commit: targetRaftIndex,
    });

    this.logger.info(
      `Raft state reset to index=${targetRaftIndex} term=${targetRaftTerm}`,
    );
  }
}
