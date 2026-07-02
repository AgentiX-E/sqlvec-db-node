/**
 * Recovery — Crash recovery and WAL replay utilities.
 *
 * @module recovery
 */

export { WalRecordReader, type CheckpointRecord, type RecoveryWalRecord } from './WalRecordReader';
export {
  MvccCrashRecovery,
  type RecoveryResult,
  type ReplayProgress,
  type ReconstructedRowVersion,
} from './MvccCrashRecovery';
export {
  PhysicalWalReplayer,
  ReplayState,
  type ReplayerOptions,
  type ReplayStatus,
  type ReplayerDatabase,
  lsnToNumber,
  numberToLSN,
  decodeTableName,
  parseHeapInsertPayload,
  parseHeapDeletePayload,
  parseHeapUpdatePayload,
  parseCommitPayload,
  parseAbortPayload,
  parseCheckpointPayload,
} from './PhysicalWalReplayer';
