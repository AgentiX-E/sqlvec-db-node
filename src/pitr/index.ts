/**
 * PITR - Point-in-Time Recovery module for SqlVec DB.
 *
 * Exports all PITR components for use throughout the system.
 *
 * Phases:
 *   1 - Core Infrastructure (Writer, Reader, Manifest)
 *   2 - Recovery Engine (Manager, Verifier)
 *   3 - Retention & Lifecycle (GC, Retention Policy)
 *   4 - Shard Integration (PITRManager + raftGroupManager)
 *   5 - Remote Storage (RemoteStorage)
 *   6 - PITR API (HTTP API server)
 *   7 - WAL Pipeline (PITRWalBridge, WalArchiveBridge)
 */

export { PITRWriter } from './PITRWriter';
export { PITRReader } from './PITRReader';
export { WALManifest } from './WALManifest';
export { PITRVerifier } from './PITRVerifier';
export { PITRManager, PITRManagerConfig, PITRStatus } from './PITRManager';
export { PITRGC, PITRGCConfig, PITRGCSummary } from './PITRGC';
export { PITRRetentionPolicy, PITRRetentionRule } from './PITRRetentionPolicy';
export { PITRRemoteStorage, PITRRemoteStorageConfig, RemoteStorageBackend, RemoteStorageStatus } from './PITRRemoteStorage';
export { PITRApi, PITRApiConfig } from './PITRApi';
export { PITRConfigManager, PITRConfigEvent, ConfigChangeHandler } from './PITRConfigManager';
export { pitrEncrypt, pitrDecrypt } from './PITRCrypto';
export {
  PitrWALEntry,
  PitrTarget,
  SegmentMeta,
  LSN,
  CRC32CHex,
  DEFAULT_SEGMENT_SIZE,
  segmentFilename,
} from './types';
export { ContinuousWalArchiver, ContinuousWalArchiverConfig } from './ContinuousWalArchiver';
export { WalLevelManager, LogicalWalRecord } from './WalLevelManager';
export { PITRWalBridge } from './PITRWalBridge';
export { WalArchiveBridge, WalArchiveBridgeConfig } from './WalArchiveBridge';
