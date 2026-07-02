/**
 * WALStreamContext — Type definitions for replication protocol streaming.
 *
 * Defines the context object returned by START_REPLICATION for managing
 * an active WAL streaming session.
 *
 * @module WALStreamContext
 */

export interface WALStreamContext {
  /** The starting LSN for this stream */
  startLsn: string;
  /** The ending LSN (latest available WAL position) */
  endLsn: string;
  /** Timeline ID */
  timeline: number;
  /** Unique identifier for this streaming session */
  sessionId: string;
  /** Timestamp when the stream started (epoch ms) */
  startedAt: number;
  /** Whether the stream is currently active */
  active: boolean;
  /** Any error message if the stream failed */
  error?: string;
}
