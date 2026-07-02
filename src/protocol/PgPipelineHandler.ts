/**
 * PgPipelineHandler — PG protocol pipeline support (Gap 14).
 *
 * PostgreSQL supports protocol pipelining where the client sends multiple
 * queries without waiting for individual responses. The server processes
 * them sequentially and flushes all responses on Sync.
 *
 * This module tracks pipelined Sync messages and aggregates responses.
 *
 * References:
 *   - PostgreSQL protocol docs: https://www.postgresql.org/docs/current/protocol-flow.html
 *   - PG pipelining (PG16+): https://www.postgresql.org/docs/current/protocol-flow-ext-query.html
 */

import { PinoLogger } from '../monitoring/PinoLogger';
import { encodeReadyForQuery } from './PgMessageHandler';

const logger = PinoLogger.forComponent('PgPipelineHandler');

// ── Types ────────────────────────────────────────────────────────

export interface PgPipelineState {
  /** Whether pipeline mode is active */
  pipelineMode: boolean;
  /** Number of pending Sync messages queued */
  pendingSync: number;
  /** Accumulated response buffers */
  pendingResponses: Buffer[];
  /** Transaction state after the last Sync */
  lastTxnState: 'I' | 'T' | 'E';
}

// ── PipelineHandler ──────────────────────────────────────────────

export class PgPipelineHandler {
  private state: PgPipelineState = {
    pipelineMode: false,
    pendingSync: 0,
    pendingResponses: [],
    lastTxnState: 'I',
  };

  /**
   * Enter pipeline mode.
   * Called when the client signals pipelining (multiple messages without waiting).
   */
  enterPipelineMode(): void {
    this.state.pipelineMode = true;
    logger.debug('Entered pipeline mode');
  }

  /**
   * Exit pipeline mode.
   * Flushes all pending responses.
   */
  exitPipelineMode(): Buffer[] {
    this.state.pipelineMode = false;
    const responses = this.flushPendingResponses();
    logger.debug({ responseCount: responses.length }, 'Exited pipeline mode');
    return responses;
  }

  /**
   * Process a Sync message in pipeline mode.
   * Instead of returning ReadyForQuery immediately, we queue it.
   *
   * @param txnState - Current transaction state ('I', 'T', or 'E')
   * @returns Buffers to send (empty if waiting for pipeline flush)
   */
  processSync(txnState: 'I' | 'T' | 'E'): Buffer[] {
    this.state.lastTxnState = txnState;

    if (this.state.pipelineMode) {
      // In pipeline mode: queue ReadyForQuery responses
      this.state.pendingSync++;
      this.state.pendingResponses.push(encodeReadyForQuery(txnState));
      logger.debug(
        { pendingSync: this.state.pendingSync, txnState },
        'Pipeline: queued ReadyForQuery on Sync',
      );
      // Return nothing yet — wait for flush
      return [];
    }

    // Normal (non-pipeline) mode: respond immediately
    return [encodeReadyForQuery(txnState)];
  }

  /**
   * Flush all pending pipeline responses.
   * Called when:
   *   - A Flush ('H') message is received
   *   - Pipeline mode is exited
   *   - An explicit sync-flush is requested
   *
   * @returns All accumulated response buffers
   */
  flushPendingResponses(): Buffer[] {
    const responses = [...this.state.pendingResponses];
    this.state.pendingResponses = [];
    this.state.pendingSync = 0;
    return responses;
  }

  /**
   * Handle a Flush ('H') message.
   * In pipeline mode, flush all buffered responses.
   *
   * @returns Buffered responses or empty array
   */
  handleFlush(): Buffer[] {
    if (!this.state.pipelineMode) {
      return [];
    }
    return this.flushPendingResponses();
  }

  /**
   * Check if pipeline mode is active.
   */
  isPipelineMode(): boolean {
    return this.state.pipelineMode;
  }

  /**
   * Get current pipeline state (for diagnostics).
   */
  getState(): Readonly<PgPipelineState> {
    return { ...this.state };
  }

  /**
   * Reset all pipeline state.
   */
  reset(): void {
    this.state = {
      pipelineMode: false,
      pendingSync: 0,
      pendingResponses: [],
      lastTxnState: 'I',
    };
  }
}
