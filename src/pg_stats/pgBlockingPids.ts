/**
 * pgBlockingPids — PostgreSQL pg_blocking_pids() function compatibility.
 *
 * Detects blocking locks using lock manager state. Given a target PID,
 * returns the array of PIDs holding conflicting locks.
 *
 * PostgreSQL equivalent:
 *   SELECT pg_blocking_pids(12345);
 *   → {10001, 10002}
 *
 * Integrates with RowLockManager or any lock state provider.
 */

import { PinoLogger } from '../monitoring/PinoLogger';

const logger = PinoLogger.forComponent('pg-blocking-pids');

export interface BlockingRelationship {
  holderPid: number;
  waiterPid: number;
  resourceId: string;
  lockMode: string;
  sinceMs: number;
}

export class PgBlockingPids {
  /** waiterPid → Set<holderPid> */
  private blockingMap: Map<number, Map<number, BlockingRelationship>> = new Map();
  private lockCounters = { registered: 0, resolved: 0 };

  // ── Lock Management ──────────────────────────────────────────

  /**
   * Register a blocking relationship.
   */
  registerBlocking(
    holderPid: number,
    waiterPid: number,
    resourceId: string,
    lockMode: string = 'RowExclusive',
  ): void {
    if (!this.blockingMap.has(waiterPid)) {
      this.blockingMap.set(waiterPid, new Map());
    }

    const holders = this.blockingMap.get(waiterPid)!;
    if (!holders.has(holderPid)) {
      holders.set(holderPid, {
        holderPid,
        waiterPid,
        resourceId,
        lockMode,
        sinceMs: Date.now(),
      });
      this.lockCounters.registered++;
      logger.debug({ holderPid, waiterPid, resourceId }, 'Blocking relationship registered');
    }
  }

  /**
   * Remove a blocking relationship (lock released).
   */
  unregisterBlocking(holderPid: number, waiterPid: number): void {
    const holders = this.blockingMap.get(waiterPid);
    if (holders) {
      if (holders.delete(holderPid)) {
        this.lockCounters.resolved++;
      }
      if (holders.size === 0) {
        this.blockingMap.delete(waiterPid);
      }
    }
  }

  /**
   * Remove all blocking entries for a PID (session disconnected).
   */
  removeSession(pid: number): void {
    this.blockingMap.delete(pid);
    for (const [, holders] of this.blockingMap) {
      holders.delete(pid);
    }
  }

  // ── Query ────────────────────────────────────────────────────

  /**
   * Get the list of PIDs blocking the given PID.
   * This implements pg_blocking_pids(pid).
   */
  getBlockingPids(pid: number): number[] {
    const holders = this.blockingMap.get(pid);
    if (!holders || holders.size === 0) return [];
    return Array.from(holders.keys()).sort((a, b) => a - b);
  }

  /**
   * Get all blocking relationships for a PID (including details).
   */
  getBlockingDetails(pid: number): BlockingRelationship[] {
    const holders = this.blockingMap.get(pid);
    if (!holders) return [];
    return Array.from(holders.values());
  }

  /**
   * Get all current blocking relationships.
   */
  getAllBlockingRelationships(): BlockingRelationship[] {
    const all: BlockingRelationship[] = [];
    for (const [, holders] of this.blockingMap) {
      for (const [, rel] of holders) {
        all.push(rel);
      }
    }
    return all;
  }

  /**
   * Count of currently blocked PIDs.
   */
  getBlockedCount(): number {
    return this.blockingMap.size;
  }

  /**
   * Count of total lock contention events.
   */
  getLockCounters(): { registered: number; resolved: number; active: number } {
    return {
      ...this.lockCounters,
      active: this.getBlockedCount(),
    };
  }

  // ─── Cycle Detection ──────────────────────────────────────────

  /**
   * Detect deadlock cycles in the current blocking graph.
   * Uses DFS-based cycle detection.
   */
  detectDeadlocks(): number[][] {
    const cycles: number[][] = [];

    const dfs = (
      startPid: number,
      currentPid: number,
      visited: Set<number>,
      path: number[],
    ): void => {
      if (visited.has(currentPid)) return;
      visited.add(currentPid);

      const holders = this.blockingMap.get(currentPid);
      if (!holders) return;

      for (const holderPid of holders.keys()) {
        if (holderPid === startPid) {
          // Cycle found: path + startPid
          cycles.push([...path, startPid]);
          return;
        }
        if (!visited.has(holderPid)) {
          dfs(startPid, holderPid, visited, [...path, holderPid]);
        }
      }
    };

    for (const waiterPid of this.blockingMap.keys()) {
      const visited = new Set<number>();
      dfs(waiterPid, waiterPid, visited, [waiterPid]);
    }

    return cycles;
  }

  /** Clear all state. */
  clear(): void {
    this.blockingMap.clear();
    this.lockCounters = { registered: 0, resolved: 0 };
  }
}
