/**
 * DeadlockDetector — Wait-For Graph based deadlock detection
 *
 * Tracks which sessions are waiting for which resources and which sessions
 * hold which resources. Detects cycles in the wait-for graph using DFS.
 *
 * Usage:
 *   const detector = new DeadlockDetector();
 *   detector.reportWait('sessA', 'shard-1', 'txn-1');
 *   detector.reportHold('sessA', ['shard-1'], 'txn-1');
 *   detector.reportWait('sessB', 'shard-1', 'txn-2');
 *   detector.reportHold('sessB', ['shard-2'], 'txn-2');
 *   const cycles = detector.detectDeadlocks();
 */

export interface LockWaiter {
  sessionId: string;
  waitingFor: string;     // resource (shard ID, row key, etc.)
  startedAt: number;      // epoch ms
  transactionId: string;
}

export interface LockHolder {
  sessionId: string;
  holds: string[];        // resources held
  transactionId: string;
}

export interface DeadlockCycle {
  cycle: string[];        // session IDs in order
  resources: string[];    // resources involved
  victim: string;         // suggested victim session
  detectedAt: number;
}

export class DeadlockDetector {
  private waiters: Map<string, LockWaiter>;   // sessionId → waiter
  private holders: Map<string, LockHolder>;   // sessionId → holder

  constructor() {
    this.waiters = new Map();
    this.holders = new Map();
  }

  /**
   * Report a session waiting for a resource.
   */
  reportWait(sessionId: string, resource: string, transactionId: string): void {
    this.waiters.set(sessionId, {
      sessionId,
      waitingFor: resource,
      startedAt: Date.now(),
      transactionId,
    });
  }

  /**
   * Report a session holding resources.
   */
  reportHold(sessionId: string, resources: string[], transactionId: string): void {
    this.holders.set(sessionId, {
      sessionId,
      holds: [...resources],
      transactionId,
    });
  }

  /**
   * Release all resources for a session (on transaction end/abort).
   */
  releaseSession(sessionId: string): void {
    this.waiters.delete(sessionId);
    this.holders.delete(sessionId);
  }

  /**
   * Detect cycles using DFS from each waiter.
   * Returns all deadlock cycles found.
   */
  detectDeadlocks(): DeadlockCycle[] {
    const cycles: DeadlockCycle[] = [];
    const sessionIds = Array.from(this.waiters.keys());
    const visited = new Set<string>();
    const recStack = new Set<string>();
    const path: string[] = [];

    for (const sessionId of sessionIds) {
      if (!visited.has(sessionId)) {
        this.dfsCycle(sessionId, visited, recStack, path, cycles);
      }
    }

    return cycles;
  }

  /**
   * DFS traversal to find cycles in the wait-for graph.
   * Edge: waiter[A] → holder[B] if A waits for a resource that B holds.
   */
  private dfsCycle(
    current: string,
    visited: Set<string>,
    recStack: Set<string>,
    path: string[],
    cycles: DeadlockCycle[],
  ): boolean {
    visited.add(current);
    recStack.add(current);
    path.push(current);

    const waiter = this.waiters.get(current);
    if (waiter) {
      // Find all sessions that hold the resource this session is waiting for
      const blockers = this.findBlockers(waiter.waitingFor);
      for (const blocker of blockers) {
        if (blocker === current) {
          // Self-wait detected
          cycles.push({
            cycle: [current],
            resources: [waiter.waitingFor],
            victim: current,
            detectedAt: Date.now(),
          });
          path.pop();
          recStack.delete(current);
          return true;
        }

        if (!visited.has(blocker)) {
          if (this.dfsCycle(blocker, visited, recStack, path, cycles)) {
            path.pop();
            recStack.delete(current);
            return true;
          }
        } else if (recStack.has(blocker)) {
          // Found a cycle: build the cycle from blocker → ... → current
          const cycleStart = path.indexOf(blocker);
          const cycleSlice = path.slice(cycleStart);
          const cycleResources: string[] = [];

          for (let i = 0; i < cycleSlice.length; i++) {
            const sid = cycleSlice[i];
            const w = this.waiters.get(sid);
            const h = this.holders.get(sid);
            if (w) cycleResources.push(w.waitingFor);
            else if (h && h.holds.length > 0) cycleResources.push(h.holds[0]);
          }

          const victim = this.selectVictim(cycleSlice);
          cycles.push({
            cycle: cycleSlice,
            resources: cycleResources,
            victim,
            detectedAt: Date.now(),
          });
          path.pop();
          recStack.delete(current);
          return true;
        }
      }
    }

    path.pop();
    recStack.delete(current);
    return false;
  }

  /**
   * Find all sessions holding a given resource.
   */
  private findBlockers(resource: string): string[] {
    const blockers: string[] = [];
    for (const [, holder] of this.holders) {
      if (holder.holds.includes(resource)) {
        blockers.push(holder.sessionId);
      }
    }
    return blockers;
  }

  /**
   * Select a victim from a deadlocked cycle.
   * Strategy: abort the session with the youngest transaction (smallest startedAt).
   */
  private selectVictim(cycleSessionIds: string[]): string {
    let victim = cycleSessionIds[0];
    let youngestStart = this.waiters.get(victim)?.startedAt ?? Infinity;

    for (const sid of cycleSessionIds) {
      const waiter = this.waiters.get(sid);
      const holder = this.holders.get(sid);
      const startedAt = waiter?.startedAt ?? holder ? 0 : Infinity;

      if (startedAt < youngestStart) {
        youngestStart = startedAt;
        victim = sid;
      }
    }

    return victim;
  }

  /**
   * Check if a specific wait would cause deadlock.
   */
  wouldCauseDeadlock(
    sessionId: string,
    resource: string,
  ): { deadlock: boolean; cycle: string[] } {
    // Temporarily add the wait
    const wasWaiting = this.waiters.has(sessionId);
    const oldWaiter = this.waiters.get(sessionId);

    this.reportWait(sessionId, resource, oldWaiter?.transactionId ?? 'simulated');

    const cycles = this.detectDeadlocks();
    const involvingSession = cycles.find(c => c.cycle.includes(sessionId));

    // Remove the temporary wait
    if (wasWaiting && oldWaiter) {
      this.waiters.set(sessionId, oldWaiter);
    } else {
      this.waiters.delete(sessionId);
    }

    if (involvingSession) {
      return { deadlock: true, cycle: involvingSession.cycle };
    }
    return { deadlock: false, cycle: [] };
  }

  /**
   * Get all registered waiters.
   */
  getWaiters(): Map<string, LockWaiter> {
    return new Map(this.waiters);
  }

  /**
   * Get all registered holders.
   */
  getHolders(): Map<string, LockHolder> {
    return new Map(this.holders);
  }
}
