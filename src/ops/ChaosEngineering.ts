import { PinoLogger } from '../monitoring/PinoLogger';

/**
 * RH18: Chaos engineering / cross-DC network latency simulation
 *
 * ## Background
 * Production database systems must be resilient to network failures, latency
 * spikes, and partial cluster failures. PostgreSQL-based distributed systems
 * use chaos engineering to validate their fault tolerance by deliberately
 * injecting failures:
 * - Network partition: drop connections between nodes
 * - Latency spikes: add artificial delay to queries
 * - Node failure: kill a replica process
 * - Disk failure: simulate full or slow disk
 *
 * ## SQLite context
 * For sqlvec-db, chaos engineering applies to:
 * 1. **Connection drops**: Force-close SQLite connections mid-transaction
 *    and verify automatic recovery.
 * 2. **Latency injection**: Wrap SQLite calls with configurable delays to
 *    simulate high-latency storage (e.g., network-mounted SQLite files).
 * 3. **Shard failure**: Remove/unlink a shard file and observe how the
 *    query router handles the missing shard.
 * 4. **Corruption**: Intentionally corrupt a SQLite page and verify that
 *    integrity_check detects it and the system falls back gracefully.
 *
 * ## Implementation plan (future)
 * - Intercept the database driver calls (better-sqlite3) with a proxy that
 *   applies configurable delay and random failure injection.
 * - Use environment flags to enable/disable chaos without code changes.
 * - Log all injected failures for post-mortem analysis.
 *
 * @stub Ops layer feature — dangerous; must only run in non-production.
 */
export interface ChaosConfig {
  /** Master kill-switch — chaos is never active unless explicitly enabled */
  enabled: boolean;
  /** Artificial latency in milliseconds to add to every query */
  latencyMs: number;
  /** Probability (0.0–1.0) of injecting a failure per operation */
  failureRate: number;
}

interface LatencyFault {
  type: 'latency';
  shardId: string;
  delayMs: number;
  injectedAt: number;
}

interface CrashFault {
  type: 'crash';
  shardId: string;
  injectedAt: number;
}

interface PartitionFault {
  type: 'partition';
  partitionGroup: string[];
  injectedAt: number;
}

export type Fault = LatencyFault | CrashFault | PartitionFault;

export class ChaosEngineering {
  private readonly logger = PinoLogger.forComponent('ChaosEngineering');
  private config: ChaosConfig;
  private activeFaults: Map<string, Fault> = new Map();

  constructor(config: ChaosConfig) {
    this.config = { ...config };
  }

  injectFailure(): void {
    this.logger.warn('injectFailure stub called — no-op');
  }

  /**
   * Inject artificial latency on the specified shard.
   */
  async injectLatency(shardId: string, delayMs: number): Promise<void> {
    if (!this.config.enabled) {
      this.logger.warn('chaos engineering is disabled — call ignored');
      return;
    }
    const fault: LatencyFault = {
      type: 'latency',
      shardId,
      delayMs,
      injectedAt: Date.now(),
    };
    this.activeFaults.set(`latency:${shardId}`, fault);
    this.logger.warn({ shardId, delayMs }, 'injectLatency: latency injected');
    await this.sleep(delayMs);
  }

  /**
   * Simulate a crash on the specified shard.
   */
  async injectCrash(shardId: string): Promise<void> {
    if (!this.config.enabled) {
      this.logger.warn('chaos engineering is disabled — call ignored');
      return;
    }
    const fault: CrashFault = {
      type: 'crash',
      shardId,
      injectedAt: Date.now(),
    };
    this.activeFaults.set(`crash:${shardId}`, fault);
    this.logger.warn({ shardId }, 'injectCrash: crash injected');
    await this.sleep(100);
  }

  /**
   * Simulate a network partition for the given group of shard IDs.
   */
  async injectPartition(partitionGroup: string[]): Promise<void> {
    if (!this.config.enabled) {
      this.logger.warn('chaos engineering is disabled — call ignored');
      return;
    }
    const partitionId = 'partition:' + partitionGroup.sort().join(',');
    const fault: PartitionFault = {
      type: 'partition',
      partitionGroup: [...partitionGroup],
      injectedAt: Date.now(),
    };
    this.activeFaults.set(partitionId, fault);
    this.logger.warn({ partitionGroup }, 'injectPartition: network partition injected');
    await this.sleep(500);
  }

  /**
   * Reset (clear) faults for the given shard.
   */
  reset(shardId: string): void {
    const keysToDelete: string[] = [];
    for (const [key, fault] of this.activeFaults.entries()) {
      if (fault.type === 'latency' && fault.shardId === shardId) {
        keysToDelete.push(key);
      } else if (fault.type === 'crash' && fault.shardId === shardId) {
        keysToDelete.push(key);
      } else if (fault.type === 'partition' && fault.partitionGroup.includes(shardId)) {
        keysToDelete.push(key);
      }
    }
    for (const key of keysToDelete) {
      this.activeFaults.delete(key);
    }
    this.logger.info({ shardId, cleared: keysToDelete.length }, 'reset: faults cleared for shard');
  }

  /**
   * Get all active faults.
   */
  getActiveFaults(): Fault[] {
    return Array.from(this.activeFaults.values());
  }

  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}
