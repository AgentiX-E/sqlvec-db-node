import { PinoLogger } from '../monitoring/PinoLogger';
import { UpgradeManager, UpgradeShardConfig, UpgradeShardStatus } from './UpgradeManager';

/**
 * Configuration for a multi-shard rolling upgrade.
 */
export interface MultiShardUpgradeConfig {
  /** List of shard configurations to upgrade */
  shards: UpgradeShardConfig[];
  /** Maximum number of shards to upgrade concurrently */
  concurrentUpgrades: number;
  /** Global timeout in milliseconds for the entire upgrade process */
  globalTimeoutMs: number;
}

/**
 * Coordinates upgrades across multiple shards with configurable concurrency,
 * graceful degradation, and global timeout.
 *
 * If one shard fails, the others continue unaffected. The caller receives a
 * comprehensive status map for all shards and can decide whether to roll back.
 *
 * @example
 * ```ts
 * const coordinator = new UpgradeCoordinator(logger);
 * const results = await coordinator.upgradeAll({
 *   shards: [
 *     { shardName: 'shard-a', dbPath: '/data/a.db', backupDir: '/backups', migrationSql: [] },
 *     { shardName: 'shard-b', dbPath: '/data/b.db', backupDir: '/backups', migrationSql: [] },
 *   ],
 *   concurrentUpgrades: 2,
 *   globalTimeoutMs: 120_000,
 * });
 * ```
 */
export class UpgradeCoordinator {
  private upgradeManager: UpgradeManager;

  constructor(private logger: PinoLogger) {
    this.upgradeManager = new UpgradeManager(logger);
  }

  /**
   * Upgrade all shards according to the given configuration.
   *
   * Behavior:
   * - Shards are upgraded concurrently up to `concurrentUpgrades` at once.
   * - If any shard fails, the remaining shards continue unaffected.
   * - If the global timeout is exceeded, remaining shards are marked as failed
   *   with a timeout error.
   *
   * @returns A map of shardName → UpgradeShardStatus for every shard.
   */
  async upgradeAll(
    config: MultiShardUpgradeConfig,
  ): Promise<Map<string, UpgradeShardStatus>> {
    const { shards, concurrentUpgrades, globalTimeoutMs } = config;
    const results = new Map<string, UpgradeShardStatus>();

    if (shards.length === 0) {
      this.logger.info('upgradeAll: no shards to upgrade');
      return results;
    }

    this.logger.info(
      { shardCount: shards.length, concurrentUpgrades, globalTimeoutMs },
      'upgradeAll: starting multi-shard upgrade',
    );

    // Global timeout controller
    const timeout = AbortSignal.timeout(globalTimeoutMs);
    const deadline = Date.now() + globalTimeoutMs;

    // Semaphore for concurrency control
    let activeCount = 0;
    let nextIndex = 0;
    const completedCount = shards.length;

    // Wait queue for concurrency
    const acquireSlot = (): Promise<void> => {
      if (activeCount < concurrentUpgrades) {
        activeCount++;
        return Promise.resolve();
      }
      return new Promise<void>(resolve => {
        const check = () => {
          if (activeCount < concurrentUpgrades) {
            activeCount++;
            resolve();
          } else {
            setTimeout(check, 10);
          }
        };
        setTimeout(check, 10);
      });
    };

    const releaseSlot = (): void => {
      activeCount--;
    };

    // Start all upgrades in parallel, limited by concurrency
    const upgradePromises: Promise<void>[] = shards.map(async (shardConfig) => {
      // Initialize pending status
      results.set(shardConfig.shardName, {
        shardName: shardConfig.shardName,
        phase: 'pending',
      });

      await acquireSlot();

      try {
        // Check global timeout
        if (Date.now() >= deadline || timeout.aborted) {
          results.set(shardConfig.shardName, {
            shardName: shardConfig.shardName,
            phase: 'failed',
            error: '42P19: upgrade cancelled due to global timeout',
          });
          return;
        }

        const status = await this.upgradeManager.upgradeShard(shardConfig);
        results.set(shardConfig.shardName, status);
      } catch (err: any) {
        results.set(shardConfig.shardName, {
          shardName: shardConfig.shardName,
          phase: 'failed',
          error: err.message || String(err),
        });
      } finally {
        releaseSlot();
      }
    });

    await Promise.all(upgradePromises);

    // Summarise results
    const completed = Array.from(results.values()).filter(
      s => s.phase === 'completed',
    ).length;
    const failed = Array.from(results.values()).filter(
      s => s.phase === 'failed' || s.phase === 'rolled-back',
    ).length;
    const skipped = Array.from(results.values()).filter(
      s => s.phase === 'pending',
    ).length;

    this.logger.info(
      { total: shards.length, completed, failed, skipped },
      'upgradeAll: multi-shard upgrade finished',
    );

    return results;
  }
}
