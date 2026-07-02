/**
 * HealthCheckServer — Lightweight HTTP health check endpoint.
 *
 * Provides endpoints using node:http (no Express dependency):
 *   GET /healthz  → { status: 'ok', version: '0.1.0', uptime: <seconds> }
 *   GET /livez    → { status: 'ok' | 'error', checks: { sqlite: boolean } }
 *   GET /readyz   → { status: 'ready', leader: <nodeId>, shardCount: <n>[, checks: {...}] }
 *   GET /raft/status → { shards: RaftHealthStatus[] }
 *   GET /raft/peers  → { shards: RaftPeerStatus[] }
 *
 * The readyz endpoint accepts an optional health check callback to verify
 * Raft leader status and shard availability.
 *
 * The livez and readyz endpoints can also accept dependency check functions
 * via the constructor `deps` parameter for automatic SQLite, Raft, and
 * ConnectionPool verification.
 *
 * Usage:
 *   const hcs = new HealthCheckServer({ port: 8080 });
 *   hcs.setReadyCheck(async () => ({ leader: 'node-1', shardCount: 4 }));
 *   await hcs.start();
 *   // ... later ...
 *   await hcs.stop();
 */

import { createServer, type Server, type IncomingMessage, type ServerResponse } from 'http';
import { type AddressInfo } from 'net';

import { createTerminus } from '@godaddy/terminus';

import { PinoLogger } from './PinoLogger';
import type { RaftHealthStatus, RaftPeerStatus } from '../consensus/RaftGroupManager';
import type { ActiveQueryRegistry } from './ActiveQueryRegistry';
import type { HASLAMetrics } from './HASLAMetrics';
import { isRaftWasmUnhealthy, getRaftWasmUnhealthyReason, performWasmCheck } from '../consensus/RaftWasmHealthCheck';
import type { RaftAdapter } from '../consensus/RaftAdapter';
const logger = PinoLogger.forComponent('HealthCheck');

// ── Types ────────────────────────────────────────────────────────

export interface HealthCheckConfig {
  /** HTTP listen port (default: 9090) */
  port?: number;
  /** Listen host (default: '127.0.0.1') */
  host?: string;
  /** Application version reported in /healthz */
  version?: string;
  /** Active query registry for long-running query tracking (optional) */
  activeQueryRegistry?: ActiveQueryRegistry;
  /** Long-running query threshold in ms (default: 60000 = 60s) */
  longRunningThresholdMs?: number;
  /** Long-running query polling interval in ms (default: 30000 = 30s) */
  longRunningPollIntervalMs?: number;
}

/** Functions that probe real dependency health. */
export interface DepsHealthCheck {
  /** Check SQLite connectivity (e.g. SELECT 1). Return true if alive. */
  sqlite?: () => Promise<boolean>;
  /** Return Raft status for readiness evaluation. */
  raftStatus?: () => Promise<any>;
  /** Return current ConnectionPool connection count. */
  poolConnections?: () => number;
  /**
   * Raft WASM health check — pings the raft-logic WASM binary and returns
   * { ok: boolean, error?: string, timestamp: number }.
   * When set, this check is included in /livez and /readyz responses.
   * Replaces the static isRaftWasmUnhealthy() global check so that the
   * probe timeout logic (<2s) is executed on every probe.
   */
  raftWasmCheck?: () => Promise<{ ok: boolean; error?: string; timestamp: number }>;
}

export interface ReadyCheckResult {
  status: 'ready' | 'not_ready';
  leader?: string;
  shardCount?: number;
  reason?: string;
}

export type ReadyCheckFn = () => Promise<ReadyCheckResult>;

// ── Helpers ──────────────────────────────────────────────────────

interface CheckResult {
  /** Human-readable check name */
  name: string;
  /** Whether the check passed */
  ok: boolean;
  /** Optional detail on failure */
  error?: string;
  /** Additional metadata (e.g. pool connection count) */
  detail?: number;
}

/**
 * Run a single dependency check with error handling.
 */
async function runCheck(name: string, fn: () => Promise<boolean>): Promise<CheckResult> {
  try {
    const ok = await fn();
    return { name, ok };
  } catch (err: any) {
    return { name, ok: false, error: err.message ?? String(err) };
  }
}

// ── Server ───────────────────────────────────────────────────────

export class HealthCheckServer {
  private server: Server;
  private config: HealthCheckConfig & Required<Omit<HealthCheckConfig, 'activeQueryRegistry'>>;
  private readyCheckFn: ReadyCheckFn | null = null;
  private raftStatusProvider: (() => Promise<RaftHealthStatus[]>) | null = null;
  private raftPeerProvider: (() => RaftPeerStatus[]) | null = null;
  private deps: DepsHealthCheck;
  private startTime: number = 0;
  /** ActiveQueryRegistry reference for long-running query tracking */
  private activeQueryRegistry: ActiveQueryRegistry | null = null;
  /** Long-running query threshold (ms) */
  private longRunningThresholdMs: number;
  /** Interval handle for periodic long-running query polling */
  private pollInterval: ReturnType<typeof setInterval> | null = null;
  /** Cached count of long-running queries (for /livez) */
  private longRunningCount: number = 0;
  /** Flag set on SIGTERM/SIGINT so endpoints can refuse traffic during graceful shutdown */
  private isShuttingDown: boolean = false;
  /** HA SLA metrics provider for /sla/metrics endpoint */
  private slaMetrics: HASLAMetrics | null = null;

  constructor(config: HealthCheckConfig = {}, deps?: DepsHealthCheck) {
    this.config = {
      port: config.port ?? 9090,
      host: config.host ?? '127.0.0.1',
      version: config.version ?? '0.1.0',
      activeQueryRegistry: config.activeQueryRegistry as ActiveQueryRegistry | undefined,
      longRunningThresholdMs: config.longRunningThresholdMs ?? 60000,
      longRunningPollIntervalMs: config.longRunningPollIntervalMs ?? 30000,
    };
    this.activeQueryRegistry = this.config.activeQueryRegistry ?? null;
    this.longRunningThresholdMs = this.config.longRunningThresholdMs;
    this.deps = deps ?? {};

    this.server = createServer((req, res) => this.handleRequest(req, res));
    this.server.on('error', (err: Error) => {
      // Suppress ECONNRESET during shutdown
      if ((err as NodeJS.ErrnoException).code === 'ECONNRESET') return;
      logger.error('[HealthCheckServer] Server error:', err.message);
    });
  }

  /**
   * Register a callback for the /readyz endpoint.
   * If not set, /readyz returns { status: 'ready' } with no additional details.
   */
  setReadyCheck(fn: ReadyCheckFn): void {
    this.readyCheckFn = fn;
  }

  /**
   * Register a provider for Raft health status (used by GET /raft/status).
   * The provider should return an array of per-shard health status objects.
   * If not set, /raft/status returns an empty array.
   */
  setRaftStatusProvider(fn: () => Promise<RaftHealthStatus[]>): void {
    this.raftStatusProvider = fn;
  }

  /**
   * Register a provider for Raft peer status (used by GET /raft/peers).
   * The provider should return an array of per-shard peer status objects.
   * If not set, /raft/peers returns an empty array.
   */
  setRaftPeerProvider(fn: () => RaftPeerStatus[]): void {
    this.raftPeerProvider = fn;
  }

  /**
   * Register the HASLAMetrics instance for the /sla/metrics endpoint.
   */
  setSLAMetrics(metrics: HASLAMetrics): void {
    this.slaMetrics = metrics;
  }

  /**
   * Start the HTTP server, wire @godaddy/terminus health checks and
   * graceful shutdown, and begin long-running query polling.
   *
   * Terminus wraps the existing request listeners so /healthz and /livez
   * are intercepted with proper K8s probe semantics (status codes + verbatim
   * response bodies).  All other routes (/readyz, /raft/*) fall through to
   * the original handler unchanged.
   */
  start(): Promise<void> {
    return new Promise((resolve, reject) => {
      this.startTime = Date.now();
      this.server.listen(this.config.port, this.config.host, () => {
        const addr = this.server.address() as AddressInfo;
        logger.info(`[HealthCheckServer] Listening on ${addr.address}:${addr.port}`);

        // Wire Terminus for graceful shutdown and health checks.
        // Our existing request handler (from createServer) is wrapped by
        // terminus: for URLs that match a healthCheck key terminus intercepts
        // and replies with proper K8s status codes; non-matching URLs fall
        // through to our handler (including /readyz, /raft/*, and OPTIONS).
        createTerminus(this.server, {
          healthChecks: {},
          signals: ['SIGTERM', 'SIGINT'],
          beforeShutdown: async () => {
            logger.info('[HealthCheckServer] Shutdown signal received, draining connections...');
            this.isShuttingDown = true;
          },
          onSignal: async () => {
            logger.info('[HealthCheckServer] Server closed, cleaning up...');
            this.stopLongRunningPolling();
          },
          onShutdown: async () => {
            logger.info('[HealthCheckServer] Graceful shutdown complete.');
          },
          logger: (msg: string, err: Error) => {
            logger.error(`[HealthCheckServer] Terminus: ${msg}`, err?.message ?? String(err));
          },
        });

        // Start periodic polling for long-running queries
        this.startLongRunningPolling();

        resolve();
      });
      this.server.once('error', reject);
    });
  }

  /**
   * Gracefully stop the HTTP server and clean up polling interval.
   */
  stop(): Promise<void> {
    return new Promise((resolve, reject) => {
      this.stopLongRunningPolling();

      if (!this.server.listening) {
        resolve();
        return;
      }
      this.server.close((err) => {
        if (err) reject(err);
        else resolve();
      });
    });
  }

  /**
   * Run the Raft WASM health check if configured in deps.
   * Returns a CheckResult or null if no WASM check is configured.
   * Falls back to the static isRaftWasmUnhealthy() flag when the
   * dynamic check function is not available.
   */
  private async runRaftWasmCheck(): Promise<CheckResult | null> {
    if (this.deps.raftWasmCheck) {
      try {
        const result = await this.deps.raftWasmCheck();
        return {
          name: 'raft-wasm',
          ok: result.ok,
          error: result.error,
        };
      } catch (err: any) {
        return {
          name: 'raft-wasm',
          ok: false,
          error: err.message ?? String(err),
        };
      }
    }

    // Fallback: check the static global flag if no dynamic check is configured.
    // This is a secondary signal (no probe timeout) — prefer raftWasmCheck().
    if (isRaftWasmUnhealthy()) {
      const reason = getRaftWasmUnhealthyReason() ?? 'unknown';
      return {
        name: 'raft-wasm',
        ok: false,
        error: `Global unhealthy flag set: ${reason}`,
      };
    }

    return null;
  }

  /**
   * Get the actual listening port (useful when port=0 is used).
   */
  getPort(): number {
    const addr = this.server.address();
    if (addr && typeof addr === 'object') {
      return addr.port;
    }
    return this.config.port;
  }

  /**
   * Get the current count of long-running queries (for external consumers).
   */
  getLongRunningCount(): number {
    return this.longRunningCount;
  }

  // ── Long-Running Query Polling ─────────────────────────────────

  /**
   * Start the periodic polling interval for long-running queries.
   */
  private startLongRunningPolling(): void {
    this.stopLongRunningPolling(); // ensure no duplicate intervals

    if (!this.activeQueryRegistry) {
      logger.debug('[HealthCheckServer] No ActiveQueryRegistry configured; long-running query polling disabled.');
      return;
    }

    const intervalMs = this.config.longRunningPollIntervalMs;
    logger.info(`[HealthCheckServer] Starting long-running query polling every ${intervalMs}ms (threshold: ${this.longRunningThresholdMs}ms)`);

    // Do an immediate first check
    this.pollLongRunningQueries();

    this.pollInterval = setInterval(() => {
      this.pollLongRunningQueries();
    }, intervalMs);

    // Allow garbage collection – unref so the timer doesn't keep the process alive
    if (typeof this.pollInterval === 'object' && 'unref' in this.pollInterval) {
      this.pollInterval.unref();
    }
  }

  /**
   * Stop the periodic polling interval.
   */
  private stopLongRunningPolling(): void {
    if (this.pollInterval !== null) {
      clearInterval(this.pollInterval);
      this.pollInterval = null;
    }
  }

  /**
   * Poll the ActiveQueryRegistry for long-running queries and log warnings.
   */
  private pollLongRunningQueries(): void {
    if (!this.activeQueryRegistry) return;

    try {
      const longRunning = this.activeQueryRegistry.listLongRunning(this.longRunningThresholdMs);
      this.longRunningCount = longRunning.length;

      if (longRunning.length > 0) {
        logger.warn(
          `[HealthCheckServer] ${longRunning.length} long-running query(s) detected (threshold: ${this.longRunningThresholdMs}ms):`
        );
        for (const q of longRunning) {
          const elapsed = Date.now() - q.queryStart;
          logger.warn(
            `  queryId=${q.queryId} sql="${q.sql.substring(0, 200)}" elapsed=${elapsed}ms state=${q.state} user=${q.userId}`
          );
        }
      }
    } catch (err: any) {
      logger.error('[HealthCheckServer] Error polling ActiveQueryRegistry:', err.message);
    }
  }

  // ── Request Router ─────────────────────────────────────────────

  private async handleRequest(req: IncomingMessage, res: ServerResponse): Promise<void> {
    // CORS headers
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
    res.setHeader('Content-Type', 'application/json');

    if (req.method === 'OPTIONS') {
      res.writeHead(204);
      res.end();
      return;
    }

    try {
      const url = new URL(req.url ?? '/', `http://${req.headers.host ?? 'localhost'}`);

      switch (url.pathname) {
        case '/healthz':
          await this.handleHealthz(res);
          break;
        case '/livez':
          await this.handleLivez(res);
          break;
        case '/readyz':
          await this.handleReadyz(res);
          break;
        case '/raft/status':
          await this.handleRaftStatus(res);
          break;
        case '/raft/peers':
          await this.handleRaftPeers(res);
          break;
        case '/sla/metrics':
          await this.handleSLAMetrics(res);
          break;
        default:
          res.writeHead(404);
          res.end(JSON.stringify({ error: 'Not Found' }));
          break;
      }
    } catch (err) {
      res.writeHead(500);
      res.end(JSON.stringify({ error: 'Internal Server Error', detail: (err as Error).message }));
    }
  }

  // ── Handlers ───────────────────────────────────────────────────

  /**
   * GET /healthz — basic liveness (backward compatible).
   * Always returns 200 with version and uptime.
   */
  private async handleHealthz(res: ServerResponse): Promise<void> {
    const uptime = Math.floor((Date.now() - this.startTime) / 1000);
    res.writeHead(200);
    res.end(JSON.stringify({
      status: 'ok',
      version: this.config.version,
      uptime,
    }));
  }

  /**
   * GET /livez — dependency-aware liveness check.
   * Probes the optional sqlite dependency check function and aggregates results.
   * Includes long-running query count when ActiveQueryRegistry is configured.
   * Includes Raft WASM health check when configured.
   */
  private async handleLivez(res: ServerResponse): Promise<void> {
    const checks: CheckResult[] = [];

    if (this.deps.sqlite) {
      checks.push(await runCheck('sqlite', this.deps.sqlite));
    }

    // Add Raft WASM health check if configured
    const wasmCheck = await this.runRaftWasmCheck();
    if (wasmCheck) checks.push(wasmCheck);

    // Add long-running query check if registry is configured
    if (this.activeQueryRegistry) {
      const longRunning = this.activeQueryRegistry.listLongRunning(this.longRunningThresholdMs);
      this.longRunningCount = longRunning.length;
      checks.push({
        name: 'long-running-queries',
        ok: longRunning.length === 0,
        detail: this.longRunningCount,
        error: longRunning.length > 0 ? `${longRunning.length} query(s) exceed threshold` : undefined,
      });
    }

    // Overall status: ok if all checks passed, or no checks configured
    const allOk = checks.length === 0 || checks.every((c) => c.ok);
    const overall = allOk ? 'ok' : 'error';

    if (allOk) {
      res.writeHead(200);
    } else {
      res.writeHead(503);
    }

    res.end(JSON.stringify({ status: overall, checks }));
  }

  /**
   * GET /readyz — dependency-aware readiness check.
   *
   * When both a readyCheckFn and deps are available, the readyCheckFn takes
   * priority for the main status. Dependency checks are appended in a
   * `checks` field for observability.
   *
   * When only deps are provided (no readyCheckFn), dependency checks drive
   * the overall status.
   *
   * When neither is provided, the default "always ready" response is returned.
   */
  private async handleReadyz(res: ServerResponse): Promise<void> {
    // Run dependency checks in parallel if configured
    const depChecks: CheckResult[] = [];

    if (this.deps.sqlite) {
      depChecks.push(await runCheck('sqlite', this.deps.sqlite));
    }

    // Add Raft WASM health check if configured
    const wasmCheck = await this.runRaftWasmCheck();
    if (wasmCheck) depChecks.push(wasmCheck);

    let raftCheckOk = true;
    if (this.deps.raftStatus) {
      try {
        const status = await this.deps.raftStatus();
        depChecks.push({ name: 'raft', ok: true, detail: status });
      } catch (err: any) {
        depChecks.push({ name: 'raft', ok: false, error: err.message ?? String(err) });
        raftCheckOk = false;
      }
    }

    let poolConnectionCount: number | undefined;
    if (this.deps.poolConnections) {
      try {
        poolConnectionCount = this.deps.poolConnections();
        depChecks.push({ name: 'pool', ok: true, detail: poolConnectionCount });
      } catch (err: any) {
        depChecks.push({ name: 'pool', ok: false, error: err.message ?? String(err) });
      }
    }

    const depsAllOk = depChecks.length === 0 || depChecks.every((c) => c.ok);

    if (this.readyCheckFn) {
      // readyCheckFn takes priority for business-level readiness
      const result = await this.readyCheckFn();
      if (result.status === 'ready') {
        const body: Record<string, any> = {
          status: 'ready',
          leader: result.leader,
          shardCount: result.shardCount,
        };
        if (depChecks.length > 0) {
          body.checks = depChecks;
        }
        res.writeHead(200);
        res.end(JSON.stringify(body));
      } else {
        const body: Record<string, any> = {
          status: 'not_ready',
          reason: result.reason,
          leader: result.leader,
          shardCount: result.shardCount,
        };
        if (depChecks.length > 0) {
          body.checks = depChecks;
        }
        res.writeHead(503);
        res.end(JSON.stringify(body));
      }
    } else if (depChecks.length > 0) {
      // No readyCheckFn but deps provided — status driven by dependency health
      if (depsAllOk) {
        const uptime = Math.floor((Date.now() - this.startTime) / 1000);
        res.writeHead(200);
        res.end(JSON.stringify({
          status: 'ready',
          uptime,
          checks: depChecks,
        }));
      } else {
        res.writeHead(503);
        res.end(JSON.stringify({
          status: 'not_ready',
          reason: 'dependency check(s) failed',
          checks: depChecks,
        }));
      }
    } else {
      // No check function and no deps — always ready (backward compatible)
      const uptime = Math.floor((Date.now() - this.startTime) / 1000);
      res.writeHead(200);
      res.end(JSON.stringify({
        status: 'ready',
        uptime,
      }));
    }
  }

  private async handleRaftStatus(res: ServerResponse): Promise<void> {
    if (!this.raftStatusProvider) {
      res.writeHead(200);
      res.end(JSON.stringify({ shards: [] }));
      return;
    }
    try {
      const statuses = await this.raftStatusProvider();
      res.writeHead(200);
      res.end(JSON.stringify({ shards: statuses }));
    } catch (err: any) {
      res.writeHead(500);
      res.end(JSON.stringify({
        error: 'Failed to collect Raft status',
        detail: err.message,
      }));
    }
  }

  private async handleRaftPeers(res: ServerResponse): Promise<void> {
    if (!this.raftPeerProvider) {
      res.writeHead(200);
      res.end(JSON.stringify({ shards: [] }));
      return;
    }
    try {
      const peers = this.raftPeerProvider();
      res.writeHead(200);
      res.end(JSON.stringify({ shards: peers }));
    } catch (err: any) {
      res.writeHead(500);
      res.end(JSON.stringify({
        error: 'Failed to collect Raft peer status',
        detail: err.message,
      }));
    }
  }

  private async handleSLAMetrics(res: ServerResponse): Promise<void> {
    if (!this.slaMetrics) {
      res.writeHead(200);
      res.end(JSON.stringify({ configured: false, message: 'SLA metrics not configured' }));
      return;
    }
    try {
      const summary = this.slaMetrics.getSLASummary();
      const mtbf = this.slaMetrics.getMTBF();
      const mttr = this.slaMetrics.getMTTR();
      res.writeHead(200);
      res.end(JSON.stringify({
        configured: true,
        summary,
        mtbf,
        mttr,
        failureCounts: {
          hour: this.slaMetrics.getFailureCount('hour'),
          day: this.slaMetrics.getFailureCount('day'),
          week: this.slaMetrics.getFailureCount('week'),
          month: this.slaMetrics.getFailureCount('month'),
        },
      }));
    } catch (err: any) {
      res.writeHead(500);
      res.end(JSON.stringify({
        error: 'Failed to collect SLA metrics',
        detail: err.message,
      }));
    }
  }
}
