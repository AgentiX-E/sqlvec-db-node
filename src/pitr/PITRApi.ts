/**
 * PITRApi — HTTP API endpoints for PITR management.
 *
 * Provides a RESTful HTTP API for triggering PITR recovery, managing
 * restore points, checking status, and controlling remote sync/GC.
 *
 * Uses Node.js built-in `http` module (no Express dependency).
 *
 * Phase 6: PITR API
 *
 * @see design-pitr.md §7 Phase 6
 */

import * as http from 'http';
import * as url from 'url';
import { PinoLogger } from '../monitoring/PinoLogger';
import {
  PITRManager,
  PITRStatus,
} from './PITRManager';
import {
  PitrTarget,
} from './types';

const logger = PinoLogger.forComponent('PITRApi');

// ── API Config ───────────────────────────────────────────────────────────────

export interface PITRApiConfig {
  /** HTTP server listen host (default: '127.0.0.1') */
  host?: string;
  /** HTTP server listen port (default: 9650) */
  port?: number;
}

// ── PITRApi ──────────────────────────────────────────────────────────────────

/**
 * PITR HTTP API server.
 *
 * Usage:
 * ```ts
 * const api = new PITRApi(manager, { host: '127.0.0.1', port: 9650 });
 * api.start();
 * // ...
 * api.stop();
 * ```
 */
export class PITRApi {
  private manager: PITRManager;
  private config: PITRApiConfig;
  private server: http.Server | null = null;

  constructor(manager: PITRManager, config: PITRApiConfig = {}) {
    this.manager = manager;
    this.config = {
      host: config.host ?? '127.0.0.1',
      port: config.port ?? 9650,
    };
  }

  /**
   * Start the PITR HTTP API server.
   */
  async start(): Promise<void> {
    return new Promise((resolve) => {
      this.server = http.createServer((req, res) => this.handleRequest(req, res));

      this.server.listen(this.config.port, this.config.host, () => {
        logger.info(
          `PITR API server listening on http://${this.config.host}:${this.config.port}`,
        );
        resolve();
      });

      // Unref so it doesn't prevent process exit
      this.server.unref();
    });
  }

  /**
   * Stop the PITR HTTP API server.
   */
  async stop(): Promise<void> {
    return new Promise((resolve) => {
      if (this.server) {
        this.server.close(() => {
          logger.info('PITR API server stopped');
          resolve();
        });
      } else {
        resolve();
      }
    });
  }

  // ── Request Router ───────────────────────────────────────────────────

  /**
   * Route incoming HTTP requests to the appropriate handler.
   *
   * Routes:
   *   POST   /pitr/recover        — Trigger PITR recovery
   *   POST   /pitr/restore-point    — Create a named restore point
   *   GET    /pitr/restore-points   — List restore points
   *   GET    /pitr/status           — Get PITR status
   *   POST   /pitr/sync             — Trigger remote sync
   *   POST   /pitr/gc               — Trigger GC cycle
   *   GET    /pitr/gc-summary       — Get GC summary
   *   POST   /pitr/restore-remote   — Restore from remote + recover
   */
  private async handleRequest(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    // Set CORS and content-type headers
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    // Handle CORS preflight
    if (req.method === 'OPTIONS') {
      res.writeHead(204);
      res.end();
      return;
    }

    try {
      const parsedUrl = url.parse(req.url || '', true);
      const pathname = parsedUrl.pathname || '';
      const method = (req.method || 'GET').toUpperCase();

      // Route: POST /pitr/recover
      if (method === 'POST' && pathname === '/pitr/recover') {
        await this.handleRecover(req, res);
        return;
      }

      // Route: POST /pitr/restore-point
      if (method === 'POST' && pathname === '/pitr/restore-point') {
        await this.handleCreateRestorePoint(req, res);
        return;
      }

      // Route: GET /pitr/restore-points
      if (method === 'GET' && pathname === '/pitr/restore-points') {
        await this.handleListRestorePoints(res);
        return;
      }

      // Route: GET /pitr/status
      if (method === 'GET' && pathname === '/pitr/status') {
        await this.handleStatus(res);
        return;
      }

      // Route: POST /pitr/sync
      if (method === 'POST' && pathname === '/pitr/sync') {
        await this.handleSync(res);
        return;
      }

      // Route: POST /pitr/gc
      if (method === 'POST' && pathname === '/pitr/gc') {
        await this.handleGC(res);
        return;
      }

      // Route: GET /pitr/gc-summary
      if (method === 'GET' && pathname === '/pitr/gc-summary') {
        await this.handleGCSummary(res);
        return;
      }

      // Route: POST /pitr/restore-remote
      if (method === 'POST' && pathname === '/pitr/restore-remote') {
        await this.handleRestoreFromRemote(req, res);
        return;
      }

      // 404 for unknown routes
      this.sendJSON(res, 404, { error: `Not found: ${method} ${pathname}` });
    } catch (err: any) {
      logger.error(`PITR API error: ${err.message}`);
      this.sendJSON(res, 500, { error: err.message });
    }
  }

  // ── Endpoint Handlers ────────────────────────────────────────────────

  /**
   * POST /pitr/recover
   * Body: { target: { type: 'timestamp'|'lsn'|'restore_point', value: string, restorePointName?: string } }
   */
  private async handleRecover(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    const body = await this.readBody(req);
    let parsed: any;

    try {
      parsed = JSON.parse(body);
    } catch {
      this.sendJSON(res, 400, { error: 'Invalid JSON body' });
      return;
    }

    if (!parsed.target || !parsed.target.type || !parsed.target.value) {
      this.sendJSON(res, 400, {
        error: 'Body must include target: { type: string, value: string }',
      });
      return;
    }

    const target: PitrTarget = {
      type: parsed.target.type,
      value: parsed.target.value,
      restorePointName: parsed.target.restorePointName,
    };

    // Run recovery asynchronously — return accepted status
    logger.info(`PITR recovery requested via API: ${JSON.stringify(target)}`);

    // Start recovery in background
    this.sendJSON(res, 202, {
      message: 'PITR recovery initiated',
      target,
    });

    // Execute recovery (fire-and-forget)
    this.manager.recover(target).catch((err: Error) => {
      logger.error(`PITR recovery failed (async): ${err.message}`);
    });
  }

  /**
   * POST /pitr/restore-point
   * Body: { name: string }
   */
  private async handleCreateRestorePoint(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    const body = await this.readBody(req);
    let parsed: any;

    try {
      parsed = JSON.parse(body);
    } catch {
      this.sendJSON(res, 400, { error: 'Invalid JSON body' });
      return;
    }

    if (!parsed.name || typeof parsed.name !== 'string') {
      this.sendJSON(res, 400, { error: 'Body must include name: string' });
      return;
    }

    await this.manager.createRestorePoint(parsed.name);

    this.sendJSON(res, 201, {
      message: 'Restore point created',
      name: parsed.name,
    });
  }

  /**
   * GET /pitr/restore-points
   */
  private async handleListRestorePoints(res: http.ServerResponse): Promise<void> {
    const points = await this.manager.listRestorePoints();

    this.sendJSON(res, 200, {
      restorePoints: points,
      count: points.length,
    });
  }

  /**
   * GET /pitr/status
   */
  private async handleStatus(res: http.ServerResponse): Promise<void> {
    const status = this.manager.getStatus();
    const gcSummary = this.manager.getGCSummary();
    const remoteStatus = this.manager.getRemoteStatus();

    this.sendJSON(res, 200, {
      ...status,
      gc: gcSummary,
      remoteStorage: remoteStatus,
    });
  }

  /**
   * POST /pitr/sync
   */
  private async handleSync(res: http.ServerResponse): Promise<void> {
    const synced = await this.manager.syncToRemote();

    this.sendJSON(res, 200, {
      message: 'Remote sync completed',
      segmentsSynced: synced,
    });
  }

  /**
   * POST /pitr/gc
   */
  private async handleGC(res: http.ServerResponse): Promise<void> {
    const removed = this.manager.runGC();

    this.sendJSON(res, 200, {
      message: 'GC cycle completed',
      segmentsRemoved: removed,
    });
  }

  /**
   * GET /pitr/gc-summary
   */
  private async handleGCSummary(res: http.ServerResponse): Promise<void> {
    const summary = this.manager.getGCSummary();

    this.sendJSON(res, 200, summary);
  }

  /**
   * POST /pitr/restore-remote
   * Body: { target: { type: 'timestamp'|'lsn'|'restore_point', value: string, restorePointName?: string } }
   */
  private async handleRestoreFromRemote(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    const body = await this.readBody(req);
    let parsed: any;

    try {
      parsed = JSON.parse(body);
    } catch {
      this.sendJSON(res, 400, { error: 'Invalid JSON body' });
      return;
    }

    if (!parsed.target || !parsed.target.type || !parsed.target.value) {
      this.sendJSON(res, 400, {
        error: 'Body must include target: { type: string, value: string }',
      });
      return;
    }

    const target: PitrTarget = {
      type: parsed.target.type,
      value: parsed.target.value,
      restorePointName: parsed.target.restorePointName,
    };

    logger.info(`PITR remote restore requested via API: ${JSON.stringify(target)}`);

    this.sendJSON(res, 202, {
      message: 'PITR remote restore initiated',
      target,
    });

    // Execute restore-from-remote (fire-and-forget)
    this.manager.restoreFromRemote(target).catch((err: Error) => {
      logger.error(`PITR remote restore failed (async): ${err.message}`);
    });
  }

  // ── Helpers ──────────────────────────────────────────────────────────

  /**
   * Send a JSON response.
   */
  private sendJSON(res: http.ServerResponse, statusCode: number, data: unknown): void {
    const body = JSON.stringify(data, null, 2);
    res.writeHead(statusCode, { 'Content-Type': 'application/json' });
    res.end(body);
  }

  /**
   * Read the full request body as a string.
   */
  private readBody(req: http.IncomingMessage): Promise<string> {
    return new Promise((resolve, reject) => {
      const chunks: Buffer[] = [];
      req.on('data', (chunk: Buffer) => chunks.push(chunk));
      req.on('end', () => resolve(Buffer.concat(chunks).toString('utf-8')));
      req.on('error', (err) => reject(err));
    });
  }
}
