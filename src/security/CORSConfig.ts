/**
 * CORSConfig — Cross-Origin Resource Sharing configuration.
 *
 * PostgreSQL enterprise supports cross-origin resource sharing policies for
 * HTTP API access. This module provides the configuration surface for defining
 * allowed origins, methods, headers, and caching duration.
 *
 * IMPORTANT: This is an application/ops-layer feature that should be
 * implemented in the reverse-proxy layer (nginx, Envoy, or a similar
 * gateway). SQLite-backed databases do not natively serve HTTP, so CORS
 * enforcement must occur at the ingress point.
 *
 * STUB — This implementation is a placeholder. For production setups, apply
 * CORS rules at the reverse-proxy level:
 *
 *   nginx:
 *     add_header Access-Control-Allow-Origin "*";
 *     add_header Access-Control-Allow-Methods "GET, POST, PUT, DELETE";
 *
 *   Envoy:
 *     cors:
 *       allow_origin_string_match: [ { exact: "*" } ]
 *       allow_methods: GET, POST, PUT, DELETE
 *
 * @module CORSConfig
 */

import { PinoLogger } from '../monitoring/PinoLogger';

const logger = PinoLogger.forComponent('CORSConfig');

// ── Types ──────────────────────────────────────────────────────

export interface OrgCORSConfig {
  /** List of allowed origins (e.g. ['https://app.example.com', '*']) */
  allowedOrigins: string[];
  /** Allowed HTTP methods (e.g. ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS']) */
  allowedMethods: string[];
  /** Allowed HTTP headers (e.g. ['Content-Type', 'Authorization', 'X-Requested-With']) */
  allowedHeaders: string[];
  /** Max age (in seconds) for the preflight OPTIONS cache */
  maxAge: number;
}

export type CORSConfig = OrgCORSConfig;

export interface CorsOptions {
  origin: string | string[];
  methods: string | string[];
  allowedHeaders: string | string[];
  exposedHeaders?: string | string[];
  credentials?: boolean;
  maxAge?: number;
}

// ── Manager ────────────────────────────────────────────────────

/**
 * CORS configuration manager.
 *
 * Collects and holds CORS policy settings. In a production setup these
 * settings should be consumed by the reverse-proxy or HTTP gateway to
 * emit the appropriate CORS response headers.
 *
 * @example
 * ```typescript
 * const mgr = new CORSConfigManager();
 * mgr.configure({
 *   allowedOrigins: ['https://app.example.com'],
 *   allowedMethods: ['GET', 'POST'],
 *   allowedHeaders: ['Content-Type'],
 *   maxAge: 86400,
 * });
 * ```
 */
export class CORSConfigManager {
  private config: CORSConfig = {
    allowedOrigins: ['*'],
    allowedMethods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
    maxAge: 86400,
  };

  constructor() {
    logger.info('CORSConfigManager initialized');
  }

  /**
   * Apply a new CORS configuration.
   */
  configure(config: CORSConfig): void {
    this.config = { ...config };
    logger.info({ config }, 'CORS configuration applied');
  }

  /**
   * Return the current allowed origins.
   * Default is ['*'] (allow all origins).
   */
  getAllowedOrigins(): string[] {
    return [...this.config.allowedOrigins];
  }

  /**
   * Return the full current CORS configuration.
   */
  getConfig(): CORSConfig {
    return { ...this.config };
  }

  /**
   * Create an Express-style CORS middleware function.
   */
  createMiddleware(): (req: { method: string; headers: Record<string, string> }, res: {
    setHeader: (key: string, value: string) => void;
    writeHead: (status: number, headers?: Record<string, string>) => void;
    end: (body?: string) => void;
  }, next: () => void) => void {
    const self = this;
    return function corsMiddleware(req, res, next): void {
      const origin = req.headers['origin'] || '';

      // Handle preflight
      if (req.method === 'OPTIONS') {
        const preflightHeaders = self.buildHeaders(origin);
        res.writeHead(204, preflightHeaders);
        res.end();
        return;
      }

      // Set CORS headers on all requests
      const headers = self.buildHeaders(origin);
      for (const [key, value] of Object.entries(headers)) {
        res.setHeader(key, value);
      }

      next();
    };
  }

  /**
   * Handle a preflight (OPTIONS) request.
   */
  preflight(req: { method: string; headers: Record<string, string> }): { status: number; headers: Record<string, string> } {
    const origin = req.headers['origin'] || '';
    return {
      status: 204,
      headers: this.buildHeaders(origin),
    };
  }

  /**
   * Validate the current CORS configuration.
   * Returns a list of error messages (empty if valid).
   */
  validate(): string[] {
    const errors: string[] = [];

    if (!this.config.allowedOrigins || this.config.allowedOrigins.length === 0) {
      errors.push('allowedOrigins must contain at least one origin');
    }
    if (!this.config.allowedMethods || this.config.allowedMethods.length === 0) {
      errors.push('allowedMethods must contain at least one method');
    }
    if (!this.config.allowedHeaders || this.config.allowedHeaders.length === 0) {
      errors.push('allowedHeaders must contain at least one header');
    }
    if (this.config.maxAge < 0) {
      errors.push('maxAge must be non-negative');
    }
    if (this.config.maxAge > 86400) {
      errors.push('maxAge must not exceed 86400 seconds (24 hours)');
    }

    return errors;
  }

  private buildHeaders(origin: string): Record<string, string> {
    const headers: Record<string, string> = {};

    // Determine allowed origin
    if (this.config.allowedOrigins.includes('*')) {
      headers['Access-Control-Allow-Origin'] = '*';
    } else if (origin && this.config.allowedOrigins.includes(origin)) {
      headers['Access-Control-Allow-Origin'] = origin;
    } else {
      headers['Access-Control-Allow-Origin'] = this.config.allowedOrigins[0] || '';
    }

    headers['Access-Control-Allow-Methods'] = this.config.allowedMethods.join(', ');
    headers['Access-Control-Allow-Headers'] = this.config.allowedHeaders.join(', ');

    // Cap maxAge at 86400s
    const effectiveMaxAge = Math.min(this.config.maxAge, 86400);
    headers['Access-Control-Max-Age'] = String(effectiveMaxAge);

    return headers;
  }
}
