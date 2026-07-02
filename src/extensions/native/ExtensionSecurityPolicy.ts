/**
 * ExtensionSecurityPolicy — Security policy for native C extensions
 *
 * Controls which extensions can be loaded, what capabilities they have,
 * and enforces sandbox constraints (timeout, I/O, network).
 *
 * Security defaults to 'strict' (no file I/O, no network).
 */

import { PinoLogger } from '../monitoring/PinoLogger';

// ──────────────────────────────────────────────
//  Types
// ──────────────────────────────────────────────

export type SandboxMode = 'strict' | 'permissive' | 'none';

export interface ExtensionSecurityOptions {
  /** Whitelist of allowed extension names (without extension suffix) */
  allowedExtensions?: string[];
  /** Sandbox enforcement level (default: 'strict') */
  sandboxMode?: SandboxMode;
  /** Per-call timeout in milliseconds (default: 5000, 0 = no timeout) */
  timeout?: number;
  /** Allow file I/O operations (default: false) */
  allowFileIO?: boolean;
  /** Allow network operations (default: false) */
  allowNetwork?: boolean;
}

export interface SecurityCheckResult {
  allowed: boolean;
  reason?: string;
}

// ──────────────────────────────────────────────
//  ExtensionSecurityPolicy
// ──────────────────────────────────────────────

export class ExtensionSecurityPolicy {
  private readonly logger: PinoLogger;
  private config: Required<ExtensionSecurityOptions>;

  constructor(options?: ExtensionSecurityOptions) {
    this.logger = PinoLogger.forComponent('ExtensionSecurityPolicy');
    this.config = {
      allowedExtensions: options?.allowedExtensions ?? [],
      sandboxMode: options?.sandboxMode ?? 'strict',
      timeout: options?.timeout ?? 5000,
      allowFileIO: options?.allowFileIO ?? false,
      allowNetwork: options?.allowNetwork ?? false,
    };
    this.logger.info({ sandboxMode: this.config.sandboxMode }, 'ExtensionSecurityPolicy initialized');
  }

  /**
   * Get a clone of the current configuration.
   */
  getConfig(): Required<ExtensionSecurityOptions> {
    return { ...this.config };
  }

  /**
   * Check if an extension is allowed in the current policy.
   * Returns { allowed: true } or { allowed: false, reason }.
   */
  checkExtensionAllowed(name: string): SecurityCheckResult {
    // In 'none' mode, everything is allowed
    if (this.config.sandboxMode === 'none') {
      return { allowed: true };
    }

    // Strip path prefix and .so/.dylib extension for matching
    const cleanName = name
      .split('/')
      .pop()!
      .replace(/\.(so|dylib|dll)(\.\d+)?$/i, '');

    // If whitelist is empty and mode is strict, deny all
    if (this.config.sandboxMode === 'strict' && this.config.allowedExtensions.length === 0) {
      this.logger.warn({ extension: cleanName }, 'Extension blocked: no extensions in whitelist');
      return { allowed: false, reason: 'No extensions are allowed (whitelist is empty, sandboxMode=strict)' };
    }

    // Check whitelist
    if (this.config.allowedExtensions.length > 0) {
      const isAllowed = this.config.allowedExtensions.some(
        allowed => cleanName === allowed || cleanName === `${allowed}.so` || cleanName === `${allowed}.dylib`,
      );
      if (!isAllowed) {
        this.logger.warn({ extension: cleanName, whitelist: this.config.allowedExtensions }, 'Extension blocked by whitelist');
        return {
          allowed: false,
          reason: `Extension '${cleanName}' is not in the allowedExtensions whitelist`,
        };
      }
    }

    return { allowed: true };
  }

  /**
   * Check if a function call should be allowed based on its capabilities.
   */
  checkCapability(requiredIO: boolean, requiredNetwork: boolean): SecurityCheckResult {
    if (this.config.sandboxMode === 'none') {
      return { allowed: true };
    }

    if (requiredIO && !this.config.allowFileIO) {
      return { allowed: false, reason: 'File I/O is not allowed by the security policy' };
    }

    if (requiredNetwork && !this.config.allowNetwork) {
      return { allowed: false, reason: 'Network access is not allowed by the security policy' };
    }

    return { allowed: true };
  }

  /**
   * Apply a timeout to an async function call.
   * Returns the result or throws an error on timeout.
   */
  async withTimeout<T>(fn: () => Promise<T>, label: string): Promise<T> {
    const timeoutMs = this.config.timeout;
    if (timeoutMs <= 0) {
      return fn();
    }

    return new Promise<T>((resolve, reject) => {
      const timer = setTimeout(() => {
        const err = new Error(`Extension call '${label}' timed out after ${timeoutMs}ms`);
        this.logger.warn({ label, timeoutMs }, 'Extension call timed out');
        reject(err);
      }, timeoutMs);

      fn()
        .then((result) => {
          clearTimeout(timer);
          resolve(result);
        })
        .catch((err) => {
          clearTimeout(timer);
          reject(err);
        });
    });
  }

  /**
   * Synchronous timeout wrapper using a try-approach.
   * For truly synchronous native calls, we can't interrupt them from JS,
   * but we log a warning if they might be blocking.
   */
  withSyncTimeout<T>(fn: () => T, label: string): T {
    const timeoutMs = this.config.timeout;
    if (timeoutMs <= 0) {
      return fn();
    }

    const start = Date.now();
    try {
      const result = fn();
      const elapsed = Date.now() - start;
      if (elapsed > timeoutMs) {
        this.logger.warn({ label, elapsed, timeoutMs }, 'Synchronous extension call exceeded timeout');
      }
      return result;
    } catch (err) {
      const elapsed = Date.now() - start;
      throw err;
    }
  }

  /**
   * Update the security policy configuration at runtime.
   */
  updateConfig(updates: Partial<ExtensionSecurityOptions>): void {
    if (updates.allowedExtensions !== undefined) {
      this.config.allowedExtensions = updates.allowedExtensions;
    }
    if (updates.sandboxMode !== undefined) {
      this.config.sandboxMode = updates.sandboxMode;
    }
    if (updates.timeout !== undefined) {
      this.config.timeout = updates.timeout;
    }
    if (updates.allowFileIO !== undefined) {
      this.config.allowFileIO = updates.allowFileIO;
    }
    if (updates.allowNetwork !== undefined) {
      this.config.allowNetwork = updates.allowNetwork;
    }
    this.logger.info({ sandboxMode: this.config.sandboxMode }, 'ExtensionSecurityPolicy updated');
  }
}
