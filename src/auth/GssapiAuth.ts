/**
 * GssapiAuth — GSSAPI (Kerberos) authentication handler.
 *
 * PostgreSQL supports GSSAPI / SSPI authentication via Kerberos.
 * This module provides the interface and an error-raising stub.
 *
 * In production, integrate with `kerberos` npm package or
 * platform-native GSSAPI libraries. The current stub returns an
 * authentication error that tells users how to enable Kerberos.
 *
 * References:
 *   - PostgreSQL GSSAPI: https://www.postgresql.org/docs/current/gssapi-auth.html
 *   - kerberos npm: https://www.npmjs.com/package/kerberos
 *
 * @module auth/GssapiAuth
 */

import { PinoLogger } from '../monitoring/PinoLogger';

const logger = PinoLogger.forComponent('GssapiAuth');

// ── Types ────────────────────────────────────────────────────────

export interface GssapiAuthInput {
  /** Kerberos principal (e.g. 'postgres/host.example.com@REALM'). */
  principal: string;
  /** Optional service name (default: 'postgres'). */
  serviceName?: string;
  /** GSSAPI context token (base64-encoded from client). */
  inputToken?: string;
}

export interface GssapiAuthResult {
  success: boolean;
  errorMessage?: string;
  /** Output token (base64-encoded) to send back to client in multi-round. */
  outputToken?: string;
  /** Authenticated principal name. */
  authenticatedPrincipal?: string;
  /** Alias for compatibility with PgWireServer usage */
  error?: string;
  /** Alias for complement of success */
  authenticated?: boolean;
  /** Alias for outputToken */
  token?: string;
}

// ── Mock injection (for tests) ──────────────────────────────────

let INJECTED_MODULE: any = null;

/**
 * Set a test/fake GSSAPI module for unit tests.
 * The module should implement { acceptFirstToken, acceptNextToken }.
 */
export function setTestGssapiModule(mod: any): void {
  INJECTED_MODULE = mod || null;
}

/**
 * Get the currently injected GSSAPI module (or null).
 */
export function getGssapiModule(): any {
  return INJECTED_MODULE;
}

// ── GssapiAuth Class ─────────────────────────────────────────────

export class GssapiAuth {
  /** Whether GSSAPI is available (kerberos module loaded or mock injected). */
  get isAvailable(): boolean {
    return INJECTED_MODULE !== null || getRealKrb5Module() !== null;
  }

  /** Static check for Kerberos availability (used by tests). */
  static isKerberosAvailable(): boolean {
    return INJECTED_MODULE !== null || getRealKrb5Module() !== null;
  }

  // Track whether acceptFirstToken has been called (context initialized)
  private _contextInitialized = false;

  /**
   * Attempt GSSAPI authentication.
   *
   * Currently a stub that returns an error with guidance on how to enable
   * Kerberos in a production deployment.
   *
   * @param input - Authentication input.
   * @returns Result indicating authentication failure with guidance.
   */
  async authenticate(
    input: GssapiAuthInput,
  ): Promise<GssapiAuthResult> {
    logger.warn(
      { principal: input.principal },
      'GSSAPI authentication attempted but not implemented. ' +
      'Install the `kerberos` npm package and configure krb5.conf ' +
      'to enable Kerberos support.',
    );

    const result: GssapiAuthResult = {
      success: false,
      errorMessage:
        'GSSAPI (Kerberos) authentication is not available in this build. ' +
        'To enable: (1) npm install kerberos, (2) set KRB5_CONFIG env, ' +
        '(3) configure keytab at /etc/krb5.keytab, ' +
        '(4) configure pg_hba.conf to use gss method.',
    };
    result.error = result.errorMessage;
    return result;
  }

  /**
   * Static helper: authenticate a Kerberos principal for a given service.
   * Used by tests and PgWireServer for Kerberos-based authentication.
   */
  static async authenticateKerberos(
    service: string,
    hostname: string,
    token: Buffer | Uint8Array,
  ): Promise<{ valid: boolean; user?: string }> {
    if (INJECTED_MODULE?.acceptFirstToken) {
      try {
        const raw = await INJECTED_MODULE.acceptFirstToken(token);
        return { valid: raw.authenticated !== false, user: raw.user || raw.error };
      } catch (err: any) {
        return { valid: false, user: err.message };
      }
    }
    return {
      valid: false,
      user: 'GSSAPI (Kerberos) authentication not available. Install kerberos npm package.',
    };
  }

  /**
   * Reset the GSSAPI auth context, allowing a fresh authentication cycle.
   */
  reset(): void {
    this._contextInitialized = false;
    (this as any).context = null;
  }

  /**
   * Accept the first GSSAPI token from the client.
   * Delegates to the injected mock module when available.
   */
  async acceptFirstToken(inputToken: Buffer | Uint8Array): Promise<GssapiAuthResult> {
    this._contextInitialized = true;
    if (INJECTED_MODULE?.acceptFirstToken) {
      try {
        const raw = await INJECTED_MODULE.acceptFirstToken(inputToken);
        return normalizeMockResult(raw);
      } catch (err: any) {
        return {
          success: false, authenticated: false,
          errorMessage: err.message, error: err.message,
        };
      }
    }
    if (INJECTED_MODULE) {
      return {
        success: false, authenticated: false,
        errorMessage: 'GSSAPI method not implemented in loaded module',
        error: 'GSSAPI method not implemented in loaded module',
      };
    }
    const tokenStr = Buffer.isBuffer(inputToken) ? inputToken.toString('base64') : Buffer.from(inputToken).toString('base64');
    const result = await this.acceptSecurityContext(tokenStr);
    result.error = result.errorMessage;
    result.authenticated = result.success;
    result.token = result.outputToken;
    return result;
  }

  /**
   * Accept the next GSSAPI token from the client.
   * Delegates to the injected mock module when available.
   */
  async acceptNextToken(inputToken: Buffer | Uint8Array): Promise<GssapiAuthResult> {
    // GSSAPI context must be initialized before acceptNextToken
    if (!this._contextInitialized) {
      return {
        success: false, authenticated: false,
        errorMessage: 'GSSAPI context not initialized',
        error: 'GSSAPI context not initialized',
      };
    }
    if (!INJECTED_MODULE.acceptNextToken) {
      return {
        success: false, authenticated: false,
        errorMessage: 'acceptNextToken is not supported by this module.',
        error: 'acceptNextToken is not supported by this module.',
      };
    }
    try {
      const raw = await INJECTED_MODULE.acceptNextToken(INJECTED_MODULE._context || null, inputToken);
      return normalizeMockResult(raw);
    } catch (err: any) {
      return {
        success: false, authenticated: false,
        errorMessage: err.message, error: err.message,
      };
    }
  }

  /**
   * Validate a GSSAPI context token (stub).
   *
   * @param inputToken - Base64-encoded GSSAPI token from client.
   * @returns Result indicating this is not supported.
   */
  async acceptSecurityContext(inputToken: string): Promise<GssapiAuthResult> {
    const result: GssapiAuthResult = {
      success: false,
      errorMessage:
        'GSSAPI (Kerberos) acceptSecurityContext is not implemented. ' +
        'Use kerberos npm package for production deployments.',
    };
    result.error = result.errorMessage;
    result.authenticated = false;
    return result;
  }
}

// ── Utility helpers ──────────────────────────────────────────────

function normalizeMockResult(raw: any): GssapiAuthResult {
  const token = raw.token ? (Buffer.isBuffer(raw.token) ? raw.token : Buffer.from(raw.token)) : undefined;
  return {
    success: raw.authenticated !== false,
    authenticated: raw.authenticated !== false,
    errorMessage: raw.error || raw.errorMessage,
    error: raw.error || raw.errorMessage,
    outputToken: token ? token.toString('base64') : undefined,
    token: token,
    authenticatedPrincipal: raw.user || raw.principal,
  };
}

function getRealKrb5Module(): any {
  try { return require('kerberos'); } catch { return null; }
}

// ── Utility: Check if GSSAPI is available ────────────────────────

/**
 * Check if GSSAPI/Kerberos support is available.
 * Returns true only if native bindings can be loaded.
 */
export async function isGssapiAvailable(): Promise<boolean> {
  try {
    let kerberos: any = null;
    try { kerberos = require('kerberos'); } catch { kerberos = null; }
    return kerberos !== null && typeof kerberos.initializeClient === 'function';
  } catch {
    return false;
  }
}
