/**
 * SslModeHandler — PostgreSQL SSLMODE 6-Level Implementation
 *
 * Implements the 6 PostgreSQL sslmode levels with full decision matrix,
 * TLS option creation, and certificate chain validation.
 *
 * PostgreSQL sslmode levels:
 *   disable    - Never use TLS
 *   allow      - Try without TLS first, fall back to TLS
 *   prefer     - Try TLS first, fall back to no TLS
 *   require    - Require TLS (no fallback, no cert validation)
 *   verify-ca  - Require TLS + verify server cert against CA
 *   verify-full - Require TLS + verify CA + verify hostname
 *
 * References:
 *   https://www.postgresql.org/docs/current/libpq-ssl.html
 *   https://www.postgresql.org/docs/current/ssl-tcp.html
 */

import * as tls from 'tls';
import { PinoLogger } from '../monitoring/PinoLogger';

const logger = PinoLogger.forComponent('SslModeHandler');

// ════════════════════════════════════════════════
//  Types
// ════════════════════════════════════════════════

export type SslMode = 'disable' | 'allow' | 'prefer' | 'require' | 'verify-ca' | 'verify-full';

export interface SslConfig {
  mode: SslMode;
  /** CA certificate path for verify-ca and verify-full */
  caCertPath?: string;
  /** Client certificate path for require and above */
  certPath?: string;
  /** Client key path for require and above */
  keyPath?: string;
  /** Server hostname for verify-full hostname checking */
  serverHostname?: string;
}

// ════════════════════════════════════════════════
//  Server-side SSL mode tracking
// ════════════════════════════════════════════════

/** Current server-side SSL mode (used for SHOW sslmode, SHOW ssl) */
let currentServerSslMode: SslMode = 'prefer';

/**
 * Set the server's SSL mode.
 */
export function setBackendSslMode(mode: SslMode): void {
  currentServerSslMode = mode;
  logger.info({ mode }, 'Server SSL mode set');
}

/**
 * Return the current server-side SSL mode.
 */
export function getBackendSslMode(): string {
  return currentServerSslMode;
}

// ════════════════════════════════════════════════
//  Parse Functions
// ════════════════════════════════════════════════

/**
 * Parse an SSLMODE string into the typed SslMode.
 * Valid values: 'disable', 'allow', 'prefer', 'require', 'verify-ca', 'verify-full'.
 *
 * @param configStr - The sslmode string to parse
 * @returns The parsed SslMode
 * @throws {Error} If the value is not a valid sslmode
 */
export function parseSslMode(configStr: string): SslMode {
  const normalized = configStr.trim().toLowerCase();

  switch (normalized) {
    case 'disable':
      return 'disable';
    case 'allow':
      return 'allow';
    case 'prefer':
      return 'prefer';
    case 'require':
      return 'require';
    case 'verify-ca':
    case 'verify_ca':
      return 'verify-ca';
    case 'verify-full':
    case 'verify_full':
      return 'verify-full';
    default:
      throw new Error(
        `Invalid sslmode "${configStr}". Valid values: disable, allow, prefer, require, verify-ca, verify-full`,
      );
  }
}

/**
 * Check whether SSL should be used based on mode and server TLS capability.
 *
 * Decision matrix:
 * | mode       | serverHasTLS=true | serverHasTLS=false |
 * |------------|-------------------|-------------------|
 * | disable    | false             | false             |
 * | allow      | false (try first) | true  (retry)     |
 * | prefer     | true              | false (fallback)  |
 * | require    | true              | error             |
 * | verify-ca  | true              | error             |
 * | verify-full| true              | error             |
 *
 * For 'allow': client first tries without TLS. If server has TLS,
 * the client will later re-connect with TLS. From server perspective,
 * we handle the initial connection (shouldUseSSL=false initially).
 * For 'prefer': client tries TLS first. If server doesn't have TLS,
 * it falls back to no TLS (shouldUseSSL=false as fallback).
 *
 * @param mode - The sslmode
 * @param serverHasTls - Whether the server supports TLS
 * @returns Whether SSL should be used on the connection
 * @throws {Error} If mode requires TLS but server doesn't support it
 */
export function shouldUseSSL(mode: SslMode, serverHasTls: boolean): boolean {
  switch (mode) {
    case 'disable':
      return false;

    case 'allow':
      // allow: try without TLS first; if server has TLS, client stays without TLS
      // If server doesn't have TLS, client retries WITH TLS (retry required)
      return !serverHasTls;

    case 'prefer':
      // prefer: try TLS first; if server has TLS, use it; otherwise fallback
      return serverHasTls;

    case 'require':
      if (!serverHasTls) {
        throw new Error(
          'sslmode "require" requires a TLS-enabled server, but the server does not support TLS',
        );
      }
      return true;

    case 'verify-ca':
      if (!serverHasTls) {
        throw new Error(
          'sslmode "verify-ca" requires a TLS-enabled server, but the server does not support TLS',
        );
      }
      return true;

    case 'verify-full':
      if (!serverHasTls) {
        throw new Error(
          'sslmode "verify-full" requires a TLS-enabled server, but the server does not support TLS',
        );
      }
      return true;
  }
}

// ════════════════════════════════════════════════
//  TLS Options
// ════════════════════════════════════════════════

/**
 * Create TLS socket options based on the SSL mode.
 *
 * - disable: throws error (no TLS options)
 * - allow/prefer: basic TLS (no client cert requested by default)
 * - require: basic TLS (no client cert requested)
 * - verify-ca: TLS with CA cert for server cert verification
 * - verify-full: TLS with CA cert + hostname check (via checkServerIdentity)
 *
 * @param config - The SSL configuration
 * @returns TLS socket options object for tls.connect()
 * @throws {Error} If mode is 'disable'
 */
export function createTlsOptions(config: SslConfig): object {
  if (config.mode === 'disable') {
    throw new Error('Cannot create TLS options in disable mode');
  }

  const baseOptions: tls.ConnectionOptions = {
    rejectUnauthorized: true,
  };

  // Add client certificate for require and above
  if (config.certPath && config.keyPath) {
    baseOptions.cert = config.certPath;
    baseOptions.key = config.keyPath;
  } else if (
    config.mode !== 'allow' &&
    config.mode !== 'prefer'
  ) {
    // For require/verify-ca/verify-full, warn if cert/key are missing
    logger.warn(
      { mode: config.mode },
      'No client certificate configured; server may reject connection if cert auth is required',
    );
  }

  switch (config.mode) {
    case 'allow':
    case 'prefer':
      // Basic TLS, no server cert verification by default
      // In PostgreSQL, prefer/allow set sslmode but don't enforce server cert
      if (config.caCertPath) {
        baseOptions.ca = config.caCertPath;
      }
      // allow and prefer use weak verification by default (libpq default)
      baseOptions.rejectUnauthorized = false;
      break;

    case 'require':
      // Require TLS, but no server certificate validation
      if (config.caCertPath) {
        baseOptions.ca = config.caCertPath;
      }
      break;

    case 'verify-ca':
      // Require TLS + verify server cert against CA
      if (!config.caCertPath) {
        throw new Error('sslmode "verify-ca" requires a CA certificate path (caCertPath)');
      }
      baseOptions.ca = config.caCertPath;
      baseOptions.rejectUnauthorized = true;
      break;

    case 'verify-full':
      // Require TLS + verify CA + verify hostname
      if (!config.caCertPath) {
        throw new Error('sslmode "verify-full" requires a CA certificate path (caCertPath)');
      }
      baseOptions.ca = config.caCertPath;
      baseOptions.rejectUnauthorized = true;

      // Custom hostname verification if serverHostname is provided
      if (config.serverHostname) {
        baseOptions.checkServerIdentity = (hostname: string, cert: tls.PeerCertificate) => {
          // First run Node.js default check
          const err = tls.checkServerIdentity(config.serverHostname!, cert);
          if (err) {
            logger.error(
              { hostname: config.serverHostname, certSubject: cert.subject },
              'Server identity verification failed (verify-full)',
            );
          }
          return err;
        };
      }
      break;
  }

  return baseOptions;
}

// ════════════════════════════════════════════════
//  Certificate Chain Validation
// ════════════════════════════════════════════════

/**
 * Validate the certificate chain for verify-ca and verify-full modes.
 *
 * For verify-ca: validates that the server certificate is signed by the CA.
 * For verify-full: validates CA signature AND hostname match.
 *
 * In this implementation, the actual TLS handshake (via Node.js tls module)
 * handles certificate validation; this function validates the configuration
 * is sound before attempting the connection.
 *
 * @param config - The SSL configuration
 * @returns Validation result with valid flag and optional error message
 */
export function validateCertificateChain(config: SslConfig): { valid: boolean; error?: string } {
  if (config.mode === 'disable' || config.mode === 'allow' || config.mode === 'prefer') {
    return { valid: true };
  }

  if (config.mode === 'require') {
    // require doesn't validate certs
    return { valid: true };
  }

  if (config.mode === 'verify-ca' || config.mode === 'verify-full') {
    // For verify-full, check serverHostname first
    if (config.mode === 'verify-full' && !config.serverHostname) {
      return {
        valid: false,
        error: 'sslmode "verify-full" requires a server hostname (serverHostname)',
      };
    }

    if (!config.caCertPath) {
      return {
        valid: false,
        error: `sslmode "${config.mode}" requires a CA certificate path (caCertPath)`,
      };
    }

    // Check that the CA cert file exists (synchronous check for validation)
    try {
      const fs = require('fs');
      if (!fs.existsSync(config.caCertPath)) {
        return {
          valid: false,
          error: `CA certificate file not found: ${config.caCertPath}`,
        };
      }
      // Try parsing the CA cert
      const caContent = fs.readFileSync(config.caCertPath, 'utf8');
      if (!caContent.includes('BEGIN CERTIFICATE') && !caContent.includes('BEGIN TRUSTED CERTIFICATE')) {
        return {
          valid: false,
          error: `CA certificate file does not contain a valid PEM certificate: ${config.caCertPath}`,
        };
      }
    } catch (err: any) {
      return {
        valid: false,
        error: `Error reading CA certificate: ${err.message}`,
      };
    }

    return { valid: true };
  }

  return { valid: false, error: `Unknown SSL mode: ${config.mode}` };
}

// ════════════════════════════════════════════════
//  SHOW GUC Handlers
// ════════════════════════════════════════════════

/**
 * SHOW-related GUC names and their current values for SSL.
 * These are handled by the PgWireServer SHOW handler.
 */

/**
 * Returns the value for `SHOW ssl` (boolean, whether SSL is supported).
 */
export function getShowSsl(): string {
  return currentServerSslMode !== 'disable' ? 'on' : 'off';
}

/**
 * Returns the value for `SHOW ssl_ca_file`.
 */
export function getShowSslCaFile(): string {
  // In production, this would return the configured CA file path
  return '';
}

/**
 * Returns the value for `SHOW ssl_cert_file`.
 */
export function getShowSslCertFile(): string {
  // In production, this would return the configured cert file path
  return '';
}

/**
 * Returns the value for `SHOW ssl_key_file`.
 */
export function getShowSslKeyFile(): string {
  // In production, this would return the configured key file path
  return '';
}

/**
 * Get all SSL-related GUC values for ParameterStatus response.
 */
export function getSslGucValues(): Array<[string, string]> {
  return [
    ['ssl', getShowSsl()],
    ['ssl_ca_file', getShowSslCaFile()],
    ['ssl_cert_file', getShowSslCertFile()],
    ['ssl_key_file', getShowSslKeyFile()],
    ['sslmode', getBackendSslMode()],
    ['ssl_ciphers', getSslCiphers()],
    ['ssl_min_protocol_version', getSslMinProtocolVersion()],
    ['ssl_max_protocol_version', getSslMaxProtocolVersion()],
  ];
}

// ════════════════════════════════════════════════
//  SSL Cipher Suite Control (Gap 6)
// ════════════════════════════════════════════════

/**
 * GUC-backed cipher suite list.
 * Default: 'HIGH:MEDIUM:!aNULL:!eNULL:!LOW'
 * Follows OpenSSL cipher string format.
 */
let sslCiphers: string = 'HIGH:MEDIUM:!aNULL:!eNULL:!LOW';
let sslMinProtocolVersion: string = 'TLSv1.2';
let sslMaxProtocolVersion: string = 'TLSv1.3';

/**
 * Set the SSL cipher suite list (GUC: ssl_ciphers).
 * @param ciphers - OpenSSL cipher string (e.g. 'HIGH:MEDIUM:!aNULL:!eNULL')
 */
export function setSslCiphers(ciphers: string): void {
  sslCiphers = ciphers;
  logger.info({ ciphers }, 'SSL ciphers updated');
}

/**
 * Get the current SSL cipher suite list.
 */
export function getSslCiphers(): string {
  return sslCiphers;
}

/**
 * Set the minimum TLS protocol version (GUC: ssl_min_protocol_version).
 * Valid values: 'TLSv1', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3'
 * Default: 'TLSv1.2'
 */
export function setSslMinProtocolVersion(version: string): void {
  const normalized = version.trim().toLowerCase();
  const validVersions = ['tlsv1', 'tlsv1.1', 'tlsv1.2', 'tlsv1.3'];
  if (!validVersions.includes(normalized)) {
    throw new Error(
      `Invalid ssl_min_protocol_version "${version}". Valid values: TLSv1, TLSv1.1, TLSv1.2, TLSv1.3`,
    );
  }
  sslMinProtocolVersion = normalized;
  logger.info({ version: normalized }, 'SSL min protocol version updated');
}

/**
 * Get the current min TLS protocol version.
 */
export function getSslMinProtocolVersion(): string {
  return sslMinProtocolVersion;
}

/**
 * Set the maximum TLS protocol version (GUC: ssl_max_protocol_version).
 * Valid values: 'TLSv1', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3'
 * Default: 'TLSv1.3'
 */
export function setSslMaxProtocolVersion(version: string): void {
  const normalized = version.trim().toLowerCase();
  const validVersions = ['tlsv1', 'tlsv1.1', 'tlsv1.2', 'tlsv1.3'];
  if (!validVersions.includes(normalized)) {
    throw new Error(
      `Invalid ssl_max_protocol_version "${version}". Valid values: TLSv1, TLSv1.1, TLSv1.2, TLSv1.3`,
    );
  }
  sslMaxProtocolVersion = normalized;
  logger.info({ version: normalized }, 'SSL max protocol version updated');
}

/**
 * Get the current max TLS protocol version.
 */
export function getSslMaxProtocolVersion(): string {
  return sslMaxProtocolVersion;
}

/**
 * Apply cipher suite restrictions to TLS options.
 * Adds `ciphers`, `minVersion`, and `maxVersion` to the TLS options.
 */
export function applyCipherSuiteOptions(
  options: tls.ConnectionOptions,
): tls.ConnectionOptions {
  return {
    ...options,
    ciphers: sslCiphers,
    minVersion: sslMinProtocolVersion as tls.SecureVersion,
    maxVersion: sslMaxProtocolVersion as tls.SecureVersion,
  };
}

/**
 * Check if GSSAPI is available and handle unavailable case.
 * In the current implementation, GSSAPI is always unavailable.
 * This function returns an error message explaining why.
 */
export function checkGssapiAvailability(): { available: boolean; error?: string } {
  return {
    available: false,
    error: 'GSSAPI/SSPI authentication is not available in this build. '
      + 'The server was compiled without GSSAPI support. '
      + 'Use md5, password, or scram-sha-256 authentication instead.',
  };
}

// ════════════════════════════════════════════════
//  Integration: createTlsOptions with cipher suites
// ════════════════════════════════════════════════

/**
 * Create TLS socket options with cipher suite and protocol version controls.
 * Wraps the base `createTlsOptions` with additional security options.
 */
export function createSecureTlsOptions(config: SslConfig): object {
  const baseOptions = createTlsOptions(config);
  return applyCipherSuiteOptions(baseOptions as tls.ConnectionOptions);
}
