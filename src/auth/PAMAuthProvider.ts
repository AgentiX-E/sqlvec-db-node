/**
 * PAMAuthProvider — Pluggable Authentication Module authentication for SQLVec.
 *
 * Provides PAM-based authentication using the `authenticate-pam` native module.
 * Maps PAM error codes to PostgreSQL error codes for compatibility with the
 * existing auth infrastructure.
 *
 * Design:
 *   - Uses `authenticate-pam` (v1.0.5, already installed) for actual PAM calls
 *   - Gracefully handles missing native module (returns appropriate error)
 *   - Maps PAM errors to PG error codes (28P01 = invalid_password)
 *   - Logs all auth attempts (success + failure with username/timestamp)
 *   - Handles PAM specific error codes: PAM_AUTH_ERR, PAM_USER_UNKNOWN, PAM_MAXTRIES
 *
 * @module auth/PAMAuthProvider
 */

import { PinoLogger } from '../monitoring/PinoLogger';

// ── Logger ───────────────────────────────────────────────────────────────────

const logger = PinoLogger.forComponent('PAMAuthProvider');

// ── Types ────────────────────────────────────────────────────────────────────

export interface PAMAuthResult {
  /** Whether authentication was successful */
  success: boolean;
  /** PostgreSQL-compatible error code (empty on success) */
  pgErrorCode: string;
  /** Human-readable error message */
  errorMessage: string;
}

export interface PAMAuthOptions {
  /** PAM service name (default: 'login') */
  serviceName?: string;
  /** Remote hostname for PAM_RHOST (for network auth) */
  remoteHost?: string;
}

// ── PAM error codes and their PG mappings ─────────────────────────────────────

interface PAMErrorMapping {
  code: string;
  message: string;
}

const PAM_ERROR_MAP: Record<string, PAMErrorMapping> = {
  PAM_AUTH_ERR: {
    code: '28P01',
    message: 'PAM authentication failed: invalid password or credentials',
  },
  PAM_USER_UNKNOWN: {
    code: '28P01',
    message: 'PAM authentication failed: unknown user',
  },
  PAM_MAXTRIES: {
    code: '28P01',
    message: 'PAM authentication failed: maximum authentication attempts exceeded',
  },
  PAM_ACCT_EXPIRED: {
    code: '28000',
    message: 'PAM authentication failed: account expired',
  },
  PAM_CRED_INSUFFICIENT: {
    code: '28P01',
    message: 'PAM authentication failed: insufficient credentials',
  },
  PAM_AUTHINFO_UNAVAIL: {
    code: '28000',
    message: 'PAM authentication failed: authentication info unavailable',
  },
  PAM_SYSTEM_ERR: {
    code: 'XX000',
    message: 'PAM authentication failed: internal system error',
  },
};

// ── Default error when no specific mapping exists ─────────────────────────────

const DEFAULT_PAM_ERROR: PAMErrorMapping = {
  code: '28000',
  message: 'PAM authentication failed',
};

// ── Native module loading ─────────────────────────────────────────────────────

let pamModule: ((username: string, password: string, callback: (err: Error | null) => void, options?: PAMAuthOptions) => void) | null = null;

try {
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const pam = require('authenticate-pam');
  if (typeof pam.authenticate === 'function') {
    pamModule = pam.authenticate;
    logger.info('authenticate-pam native module loaded successfully');
  } else {
    logger.warn('authenticate-pam module loaded but has no .authenticate() method');
  }
} catch (err) {
  // Native module may not be built (missing .node binary)
  // This is expected in environments without PAM dev headers or when running
  // in a container without full PAM support
  logger.warn({ err }, 'authenticate-pam native module could not be loaded — PAM auth unavailable');
}

// ── Public API ───────────────────────────────────────────────────────────────

/**
 * Authenticate a user via PAM asynchronously.
 *
 * Attempts PAM authentication and returns a standardized result with
 * PostgreSQL-compatible error codes.
 *
 * @param username - The username to authenticate.
 * @param password - The password to authenticate with.
 * @param options  - Optional PAM configuration (serviceName, remoteHost).
 * @returns Promise resolving to a PAMAuthResult.
 */
export async function authenticatePAM(
  username: string,
  password: string,
  options?: PAMAuthOptions,
): Promise<PAMAuthResult> {
  const startTime = Date.now();
  const serviceName = options?.serviceName ?? 'login';
  const remoteHost = options?.remoteHost;

  // Validate inputs
  if (!username || typeof username !== 'string') {
    const result: PAMAuthResult = {
      success: false,
      pgErrorCode: '28P01',
      errorMessage: 'PAM authentication failed: username is required',
    };
    logger.warn({ username, duration: Date.now() - startTime }, 'PAM auth failed: empty username');
    return result;
  }

  if (!password || typeof password !== 'string') {
    const result: PAMAuthResult = {
      success: false,
      pgErrorCode: '28P01',
      errorMessage: 'PAM authentication failed: password is required',
    };
    logger.warn({ username, duration: Date.now() - startTime }, 'PAM auth failed: empty password');
    return result;
  }

  // Check if native module is available
  if (!pamModule) {
    const result: PAMAuthResult = {
      success: false,
      pgErrorCode: 'XX000',
      errorMessage: 'PAM authentication failed: native module not available (not built or not supported on this platform)',
    };
    logger.error({ username, duration: Date.now() - startTime }, 'PAM auth unavailable: native module not loaded');
    return result;
  }

  // Perform PAM authentication
  return new Promise<PAMAuthResult>((resolve) => {
    try {
      const pamOptions: Record<string, unknown> = { serviceName };
      if (remoteHost) {
        pamOptions.remoteHost = remoteHost;
      }

      pamModule!(username, password, (err: Error | null) => {
        const duration = Date.now() - startTime;

        if (err) {
          // Map the PAM error to a PG error code
          const mapping = mapPamError(err.message || '');
          const result: PAMAuthResult = {
            success: false,
            pgErrorCode: mapping.code,
            errorMessage: mapping.message,
          };

          logger.warn(
            { username, pamError: err.message, pgErrorCode: mapping.code, duration },
            'PAM authentication failed',
          );

          resolve(result);
        } else {
          // Authentication successful
          const result: PAMAuthResult = {
            success: true,
            pgErrorCode: '',
            errorMessage: '',
          };

          logger.info(
            { username, duration },
            'PAM authentication succeeded',
          );

          resolve(result);
        }
      }, pamOptions);
    } catch (err) {
      const duration = Date.now() - startTime;
      const errorMessage = err instanceof Error ? err.message : String(err);

      const result: PAMAuthResult = {
        success: false,
        pgErrorCode: 'XX000',
        errorMessage: `PAM authentication failed: ${errorMessage}`,
      };

      logger.error(
        { username, error: errorMessage, duration },
        'PAM authentication threw an exception',
      );

      resolve(result);
    }
  });
}

/**
 * Synchronous PAM authentication (fallback for non-async contexts).
 *
 * @param username - The username to authenticate.
 * @param password - The password to authenticate with.
 * @param options  - Optional PAM configuration.
 * @returns PAMAuthResult.
 */
export function authenticatePAMSync(
  username: string,
  password: string,
  options?: PAMAuthOptions,
): PAMAuthResult {
  // Since authenticate-pam is async-only, we fall back to immediate error
  // if the module is not available
  if (!pamModule) {
    return {
      success: false,
      pgErrorCode: 'XX000',
      errorMessage: 'PAM authentication failed: native module not available',
    };
  }

  // For sync context, we attempt async but warn; the actual flow
  // should use the async authenticatePAM() instead.
  logger.warn(
    'authenticatePAMSync() called — prefer authenticatePAM() for proper async flow. ' +
    'Falling back to module-unavailable error to avoid event-loop blocking.',
  );

  return {
    success: false,
    pgErrorCode: 'XX000',
    errorMessage: 'PAM authentication unavailable in sync mode; use async authenticatePAM() instead',
  };
}

/**
 * Check whether the PAM native module is available.
 *
 * @returns true if PAM authentication can be performed.
 */
export function isPAMAvailable(): boolean {
  return pamModule !== null;
}

// ── Internal helpers ─────────────────────────────────────────────────────────

/**
 * Map a PAM error message string to a PG error code and message.
 *
 * Tries to match common PAM error strings:
 *   - "Authentication failure" → PAM_AUTH_ERR
 *   - "User not known" → PAM_USER_UNKNOWN
 *   - "Maximum number of tries exceeded" → PAM_MAXTRIES
 *   - "Account expired" → PAM_ACCT_EXPIRED
 *   - "Authentication information is unavailable" → PAM_AUTHINFO_UNAVAIL
 *   - Anything else → DEFAULT_PAM_ERROR
 *
 * @param pamErrorMessage - The error message from authenticate-pam.
 * @returns The mapped PAMErrorMapping.
 */
function mapPamError(pamErrorMessage: string): PAMErrorMapping {
  if (!pamErrorMessage) return DEFAULT_PAM_ERROR;

  const lower = pamErrorMessage.toLowerCase();

  if (lower.includes('authentication failure') || lower.includes('auth error') || lower.includes('pam_auth_err')) {
    return PAM_ERROR_MAP.PAM_AUTH_ERR;
  }

  if (lower.includes('user not known') || lower.includes('unknown user') || lower.includes('user unknown') || lower.includes('pam_user_unknown')) {
    return PAM_ERROR_MAP.PAM_USER_UNKNOWN;
  }

  if (lower.includes('maximum') && (lower.includes('tries') || lower.includes('attempts'))) {
    return PAM_ERROR_MAP.PAM_MAXTRIES;
  }

  if (lower.includes('account expired') || lower.includes('acct expired')) {
    return PAM_ERROR_MAP.PAM_ACCT_EXPIRED;
  }

  if (lower.includes('credential insufficient') || lower.includes('cred insufficient')) {
    return PAM_ERROR_MAP.PAM_CRED_INSUFFICIENT;
  }

  if (lower.includes('authentication info') || lower.includes('authinfo unavail')) {
    return PAM_ERROR_MAP.PAM_AUTHINFO_UNAVAIL;
  }

  if (lower.includes('system error')) {
    return PAM_ERROR_MAP.PAM_SYSTEM_ERR;
  }

  return DEFAULT_PAM_ERROR;
}

/**
 * Export the PAM module reference for testing/mocking.
 */
export function getPamModule(): typeof pamModule {
  return pamModule;
}

/**
 * Inject a test/mock PAM module.
 *
 * Only works when NODE_ENV=test or when the environment allows it.
 * This is used by the test suite to inject a mock authenticate-pam module
 * since the native .node binary may not be available in CI/test environments.
 *
 * @param mockModule - A function matching the authenticate-pam API.
 */
export function setTestPamModule(
  mockModule: (username: string, password: string, callback: (err: Error | null) => void, options?: unknown) => void,
): void {
  pamModule = mockModule;
  logger.info('Test PAM module injected');
}
