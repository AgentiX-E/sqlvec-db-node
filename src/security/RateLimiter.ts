/**
 * RateLimiter — Sliding-window rate limiting for SQL operations.
 *
 * Protects against resource exhaustion by tracking per-key request
 * rates using a sliding window algorithm (avoids the "thundering herd"
 * spikes of fixed-window approaches).
 *
 * Design:
 *   - Uses Map<key, { timestamps: number[] }> for O(1) key lookup
 *     and O(n) window pruning (n = requests in window, typically small).
 *   - Lazy pruning on each check, plus a periodic background sweep
 *     every 60 s to reclaim memory from idle keys.
 *   - Burst allowance via burstMultiplier (default 2× QPS) so brief
 *     traffic spikes are tolerated without triggering false positives.
 *
 * @module RateLimiter
 */

import { PinoLogger } from '../monitoring/PinoLogger';

// ── Constants ─────────────────────────────────────────────────────────────────

/** QPM sliding-window size in milliseconds (1 minute). */
const QPM_WINDOW_MS = 60_000;

/** Background cleanup interval in milliseconds (60 s). */
const CLEANUP_INTERVAL_MS = 60_000;

// ── Types ─────────────────────────────────────────────────────────────────────

/** Per-key internal storage. */
interface KeyEntry {
  /** Sorted timestamps (ms epoch) of recent requests for this key. */
  timestamps: number[];
}

/**
 * Rate-limit configuration.
 *
 * The effective per-second burst ceiling is `queriesPerSecond × burstMultiplier`.
 */
export interface RateLimitConfig {
  /** Maximum queries per second (default: 100). */
  queriesPerSecond: number;
  /** Maximum queries per minute (default: 1000). */
  queriesPerMinute: number;
  /** Burst multiplier applied to QPS (default: 2 → 200 QPS burst). */
  burstMultiplier: number;
  /** Sliding window size in ms for QPS (default: 1000). */
  windowMs: number;
}

/**
 * Result of a rate-limit check.
 */
export interface RateLimitResult {
  /** Whether the request is allowed through. */
  allowed: boolean;
  /** Current queries-per-second rate (includes this request if allowed). */
  currentQps: number;
  /** Current queries-per-minute rate (includes this request if allowed). */
  currentQpm: number;
  /** Suggested wait time in ms before retrying; 0 = no wait needed. */
  retryAfterMs: number;
  /** Remaining quota before the limit is hit. */
  remaining: number;
}

// ── Defaults ──────────────────────────────────────────────────────────────────

const DEFAULT_CONFIG: RateLimitConfig = {
  queriesPerSecond: 100,
  queriesPerMinute: 1000,
  burstMultiplier: 2,
  windowMs: 1000,
} as const;

// ── Rate Limiter ──────────────────────────────────────────────────────────────

/**
 * Sliding-window rate limiter.
 *
 * Thread-safe within a single process. Each `RateLimiter` instance maintains
 * its own independent state map and background cleanup timer.
 */
export class RateLimiter {
  private entries: Map<string, KeyEntry> = new Map();
  private config: RateLimitConfig;
  private readonly logger: PinoLogger;
  private cleanupTimer: ReturnType<typeof setInterval> | null = null;

  /**
   * @param config  Partial config overrides; omitted fields fall back to defaults.
   */
  constructor(config?: Partial<RateLimitConfig>) {
    this.config = { ...DEFAULT_CONFIG, ...config };
    this.logger = PinoLogger.forComponent('RateLimiter');
    this.startCleanup();
  }

  // ── Public API ───────────────────────────────────────────────────────────────

  /**
   * Check whether a request identified by `key` is allowed.
   *
   * - Removes expired timestamps (lazy pruning).
   * - If allowed, records the current timestamp.
   * - If denied, calculates `retryAfterMs` from the oldest timestamp that
   *   must expire before the next request can be served.
   */
  check(key: string): RateLimitResult {
    const now = Date.now();
    const qpsWindowStart = now - this.config.windowMs;
    const qpmWindowStart = now - QPM_WINDOW_MS;
    const burstLimit = this.config.queriesPerSecond * this.config.burstMultiplier;

    // Lazily initialise entry for this key
    let entry = this.entries.get(key);
    if (!entry) {
      entry = { timestamps: [] };
      this.entries.set(key, entry);
    }

    // Prune timestamps outside the 1-minute QPM window
    if (entry.timestamps.length > 0) {
      const oldestAllowed = qpmWindowStart;
      // Binary search for first timestamp > oldestAllowed
      const firstValid = this.lowerBound(entry.timestamps, oldestAllowed);
      if (firstValid > 0) {
        entry.timestamps = entry.timestamps.slice(firstValid);
      }
    }

    // Count timestamps within each window
    const qpsTimestamps = this.filterAfter(entry.timestamps, qpsWindowStart);
    const currentQps = qpsTimestamps.length;
    const currentQpm = entry.timestamps.length;

    // Evaluate limits
    const qpsAllowed = currentQps < burstLimit;
    const qpmAllowed = currentQpm < this.config.queriesPerMinute;
    const allowed = qpsAllowed && qpmAllowed;

    if (allowed) {
      // Record this request
      entry.timestamps.push(now);
    }

    // ── Compute response fields ──

    const resultCurrentQps = allowed ? currentQps + 1 : currentQps;
    const resultCurrentQpm = allowed ? currentQpm + 1 : currentQpm;

    let retryAfterMs = 0;
    let remaining = 0;

    if (allowed) {
      remaining = Math.min(
        burstLimit - resultCurrentQps,
        this.config.queriesPerMinute - resultCurrentQpm,
      );
    } else {
      // Determine when the oldest blocking timestamp expires
      if (!qpsAllowed && qpsTimestamps.length >= burstLimit) {
        const oldestBlocking = qpsTimestamps[0]!;
        retryAfterMs = Math.max(retryAfterMs, oldestBlocking + this.config.windowMs - now);
      }
      if (!qpmAllowed && entry.timestamps.length >= this.config.queriesPerMinute) {
        const oldestBlocking = entry.timestamps[0]!;
        retryAfterMs = Math.max(retryAfterMs, oldestBlocking + QPM_WINDOW_MS - now);
      }
      retryAfterMs = Math.max(0, Math.ceil(retryAfterMs));
    }

    return {
      allowed,
      currentQps: resultCurrentQps,
      currentQpm: resultCurrentQpm,
      retryAfterMs,
      remaining,
    };
  }

  /**
   * Reset the rate-limit state for a single key.
   */
  reset(key: string): void {
    this.entries.delete(key);
    this.logger.debug({ key }, 'Rate limit reset for key');
  }

  /**
   * Reset rate-limit state for every key.
   */
  resetAll(): void {
    this.entries.clear();
    this.logger.debug('All rate limit entries cleared');
  }

  /**
   * Update configuration at runtime.
   *
   * Existing state is preserved (only future checks use the new limits).
   */
  updateConfig(config: Partial<RateLimitConfig>): void {
    const prev = { ...this.config };
    Object.assign(this.config, config);
    this.logger.info(
      { from: prev, to: this.config },
      'Rate limit configuration updated',
    );
  }

  /**
   * Return a read-only snapshot of the current config.
   */
  getConfig(): Readonly<RateLimitConfig> {
    return { ...this.config };
  }

  /**
   * Return the number of distinct keys currently tracked.
   */
  getActiveKeyCount(): number {
    return this.entries.size;
  }

  // ── Lifecycle ────────────────────────────────────────────────────────────────

  /**
   * Stop the background cleanup timer and release resources.
   *
   * Call this when the limiter is no longer needed to prevent memory leaks
   * in long-running processes.
   */
  destroy(): void {
    if (this.cleanupTimer !== null) {
      clearInterval(this.cleanupTimer);
      this.cleanupTimer = null;
    }
    this.entries.clear();
    this.logger.info('RateLimiter destroyed');
  }

  // ── Private Helpers ──────────────────────────────────────────────────────────

  /**
   * Start the periodic background sweep that purges keys with no recent
   * activity, preventing unchecked growth of the internal map.
   */
  private startCleanup(): void {
    this.cleanupTimer = setInterval(() => {
      this.sweepExpired();
    }, CLEANUP_INTERVAL_MS);

    // Allow the Node.js process to exit even if the timer is still active.
    if (this.cleanupTimer && typeof this.cleanupTimer === 'object' && 'unref' in this.cleanupTimer) {
      this.cleanupTimer.unref();
    }
  }

  /**
   * Remove all keys whose latest timestamp is older than the QPM window.
   */
  private sweepExpired(): void {
    const cutoff = Date.now() - QPM_WINDOW_MS;
    let purged = 0;

    for (const [key, entry] of this.entries) {
      if (entry.timestamps.length === 0 || entry.timestamps[entry.timestamps.length - 1]! <= cutoff) {
        this.entries.delete(key);
        purged++;
      }
    }

    if (purged > 0) {
      this.logger.debug({ purgedKeys: purged, remainingKeys: this.entries.size }, 'Rate limiter sweep completed');
    }
  }

  /**
   * Return a new array with only elements > `threshold`.
   *
   * Uses simple filter since the typical window has few entries.
   */
  private filterAfter(sorted: number[], threshold: number): number[] {
    const idx = this.lowerBound(sorted, threshold);
    return sorted.slice(idx);
  }

  /**
   * Lower-bound binary search: index of the first element > `value`.
   */
  private lowerBound(sorted: number[], value: number): number {
    let lo = 0;
    let hi = sorted.length;
    while (lo < hi) {
      const mid = (lo + hi) >>> 1;
      if (sorted[mid]! <= value) {
        lo = mid + 1;
      } else {
        hi = mid;
      }
    }
    return lo;
  }
}

// ── Utility ───────────────────────────────────────────────────────────────────

/**
 * Build a rate-limit key from a session identifier and an optional user id.
 *
 * Keys follow the pattern:
 *   `session:<sessionId>`
 *   `session:<sessionId>:user:<userId>`
 *
 * This enables per-session limiting as the base policy, with optional
 * per-user sub-policy when a logged-in identity is available.
 *
 * @param sessionId  Unique session identifier.
 * @param userId     Optional authenticated user identifier.
 * @returns Canonical rate-limit key string.
 */
export function buildRateLimitKey(sessionId: string, userId?: string): string {
  if (userId !== undefined) {
    return `session:${sessionId}:user:${userId}`;
  }
  return `session:${sessionId}`;
}

// ══════════════════════════════════════════════════════════════════
//  AuthRateLimiter — Login failure lockout + exponential backoff
//  Gap: AUTH-03
// ══════════════════════════════════════════════════════════════════

export interface AuthRateLimitConfig {
  /** Maximum consecutive failures before account is locked (default: 10). */
  maxFailures: number;
  /** Lockout duration in ms after max failures (default: 30 min). */
  lockoutDurationMs: number;
  /** Base delay for first failure in ms (default: 1000). */
  baseDelayMs: number;
}

const DEFAULT_AUTH_CONFIG: AuthRateLimitConfig = {
  maxFailures: 10,
  lockoutDurationMs: 30 * 60 * 1000, // 30 minutes
  baseDelayMs: 1000,
};

export interface AuthRateLimitResult {
  /** Whether authentication is allowed to proceed. */
  allowed: boolean;
  /** Suggested delay in ms before responding (for exponential backoff). */
  delayMs: number;
  /** Number of consecutive failures so far. */
  failures: number;
  /** Whether the account is locked. */
  locked: boolean;
  /** Time remaining in lockout (ms), if locked. */
  lockoutRemainingMs: number;
}

interface AuthEntry {
  failures: number;
  lastFailureTime: number;
  lockoutUntil: number;
}

/**
 * Authentication rate limiter with exponential backoff delay and account lockout.
 *
 * Delay formula: baseDelay × 2^failures (exponential backoff)
 * Lockout: after maxFailures consecutive failures, lock for lockoutDurationMs
 */
export class AuthRateLimiter {
  private entries: Map<string, AuthEntry> = new Map();
  private config: AuthRateLimitConfig;
  private readonly logger: PinoLogger;

  constructor(config?: Partial<AuthRateLimitConfig>) {
    this.config = { ...DEFAULT_AUTH_CONFIG, ...config };
    this.logger = PinoLogger.forComponent('AuthRateLimiter');
  }

  /**
   * Record an authentication attempt and check if it should be allowed.
   */
  check(userId: string): AuthRateLimitResult {
    const now = Date.now();
    let entry = this.entries.get(userId);

    // Check lockout expiry
    if (entry && entry.lockoutUntil > now) {
      const lockoutRemainingMs = entry.lockoutUntil - now;
      return {
        allowed: false,
        delayMs: 0,
        failures: entry.failures,
        locked: true,
        lockoutRemainingMs,
      };
    }

    // Clear lockout if expired
    if (entry && entry.lockoutUntil > 0 && entry.lockoutUntil <= now) {
      this.reset(userId);
      entry = undefined;
    }

    if (!entry) {
      entry = { failures: 0, lastFailureTime: 0, lockoutUntil: 0 };
      this.entries.set(userId, entry);
    }

    // Compute exponential backoff delay
    const delayMs = Math.min(
      this.config.baseDelayMs * Math.pow(2, entry.failures),
      30_000, // Cap at 30 seconds
    );

    return {
      allowed: true,
      delayMs: entry.failures > 0 ? delayMs : 0,
      failures: entry.failures,
      locked: false,
      lockoutRemainingMs: 0,
    };
  }

  /**
   * Record a successful authentication — resets failure count.
   */
  recordSuccess(userId: string): void {
    this.entries.delete(userId);
    this.logger.debug({ userId }, 'Auth success — resetting rate limiter');
  }

  /**
   * Record a failed authentication — increments failure count.
   * Locks account if maxFailures exceeded.
   */
  recordFailure(userId: string): void {
    const now = Date.now();
    let entry = this.entries.get(userId);

    if (!entry) {
      entry = { failures: 0, lastFailureTime: 0, lockoutUntil: 0 };
      this.entries.set(userId, entry);
    }

    entry.failures++;
    entry.lastFailureTime = now;

    if (entry.failures >= this.config.maxFailures) {
      entry.lockoutUntil = now + this.config.lockoutDurationMs;
      this.logger.warn(
        { userId, failures: entry.failures, lockoutDurationMs: this.config.lockoutDurationMs },
        'Auth rate limiter: account locked due to too many failures',
      );
    } else {
      this.logger.debug(
        { userId, failures: entry.failures },
        'Auth rate limiter: recorded failure',
      );
    }
  }

  /**
   * Reset the rate limiter state for a user.
   */
  reset(userId: string): void {
    this.entries.delete(userId);
  }

  /**
   * Reset all entries.
   */
  resetAll(): void {
    this.entries.clear();
    this.logger.debug('All auth rate limiter entries cleared');
  }

  /**
   * Get current state for a user (for diagnostics).
   */
  getState(userId: string): AuthRateLimitResult | null {
    const entry = this.entries.get(userId);
    if (!entry) return null;

    const now = Date.now();
    const delayMs = Math.min(
      this.config.baseDelayMs * Math.pow(2, entry.failures),
      30_000,
    );

    return {
      allowed: entry.lockoutUntil <= now,
      delayMs: entry.failures > 0 ? delayMs : 0,
      failures: entry.failures,
      locked: entry.lockoutUntil > now,
      lockoutRemainingMs: Math.max(0, entry.lockoutUntil - now),
    };
  }

  /**
   * Destroy the rate limiter.
   */
  destroy(): void {
    this.entries.clear();
    this.logger.info('AuthRateLimiter destroyed');
  }
}

// ══════════════════════════════════════════════════════════════════
//  IpAccessController — Pre-auth IP black/whitelist
//  Gap: NET-01
// ══════════════════════════════════════════════════════════════════

/** IP access control mode. */
export type IpAccessMode = 'whitelist' | 'blacklist' | 'none';

export interface IpAccessConfig {
  /** Access control mode. */
  mode: IpAccessMode;
  /** List of CIDR ranges for the selected mode. */
  cidrs: string[];
}

export interface IpAccessResult {
  /** Whether the IP is allowed to connect. */
  allowed: boolean;
  /** Reason for deny. */
  reason: string;
}

/**
 * Pre-authentication IP access controller.
 *
 * Checks client IP addresses against whitelist/blacklist rules
 * before authentication begins. Supports CIDR notation for both
 * IPv4 and IPv6.
 */
export class IpAccessController {
  private whitelist: IpAccessConfig = { mode: 'none', cidrs: [] };
  private blacklist: IpAccessConfig = { mode: 'none', cidrs: [] };
  private readonly logger: PinoLogger;

  constructor() {
    this.logger = PinoLogger.forComponent('IpAccessController');
  }

  /**
   * Set whitelist CIDRs (only these IPs are allowed).
   */
  setWhitelist(cidrs: string[]): void {
    this.whitelist = { mode: cidrs.length > 0 ? 'whitelist' : 'none', cidrs: [...cidrs] };
    this.logger.info({ cidrs }, 'IP whitelist configured');
  }

  /**
   * Set blacklist CIDRs (these IPs are blocked).
   */
  setBlacklist(cidrs: string[]): void {
    this.blacklist = { mode: cidrs.length > 0 ? 'blacklist' : 'none', cidrs: [...cidrs] };
    this.logger.info({ cidrs }, 'IP blacklist configured');
  }

  /**
   * Check if an IP address is allowed.
   * Whitelist takes precedence over blacklist.
   */
  check(ip: string): IpAccessResult {
    if (!ip) {
      return { allowed: true, reason: 'No IP address' };
    }

    // Normalize IPv4-mapped IPv6 addresses
    const normalizedIp = ip.replace(/^::ffff:/, '');

    // Check whitelist first (whitelist mode)
    if (this.whitelist.mode === 'whitelist') {
      if (!this.isIpInCidrList(normalizedIp, this.whitelist.cidrs)) {
        return {
          allowed: false,
          reason: `IP ${normalizedIp} is not in the whitelist`,
        };
      }
      return { allowed: true, reason: 'IP is in the whitelist' };
    }

    // Check blacklist
    if (this.blacklist.mode === 'blacklist') {
      if (this.isIpInCidrList(normalizedIp, this.blacklist.cidrs)) {
        return {
          allowed: false,
          reason: `IP ${normalizedIp} is in the blacklist`,
        };
      }
    }

    return { allowed: true, reason: 'IP is allowed' };
  }

  /**
   * Get the current configuration.
   */
  getConfig(): { whitelist: IpAccessConfig; blacklist: IpAccessConfig } {
    return {
      whitelist: { ...this.whitelist, cidrs: [...this.whitelist.cidrs] },
      blacklist: { ...this.blacklist, cidrs: [...this.blacklist.cidrs] },
    };
  }

  // ── Private ────────────────────────────────────────────────────

  /**
   * Check if an IP is in any of the CIDR ranges.
   * Simple implementation using ip-address library compatible logic.
   */
  private isIpInCidrList(ip: string, cidrs: string[]): boolean {
    for (const cidr of cidrs) {
      if (this.ipMatchesCidr(ip, cidr)) {
        return true;
      }
    }
    return false;
  }

  /**
   * Simple CIDR matching for both IPv4 and IPv6.
   */
  private ipMatchesCidr(ip: string, cidr: string): boolean {
    try {
      const [networkStr, bitsStr] = cidr.split('/');
      const bits = bitsStr ? parseInt(bitsStr, 10) : (ip.includes(':') ? 128 : 32);

      const ipBig = this.ipToBigint(ip);
      const netBig = this.ipToBigint(networkStr!);

      if (ip.includes(':') || networkStr!.includes(':')) {
        // IPv6
        const shift = BigInt(128 - bits);
        return (ipBig >> shift) === (netBig >> shift);
      } else {
        // IPv4
        const mask = bits === 0 ? BigInt(0) : (BigInt(0xffffffff) << BigInt(32 - bits)) & BigInt(0xffffffff);
        return (ipBig & mask) === (netBig & mask);
      }
    } catch {
      this.logger.warn({ ip, cidr }, 'CIDR matching failed');
      return false;
    }
  }

  /**
   * Convert an IP string to a BigInt for comparison.
   */
  private ipToBigint(ip: string): bigint {
    const cleanIp = ip.replace(/^::ffff:/, '');
    if (cleanIp.includes(':')) {
      // IPv6
      return this.ipv6ToBigint(cleanIp);
    }
    // IPv4
    const parts = cleanIp.split('.').map(Number);
    return BigInt(parts[0]! << 24 | parts[1]! << 16 | parts[2]! << 8 | parts[3]!);
  }

  private ipv6ToBigint(ip: string): bigint {
    // Expand IPv6 to 8 groups of 16-bit
    let full = ip;
    const doubleColon = full.indexOf('::');
    if (doubleColon >= 0) {
      const prefix = doubleColon === 0 ? '' : full.substring(0, doubleColon);
      const suffix = doubleColon + 2 >= full.length ? '' : full.substring(doubleColon + 2);
      const prefixCount = prefix ? prefix.split(':').length : 0;
      const suffixCount = suffix ? suffix.split(':').length : 0;
      const missing = 8 - prefixCount - suffixCount;
      full = [
        prefix,
        ...Array(missing).fill('0'),
        suffix,
      ].filter(Boolean).join(':');
    }

    let result = BigInt(0);
    for (const group of full.split(':')) {
      result = (result << BigInt(16)) | BigInt(parseInt(group || '0', 16));
    }
    return result;
  }
}

// ══════════════════════════════════════════════════════════════════
//  EnhancedRateLimiter — Token bucket + sliding window
//  with per-user / per-IP / per-database support
//  Gap: P1-P2 Rate Limiting
// ══════════════════════════════════════════════════════════════════

export type RateLimitDimension = 'user' | 'ip' | 'database' | 'global';

export interface EnhancedRateLimitConfig {
  /** Token bucket: tokens added per second */
  tokensPerSecond: number;
  /** Token bucket: max token capacity (burst size) */
  bucketCapacity: number;
  /** Sliding window: max requests per window */
  windowLimit: number;
  /** Sliding window size in ms (default: 60000 / 1 minute) */
  windowMs: number;
  /** Per-user limit: max requests per window (overrides windowLimit if set) */
  perUserLimit: number;
  /** Per-IP limit: max requests per window (overrides windowLimit if set) */
  perIpLimit: number;
  /** Per-database limit: max requests per window (overrides windowLimit if set) */
  perDatabaseLimit: number;
}

export interface EnhancedRateLimitResult {
  allowed: boolean;
  /** Token bucket: remaining tokens */
  tokens: number;
  /** Sliding window: remaining requests in current window */
  windowRemaining: number;
  /** Global: retry-after in ms */
  retryAfterMs: number;
  /** Which dimension triggered the block (if any) */
  blockedBy?: 'token-bucket' | 'sliding-window' | 'per-user' | 'per-ip' | 'per-database';
}

const DEFAULT_ENHANCED_CONFIG: EnhancedRateLimitConfig = {
  tokensPerSecond: 100,
  bucketCapacity: 200,
  windowLimit: 1000,
  windowMs: 60_000,
  perUserLimit: 500,
  perIpLimit: 2000,
  perDatabaseLimit: 5000,
};

interface TokenBucketEntry {
  tokens: number;
  lastRefill: number;
}

interface SlidingWindowEntry {
  timestamps: number[];
}

interface EnhancedEntry {
  bucket: TokenBucketEntry;
  window: SlidingWindowEntry;
}

/**
 * EnhancedRateLimiter — Combines token bucket + sliding window algorithms.
 *
 * ## Algorithms
 *
 * - **Token bucket**: Allows burst traffic up to `bucketCapacity`, then
 *   refills at `tokensPerSecond`. Best for short burst handling.
 * - **Sliding window**: Limits sustained traffic over a longer window.
 *   Best for preventing resource exhaustion.
 *
 * ## Per-dimension limits
 *
 * Supports independent limits for:
 *   - Per-user (`user:<userId>`)
 *   - Per-IP (`ip:<address>`)
 *   - Per-database (`db:<name>`)
 *   - Global (`global`)
 *
 * ## Usage
 *
 * ```ts
 * const rl = new EnhancedRateLimiter();
 *
 * // Global check
 * rl.check('global');
 *
 * // Per-user check
 * rl.check('user:alice');
 *
 * // Per-IP check
 * rl.check('ip:192.168.1.1');
 * ```
 */
export class EnhancedRateLimiter {
  private entries: Map<string, EnhancedEntry> = new Map();
  private config: EnhancedRateLimitConfig;
  private readonly logger: PinoLogger;
  private cleanupTimer: ReturnType<typeof setInterval> | null = null;
  private static readonly CLEANUP_INTERVAL_MS = 60_000;

  constructor(config?: Partial<EnhancedRateLimitConfig>) {
    this.config = { ...DEFAULT_ENHANCED_CONFIG, ...config };
    this.logger = PinoLogger.forComponent('EnhancedRateLimiter');
    this.startCleanup();
  }

  // ── Public API ────────────────────────────────────────────────

  /**
   * Check whether a request identified by `key` is allowed.
   *
   * Key conventions:
   *   - `global` — global rate limit
   *   - `user:<userId>` — per-user limit
   *   - `ip:<address>` — per-IP limit
   *   - `db:<database>` — per-database limit
   *
   * @param key Rate limit key.
   * @returns Result with allowed flag and diagnostics.
   */
  check(key: string): EnhancedRateLimitResult {
    const now = Date.now();

    let entry = this.entries.get(key);
    if (!entry) {
      entry = {
        bucket: { tokens: this.config.bucketCapacity, lastRefill: now },
        window: { timestamps: [] },
      };
      this.entries.set(key, entry);
    }

    // ── 1. Token bucket refill ────────────────────────────────────
    const elapsed = (now - entry.bucket.lastRefill) / 1000;
    const refill = elapsed * this.config.tokensPerSecond;
    if (refill > 0) {
      entry.bucket.tokens = Math.min(
        this.config.bucketCapacity,
        entry.bucket.tokens + refill,
      );
      entry.bucket.lastRefill = now;
    }

    // ── 2. Sliding window pruning ─────────────────────────────────
    const windowStart = now - this.config.windowMs;
    const firstValid = this.lowerBound(entry.window.timestamps, windowStart);
    if (firstValid > 0) {
      entry.window.timestamps = entry.window.timestamps.slice(firstValid);
    }

    // ── 3. Determine per-dimension limits ─────────────────────────
    let activeWindowLimit = this.config.windowLimit;
    let blockedBy: EnhancedRateLimitResult['blockedBy'] = undefined;

    if (key.startsWith('user:')) {
      activeWindowLimit = this.config.perUserLimit;
    } else if (key.startsWith('ip:')) {
      activeWindowLimit = this.config.perIpLimit;
    } else if (key.startsWith('db:')) {
      activeWindowLimit = this.config.perDatabaseLimit;
    }

    // ── 4. Token bucket check ─────────────────────────────────────
    if (entry.bucket.tokens < 1) {
      const retryAfterMs = Math.ceil((1 / this.config.tokensPerSecond) * 1000);
      return {
        allowed: false,
        tokens: 0,
        windowRemaining: activeWindowLimit - entry.window.timestamps.length,
        retryAfterMs,
        blockedBy: 'token-bucket',
      };
    }

    // ── 5. Sliding window check ───────────────────────────────────
    if (entry.window.timestamps.length >= activeWindowLimit) {
      const oldest = entry.window.timestamps[0]!;
      const retryAfterMs = Math.max(0, Math.ceil(oldest + this.config.windowMs - now));
      return {
        allowed: false,
        tokens: Math.floor(entry.bucket.tokens),
        windowRemaining: 0,
        retryAfterMs,
        blockedBy: key.startsWith('user:') ? 'per-user'
          : key.startsWith('ip:') ? 'per-ip'
          : key.startsWith('db:') ? 'per-database'
          : 'sliding-window',
      };
    }

    // ── 6. Allow: consume token and record timestamp ──────────────
    entry.bucket.tokens -= 1;
    entry.window.timestamps.push(now);

    return {
      allowed: true,
      tokens: Math.floor(entry.bucket.tokens),
      windowRemaining: activeWindowLimit - entry.window.timestamps.length,
      retryAfterMs: 0,
    };
  }

  /**
   * Reset state for a specific key.
   */
  reset(key: string): void {
    this.entries.delete(key);
  }

  /**
   * Reset all state.
   */
  resetAll(): void {
    this.entries.clear();
    this.logger.debug('EnhancedRateLimiter reset all');
  }

  /**
   * Update config at runtime.
   */
  updateConfig(config: Partial<EnhancedRateLimitConfig>): void {
    Object.assign(this.config, config);
    this.logger.info({ config: this.config }, 'EnhancedRateLimiter config updated');
  }

  /**
   * Get current config.
   */
  getConfig(): Readonly<EnhancedRateLimitConfig> {
    return { ...this.config };
  }

  /**
   * Number of distinct keys currently tracked.
   */
  get keyCount(): number {
    return this.entries.size;
  }

  /**
   * Destroy the limiter and release resources.
   */
  destroy(): void {
    if (this.cleanupTimer !== null) {
      clearInterval(this.cleanupTimer);
      this.cleanupTimer = null;
    }
    this.entries.clear();
    this.logger.info('EnhancedRateLimiter destroyed');
  }

  // ── Private ───────────────────────────────────────────────────

  private startCleanup(): void {
    this.cleanupTimer = setInterval(() => {
      this.sweepExpired();
    }, EnhancedRateLimiter.CLEANUP_INTERVAL_MS);

    if (this.cleanupTimer && typeof this.cleanupTimer === 'object' && 'unref' in this.cleanupTimer) {
      this.cleanupTimer.unref();
    }
  }

  private sweepExpired(): void {
    const cutoff = Date.now() - this.config.windowMs;
    let purged = 0;
    for (const [key, entry] of this.entries) {
      const lastTs = entry.window.timestamps[entry.window.timestamps.length - 1];
      if (!lastTs || lastTs <= cutoff) {
        this.entries.delete(key);
        purged++;
      }
    }
    if (purged > 0) {
      this.logger.debug({ purged, remaining: this.entries.size }, 'Enhanced sweep completed');
    }
  }

  private lowerBound(sorted: number[], value: number): number {
    let lo = 0;
    let hi = sorted.length;
    while (lo < hi) {
      const mid = (lo + hi) >>> 1;
      if (sorted[mid]! <= value) lo = mid + 1;
      else hi = mid;
    }
    return lo;
  }
}
