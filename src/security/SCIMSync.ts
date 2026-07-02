/**
 * SCIMSync — System for Cross-domain Identity Management (SCIM 2.0) synchronization.
 *
 * PostgreSQL enterprise provides SCIM 2.0 endpoints for automated user and group
 * provisioning from identity providers (IdP) such as Azure AD, Okta, or Keycloak.
 *
 * SCIM 2.0 defines standardised schemas for:
 *   - Users (urn:ietf:params:scim:schemas:core:2.0:User)
 *   - Groups (urn:ietf:params:scim:schemas:core:2.0:Group)
 *   - Bulk operations, filtering, and pagination
 *
 * This implementation provides a SCIMClient that connects to an external SCIM 2.0
 * provider, with methods for user/group sync, configuration validation, and a
 * stub fallback when no provider is configured.
 *
 * @module SCIMSync
 */

import { PinoLogger } from '../monitoring/PinoLogger';

const logger = PinoLogger.forComponent('SCIMSync');

// ── Types ──────────────────────────────────────────────────────

export interface SCIMConfig {
  /** Base URL of the SCIM API endpoint (e.g. 'https://idp.example.com/scim/v2') */
  endpoint: string;
  /** Bearer token for authenticating SCIM API requests */
  bearerToken: string;
  /** Synchronisation interval in milliseconds (default: 3600000 = 1 hour) */
  syncIntervalMs: number;
}

export interface SCIMUser {
  id: string;
  userName: string;
  active: boolean;
  emails?: Array<{ value: string; primary?: boolean; type?: string }>;
  displayName?: string;
  name?: {
    givenName?: string;
    familyName?: string;
  };
  externalId?: string;
  meta?: {
    lastModified?: string;
  };
}

export interface SCIMGroup {
  id: string;
  displayName: string;
  members?: Array<{ value: string; type?: string; display?: string }>;
  meta?: {
    lastModified?: string;
  };
}

export interface SCIMSyncResult {
  usersCreated: number;
  usersUpdated: number;
  usersDisabled: number;
  groupsCreated: number;
  groupsUpdated: number;
  groupsDeleted: number;
}

export interface SCIMListResponse<T> {
  totalResults: number;
  itemsPerPage: number;
  startIndex: number;
  Resources: T[];
}

// ── SCIM Client ────────────────────────────────────────────────

/**
 * SCIMClient connects to a SCIM 2.0-compliant identity provider and fetches
 * users and groups. Supports paginated queries and optional filtering by
 * modification date.
 */
export class SCIMClient {
  private readonly config: SCIMConfig;

  constructor(config: SCIMConfig) {
    validateSCIMConfig(config);
    this.config = { ...config };
  }

  /**
   * Fetch all users from the SCIM provider.
   * Supports filtering by `since` date using the `meta.lastModified` attribute.
   */
  async getUsers(since?: Date): Promise<SCIMUser[]> {
    const users: SCIMUser[] = [];
    let startIndex = 1;
    const perPage = 100;
    let totalResults = Infinity;

    while (startIndex <= totalResults) {
      let url = `${this.config.endpoint}/Users?startIndex=${startIndex}&count=${perPage}`;
      if (since) {
        url += `&filter=meta.lastModified gt "${since.toISOString()}"`;
      }

      const response = await this.fetchSCIM<SCIMListResponse<SCIMUser>>(url);
      if (response.Resources) {
        users.push(...response.Resources);
      }
      totalResults = response.totalResults;
      startIndex += perPage;
    }

    return users;
  }

  /**
   * Fetch all groups from the SCIM provider.
   */
  async getGroups(): Promise<SCIMGroup[]> {
    const groups: SCIMGroup[] = [];
    let startIndex = 1;
    const perPage = 100;
    let totalResults = Infinity;

    while (startIndex <= totalResults) {
      const url = `${this.config.endpoint}/Groups?startIndex=${startIndex}&count=${perPage}`;
      const response = await this.fetchSCIM<SCIMListResponse<SCIMGroup>>(url);
      if (response.Resources) {
        groups.push(...response.Resources);
      }
      totalResults = response.totalResults;
      startIndex += perPage;
    }

    return groups;
  }

  /**
   * Generic SCIM API fetch with bearer auth.
   */
  private async fetchSCIM<T>(url: string): Promise<T> {
    const response = await fetch(url, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${this.config.bearerToken}`,
        'Content-Type': 'application/json',
        'Accept': 'application/scim+json, application/json',
      },
      signal: AbortSignal.timeout(30000),
    });

    if (!response.ok) {
      throw new Error(`SCIM API error: ${response.status} ${response.statusText} for ${url}`);
    }

    return response.json() as Promise<T>;
  }
}

// ── Validation ─────────────────────────────────────────────────

const URL_REGEX = /^https?:\/\/.+/i;
const TOKEN_MIN_LENGTH = 8;

/**
 * Validate SCIM configuration.
 * Throws if the endpoint URL is malformed or the bearer token is missing/too short.
 */
export function validateSCIMConfig(config: SCIMConfig): void {
  if (!config.endpoint || typeof config.endpoint !== 'string') {
    throw new Error('SCIM endpoint URL is required');
  }

  const trimmed = config.endpoint.trim();

  if (!URL_REGEX.test(trimmed)) {
    throw new Error(`SCIM endpoint must be a valid HTTP(S) URL, got: "${trimmed}"`);
  }

  // Normalize: remove trailing slash for consistent URL building
  config.endpoint = trimmed.replace(/\/+$/, '');

  if (!config.bearerToken || typeof config.bearerToken !== 'string') {
    throw new Error('SCIM bearer token is required');
  }

  if (config.bearerToken.trim().length < TOKEN_MIN_LENGTH) {
    throw new Error(`SCIM bearer token must be at least ${TOKEN_MIN_LENGTH} characters`);
  }

  if (typeof config.syncIntervalMs !== 'number' || config.syncIntervalMs < 10000) {
    throw new Error('SCIM sync interval must be at least 10000ms');
  }
}

// ── Sync Manager ───────────────────────────────────────────────

/**
 * SCIM user/group synchronisation manager.
 *
 * Manages the lifecycle of SCIM sync operations:
 * - Connects to an external SCIM 2.0 provider via SCIMClient
 * - Diffs fetched users/groups against a local in-memory store
 * - Creates, updates, or disables records as needed
 * - Falls back to no-op stub when no provider is configured
 *
 * @example
 * ```typescript
 * const syncer = new SCIMSync({
 *   endpoint: 'https://idp.example.com/scim/v2',
 *   bearerToken: process.env.SCIM_TOKEN!,
 *   syncIntervalMs: 3_600_000,
 * });
 * await syncer.sync();
 * ```
 */
export class SCIMSync {
  private readonly config: SCIMConfig;
  private intervalHandle: ReturnType<typeof setInterval> | null = null;
  private client: SCIMClient | null = null;

  /** In-memory local user/group store for diff-based sync */
  private localUsers: Map<string, SCIMUser> = new Map();
  private localGroups: Map<string, SCIMGroup> = new Map();

  /** Provider URL and token for dynamic configuration */
  private providerUrl: string | null = null;
  private providerToken: string | null = null;

  constructor(config: SCIMConfig) {
    this.config = { ...config };
    this.client = new SCIMClient(this.config);
    logger.info({ endpoint: config.endpoint, syncIntervalMs: config.syncIntervalMs }, 'SCIMSync initialized');
  }

  /**
   * Configure or re-configure the SCIM provider at runtime.
   * Pass `null` values to clear the configuration (stub fallback).
   */
  setProvider(url: string | null, token: string | null): void {
    if (url && token) {
      const testConfig: SCIMConfig = {
        endpoint: url,
        bearerToken: token,
        syncIntervalMs: this.config.syncIntervalMs,
      };
      validateSCIMConfig(testConfig);
      this.providerUrl = testConfig.endpoint;
      this.providerToken = token;
      this.config.endpoint = testConfig.endpoint;
      this.config.bearerToken = token;
      this.client = new SCIMClient(this.config);
      logger.info({ endpoint: url }, 'SCIM provider configured');
    } else {
      this.providerUrl = null;
      this.providerToken = null;
      this.client = null;
      logger.info('SCIM provider cleared — using stub fallback');
    }
  }

  /**
   * Trigger a synchronisation cycle.
   *
   * When a provider is configured, fetches users and groups from the SCIM
   * endpoint, diffs against the local store, and applies changes.
   * When no provider is configured, this is a no-op.
   */
  async sync(): Promise<SCIMSyncResult> {
    if (!this.client) {
      logger.info('SCIM sync triggered but no provider configured (stub — no-op)');
      return { usersCreated: 0, usersUpdated: 0, usersDisabled: 0, groupsCreated: 0, groupsUpdated: 0, groupsDeleted: 0 };
    }

    try {
      logger.info('SCIM sync cycle started');
      const result: SCIMSyncResult = {
        usersCreated: 0,
        usersUpdated: 0,
        usersDisabled: 0,
        groupsCreated: 0,
        groupsUpdated: 0,
        groupsDeleted: 0,
      };

      // Sync users
      const remoteUsers = await this.client.getUsers();
      const resultUsers = this.syncUsers(remoteUsers);
      result.usersCreated = resultUsers.created;
      result.usersUpdated = resultUsers.updated;
      result.usersDisabled = resultUsers.disabled;

      // Sync groups
      const remoteGroups = await this.client.getGroups();
      const resultGroups = this.syncGroups(remoteGroups);
      result.groupsCreated = resultGroups.created;
      result.groupsUpdated = resultGroups.updated;
      result.groupsDeleted = resultGroups.deleted;

      logger.info({ result }, 'SCIM sync cycle completed');
      return result;
    } catch (err: any) {
      logger.error({ err: err.message }, 'SCIM sync cycle failed');
      throw err;
    }
  }

  /**
   * Diff remote users against local store and apply changes.
   * New users are added, existing users are updated if changed,
   * and local users not present remotely are disabled.
   */
  syncUsers(remoteUsers: SCIMUser[]): { created: number; updated: number; disabled: number } {
    let created = 0;
    let updated = 0;
    let disabled = 0;

    const remoteIds = new Set<string>();

    for (const remoteUser of remoteUsers) {
      remoteIds.add(remoteUser.id);
      const local = this.localUsers.get(remoteUser.id);

      if (!local) {
        // New user
        this.localUsers.set(remoteUser.id, { ...remoteUser });
        created++;
        logger.debug({ userId: remoteUser.id, userName: remoteUser.userName }, 'SCIM user created locally');
      } else {
        // Existing user — update if changed
        const changed =
          local.userName !== remoteUser.userName ||
          local.active !== remoteUser.active ||
          JSON.stringify(local.emails) !== JSON.stringify(remoteUser.emails);

        if (changed) {
          this.localUsers.set(remoteUser.id, { ...remoteUser });
          updated++;
          logger.debug({ userId: remoteUser.id, userName: remoteUser.userName }, 'SCIM user updated locally');
        }
      }
    }

    // Disable local users no longer in remote
    for (const [localId, localUser] of this.localUsers) {
      if (!remoteIds.has(localId) && localUser.active) {
        this.localUsers.set(localId, { ...localUser, active: false });
        disabled++;
        logger.debug({ userId: localId, userName: localUser.userName }, 'SCIM user disabled locally');
      }
    }

    return { created, updated, disabled };
  }

  /**
   * Diff remote groups against local store and apply changes.
   * New groups are added, existing groups are updated if changed,
   * and groups absent remotely are removed.
   */
  syncGroups(remoteGroups: SCIMGroup[]): { created: number; updated: number; deleted: number } {
    let created = 0;
    let updated = 0;
    let deleted = 0;

    const remoteIds = new Set<string>();

    for (const remoteGroup of remoteGroups) {
      remoteIds.add(remoteGroup.id);
      const local = this.localGroups.get(remoteGroup.id);

      if (!local) {
        this.localGroups.set(remoteGroup.id, { ...remoteGroup });
        created++;
        logger.debug({ groupId: remoteGroup.id, displayName: remoteGroup.displayName }, 'SCIM group created locally');
      } else {
        const changed =
          local.displayName !== remoteGroup.displayName ||
          JSON.stringify(local.members) !== JSON.stringify(remoteGroup.members);

        if (changed) {
          this.localGroups.set(remoteGroup.id, { ...remoteGroup });
          updated++;
          logger.debug({ groupId: remoteGroup.id, displayName: remoteGroup.displayName }, 'SCIM group updated locally');
        }
      }
    }

    // Delete local groups no longer in remote
    const toDelete: string[] = [];
    for (const [localId] of this.localGroups) {
      if (!remoteIds.has(localId)) {
        toDelete.push(localId);
      }
    }
    for (const id of toDelete) {
      this.localGroups.delete(id);
      deleted++;
      logger.debug({ groupId: id }, 'SCIM group deleted locally');
    }

    return { created, updated, deleted };
  }

  /**
   * Get all locally known users (for inspection / export).
   */
  getLocalUsers(): SCIMUser[] {
    return Array.from(this.localUsers.values());
  }

  /**
   * Get all locally known groups (for inspection / export).
   */
  getLocalGroups(): SCIMGroup[] {
    return Array.from(this.localGroups.values());
  }

  /**
   * Start periodic synchronisation on the configured interval.
   */
  startAutoSync(): void {
    if (this.intervalHandle) {
      logger.warn('Auto-sync already running');
      return;
    }
    this.intervalHandle = setInterval(() => {
      void this.sync();
    }, this.config.syncIntervalMs);
    logger.info({ intervalMs: this.config.syncIntervalMs }, 'Auto-sync started');
  }

  /**
   * Stop periodic synchronisation.
   */
  stopAutoSync(): void {
    if (this.intervalHandle) {
      clearInterval(this.intervalHandle);
      this.intervalHandle = null;
      logger.info('Auto-sync stopped');
    }
  }

  /**
   * Return the current configuration (read-only copy).
   */
  getConfig(): SCIMConfig {
    return { ...this.config };
  }

  /**
   * Check if a SCIM provider has been configured.
   */
  hasActiveClient(): boolean {
    return this.client !== null;
  }
}
