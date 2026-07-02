/**
 * RoleManager — Role-based access control for PostgreSQL Wire Protocol
 *
 * Implements the PostgreSQL role model:
 *   - Roles can be users or groups
 *   - Roles have attributes: superuser, login, create-db, create-role
 *   - Roles can be members of other roles (role hierarchy)
 *   - Default roles: pg_read_all_data, pg_write_all_data
 *   - Superuser bypasses all permission checks
 *   - Permission inheritance via memberOf chain
 *
 * Portions based on PostgreSQL's src/backend/commands/user.c.
 */

// ════════════════════════════════════════════════
//  Types
// ════════════════════════════════════════════════

export interface DatabaseRole {
  roleName: string;
  superuser: boolean;
  login: boolean;
  canCreateDb: boolean;
  canCreateRole: boolean;
  /** List of group roles this role is a member of */
  memberOf: string[];
  /** Additional custom attributes */
  attributes: Record<string, boolean>;
}

import { PinoLogger } from '../monitoring/PinoLogger';
import { AuditLogger } from '../security/AuditLogger';
import { DatabaseError } from '../error/DatabaseError';
import {
  SQLSTATE_DUPLICATE_OBJECT,
  SQLSTATE_UNDEFINED_OBJECT,
  SQLSTATE_OBJECT_NOT_IN_PREREQUISITE_STATE,
} from '../constants/sqlstate';

// ════════════════════════════════════════════════
//  RoleManager class
// ════════════════════════════════════════════════

export class RoleManager {
  private readonly logger = PinoLogger.forComponent('RoleManager');
  private auditLogger?: AuditLogger;
  private roles: Map<string, DatabaseRole>;
  private membershipCache: Map<string, Set<string>>;

  setAuditLogger(logger: AuditLogger): void {
    this.auditLogger = logger;
  }

  constructor() {
    this.roles = new Map();
    this.membershipCache = new Map();
    this.initDefaultRoles();
  }

  /**
   * Initialize default roles (pg_read_all_data, pg_write_all_data).
   * These are special system roles as defined in PostgreSQL 14+.
   */
  private initDefaultRoles(): void {
    const defaultRoles = this.getDefaultRoles();
    for (const role of defaultRoles) {
      this.roles.set(role.roleName.toLowerCase(), role);
    }
  }

  // ── CRUD operations ──

  createRole(role: DatabaseRole): void {
    const key = role.roleName.toLowerCase();
    if (this.roles.has(key)) {
      throw new DatabaseError(
        `Role "${role.roleName}" already exists`,
        SQLSTATE_DUPLICATE_OBJECT,
      );
    }

    this.roles.set(key, { ...role, memberOf: [...role.memberOf] });
    // Clear entire cache since memberships may change
    this.membershipCache.clear();
    // Audit log: specific role_created event with role name + attributes
    this.auditLogger?.logCustom(
      'role_created',
      'system',
      'admin',
      JSON.stringify({
        roleName: role.roleName,
        superuser: role.superuser,
        login: role.login,
        canCreateDb: role.canCreateDb,
        canCreateRole: role.canCreateRole,
        memberOf: role.memberOf,
        attributes: role.attributes,
      }),
      'success',
    );
  }

  dropRole(roleName: string): void {
    const key = roleName.toLowerCase();
    if (!this.roles.has(key)) {
      throw new DatabaseError(
        `Role "${roleName}" does not exist`,
        SQLSTATE_UNDEFINED_OBJECT,
      );
    }

    // Cannot drop default roles
    const role = this.roles.get(key)!;
    if (role.roleName.startsWith('pg_')) {
      throw new DatabaseError(
        `Cannot drop system role "${role.roleName}"`,
        SQLSTATE_OBJECT_NOT_IN_PREREQUISITE_STATE,
      );
    }

    this.roles.delete(key);
    // Clear entire cache since memberships may change
    this.membershipCache.clear();
    // Audit log: specific role_dropped event with role name
    this.auditLogger?.logCustom(
      'role_dropped',
      'system',
      'admin',
      JSON.stringify({ roleName }),
      'success',
    );
  }

  // ── Query operations ──

  hasRole(roleName: string): boolean {
    return this.roles.has(roleName.toLowerCase());
  }

  /**
   * Check if a role is a member of a group (directly or transitively).
   * Resolves through the full membership chain.
   */
  isMemberOf(roleName: string, groupName: string): boolean {
    const roleKey = roleName.toLowerCase();
    const groupKey = groupName.toLowerCase();

    // Direct membership
    const role = this.roles.get(roleKey);
    if (!role) return false;

    // A role is a member of itself
    if (roleKey === groupKey) return true;

    // Use cache if available
    if (this.membershipCache.has(roleKey)) {
      return this.membershipCache.get(roleKey)!.has(groupKey);
    }

    // BFS through the membership chain
    return this.computeMembership(roleKey).has(groupKey);
  }

  /**
   * Check if a role has the LOGIN attribute.
   */
  canConnect(roleName: string, _database: string): boolean {
    const role = this.roles.get(roleName.toLowerCase());
    if (!role) return false;

    // Superuser can always connect (unless explicitly denied—not supported yet)
    if (role.superuser) return true;

    return role.login;
  }

  /**
   * Check if a role has a specific privilege.
   *
   * @param roleName - The role to check
   * @param operation - Operation: 'SELECT', 'INSERT', 'UPDATE', 'DELETE',
   *                    'CREATE', 'CONNECT', 'TEMPORARY', 'USAGE', 'ALL'
   * @param objectName - Optional database object name
   */
  checkPrivilege(roleName: string, operation: string, _objectName?: string): boolean {
    const role = this.roles.get(roleName.toLowerCase());
    if (!role) return false;

    const op = operation.toUpperCase();

    // Superuser bypasses all permission checks
    if (role.superuser) return true;

    // Check role attributes for certain operations
    if (op === 'CREATE' && role.canCreateDb) return true;
    if (op === 'CREATE' && role.canCreateRole) return true;

    // Check pg_read_all_data membership
    if (op === 'SELECT') {
      if (this.isMemberOf(roleName, 'pg_read_all_data')) return true;
    }

    // Check pg_write_all_data membership
    if (op === 'INSERT' || op === 'UPDATE' || op === 'DELETE') {
      if (this.isMemberOf(roleName, 'pg_write_all_data')) return true;
    }

    // For now, LOGIN roles get basic access by default
    // (This is simplified — real PG also checks object-level ACLs)
    if (op === 'CONNECT') return role.login || role.superuser;

    return false;
  }

  // ── Default roles ──

  getDefaultRoles(): DatabaseRole[] {
    return [
      {
        roleName: 'pg_read_all_data',
        superuser: false,
        login: false,
        canCreateDb: false,
        canCreateRole: false,
        memberOf: [],
        attributes: {},
      },
      {
        roleName: 'pg_write_all_data',
        superuser: false,
        login: false,
        canCreateDb: false,
        canCreateRole: false,
        memberOf: [],
        attributes: {},
      },
      {
        roleName: 'pg_database_owner',
        superuser: false,
        login: false,
        canCreateDb: false,
        canCreateRole: false,
        memberOf: [],
        attributes: {},
      },
    ];
  }

  /**
   * Get a role by name.
   */
  getRole(roleName: string): DatabaseRole | undefined {
    const role = this.roles.get(roleName.toLowerCase());
    return role ? { ...role, memberOf: [...role.memberOf] } : undefined;
  }

  /**
   * Get all roles.
   */
  getAllRoles(): DatabaseRole[] {
    return Array.from(this.roles.values()).map((r) => ({
      ...r,
      memberOf: [...r.memberOf],
    }));
  }

  // ════════════════════════════════════════════════
  //  Private helpers
  // ════════════════════════════════════════════════

  /**
   * Compute the transitive closure of group memberships for a role.
   * Uses BFS to avoid infinite loops in case of circular membership.
   */
  private computeMembership(roleKey: string): Set<string> {
    const visited = new Set<string>();
    const queue: string[] = [roleKey];
    const role = this.roles.get(roleKey);

    if (!role) return visited;

    while (queue.length > 0) {
      const currentKey = queue.shift()!;
      if (visited.has(currentKey)) continue;
      visited.add(currentKey);

      const current = this.roles.get(currentKey);
      if (!current) {
        // Role doesn't exist in the map (e.g., being created).
        // Remove it from visited so it doesn't count as a resolved member.
        visited.delete(currentKey);
        continue;
      }

      for (const group of current.memberOf) {
        const groupKey = group.toLowerCase();
        if (!visited.has(groupKey)) {
          queue.push(groupKey);
        }
      }
    }

    // Cache the result (excluding self)
    const result = new Set<string>(visited);
    result.delete(roleKey);
    this.membershipCache.set(roleKey, result);

    return result;
  }
}
