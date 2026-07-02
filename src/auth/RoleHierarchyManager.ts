/**
 * RoleHierarchyManager — RBAC role hierarchy with recursive CTE resolution.
 *
 * Implements role inheritance via three SQLite tables:
 *   - roles(name, parent)         — role hierarchy (directed acyclic graph)
 *   - role_members(role, user)    — user-to-role assignments
 *   - role_permissions(role, resource, action) — fine-grained ACLs
 *
 * Permission resolution uses a recursive CTE (WITH RECURSIVE) to compute
 * the transitive closure of role membership, enabling up to N-level
 * inheritance without iterative application code.
 *
 * Exposes pg_roles / pg_auth_members system table interfaces for
 * PostgreSQL Wire Protocol compatibility.
 *
 * @module auth/RoleHierarchyManager
 */

import Database from 'better-sqlite3';
import * as path from 'path';
import * as fs from 'fs';

import { PinoLogger } from '../monitoring/PinoLogger';

const logger = PinoLogger.forComponent('RoleHierarchyManager');

// ── Types ────────────────────────────────────────────────────────

export interface RoleNode {
  name: string;
  parent: string | null;
}

export interface RoleMember {
  role: string;
  user: string;
}

export interface RolePermission {
  role: string;
  resource: string;
  action: string;
}

export interface ResolvedPermission {
  role: string;
  resource: string;
  action: string;
  /** Depth from the original role (0 = direct assignment) */
  inheritanceDepth: number;
}

export type PgRoleRow = {
  rolname: string;
  rolsuper: boolean;
  rolinherit: boolean;
  rolcreaterole: boolean;
  rolcreatedb: boolean;
  rolcanlogin: boolean;
  rolconnlimit: number;
};

export type PgAuthMembersRow = {
  roleid: string;
  member: string;
  grantor: string;
  admin_option: boolean;
};

// ── RoleHierarchyManager ─────────────────────────────────────────

export class RoleHierarchyManager {
  private db: Database.Database;
  private initialized = false;

  /**
   * @param dbPath - Path to the SQLite database file for role storage.
   *                 Defaults to './roles.db' inside the data directory.
   */
  constructor(dbPath?: string) {
    const resolvedPath = dbPath || path.join(process.env.DATA_DIR || '/tmp/sqlvec-db', 'roles.db');
    const dir = path.dirname(resolvedPath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    this.db = new Database(resolvedPath);
    this.db.pragma('journal_mode = WAL');
  }

  /**
   * Initialize the schema (role hierarchy tables, indexes, recursive view).
   */
  init(): void {
    if (this.initialized) return;

    this.db.exec(`
      CREATE TABLE IF NOT EXISTS roles (
        name TEXT PRIMARY KEY,
        parent TEXT,
        FOREIGN KEY (parent) REFERENCES roles(name) ON DELETE SET NULL
      );

      CREATE TABLE IF NOT EXISTS role_members (
        role TEXT NOT NULL,
        user TEXT NOT NULL,
        PRIMARY KEY (role, user),
        FOREIGN KEY (role) REFERENCES roles(name) ON DELETE CASCADE
      );

      CREATE TABLE IF NOT EXISTS role_permissions (
        role TEXT NOT NULL,
        resource TEXT NOT NULL,
        action TEXT NOT NULL,
        PRIMARY KEY (role, resource, action),
        FOREIGN KEY (role) REFERENCES roles(name) ON DELETE CASCADE
      );

      CREATE INDEX IF NOT EXISTS idx_role_members_user ON role_members(user);
      CREATE INDEX IF NOT EXISTS idx_role_permissions_resource ON role_permissions(resource);

      -- Recursive view providing the transitive closure of role inheritance
      CREATE VIEW IF NOT EXISTS role_inheritance AS
      WITH RECURSIVE role_tree(name, ancestor, depth) AS (
        SELECT r.name, r.name, 0 FROM roles r
        UNION ALL
        SELECT rt.name, r.parent, rt.depth + 1
        FROM role_tree rt
        JOIN roles r ON r.name = rt.ancestor
        WHERE r.parent IS NOT NULL
      )
      SELECT * FROM role_tree;
    `);

    this.initialized = true;
    logger.info('RoleHierarchyManager initialized');
  }

  // ── Role CRUD ──────────────────────────────────────────────────

  /**
   * Create or update a role node in the hierarchy.
   *
   * @param name   - Role name
   * @param parent - Optional parent role name (null = root)
   */
  createRole(name: string, parent: string | null = null): void {
    this.ensureInitialized();
    const existing = this.db.prepare('SELECT name FROM roles WHERE name = ?').get(name);
    if (existing) {
      this.db.prepare('UPDATE roles SET parent = ? WHERE name = ?').run(parent, name);
    } else {
      this.db.prepare('INSERT INTO roles (name, parent) VALUES (?, ?)').run(name, parent);
    }
    logger.debug({ role: name, parent }, 'Role created/updated');
  }

  /**
   * Remove a role and all its assignments (cascading).
   */
  dropRole(name: string): void {
    this.ensureInitialized();
    this.db.prepare('DELETE FROM roles WHERE name = ?').run(name);
    logger.debug({ role: name }, 'Role dropped');
  }

  /**
   * Get the direct parent of a role.
   */
  getParent(name: string): string | null {
    this.ensureInitialized();
    const row = this.db.prepare('SELECT parent FROM roles WHERE name = ?').get(name) as { parent: string | null } | undefined;
    return row ? row.parent : null;
  }

  /**
   * Get all roles.
   */
  getAllRoles(): RoleNode[] {
    this.ensureInitialized();
    return this.db.prepare('SELECT name, parent FROM roles ORDER BY name').all() as RoleNode[];
  }

  // ── Membership ─────────────────────────────────────────────────

  /**
   * Assign a user to a role.
   */
  addMember(role: string, user: string): void {
    this.ensureInitialized();
    this.db.prepare('INSERT OR IGNORE INTO role_members (role, user) VALUES (?, ?)').run(role, user);
    logger.debug({ role, user }, 'User added to role');
  }

  /**
   * Remove a user from a role.
   */
  removeMember(role: string, user: string): void {
    this.ensureInitialized();
    this.db.prepare('DELETE FROM role_members WHERE role = ? AND user = ?').run(role, user);
  }

  /**
   * Get all roles a user is directly assigned to.
   */
  getUserRoles(user: string): string[] {
    this.ensureInitialized();
    const rows = this.db.prepare('SELECT role FROM role_members WHERE user = ?').all(user) as { role: string }[];
    return rows.map(r => r.role);
  }

  /**
   * Get all users directly assigned to a role.
   */
  getRoleMembers(role: string): string[] {
    this.ensureInitialized();
    const rows = this.db.prepare('SELECT user FROM role_members WHERE role = ?').all(role) as { user: string }[];
    return rows.map(r => r.user);
  }

  /**
   * Compute all roles a user inherits from (recursively via CTE).
   * Returns role names and inheritance depth.
   */
  getUserInheritedRoles(user: string): { role: string; depth: number }[] {
    this.ensureInitialized();
    // Uses recursive CTE to walk the role hierarchy from the user's direct roles upward
    const rows = this.db.prepare(`
      WITH RECURSIVE inherited(role, depth) AS (
        SELECT rm.role, 0
        FROM role_members rm
        WHERE rm.user = ?
        UNION ALL
        SELECT r.name, i.depth + 1
        FROM inherited i
        JOIN roles r ON r.parent = i.role
      )
      SELECT DISTINCT role, MIN(depth) as depth
      FROM inherited
      WHERE role IS NOT NULL
      GROUP BY role
      ORDER BY depth ASC
    `).all(user) as { role: string; depth: number }[];

    return rows;
  }

  /**
   * Check if a user is a member of a specific role (directly or through inheritance).
   */
  userHasRole(user: string, roleName: string): boolean {
    const inherited = this.getUserInheritedRoles(user);
    return inherited.some(r => r.role === roleName);
  }

  // ── Permissions ────────────────────────────────────────────────

  /**
   * Grant a permission to a role.
   */
  grantPermission(role: string, resource: string, action: string): void {
    this.ensureInitialized();
    this.db.prepare('INSERT OR IGNORE INTO role_permissions (role, resource, action) VALUES (?, ?, ?)')
      .run(role, resource, action);
    logger.debug({ role, resource, action }, 'Permission granted');
  }

  /**
   * Revoke a permission from a role.
   */
  revokePermission(role: string, resource: string, action: string): void {
    this.ensureInitialized();
    this.db.prepare('DELETE FROM role_permissions WHERE role = ? AND resource = ? AND action = ?')
      .run(role, resource, action);
  }

  /**
   * Get all permissions for a user (resolved through role inheritance).
   * Uses a recursive CTE to fetch permissions from all inherited roles.
   */
  getUserPermissions(user: string): ResolvedPermission[] {
    this.ensureInitialized();

    const rows = this.db.prepare(`
      WITH RECURSIVE inherited(role, depth) AS (
        SELECT rm.role, 0
        FROM role_members rm
        WHERE rm.user = ?
        UNION ALL
        SELECT r.name, i.depth + 1
        FROM inherited i
        JOIN roles r ON r.parent = i.role
      )
      SELECT DISTINCT rp.role, rp.resource, rp.action, i.depth
      FROM inherited i
      JOIN role_permissions rp ON rp.role = i.role
      ORDER BY i.depth ASC, rp.resource, rp.action
    `).all(user) as { role: string; resource: string; action: string; depth: number }[];

    return rows.map(r => ({
      role: r.role,
      resource: r.resource,
      action: r.action,
      inheritanceDepth: r.depth,
    }));
  }

  /**
   * Check if a user has a specific permission (resolved through inheritance).
   */
  userHasPermission(user: string, resource: string, action: string): boolean {
    const permissions = this.getUserPermissions(user);
    return permissions.some(p => p.resource === resource && p.action === action);
  }

  /**
   * Check if any inherited role has permission to the resource (wildcard support).
   */
  userCanAccess(user: string, resource: string): string[] {
    const permissions = this.getUserPermissions(user);
    const actions = permissions
      .filter(p => p.resource === resource || p.resource === '*')
      .map(p => p.action);
    return [...new Set(actions)];
  }

  // ── PostgreSQL System Table Interface ──────────────────────────

  /**
   * Simulate pg_roles system table (list of roles and their attributes).
   */
  getPgRoles(): PgRoleRow[] {
    this.ensureInitialized();
    const roles = this.getAllRoles();
    return roles.map(r => ({
      rolname: r.name,
      rolsuper: false,
      rolinherit: true,
      rolcreaterole: false,
      rolcreatedb: false,
      rolcanlogin: false,
      rolconnlimit: -1,
    }));
  }

  /**
   * Simulate pg_auth_members system table (membership relationships).
   */
  getPgAuthMembers(): PgAuthMembersRow[] {
    this.ensureInitialized();
    const rows = this.db.prepare(`
      SELECT rm.role, rm.user, COALESCE(r.parent, '') as grantor, 0 as admin_option
      FROM role_members rm
      LEFT JOIN roles r ON r.name = rm.role
    `).all() as { role: string; user: string; grantor: string; admin_option: number }[];

    return rows.map(r => ({
      roleid: r.role,
      member: r.user,
      grantor: r.grantor || 'postgres',
      admin_option: r.admin_option === 1,
    }));
  }

  // ── Utility ────────────────────────────────────────────────────

  /**
   * Get the full inheritance chain for a role (list of ancestor roles).
   */
  getRoleAncestors(roleName: string): string[] {
    this.ensureInitialized();
    const rows = this.db.prepare(`
      WITH RECURSIVE ancestors(name) AS (
        SELECT r.parent FROM roles r WHERE r.name = ?
        UNION ALL
        SELECT r.parent FROM ancestors a
        JOIN roles r ON r.name = a.name
        WHERE r.parent IS NOT NULL
      )
      SELECT name FROM ancestors WHERE name IS NOT NULL
    `).all(roleName) as { name: string }[];

    return rows.map(r => r.name);
  }

  /**
   * Count total roles.
   */
  roleCount(): number {
    this.ensureInitialized();
    const row = this.db.prepare('SELECT COUNT(*) as cnt FROM roles').get() as { cnt: number };
    return row.cnt;
  }

  /**
   * Close the database connection.
   */
  close(): void {
    this.db.close();
  }

  // ── Internal ───────────────────────────────────────────────────

  private ensureInitialized(): void {
    if (!this.initialized) {
      this.init();
    }
  }
}
