/**
 * PortalManager — Manages portal state for PostgreSQL Extended Query Protocol.
 *
 * A portal holds the result set of a prepared statement after Bind, and
 * provides cursor-based access via Execute with maxRows.
 *
 * ## PortalSuspended semantics
 *
 * When Execute includes maxRows > 0:
 *   1. The portal returns up to maxRows rows from the current cursor position
 *   2. If more rows remain, PortalSuspended is signaled (the portal stays open)
 *   3. The client can send another Execute to fetch the next batch
 *   4. When all rows are consumed, the portal is auto-closed
 *
 * Edge cases:
 *   - maxRows = 0 → return all remaining rows, no suspend
 *   - Named portals vs unnamed portal (empty string)
 *   - Multiple portals active simultaneously
 *   - Close without draining remaining rows
 *   - Empty result set → immediately complete
 */

import { PinoLogger } from '../monitoring/PinoLogger';
import { DatabaseError } from '../error/DatabaseError';
import {
  SQLSTATE_INVALID_CURSOR_NAME,
  SQLSTATE_OBJECT_NOT_IN_PREREQUISITE_STATE,
} from '../constants/sqlstate';

export interface CachedPortal {
  /** Name of the portal (empty string = unnamed) */
  name: string;
  /** The prepared statement name this portal is bound to */
  statementName: string;
  /** Parameter values passed during Bind */
  params: any[];
  /** All rows cached from the initial query execution */
  rows: Record<string, unknown>[];
  /** Column names derived from the result set */
  columns: string[];
  /** Current cursor position (index into `rows`) */
  cursorPosition: number;
  /** Whether this portal has been fully consumed */
  drained: boolean;
  /** The SQL (for statement lookup / metadata) */
  sql: string;
}

export interface ExecuteResult {
  /** Rows returned in this batch */
  rows: Record<string, unknown>[];
  /** Column names from the result set */
  columns: string[];
  /** Whether this batch completes the portal (no more rows) */
  completed: boolean;
  /** Whether PortalSuspended should be sent (more rows available) */
  suspended: boolean;
}

export class PortalManager {
  private readonly logger = PinoLogger.forComponent('PortalManager');
  private portals: Map<string, CachedPortal> = new Map();

  /**
   * Create or overwrite a portal from a prepared statement's result set.
   *
   * @param name - Portal name (empty string = unnamed portal)
   * @param statementName - Prepared statement name
   * @param params - Parameter values bound to the portal
   * @param sql - The SQL text (for metadata)
   * @param rows - Complete result set to cache in the portal
   * @param columns - Column names
   */
  createPortal(
    name: string,
    statementName: string,
    params: any[],
    sql: string,
    rows: Record<string, unknown>[],
    columns: string[],
  ): void {
    this.portals.set(name, {
      name,
      statementName,
      params,
      rows,
      columns,
      cursorPosition: 0,
      drained: false,
      sql,
    });
    this.logger.debug({ portalName: name, rowCount: rows.length }, 'createPortal: portal created');
  }

  /**
   * Execute a portal, returning up to maxRows rows.
   *
   * @param name - Portal name
   * @param maxRows - Maximum rows to return (0 = all remaining, no suspend)
   * @returns Rows and completion status
   * @throws If the portal does not exist or has already been drained
   */
  executePortal(name: string, maxRows: number): ExecuteResult {
    const portal = this.portals.get(name);
    if (!portal) {
      throw new DatabaseError(
        '26000: portal "' + name + '" does not exist',
        SQLSTATE_INVALID_CURSOR_NAME,
      );
    }

    if (portal.drained) {
      throw new DatabaseError(
        '26001: portal "' + name + '" has already been closed',
        SQLSTATE_OBJECT_NOT_IN_PREREQUISITE_STATE,
      );
    }

    const { rows, columns, cursorPosition } = portal;
    const totalRemaining = rows.length - cursorPosition;

    // maxRows = 0 means return all remaining rows
    if (maxRows === 0) {
      const resultRows = rows.slice(cursorPosition);
      portal.cursorPosition = rows.length;
      portal.drained = true;
      this.portals.delete(name); // auto-close

      this.logger.debug({ portalName: name, rowsReturned: resultRows.length }, 'executePortal: all rows returned');
      return {
        rows: resultRows,
        columns,
        completed: true,
        suspended: false,
      };
    }

    // maxRows > 0: return up to maxRows
    const endIndex = Math.min(cursorPosition + maxRows, rows.length);
    const resultRows = rows.slice(cursorPosition, endIndex);
    portal.cursorPosition = endIndex;

    const hasMore = endIndex < rows.length;

    if (!hasMore) {
      // Portal fully consumed — auto-close
      portal.drained = true;
      this.portals.delete(name);
      this.logger.debug({ portalName: name, rowsReturned: resultRows.length }, 'executePortal: portal drained and closed');
    }

    return {
      rows: resultRows,
      columns,
      completed: !hasMore,
      suspended: hasMore,
    };
  }

  /**
   * Close a portal without draining remaining rows.
   *
   * @param name - Portal name
   * @throws If the portal does not exist
   */
  closePortal(name: string): void {
    const portal = this.portals.get(name);
    if (!portal) {
      // PG silently ignores close on non-existent portals
      this.logger.warn({ portalName: name }, 'closePortal: portal not found, ignoring');
      return;
    }

    portal.drained = true;
    this.portals.delete(name);
    this.logger.debug({ portalName: name, rowsRemaining: portal.rows.length - portal.cursorPosition }, 'closePortal: portal closed');
  }

  /**
   * Check if a portal has more rows available.
   *
   * @param name - Portal name
   * @returns true if the portal exists and has unconsumed rows
   */
  hasMoreRows(name: string): boolean {
    const portal = this.portals.get(name);
    if (!portal || portal.drained) {
      return false;
    }
    return portal.cursorPosition < portal.rows.length;
  }

  /**
   * Get a portal by name.
   *
   * @param name - Portal name
   * @returns The portal or undefined
   */
  getPortal(name: string): CachedPortal | undefined {
    return this.portals.get(name);
  }

  /**
   * Get total number of active (non-drained) portals.
   */
  get activePortalCount(): number {
    let count = 0;
    for (const portal of this.portals.values()) {
      if (!portal.drained) {
        count++;
      }
    }
    return count;
  }

  /**
   * Get all active portal names.
   */
  getActivePortalNames(): string[] {
    const names: string[] = [];
    for (const [name, portal] of this.portals.entries()) {
      if (!portal.drained) {
        names.push(name);
      }
    }
    return names;
  }

  /**
   * Close all portals for a given session (cleanup on disconnect).
   */
  closeAllPortals(): void {
    this.portals.clear();
    this.logger.debug('closeAllPortals: all portals cleared');
  }

  /**
   * Get the cursor position for a portal.
   *
   * @param name - Portal name
   * @returns Cursor row index, or -1 if portal doesn't exist
   */
  getCursorPosition(name: string): number {
    const portal = this.portals.get(name);
    return portal ? portal.cursorPosition : -1;
  }

  /**
   * Get remaining row count for a portal.
   *
   * @param name - Portal name
   * @returns Remaining rows count, or -1 if portal doesn't exist
   */
  getRemainingRowCount(name: string): number {
    const portal = this.portals.get(name);
    if (!portal || portal.drained) return -1;
    return portal.rows.length - portal.cursorPosition;
  }
}
