/**
 * DeferrableConstraintManager — PostgreSQL DEFERRABLE constraint support.
 *
 * Implements PostgreSQL's DEFERRABLE constraint checking for SQLite-backed
 * query layers. When constraints are marked DEFERRABLE INITIALLY DEFERRED
 * or when `SET CONSTRAINTS ALL DEFERRED` is executed, constraint checks
 * are deferred until COMMIT time.
 *
 * ## Key concepts
 *
 * - **DEFERRABLE**: The constraint can be deferred (doesn't have to be checked immediately).
 * - **INITIALLY DEFERRED**: The constraint is deferred by default at start of transaction.
 * - **INITIALLY IMMEDIATE**: The constraint is checked immediately by default
 *   (but can be deferred via SET CONSTRAINTS).
 * - **NOT DEFERRABLE**: The constraint can NEVER be deferred (PG default).
 * - **SET CONSTRAINTS**: Transaction-level control to defer or make immediate.
 *
 * ## Supported constraint types
 *
 * - FOREIGN KEY (primary use case)
 * - UNIQUE
 * - CHECK
 * - EXCLUDE
 *
 * ## Example
 *
 * ```typescript
 * const mgr = new DeferrableConstraintManager();
 *
 * // Register a deferrable constraint
 * mgr.registerConstraint({
 *   name: 'orders_customer_fkey',
 *   type: 'FOREIGN KEY',
 *   table: 'orders',
 *   columns: ['customer_id'],
 *   refTable: 'customers',
 *   refColumns: ['id'],
 *   deferrable: true,
 *   initiallyDeferred: true,
 * });
 *
 * // Start a transaction and defer checks
 * mgr.beginTransaction('txn-1');
 * mgr.setDeferred('txn-1', true);
 *
 * // Queue checks
 * mgr.queueFkCheck('txn-1', 'orders', ['customer_id'], 'customers', ['id'], [42]);
 *
 * // Validate at commit
 * const violations = await mgr.validateAtCommit('txn-1');
 * ```
 *
 * @module constraint/DeferrableConstraintManager
 */

import { PinoLogger } from '../monitoring/PinoLogger';

// ── Types ────────────────────────────────────────────────────────

export type DeferrableConstraintType = 'FOREIGN KEY' | 'UNIQUE' | 'CHECK' | 'EXCLUDE';

export type DeferrableStatus = 'deferred' | 'immediate';

export interface DeferrableConstraintDef {
  /** Constraint name (e.g. 'orders_customer_fkey') */
  name: string;
  /** Constraint type */
  type: DeferrableConstraintType;
  /** Table the constraint is on */
  table: string;
  /** Column(s) involved */
  columns: string[];
  /** Referenced table (for FK) */
  refTable?: string;
  /** Referenced column(s) (for FK) */
  refColumns?: string[];
  /** Expression (for CHECK constraints) */
  checkExpr?: string;
  /** Whether the constraint is DEFERRABLE */
  deferrable: boolean;
  /** Whether the constraint is INITIALLY DEFERRED */
  initiallyDeferred: boolean;
}

export interface DeferredFkConstraintCheck {
  type: 'FOREIGN KEY';
  constraintName: string;
  childTable: string;
  childColumns: string[];
  parentTable: string;
  parentColumns: string[];
  values: any[];
  deferred: boolean;
}

export interface DeferredUniqueConstraintCheck {
  type: 'UNIQUE';
  constraintName: string;
  table: string;
  columns: string[];
  values: any[];
  rowId: string;
  deferred: boolean;
}

export interface DeferredCheckConstraintCheck {
  type: 'CHECK';
  constraintName: string;
  table: string;
  expression: string;
  values: Record<string, any>;
  deferred: boolean;
}

export type DeferredConstraintCheck =
  | DeferredFkConstraintCheck
  | DeferredUniqueConstraintCheck
  | DeferredCheckConstraintCheck;

export interface ConstraintViolationInfo {
  constraintType: DeferrableConstraintType;
  constraintName: string;
  table: string;
  message: string;
  sqlState: string;
  detail?: string;
}

// ── Transaction state ────────────────────────────────────────────

interface TransactionConstraintsState {
  /** Transaction ID */
  transactionId: string;
  /** Whether constraints are currently deferred */
  deferred: boolean;
  /**
   * Per-constraint override: constraint name -> deferred status.
   * SET CONSTRAINTS foo DEFERRED sets this.
   */
  constraintOverrides: Map<string, boolean>;
  /** Pending constraint checks */
  pendingChecks: DeferredConstraintCheck[];
}

// ── DeferrableConstraintManager ──────────────────────────────────

export class DeferrableConstraintManager {
  private readonly logger = PinoLogger.forComponent('deferrable-constraint');

  /** Registered constraint definitions */
  private constraintDefs: Map<string, DeferrableConstraintDef> = new Map();

  /** Per-transaction state */
  private transactions: Map<string, TransactionConstraintsState> = new Map();

  /** Default session-level deferral state */
  private sessionDeferred: boolean = false;

  // ── Constraint Registration ────────────────────────────────────

  /**
   * Register a constraint definition.
   */
  registerConstraint(def: DeferrableConstraintDef): void {
    if (this.constraintDefs.has(def.name)) {
      throw new Error(`Constraint "${def.name}" already registered`);
    }
    this.constraintDefs.set(def.name, { ...def });
    this.logger.info(
      {
        name: def.name,
        type: def.type,
        table: def.table,
        deferrable: def.deferrable,
        initiallyDeferred: def.initiallyDeferred,
      },
      'Deferrable constraint registered',
    );
  }

  /**
   * Unregister a constraint.
   */
  unregisterConstraint(name: string): boolean {
    if (!this.constraintDefs.has(name)) return false;
    this.constraintDefs.delete(name);
    return true;
  }

  /**
   * Get a registered constraint definition.
   */
  getConstraint(name: string): DeferrableConstraintDef | undefined {
    return this.constraintDefs.get(name);
  }

  /**
   * Get all registered constraints.
   */
  getAllConstraints(): DeferrableConstraintDef[] {
    return Array.from(this.constraintDefs.values());
  }

  // ── Transaction Management ─────────────────────────────────────

  /**
   * Begin a transaction and initialize its constraint state.
   *
   * @param transactionId - Unique transaction ID
   */
  beginTransaction(transactionId: string): void {
    if (this.transactions.has(transactionId)) {
      this.logger.warn({ transactionId }, 'Transaction already exists, resetting');
    }

    // Determine initial deferred state based on registered constraints
    const hasInitiallyDeferred = Array.from(this.constraintDefs.values()).some(
      (def) => def.deferrable && def.initiallyDeferred,
    );

    const state: TransactionConstraintsState = {
      transactionId,
      deferred: hasInitiallyDeferred || this.sessionDeferred,
      constraintOverrides: new Map(),
      pendingChecks: [],
    };

    this.transactions.set(transactionId, state);
    this.logger.info({ transactionId, deferred: state.deferred }, 'Transaction constraint state initialized');
  }

  /**
   * Commit a transaction — validates all deferred constraints.
   *
   * @param transactionId - Transaction ID to commit
   * @param validators    - Optional validator functions for each constraint type
   * @returns Array of constraint violations (empty = successful commit)
   */
  async validateAtCommit(
    transactionId: string,
    validators?: {
      checkFk?: (check: DeferredFkConstraintCheck) => Promise<boolean>;
      checkUnique?: (check: DeferredUniqueConstraintCheck) => Promise<boolean>;
      checkCheck?: (check: DeferredCheckConstraintCheck) => Promise<boolean>;
    },
  ): Promise<ConstraintViolationInfo[]> {
    const state = this.transactions.get(transactionId);
    if (!state) {
      this.logger.warn({ transactionId }, 'No transaction state found');
      return [];
    }

    const violations: ConstraintViolationInfo[] = [];

    for (const check of state.pendingChecks) {
      const violation = await this.validateCheck(check, validators, state);

      if (violation) {
        violations.push(violation);
      }
    }

    if (violations.length > 0) {
      this.logger.warn(
        { transactionId, total: state.pendingChecks.length, violations: violations.length },
        'Deferred constraint violations detected at commit',
      );
    } else {
      this.logger.info(
        { transactionId, total: state.pendingChecks.length },
        'All deferred constraints passed at commit',
      );
    }

    // Clear pending checks
    state.pendingChecks = [];

    return violations;
  }

  /**
   * Rollback a transaction — clears all pending checks.
   *
   * @param transactionId - Transaction ID to rollback
   */
  rollbackTransaction(transactionId: string): void {
    const state = this.transactions.get(transactionId);
    if (state) {
      const count = state.pendingChecks.length;
      state.pendingChecks = [];
      state.constraintOverrides.clear();
      this.logger.info({ transactionId, cleared: count }, 'Transaction rolled back, checks cleared');
    }
    this.transactions.delete(transactionId);
  }

  /**
   * End a transaction — cleans up state.
   *
   * @param transactionId - Transaction ID to end
   */
  endTransaction(transactionId: string): void {
    this.transactions.delete(transactionId);
    this.logger.info({ transactionId }, 'Transaction constraint state cleaned up');
  }

  // ── DEFERRABLE Control ─────────────────────────────────────────

  /**
   * Set whether constraints are currently deferred in a transaction.
   *
   * Corresponds to `SET CONSTRAINTS ALL DEFERRED` / `SET CONSTRAINTS ALL IMMEDIATE`.
   *
   * @param transactionId - Transaction ID
   * @param deferred      - Whether to defer
   */
  setDeferred(transactionId: string, deferred: boolean): void {
    const state = this.transactions.get(transactionId);
    if (!state) {
      this.logger.warn({ transactionId }, 'No transaction state to set deferred');
      return;
    }
    state.deferred = deferred;
    this.logger.info({ transactionId, deferred }, 'Transaction constraint deferral state set');
  }

  /**
   * Set a specific constraint to deferred or immediate.
   *
   * Corresponds to `SET CONSTRAINTS constraint_name DEFERRED`.
   *
   * @param transactionId - Transaction ID
   * @param constraintName - Specific constraint to set
   * @param deferred       - Whether to defer it
   * @returns true if the constraint was found and set
   */
  setSingleConstraint(transactionId: string, constraintName: string, deferred: boolean): boolean {
    const state = this.transactions.get(transactionId);
    if (!state) {
      this.logger.warn({ transactionId }, 'No transaction state');
      return false;
    }

    const def = this.constraintDefs.get(constraintName);
    if (!def) {
      this.logger.warn({ constraintName }, 'Unknown constraint for SET CONSTRAINTS');
      return false;
    }

    if (!def.deferrable) {
      this.logger.warn({ constraintName }, 'Cannot defer a non-deferrable constraint');
      return false;
    }

    state.constraintOverrides.set(constraintName, deferred);
    this.logger.info({ constraintName, deferred }, 'Single constraint deferral set');
    return true;
  }

  /**
   * Set multiple constraints to deferred or immediate.
   *
   * @param transactionId - Transaction ID
   * @param constraintNames - Constraint names to set
   * @param deferred - Whether to defer them
   * @returns Number of constraints successfully set
   */
  setConstraints(transactionId: string, constraintNames: string[], deferred: boolean): number {
    let count = 0;
    for (const name of constraintNames) {
      if (this.setSingleConstraint(transactionId, name, deferred)) {
        count++;
      }
    }
    return count;
  }

  /**
   * Set session-level default deferral (not transaction-scoped).
   */
  setSessionDeferred(deferred: boolean): void {
    this.sessionDeferred = deferred;
  }

  /**
   * Check if a constraint is currently deferred for a transaction.
   *
   * @param transactionId - Transaction ID
   * @param constraintName - Constraint name
   * @returns true if the constraint should be deferred
   */
  isConstraintDeferred(transactionId: string, constraintName: string): boolean {
    const state = this.transactions.get(transactionId);
    if (!state) return false;

    // Check per-constraint override first (SET CONSTRAINTS name DEFERRED/IMMEDIATE)
    const override = state.constraintOverrides.get(constraintName);
    if (override !== undefined) return override;

    // Check the constraint definition for initiallyDeferred as fallback,
    // but only if the transaction hasn't set an explicit state
    const def = this.constraintDefs.get(constraintName);
    if (def && def.deferrable && def.initiallyDeferred && state.deferred) {
      return true;
    }

    // Fall back to transaction-level deferral (set via SET CONSTRAINTS ALL)
    return state.deferred;
  }

  /**
   * Get the transaction-level deferred status.
   */
  isTransactionDeferred(transactionId: string): boolean {
    const state = this.transactions.get(transactionId);
    return state?.deferred ?? this.sessionDeferred;
  }

  // ── Constraint Checks ──────────────────────────────────────────

  /**
   * Queue a FOREIGN KEY constraint check.
   * Only queued if the constraint is currently deferred.
   *
   * @param transactionId  - Transaction ID
   * @param constraintName - Constraint name
   * @param childTable     - Child table
   * @param childColumns   - FK columns in child
   * @param parentTable    - Referenced parent table
   * @param parentColumns  - PK columns in parent
   * @param values         - The values to check
   */
  queueFkCheck(
    transactionId: string,
    constraintName: string,
    childTable: string,
    childColumns: string[],
    parentTable: string,
    parentColumns: string[],
    values: any[],
  ): boolean {
    const state = this.transactions.get(transactionId);
    if (!state) return false;

    const deferred = this.isConstraintDeferred(transactionId, constraintName);

    if (!deferred) {
      // Not deferred — caller must check immediately
      return false;
    }

    state.pendingChecks.push({
      type: 'FOREIGN KEY',
      constraintName,
      childTable,
      childColumns,
      parentTable,
      parentColumns,
      values,
      deferred: true,
    });

    this.logger.debug(
      { transactionId, constraintName, childTable, values },
      'FK check queued for deferred validation',
    );

    return true;
  }

  /**
   * Queue a UNIQUE constraint check.
   */
  queueUniqueCheck(
    transactionId: string,
    constraintName: string,
    table: string,
    columns: string[],
    values: any[],
    rowId: string,
  ): boolean {
    const state = this.transactions.get(transactionId);
    if (!state) return false;

    const deferred = this.isConstraintDeferred(transactionId, constraintName);
    if (!deferred) return false;

    state.pendingChecks.push({
      type: 'UNIQUE',
      constraintName,
      table,
      columns,
      values,
      rowId,
      deferred: true,
    });

    return true;
  }

  /**
   * Queue a CHECK constraint check.
   */
  queueCheckCheck(
    transactionId: string,
    constraintName: string,
    table: string,
    expression: string,
    values: Record<string, any>,
  ): boolean {
    const state = this.transactions.get(transactionId);
    if (!state) return false;

    const deferred = this.isConstraintDeferred(transactionId, constraintName);
    if (!deferred) return false;

    state.pendingChecks.push({
      type: 'CHECK',
      constraintName,
      table,
      expression,
      values,
      deferred: true,
    });

    return true;
  }

  /**
   * Get all pending checks for a transaction.
   */
  getPendingChecks(transactionId: string): DeferredConstraintCheck[] {
    const state = this.transactions.get(transactionId);
    if (!state) return [];
    return [...state.pendingChecks];
  }

  /**
   * Get the count of pending checks.
   */
  getPendingCount(transactionId: string): number {
    const state = this.transactions.get(transactionId);
    return state ? state.pendingChecks.length : 0;
  }

  /**
   * Get the total number of pending checks across all transactions.
   */
  getTotalPendingCount(): number {
    let total = 0;
    for (const state of this.transactions.values()) {
      total += state.pendingChecks.length;
    }
    return total;
  }

  /**
   * Get all active transaction IDs.
   */
  getActiveTransactionIds(): string[] {
    return Array.from(this.transactions.keys());
  }

  /**
   * Reset all state (for testing).
   */
  reset(): void {
    this.constraintDefs.clear();
    this.transactions.clear();
    this.sessionDeferred = false;
    this.logger.info('DeferrableConstraintManager state reset');
  }

  // ── Internal ───────────────────────────────────────────────────

  private async validateCheck(
    check: DeferredConstraintCheck,
    validators?: {
      checkFk?: (check: DeferredFkConstraintCheck) => Promise<boolean>;
      checkUnique?: (check: DeferredUniqueConstraintCheck) => Promise<boolean>;
      checkCheck?: (check: DeferredCheckConstraintCheck) => Promise<boolean>;
    },
    state?: TransactionConstraintsState,
  ): Promise<ConstraintViolationInfo | null> {
    switch (check.type) {
      case 'FOREIGN KEY':
        return this.validateFkCheck(check, validators?.checkFk);
      case 'UNIQUE':
        return this.validateUniqueCheck(check, validators?.checkUnique);
      case 'CHECK':
        return this.validateCheckConstraint(check, validators?.checkCheck);
      default:
        return null;
    }
  }

  private async validateFkCheck(
    check: DeferredFkConstraintCheck,
    validator?: (check: DeferredFkConstraintCheck) => Promise<boolean>,
  ): Promise<ConstraintViolationInfo | null> {
    if (!validator) {
      // No validator — assume it passes
      return null;
    }

    const exists = await validator(check);
    if (!exists) {
      const valueStr = check.values.map((v) => `'${v}'`).join(', ');
      return {
        constraintType: 'FOREIGN KEY',
        constraintName: check.constraintName,
        table: check.childTable,
        message: `insert or update on table "${check.childTable}" violates foreign key constraint "${check.constraintName}"`,
        sqlState: '23503',
        detail: `Key (${check.childColumns.join(', ')}) = (${valueStr}) is not present in table "${check.parentTable}"`,
      };
    }

    return null;
  }

  private async validateUniqueCheck(
    check: DeferredUniqueConstraintCheck,
    validator?: (check: DeferredUniqueConstraintCheck) => Promise<boolean>,
  ): Promise<ConstraintViolationInfo | null> {
    if (!validator) return null;

    const exists = await validator(check);
    if (exists) {
      const valueStr = check.values.map((v) => `'${v}'`).join(', ');
      return {
        constraintType: 'UNIQUE',
        constraintName: check.constraintName,
        table: check.table,
        message: `duplicate key value violates unique constraint "${check.constraintName}"`,
        sqlState: '23505',
        detail: `Key (${check.columns.join(', ')}) = (${valueStr}) already exists`,
      };
    }

    return null;
  }

  private async validateCheckConstraint(
    check: DeferredCheckConstraintCheck,
    validator?: (check: DeferredCheckConstraintCheck) => Promise<boolean>,
  ): Promise<ConstraintViolationInfo | null> {
    if (!validator) return null;

    const passes = await validator(check);
    if (!passes) {
      return {
        constraintType: 'CHECK',
        constraintName: check.constraintName,
        table: check.table,
        message: `new row for relation "${check.table}" violates check constraint "${check.constraintName}"`,
        sqlState: '23514',
        detail: `Failing row contains ${JSON.stringify(check.values)}`,
      };
    }

    return null;
  }
}
