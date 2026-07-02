/**
 * ExtFunctionRegistry — Bridge for registering C-origin functions into SqlVec's FunctionRegistry
 *
 * Maps C types to SqlVec types and handles function metadata registration.
 */

import { PinoLogger } from '../monitoring/PinoLogger';
import { FunctionRegistry, type PgFunction } from '../system/FunctionRegistry';

// ──────────────────────────────────────────────
//  Types
// ──────────────────────────────────────────────

/** C native types understood by the FFI bridge */
export type CType =
  | 'void'
  | 'int'
  | 'long'
  | 'double'
  | 'float'
  | 'char'
  | 'char*'
  | 'int8'
  | 'int16'
  | 'int32'
  | 'int64'
  | 'uint8'
  | 'uint16'
  | 'uint32'
  | 'uint64'
  | 'float4'
  | 'float8'
  | 'bool'
  | 'size_t'
  | 'pointer';

/** SqlVec-compatible return types */
export type ExtReturnType =
  | 'integer'
  | 'numeric'
  | 'float8'
  | 'text'
  | 'boolean'
  | 'void'
  | 'bigint'
  | 'bytea';

/** Metadata for a C-origin function to be registered */
export interface ExtFunctionDef {
  /** Function name as exposed to SQL */
  name: string;
  /** C function name in the shared library (defaults to name) */
  cName?: string;
  /** C parameter types */
  paramTypes: CType[];
  /** C return type */
  returnType: CType;
  /** SqlVec return type override */
  sqlReturnType?: ExtReturnType;
  /** Minimum argument count (defaults to paramTypes.length) */
  minArgs?: number;
  /** Maximum argument count (defaults to paramTypes.length) */
  maxArgs?: number;
  /** Whether this function requires file I/O */
  requiresFileIO?: boolean;
  /** Whether this function requires network access */
  requiresNetwork?: boolean;
  /** Source extension name */
  extensionName: string;
  /** Description for documentation */
  description?: string;
}

// ──────────────────────────────────────────────
//  C → SqlVec Type Mapping
// ──────────────────────────────────────────────

const C_TO_SQLVEC_TYPE: Record<CType, ExtReturnType> = {
  'void': 'void',
  'int': 'integer',
  'long': 'bigint',
  'double': 'float8',
  'float': 'float8',
  'char': 'text',
  'char*': 'text',
  'int8': 'integer',
  'int16': 'integer',
  'int32': 'integer',
  'int64': 'bigint',
  'uint8': 'integer',
  'uint16': 'integer',
  'uint32': 'bigint',
  'uint64': 'bigint',
  'float4': 'float8',
  'float8': 'float8',
  'bool': 'boolean',
  'size_t': 'bigint',
  'pointer': 'text',
};

/** Mapping from SqlVec return types to the FunctionRegistry's PgReturnType */
type PgReturnType =
  | 'integer'
  | 'numeric'
  | 'text'
  | 'boolean'
  | 'timestamp'
  | 'timestamptz'
  | 'interval'
  | 'setof integer'
  | 'setof text';

const EXT_TO_PG_RETURN: Record<ExtReturnType, PgReturnType> = {
  'integer': 'integer',
  'numeric': 'numeric',
  'float8': 'numeric',
  'text': 'text',
  'boolean': 'boolean',
  'void': 'text',
  'bigint': 'numeric',
  'bytea': 'text',
};

// ──────────────────────────────────────────────
//  ExtFunctionRegistry
// ──────────────────────────────────────────────

export class ExtFunctionRegistry {
  private readonly logger: PinoLogger;
  private readonly functionRegistry: FunctionRegistry;
  /** Map of extension name → Set of registered function names */
  private readonly extensionFunctions: Map<string, Set<string>> = new Map();
  /** Map of function name → ExtFunctionDef metadata */
  private readonly functionDefs: Map<string, ExtFunctionDef> = new Map();

  constructor(functionRegistry: FunctionRegistry) {
    this.logger = PinoLogger.forComponent('ExtFunctionRegistry');
    this.functionRegistry = functionRegistry;
  }

  /**
   * Map a C return type to a SqlVec return type.
   */
  mapCTypeToSqlVec(cType: CType): ExtReturnType {
    return C_TO_SQLVEC_TYPE[cType] ?? 'text';
  }

  /**
   * Map an ExtReturnType to a PgReturnType for FunctionRegistry compatibility.
   */
  mapToPgReturnType(extReturnType: ExtReturnType): PgReturnType {
    return EXT_TO_PG_RETURN[extReturnType] ?? 'text';
  }

  /**
   * Register a C-origin function into the SqlVec FunctionRegistry.
   * The fn parameter is the JavaScript wrapper that handles the actual call.
   */
  register(def: ExtFunctionDef, fn: (...args: any[]) => any): void {
    const name = def.name.toLowerCase();
    const sqlReturnType = def.sqlReturnType ?? this.mapCTypeToSqlVec(def.returnType);
    const pgReturnType = this.mapToPgReturnType(sqlReturnType);

    const minArgs = def.minArgs ?? def.paramTypes.length;
    const maxArgs = def.maxArgs ?? def.paramTypes.length;

    const pgFn: PgFunction = {
      name,
      minArgs,
      maxArgs,
      returns: pgReturnType,
      fn,
    };

    this.functionRegistry.register(name, pgFn);

    // Track by extension
    if (!this.extensionFunctions.has(def.extensionName)) {
      this.extensionFunctions.set(def.extensionName, new Set());
    }
    this.extensionFunctions.get(def.extensionName)!.add(name);

    // Store metadata
    this.functionDefs.set(name, def);

    this.logger.info(
      { extension: def.extensionName, function: name, returns: sqlReturnType },
      'C extension function registered',
    );
  }

  /**
   * Unregister all functions for a given extension.
   */
  unregisterExtension(extensionName: string): number {
    const functionNames = this.extensionFunctions.get(extensionName);
    if (!functionNames) {
      return 0;
    }

    let count = 0;
    for (const name of functionNames) {
      this.functionDefs.delete(name);
      this.functionRegistry.remove(name);
      count++;
    }
    this.extensionFunctions.delete(extensionName);

    this.logger.info({ extension: extensionName, count }, 'Extension functions unregistered');
    return count;
  }

  /**
   * Get metadata for a registered function.
   */
  getFunctionDef(name: string): ExtFunctionDef | undefined {
    return this.functionDefs.get(name.toLowerCase());
  }

  /**
   * Get all function names registered by a specific extension.
   */
  getExtensionFunctions(extensionName: string): string[] {
    const names = this.extensionFunctions.get(extensionName);
    return names ? Array.from(names) : [];
  }

  /**
   * Get all registered extension names.
   */
  getRegisteredExtensions(): string[] {
    return Array.from(this.extensionFunctions.keys());
  }

  /**
   * Get total count of registered extension functions.
   */
  get totalCount(): number {
    return this.functionDefs.size;
  }

  /**
   * Check if a function is a C-extension origin function.
   */
  isExtensionFunction(name: string): boolean {
    return this.functionDefs.has(name.toLowerCase());
  }

  /**
   * Get the C type conversion for FFI calls.
   * Returns the koffi-compatible type string.
   */
  getFfiReturnType(cType: CType): string {
    switch (cType) {
      case 'void': return 'void';
      case 'int':
      case 'int32': return 'int';
      case 'long':
      case 'int64': return 'long';
      case 'double':
      case 'float8': return 'double';
      case 'float':
      case 'float4': return 'float';
      case 'char': return 'char';
      case 'char*':
      case 'pointer': return 'string';
      case 'bool': return 'int';
      case 'size_t':
      case 'uint64': return 'ulong';
      case 'int8':
      case 'int16': return 'int';
      case 'uint8':
      case 'uint16':
      case 'uint32': return 'uint';
      default: return 'string';
    }
  }

  /**
   * Get FFI parameter types for a C function signature.
   */
  getFfiParamTypes(paramTypes: CType[]): string[] {
    return paramTypes.map(pt => this.getFfiReturnType(pt));
  }
}
