/**
 * NativeExtensionBridge — Bridge for loading C extension libraries (.so/.dylib)
 * and calling their functions via Node.js FFI.
 *
 * Loading strategy (fallback chain):
 *   1. Primary: Try `koffi` (modern, cross-platform FFI)
 *   2. Fallback: Try `ffi-napi` (legacy FFI)
 *   3. Graceful: If neither available, throw descriptive error
 *
 * Each loaded extension tracks handle lifecycle and registered functions.
 */

import { PinoLogger } from '../monitoring/PinoLogger';
import { ExtFunctionRegistry, type ExtFunctionDef, type CType } from './ExtFunctionRegistry';
import { ExtensionSecurityPolicy, type SecurityCheckResult } from './ExtensionSecurityPolicy';
import { FunctionRegistry } from '../system/FunctionRegistry';

// ──────────────────────────────────────────────
//  Types
// ──────────────────────────────────────────────

export type FfiBackend = 'koffi' | 'ffi-napi' | 'none';

export interface NativeExtensionBridgeOptions {
  /** Function registry to register into */
  functionRegistry: FunctionRegistry;
  /** Security policy (defaults to strict) */
  securityPolicy?: ExtensionSecurityPolicy;
  /** Force a specific FFI backend */
  forceFfiBackend?: FfiBackend;
}

export interface LoadOptions {
  /** API version expected by the bridge (for compatibility check) */
  apiVersion?: string;
  /** Function definitions to auto-register */
  functions?: ExtFunctionDef[];
  /** Initialize function to call after loading (name only, no arg) */
  initFunction?: string;
}

export interface LoadedExtension {
  name: string;
  path: string;
  handle: any; // dlopen handle from koffi/ffi-napi
  functions: ExtFunctionDef[];
  loadedAt: Date;
  ffiBackend: FfiBackend;
}

// ──────────────────────────────────────────────
//  FFI Backend Discovery
// ──────────────────────────────────────────────

let cachedFfiBackend: FfiBackend | null = null;
let koffiModule: any = null;
let ffiNapiModule: any = null;

/**
 * Detect available FFI backend.
 */
function detectFfiBackend(): { backend: FfiBackend; module: any } {
  if (cachedFfiBackend) {
    return { backend: cachedFfiBackend, module: cachedFfiBackend === 'koffi' ? koffiModule : ffiNapiModule };
  }

  // Try koffi first (modern, active)
  try {
    koffiModule = require('koffi');
    cachedFfiBackend = 'koffi';
    return { backend: 'koffi', module: koffiModule };
  } catch {
    // koffi not available
  }

  // Try ffi-napi as fallback
  try {
    ffiNapiModule = require('ffi-napi');
    cachedFfiBackend = 'ffi-napi';
    return { backend: 'ffi-napi', module: ffiNapiModule };
  } catch {
    // Neither available
  }

  cachedFfiBackend = 'none';
  return { backend: 'none', module: null };
}

// ──────────────────────────────────────────────
//  NativeExtensionBridge
// ──────────────────────────────────────────────

export class NativeExtensionBridge {
  private readonly logger: PinoLogger;
  private readonly extFunctionRegistry: ExtFunctionRegistry;
  private readonly securityPolicy: ExtensionSecurityPolicy;
  private readonly ffiBackend: FfiBackend;
  private readonly ffiModule: any;

  /** Map of extension name → LoadedExtension */
  private readonly loadedExtensions: Map<string, LoadedExtension> = new Map();

  constructor(options: NativeExtensionBridgeOptions) {
    this.logger = PinoLogger.forComponent('NativeExtensionBridge');
    this.extFunctionRegistry = new ExtFunctionRegistry(options.functionRegistry);
    this.securityPolicy = options.securityPolicy ?? new ExtensionSecurityPolicy();

    const { backend, module } = options.forceFfiBackend
      ? this.forceBackend(options.forceFfiBackend)
      : detectFfiBackend();

    this.ffiBackend = backend;
    this.ffiModule = module;

    if (backend === 'none') {
      this.logger.warn(
        'No FFI backend available (koffi or ffi-napi). Native C extensions cannot be loaded. ' +
        'Install via: npm install koffi  OR  npm install ffi-napi',
      );
    } else {
      this.logger.info({ backend }, 'FFI backend initialized');
    }
  }

  /**
   * Try to force a specific FFI backend.
   */
  private forceBackend(backend: FfiBackend): { backend: FfiBackend; module: any } {
    if (backend === 'koffi') {
      try {
        const mod = require('koffi');
        return { backend: 'koffi', module: mod };
      } catch {
        throw new Error('Forced backend "koffi" is not installed. Run: npm install koffi');
      }
    }
    if (backend === 'ffi-napi') {
      try {
        const mod = require('ffi-napi');
        return { backend: 'ffi-napi', module: mod };
      } catch {
        throw new Error('Forced backend "ffi-napi" is not installed. Run: npm install ffi-napi');
      }
    }
    return { backend: 'none', module: null };
  }

  /**
   * Get the ExtFunctionRegistry instance.
   */
  getExtFunctionRegistry(): ExtFunctionRegistry {
    return this.extFunctionRegistry;
  }

  /**
   * Get the security policy instance.
   */
  getSecurityPolicy(): ExtensionSecurityPolicy {
    return this.securityPolicy;
  }

  /**
   * Load a native shared library (.so / .dylib).
   *
   * @param path - Absolute or relative path to the .so/.dylib file
   * @param options - Load options (functions, apiVersion, initFunction)
   * @returns LoadedExtension on success
   * @throws Error if FFI backend unavailable, security policy denies, or load fails
   */
  async load(path: string, options?: LoadOptions): Promise<LoadedExtension> {
    // Extract extension name from path FIRST (before any throws)
    const name = this.extractName(path);

    // Check security policy BEFORE FFI availability check
    const securityCheck: SecurityCheckResult = this.securityPolicy.checkExtensionAllowed(name);
    if (!securityCheck.allowed) {
      throw new Error(`Security policy blocked loading extension '${name}': ${securityCheck.reason}`);
    }

    // Check FFI backend availability
    if (this.ffiBackend === 'none') {
      throw new Error(
        'Cannot load native extension: no FFI backend available. ' +
        'Install koffi (npm install koffi) or ffi-napi (npm install ffi-napi). ' +
        'Alternatively, use a pure-JS implementation of the extension.',
      );
    }

    // Check if already loaded
    if (this.loadedExtensions.has(name)) {
      this.logger.warn({ extension: name }, 'Extension is already loaded, unloading first');
      await this.unload(name);
    }

    this.logger.info({ extension: name, path, backend: this.ffiBackend }, 'Loading native extension');

    // Resolve the library path
    const resolvedPath = path.startsWith('/') ? path : require('path').resolve(process.cwd(), path);

    // Load using the appropriate backend
    let handle: any;
    const startTime = Date.now();

    try {
      if (this.ffiBackend === 'koffi') {
        handle = this.loadWithKoffi(resolvedPath);
      } else if (this.ffiBackend === 'ffi-napi') {
        handle = this.loadWithFfiNapi(resolvedPath);
      } else {
        throw new Error(`Unsupported FFI backend: ${this.ffiBackend}`);
      }
    } catch (err: any) {
      this.logger.error({ extension: name, error: err.message }, 'Failed to load native extension');
      throw new Error(`Failed to load native extension '${name}' from '${resolvedPath}': ${err.message}`);
    }

    const functions = options?.functions ?? [];

    // Auto-register functions
    for (const fnDef of functions) {
      this.registerFunction(name, fnDef, handle);
    }

    // Call init function if specified
    if (options?.initFunction) {
      try {
        await this.call(name, options.initFunction, []);
        this.logger.info({ extension: name, fn: options.initFunction }, 'Extension init function called');
      } catch (err: any) {
        this.logger.warn({ extension: name, fn: options.initFunction, error: err.message }, 'Init function failed');
      }
    }

    const extension: LoadedExtension = {
      name,
      path: resolvedPath,
      handle,
      functions,
      loadedAt: new Date(),
      ffiBackend: this.ffiBackend,
    };

    this.loadedExtensions.set(name, extension);
    this.logger.info(
      { extension: name, functions: functions.length, loadTime: Date.now() - startTime },
      'Native extension loaded successfully',
    );

    return extension;
  }

  /**
   * Unload a previously loaded extension.
   * Unregisters all functions and attempts to dlclose.
   */
  async unload(name: string): Promise<boolean> {
    const extension = this.loadedExtensions.get(name);
    if (!extension) {
      return false;
    }

    this.logger.info({ extension: name }, 'Unloading native extension');

    // Unregister functions from FunctionRegistry
    const unregisterCount = this.extFunctionRegistry.unregisterExtension(name);

    // dlclose — for koffi/ffi-napi, handles are GC-managed; we release the reference
    // For koffi: the handle is a library object with .close()
    if (extension.handle?.close) {
      try {
        extension.handle.close();
      } catch (err: any) {
        this.logger.warn({ extension: name, error: err.message }, 'dlclose warning');
      }
    }

    // Remove from loaded map
    this.loadedExtensions.delete(name);

    this.logger.info({ extension: name, unregistered: unregisterCount }, 'Native extension unloaded');
    return true;
  }

  /**
   * Call a function from a loaded native extension.
   *
   * @param extension - Extension name
   * @param fnName - Function name (C symbol name)
   * @param args - Arguments to pass
   * @returns The function result
   */
  async call(extension: string, fnName: string, args: any[]): Promise<any> {
    const loaded = this.loadedExtensions.get(extension);
    if (!loaded) {
      throw new Error(`Extension '${extension}' is not loaded`);
    }

    // Check security for I/O/Network capabilities
    const fnDef = this.extFunctionRegistry.getFunctionDef(fnName);
    if (fnDef?.requiresFileIO || fnDef?.requiresNetwork) {
      const capCheck = this.securityPolicy.checkCapability(
        !!fnDef.requiresFileIO,
        !!fnDef.requiresNetwork,
      );
      if (!capCheck.allowed) {
        throw new Error(`Security policy blocked call to '${fnName}': ${capCheck.reason}`);
      }
    }

    this.logger.debug({ extension, function: fnName, args }, 'Calling native extension function');

    // Get function reference from the handle
    const fnRef = this.getFunctionRef(loaded, fnName);
    if (!fnRef) {
      throw new Error(`Function '${fnName}' not found in extension '${extension}'`);
    }

    // Call with timeout
    const result = await this.securityPolicy.withTimeout(
      async () => {
        // Build koffi/ffi-napi argument tuple
        try {
          return this.callFunctionRef(fnRef, args);
        } catch (err: any) {
          throw new Error(`Native call to '${fnName}' failed: ${err.message}`);
        }
      },
      `${extension}.${fnName}`,
    );

    return result;
  }

  /**
   * Check if an extension is loaded.
   */
  isLoaded(name: string): boolean {
    return this.loadedExtensions.has(name);
  }

  /**
   * List all loaded extensions.
   */
  getLoaded(): LoadedExtension[] {
    return Array.from(this.loadedExtensions.values());
  }

  /**
   * Get the loaded extension by name.
   */
  getExtension(name: string): LoadedExtension | undefined {
    return this.loadedExtensions.get(name);
  }

  /**
   * Check if a native FFI backend is available.
   */
  hasNativeSupport(): boolean {
    return this.ffiBackend !== 'none';
  }

  /**
   * Get the current FFI backend name.
   */
  getFfiBackend(): FfiBackend {
    return this.ffiBackend;
  }

  // ──────────────────────────────────────────────
  //  Private helpers
  // ──────────────────────────────────────────────

  /**
   * Extract a clean extension name from a file path.
   */
  private extractName(path: string): string {
    const base = path.split('/').pop()!;
    return base.replace(/\.(so|dylib|dll)(\.\d+)?$/i, '') || base;
  }

  /**
   * Load a shared library with koffi.
   */
  private loadWithKoffi(path: string): any {
    // koffi.load(path) returns a library object
    return koffiModule.load(path);
  }

  /**
   * Load a shared library with ffi-napi.
   * ffi-napi uses 'ref-napi' for type description
   */
  private loadWithFfiNapi(path: string): any {
    // ffi-napi: Library(libPath) or DLib
    const ffi = ffiNapiModule;
    const ref = require('ref-napi');
    return {
      _path: path,
      _ffi: ffi,
      _ref: ref,
      _functions: new Map<string, any>(),
    };
  }

  /**
   * Get a function reference from a loaded library handle.
   */
  private getFunctionRef(loaded: LoadedExtension, fnName: string): any {
    if (loaded.ffiBackend === 'koffi') {
      // koffi: library.func('name', retType, [paramTypes])
      // We need to look up the registered function definition
      const fnDef = this.extFunctionRegistry.getFunctionDef(fnName);
      if (!fnDef) {
        return loaded.handle.func(fnName);
      }
      return loaded.handle.func(
        fnName,
        this.extFunctionRegistry.getFfiReturnType(fnDef.returnType),
        fnDef.paramTypes,
      );
    }

    if (loaded.ffiBackend === 'ffi-napi') {
      return loaded.handle._functions.get(fnName);
    }

    return undefined;
  }

  /**
   * Call a function reference with arguments.
   */
  private callFunctionRef(fnRef: any, args: any[]): any {
    return fnRef(...args);
  }

  /**
   * Register an extension function for FFI calling.
   */
  private registerFunction(extensionName: string, fnDef: ExtFunctionDef, handle: any): void {
    const name = fnDef.name.toLowerCase();

    // Create a JS wrapper that bridges to the native function
    const wrapper = (...args: any[]) => {
      const fnRef = this.getFunctionRef(
        { name: extensionName, path: '', handle, functions: [], loadedAt: new Date(), ffiBackend: this.ffiBackend },
        fnDef.cName ?? fnDef.name,
      );
      if (!fnRef) {
        throw new Error(`Native function '${fnDef.cName ?? fnDef.name}' not resolvable`);
      }
      return this.callFunctionRef(fnRef, args);
    };

    this.extFunctionRegistry.register(fnDef, wrapper);
  }
}
