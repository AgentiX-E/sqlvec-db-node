import * as crypto from 'node:crypto';
import { PinoLogger } from '../monitoring/PinoLogger';

const logger = PinoLogger.forComponent('dist-tracer');

/**
 * DistributedTracer — Lightweight distributed tracing for SQLVec.
 *
 * Provides trace-id propagation across Raft nodes and nested span tracking
 * for request-level observability. Mimics the OpenTelemetry span model in
 * a minimal, zero-dependency fashion.
 *
 * Each request (query, Raft RPC, background job) gets a unique trace ID.
 * Within that trace, nested spans track sub-operations (e.g. lock acquire,
 * WAL write, consensus round). Spans are logged via PinoLogger with
 * structured fields for downstream analysis.
 *
 * Optionally exports spans via OpenTelemetry when enableOpenTelemetry()
 * is called. OTEL packages are loaded lazily (dynamic import) so there is
 * zero overhead when OTEL is not enabled.
 *
 * Usage:
 *   const tracer = DistributedTracer.getInstance();
 *   const traceId = tracer.startTrace('SELECT query');
 *   const span = tracer.startSpan('parse');
 *   // ... do work ...
 *   tracer.endSpan();
 *   tracer.endTrace();
 *
 * For Raft message header propagation:
 *   const headers = tracer.getPropagationHeaders();
 *   // send headers in Raft message
 *   // on receiver:
 *   tracer.continueTraceFromHeaders(headers);
 *
 * To enable OpenTelemetry export:
 *   await DistributedTracer.getInstance().enableOpenTelemetry({
 *     serviceName: 'my-service',
 *     endpoint: 'http://otel-collector:4318/v1/traces',
 *   });
 */

export interface Span {
  name: string;
  startTime: [number, number]; // process.hrtime()
  children: Span[];
}

export interface OtelOptions {
  /** Service name reported to the OTLP backend (default: "sqlvec-db"). */
  serviceName?: string;
  /** OTLP HTTP endpoint (default: "http://localhost:4318/v1/traces"). */
  endpoint?: string;
  /** Additional headers for the OTLP exporter (e.g. auth tokens). */
  headers?: Record<string, string>;
}

export class DistributedTracer {
  private static instance: DistributedTracer;

  /** Current trace ID (UUID v4). Undefined if no active trace. */
  private traceId?: string;

  /** Current span stack (LIFO). */
  private spanStack: Span[] = [];

  /** Root span (never popped). */
  private rootSpan?: Span;

  // ── OpenTelemetry integration (lazy-loaded) ──────────────────────────────

  private otelEnabled = false;
  private otelTracer: any = null;
  private otelProvider: any = null;
  private otelSpanStack: any[] = [];
  private otelModules: { trace: any; context: any } | null = null;
  private serviceName = 'sqlvec-db';

  private constructor() {}

  static getInstance(): DistributedTracer {
    if (!DistributedTracer.instance) {
      DistributedTracer.instance = new DistributedTracer();
    }
    return DistributedTracer.instance;
  }

  /**
   * Enable OpenTelemetry span export.
   *
   * OTEL packages are loaded lazily via dynamic import, so calling this
   * method is the only time the OTEL dependencies are resolved. When
   * OpenTelemetry is not enabled (the default), there is zero import
   * overhead.
   *
   * Once enabled, every span created by startSpan() / startTrace() will
   * also produce an OTEL span sent via OTLP HTTP, with proper parent-child
   * relationships.
   *
   * Calling this method multiple times is safe — subsequent calls are
   * no-ops after the first successful initialization.
   */
  async enableOpenTelemetry(opts?: OtelOptions): Promise<void> {
    if (this.otelEnabled) return;

    try {
      const { trace, context } = await import('@opentelemetry/api');
      const { BasicTracerProvider, SimpleSpanProcessor } = await import('@opentelemetry/sdk-trace-base');
      const { OTLPTraceExporter } = await import('@opentelemetry/exporter-trace-otlp-http');
      const { resourceFromAttributes } = await import('@opentelemetry/resources');

      this.serviceName = opts?.serviceName || 'sqlvec-db';

      const exporter = new OTLPTraceExporter({
        url: opts?.endpoint || 'http://localhost:4318/v1/traces',
        headers: opts?.headers,
      });

      const provider = new BasicTracerProvider({
        resource: resourceFromAttributes({
          'service.name': this.serviceName,
        }),
        spanProcessors: [new SimpleSpanProcessor(exporter)],
      });

      trace.setGlobalTracerProvider(provider);

      this.otelProvider = provider;
      this.otelTracer = trace.getTracer(this.serviceName);
      this.otelModules = { trace, context };
      this.otelEnabled = true;

      logger.info({ serviceName: this.serviceName }, 'OpenTelemetry tracing enabled');
    } catch (err) {
      logger.error({ err }, 'Failed to enable OpenTelemetry — OTEL packages not available');
      this.otelEnabled = false;
    }
  }

  /**
   * Start a new trace.
   *
   * @param operationName Human-readable name for the root span
   * @param explicitTraceId Optional trace ID (for propagation from upstream)
   * @returns The trace ID
   */
  startTrace(operationName: string, explicitTraceId?: string): string {
    this.traceId = explicitTraceId || crypto.randomUUID();
    this.spanStack = [];
    this.rootSpan = {
      name: operationName,
      startTime: process.hrtime(),
      children: [],
    };
    this.spanStack.push(this.rootSpan);

    // OTEL: Create root span
    if (this.otelEnabled && this.otelTracer) {
      const otelSpan = this.otelTracer.startSpan(operationName, {
        attributes: { 'sqlvec.trace_id': this.traceId },
      });
      this.otelSpanStack = [otelSpan];
    }

    logger.debug({ traceId: this.traceId, operation: operationName }, 'Trace started');
    return this.traceId;
  }

  /**
   * End the current trace and log the timing.
   */
  endTrace(): void {
    if (!this.traceId || !this.rootSpan) {
      logger.warn('endTrace called without active trace');
      return;
    }

    const elapsed = process.hrtime(this.rootSpan.startTime);
    const durationMs = elapsed[0] * 1_000 + elapsed[1] / 1_000_000;

    logger.debug({
      traceId: this.traceId,
      operation: this.rootSpan.name,
      durationMs: Math.round(durationMs * 100) / 100,
      spanCount: this.countSpans(this.rootSpan),
    }, 'Trace ended');

    // OTEL: End root span
    if (this.otelEnabled && this.otelSpanStack.length > 0) {
      const rootOtelSpan = this.otelSpanStack[0];
      if (rootOtelSpan) {
        rootOtelSpan.end();
      }
    }

    this.traceId = undefined;
    this.spanStack = [];
    this.rootSpan = undefined;
    this.otelSpanStack = [];
  }

  /**
   * Start a new child span within the current trace.
   *
   * @param name Span name
   */
  startSpan(name: string): void {
    if (!this.traceId) {
      logger.debug('startSpan called without active trace, starting implicit trace');
      this.startTrace(name);
      return;
    }

    const parent = this.spanStack[this.spanStack.length - 1];
    const span: Span = {
      name,
      startTime: process.hrtime(),
      children: [],
    };

    if (parent) {
      parent.children.push(span);
    }

    this.spanStack.push(span);

    // OTEL: Create child span with proper parent context
    if (this.otelEnabled && this.otelTracer && this.otelModules) {
      const { trace, context } = this.otelModules;
      const parentOtelSpan = this.otelSpanStack[this.otelSpanStack.length - 1];
      let otelSpan;
      if (parentOtelSpan) {
        const ctx = trace.setSpan(context.active(), parentOtelSpan);
        otelSpan = this.otelTracer.startSpan(name, undefined, ctx);
      } else {
        otelSpan = this.otelTracer.startSpan(name);
      }
      this.otelSpanStack.push(otelSpan);
    }

    logger.debug({ traceId: this.traceId, span: name }, 'Span started');
  }

  /**
   * End the current leaf span.
   */
  endSpan(): void {
    if (this.spanStack.length <= 1) {
      logger.warn('endSpan called but only root span remains — use endTrace instead');
      return;
    }

    const span = this.spanStack.pop();
    if (!span) return;

    // OTEL: End the corresponding OTEL span
    if (this.otelEnabled && this.otelSpanStack.length > 1) {
      const otelSpan = this.otelSpanStack.pop();
      if (otelSpan) {
        otelSpan.end();
      }
    }

    const elapsed = process.hrtime(span.startTime);
    const durationMs = elapsed[0] * 1_000 + elapsed[1] / 1_000_000;

    logger.debug({
      traceId: this.traceId,
      span: span.name,
      durationMs: Math.round(durationMs * 100) / 100,
    }, 'Span ended');
  }

  /**
   * Get propagation headers (trace ID) for Raft messages.
   */
  getPropagationHeaders(): Record<string, string> {
    if (!this.traceId) {
      return {};
    }
    return {
      'x-sqlvec-trace-id': this.traceId,
    };
  }

  /**
   * Continue a trace from headers received in a Raft message.
   *
   * @param headers Incoming message headers
   */
  continueTraceFromHeaders(headers: Record<string, string>): void {
    const traceId = headers['x-sqlvec-trace-id'];
    if (traceId) {
      this.startTrace('continued-trace', traceId);
      logger.debug({ traceId }, 'Trace continued from Raft headers');
    }
  }

  /**
   * Get the current trace ID.
   */
  getTraceId(): string | undefined {
    return this.traceId;
  }

  /**
   * Count all spans recursively.
   */
  private countSpans(span: Span): number {
    let count = 1;
    for (const child of span.children) {
      count += this.countSpans(child);
    }
    return count;
  }
}
