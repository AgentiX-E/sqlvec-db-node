/**
 * pgBackslashQuote — PostgreSQL backslash_quote / standard_conforming_strings control.
 *
 * Controls backslash escaping behavior in string literals:
 *   - standard_conforming_strings = on/off
 *   - escape_string_warning = on/off
 *   - backslash_quote = safe/on/off
 *
 * PostgreSQL GUC reference:
 *   backslash_quote:
 *     'safe'  — allow backslash in string literals (default)
 *     'on'    — allow \'  (deprecated escape)
 *     'off'   — disallow \' entirely
 *
 *   standard_conforming_strings:
 *     'on'    — backslashes are NOT escape characters (SQL standard)
 *     'off'   — backslashes ARE escape characters
 *
 *   escape_string_warning:
 *     'on'    — warn when backslash appears in non-E string literal
 *     'off'   — suppress warning
 */

import { PinoLogger } from '../monitoring/PinoLogger';

const logger = PinoLogger.forComponent('pg-backslash-quote');

export type BackslashQuoteMode = 'safe' | 'on' | 'off';

export interface BackslashQuoteSettings {
  standardConformingStrings: boolean;
  escapeStringWarning: boolean;
  backslashQuote: BackslashQuoteMode;
}

const DEFAULT_SETTINGS: BackslashQuoteSettings = {
  standardConformingStrings: true, // SQL standard
  escapeStringWarning: true,       // warn by default
  backslashQuote: 'safe',          // safe by default
};

export class PgBackslashQuote {
  private perSessionSettings: Map<string, BackslashQuoteSettings> = new Map();

  // ── Session Management ──────────────────────────────────────

  private getSession(sessionId: string = 'default'): BackslashQuoteSettings {
    if (!this.perSessionSettings.has(sessionId)) {
      this.perSessionSettings.set(sessionId, { ...DEFAULT_SETTINGS });
    }
    return this.perSessionSettings.get(sessionId)!;
  }

  // ── SET Handling ────────────────────────────────────────────

  /**
   * Handle a SET statement for backslash-related GUCs.
   * Returns true if the statement was consumed.
   */
  handleSet(sql: string, sessionId?: string): boolean {
    const trimmed = sql.trim().replace(/;+$/, '');
    const settings = this.getSession(sessionId);

    // SET standard_conforming_strings = on|off
    const scsMatch = trimmed.match(
      /^SET\s+standard_conforming_strings\s*=\s*(on|off|true|false|1|0)\s*;?$/i,
    );
    if (scsMatch) {
      settings.standardConformingStrings = ['on', 'true', '1'].includes(scsMatch[1].toLowerCase());
      logger.debug({ sessionId: sessionId || 'default', value: settings.standardConformingStrings });
      return true;
    }

    // SET escape_string_warning = on|off
    const eswMatch = trimmed.match(
      /^SET\s+escape_string_warning\s*=\s*(on|off|true|false|1|0)\s*;?$/i,
    );
    if (eswMatch) {
      settings.escapeStringWarning = ['on', 'true', '1'].includes(eswMatch[1].toLowerCase());
      logger.debug({ sessionId: sessionId || 'default', value: settings.escapeStringWarning });
      return true;
    }

    // SET backslash_quote = safe|on|off
    const bqMatch = trimmed.match(
      /^SET\s+backslash_quote\s*=\s*(safe|on|off)\s*;?$/i,
    );
    if (bqMatch) {
      const mode = bqMatch[1].toLowerCase() as BackslashQuoteMode;
      if (['safe', 'on', 'off'].includes(mode)) {
        settings.backslashQuote = mode;
        logger.debug({ sessionId: sessionId || 'default', value: mode });
        return true;
      }
    }

    return false;
  }

  // ── SHOW Handling ───────────────────────────────────────────

  /**
   * Get the value of a backslash-related GUC.
   */
  show(param: string, sessionId?: string): string | undefined {
    const settings = this.getSession(sessionId);
    const key = param.toLowerCase().replace(/;+$/, '');

    switch (key) {
      case 'standard_conforming_strings':
        return settings.standardConformingStrings ? 'on' : 'off';
      case 'escape_string_warning':
        return settings.escapeStringWarning ? 'on' : 'off';
      case 'backslash_quote':
        return settings.backslashQuote;
      default:
        return undefined;
    }
  }

  // ── Escape Checking ─────────────────────────────────────────

  /**
   * Check a SQL string for backslash escapes and return warnings.
   */
  checkEscapes(sql: string, sessionId?: string): string[] {
    const warnings: string[] = [];
    const settings = this.getSession(sessionId);

    if (!settings.escapeStringWarning) {
      return warnings;
    }

    // Find backslashes in single-quoted strings
    const stringLitRe = /'(?:[^'\\]|\\.)*'/g;
    let match;
    while ((match = stringLitRe.exec(sql)) !== null) {
      const lit = match[0];
      if (!lit.includes('\\')) continue;

      if (settings.standardConformingStrings) {
        warnings.push(
          `WARNING: non-standard escape sequence in string literal ` +
          `(standard_conforming_strings = on). Use E'...' for escape syntax ` +
          `if backslash escaping is intended.`,
        );
      }

      // Check backslash_quote mode for \' sequences
      if (lit.includes("\\'") && settings.backslashQuote === 'off') {
        warnings.push(
          `ERROR: backslash_quote = off prohibits \\' in string literals.`,
        );
      }
    }

    return warnings;
  }

  // ── Utilities ───────────────────────────────────────────────

  /** Get all current settings. */
  getAllSettings(): Map<string, BackslashQuoteSettings> {
    return new Map(this.perSessionSettings);
  }

  /** Get number of active sessions. */
  getSessionCount(): number {
    return this.perSessionSettings.size;
  }

  /** Reset all settings to defaults. */
  reset(): void {
    this.perSessionSettings.clear();
  }
}
