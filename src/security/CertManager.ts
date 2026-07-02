/**
 * CertManager — Certificate chain validation with node-forge.
 *
 * Provides comprehensive certificate validation including CA chain verification,
 * SAN matching, expiration checks, key usage validation, and basic constraints
 * enforcement (leaf cert must NOT be a CA).
 *
 * Design:
 *   - Uses node-forge for all crypto operations (already installed v1.4.0)
 *   - validateCertChain() performs a full chain walk from leaf up to a trusted root
 *   - Returns a structured CertValidationResult with chain status + error reason
 *   - Supports revocation checking via optional OCSP/CRL (stub ready for extension)
 *
 * @module security/CertManager
 */

import * as forge from 'node-forge';
import { PinoLogger } from '../monitoring/PinoLogger';

// ── Logger ───────────────────────────────────────────────────────────────────

const logger = PinoLogger.forComponent('CertManager');

// ── Types ────────────────────────────────────────────────────────────────────

export interface CertValidationResult {
  /** Whether the certificate chain is fully valid */
  valid: boolean;
  /** Human-readable error message (only set when valid === false) */
  error?: string;
  /** Whether the chain connects to a trusted root CA */
  chainVerified: boolean;
  /** Whether the certificate has expired */
  expired: boolean;
  /** Whether the subjectAltName matches the expected hostname */
  sanMatch: boolean;
  /** Whether the certificate's key usage permits the required operations */
  keyUsageValid: boolean;
  /** Whether the basic constraints CA flag is correct (leaf must NOT be CA) */
  caFlagValid: boolean;
  /** Number of certificates in the chain (including leaf) */
  chainDepth: number;
}

export interface CertChainValidationOptions {
  /** Expected hostname to match against SubjectAltName */
  expectedHostname: string;
  /** Trusted CA certificates in PEM format */
  trustedCAs: string[];
  /** Whether to perform revocation checking (default: false) */
  checkRevocation?: boolean;
}

// ── Error codes for internal use ─────────────────────────────────────────────

const enum CertError {
  PARSE_FAILED = 'Failed to parse certificate PEM',
  EMPTY_CHAIN = 'Certificate chain is empty',
  NO_TRUSTED_CAS = 'No trusted CA certificates provided',
  CHAIN_VERIFY_FAILED = 'Certificate chain verification failed',
  EXPIRED = 'Certificate has expired',
  NOT_YET_VALID = 'Certificate is not yet valid',
  SAN_MISMATCH = 'SubjectAltName does not match expected hostname',
  NO_SAN = 'Certificate has no SubjectAltName extension',
  KEY_USAGE_INVALID = 'Key usage does not include digitalSignature or keyEncipherment',
  LEAF_IS_CA = 'Leaf certificate has CA flag set to true',
  NO_BASIC_CONSTRAINTS = 'Leaf certificate has no basicConstraints extension',
  REVOKED = 'Certificate has been revoked',
  INTERMEDIATE_IS_NOT_CA = 'Intermediate certificate does not have CA flag',
}

// ── Default configuration ────────────────────────────────────────────────────

const DEFAULT_CHECK_REVOCATION = false;

// ── Public API ───────────────────────────────────────────────────────────────

/**
 * Validate a certificate chain against a set of trusted CA certificates.
 *
 * Performs the following validations in order:
 *   1. Parse the leaf certificate and all intermediate certificates
 *   2. Build a chain from leaf to a trusted root CA
 *   3. Verify each certificate in the chain links to the next
 *   4. Check the leaf certificate's SubjectAltName against expectedHostname
 *   5. Check the leaf certificate has not expired
 *   6. Check key usage: requires digitalSignature and keyEncipherment
 *   7. Check basic constraints: leaf must NOT be a CA; intermediates MUST be
 *   8. (Optional) Check revocation status (stub — extend with OCSP/CRL)
 *
 * @param certPem   - The leaf/end-entity certificate in PEM format.
 * @param options   - Validation options including trusted CAs and expected hostname.
 * @returns A detailed CertValidationResult.
 */
export function validateCertChain(
  certPem: string,
  options: CertChainValidationOptions,
): CertValidationResult {
  const { expectedHostname, trustedCAs, checkRevocation = DEFAULT_CHECK_REVOCATION } = options;

  // Immediate result helper
  const fail = (error: string, partial?: Partial<CertValidationResult>): CertValidationResult => ({
    valid: false,
    error,
    chainVerified: partial?.chainVerified ?? false,
    expired: partial?.expired ?? false,
    sanMatch: partial?.sanMatch ?? false,
    keyUsageValid: partial?.keyUsageValid ?? false,
    caFlagValid: partial?.caFlagValid ?? false,
    chainDepth: partial?.chainDepth ?? 0,
  });

  // ── 1. Parse certificates ──────────────────────────────────────────

  let leafCert: forge.pki.Certificate;
  try {
    leafCert = forge.pki.certificateFromPem(certPem);
  } catch (err) {
    logger.error({ err }, CertError.PARSE_FAILED);
    return fail(CertError.PARSE_FAILED);
  }

  if (!trustedCAs || trustedCAs.length === 0) {
    return fail(CertError.NO_TRUSTED_CAS);
  }

  // ── 2. Parse all intermediate + root CA certs ──────────────────────

  const caCerts: forge.pki.Certificate[] = [];
  const intermediateCerts: forge.pki.Certificate[] = [];

  for (const caPem of trustedCAs) {
    try {
      const cert = forge.pki.certificateFromPem(caPem);
      // Distinguish root CAs from intermediates by checking self-signature
      const subjectCN = cert.subject.attributes.find((a: forge.pki.Attribute) => a.name === 'commonName')?.value ?? '';
      const issuerCN = cert.issuer.attributes.find((a: forge.pki.Attribute) => a.name === 'commonName')?.value ?? '';

      // A self-signed cert (subject == issuer) is a root CA
      if (subjectCN === issuerCN && subjectCN !== '' && cert.verify(cert)) {
        caCerts.push(cert);
      } else {
        intermediateCerts.push(cert);
      }
    } catch (err) {
      logger.warn({ err }, 'Failed to parse CA certificate PEM, skipping');
    }
  }

  // Build full chain: leaf + intermediates (in order) + roots (used as trust anchors)
  // node-forge's verifyCertificateChain expects [leaf, intermediate, ...] with trust anchors in CaStore
  const fullChain: forge.pki.Certificate[] = [leafCert, ...intermediateCerts];

  // ── 3. Chain verification via node-forge ───────────────────────────

  let chainVerified = false;
  try {
    const caStore = forge.pki.createCaStore(caCerts);
    chainVerified = forge.pki.verifyCertificateChain(caStore, fullChain);
  } catch (err) {
    logger.warn({ err }, 'Certificate chain verification threw an exception');
    chainVerified = false;
  }

  if (!chainVerified) {
    return fail(CertError.CHAIN_VERIFY_FAILED, {
      chainVerified: false,
      chainDepth: fullChain.length,
    });
  }

  // ── 4. Validate SubjectAltName ─────────────────────────────────────

  const sanExt = leafCert.getExtension('subjectAltName') as forge.pki.SubjectAltNameExtension | null;
  let sanMatch = false;

  if (!sanExt || !sanExt.altNames || sanExt.altNames.length === 0) {
    return fail(CertError.NO_SAN, {
      chainVerified,
      chainDepth: fullChain.length,
    });
  }

  // Match expected hostname against altNames (type 2 = dNSName)
  sanMatch = sanExt.altNames.some((altName: forge.pki.AltName) => {
    if (altName.type === 2) {
      return matchHostname(expectedHostname, altName.value);
    }
    return false;
  });

  if (!sanMatch) {
    return fail(CertError.SAN_MISMATCH, {
      chainVerified,
      chainDepth: fullChain.length,
    });
  }

  // ── 5. Expiration check ────────────────────────────────────────────

  const now = new Date();
  const notBefore = new Date(leafCert.validity.notBefore);
  const notAfter = new Date(leafCert.validity.notAfter);
  const expired = now > notAfter;
  const notYetValid = now < notBefore;

  if (expired) {
    return fail(CertError.EXPIRED, {
      chainVerified,
      sanMatch,
      expired: true,
      chainDepth: fullChain.length,
    });
  }

  if (notYetValid) {
    return fail(CertError.NOT_YET_VALID, {
      chainVerified,
      sanMatch,
      expired: false,
      chainDepth: fullChain.length,
    });
  }

  // ── 6. Key usage check ────────────────────────────────────────────
  //
  // node-forge's getExtension('keyUsage') returns an object with individual
  // boolean properties (digitalSignature, keyEncipherment, etc.) rather than
  // an array.  See: https://github.com/digitalbazaar/forge/issues/547
  //
  // We check the boolean properties directly for digitalSignature and
  // keyEncipherment.

  const kuExt = leafCert.getExtension('keyUsage') as Record<string, unknown> | null;
  let keyUsageValid = false;

  if (kuExt) {
    const hasDigitalSig = kuExt.digitalSignature === true;
    const hasKeyEnci = kuExt.keyEncipherment === true;
    keyUsageValid = hasDigitalSig && hasKeyEnci;
  } else {
    // If keyUsage is absent, some CAs allow all uses per RFC 5280 §4.2.1.3
    // We treat it as valid but log a warning
    logger.warn('Leaf certificate has no keyUsage extension — allowing all uses');
    keyUsageValid = true;
  }

  if (!keyUsageValid) {
    return fail(CertError.KEY_USAGE_INVALID, {
      chainVerified,
      sanMatch,
      expired: false,
      chainDepth: fullChain.length,
    });
  }

  // ── 7. Basic constraints: leaf must NOT be CA ──────────────────────

  const bcExt = leafCert.getExtension('basicConstraints') as forge.pki.BasicConstraintsExtension | null;
  let caFlagValid = false;

  if (!bcExt) {
    // For leaf certs, missing basicConstraints means it's assumed not a CA
    caFlagValid = true;
  } else {
    caFlagValid = bcExt.cA === false;
  }

  if (!caFlagValid) {
    return fail(CertError.LEAF_IS_CA, {
      chainVerified,
      sanMatch,
      expired: false,
      keyUsageValid,
      chainDepth: fullChain.length,
    });
  }

  // ── 8. Verify intermediate certs have CA flag ───────────────────────

  for (const intermediate of intermediateCerts) {
    const intBcExt = intermediate.getExtension('basicConstraints') as forge.pki.BasicConstraintsExtension | null;
    if (!intBcExt || intBcExt.cA !== true) {
      return fail(CertError.INTERMEDIATE_IS_NOT_CA, {
        chainVerified,
        sanMatch,
        expired: false,
        keyUsageValid,
        caFlagValid,
        chainDepth: fullChain.length,
      });
    }
  }

  // ── 9. (Optional) Revocation check (stub) ──────────────────────────

  if (checkRevocation) {
    // Placeholder for OCSP/CRL-based revocation checking.
    // Per RFC 5280, implementers should check CRL Distribution Points
    // or OCSP responder URLs from the certificate.
    // For now, we log a warning since the stub is not yet implemented.
    logger.warn('Revocation checking is not yet implemented — OCSP/CRL stub');
  }

  // ── All checks passed ──────────────────────────────────────────────

  logger.info(
    { chainDepth: fullChain.length, hostname: expectedHostname },
    'Certificate chain validation passed',
  );

  return {
    valid: true,
    chainVerified: true,
    expired: false,
    sanMatch: true,
    keyUsageValid: true,
    caFlagValid: true,
    chainDepth: fullChain.length,
  };
}

/**
 * Check whether `hostname` matches a DNS name pattern from a certificate SAN.
 *
 * Supports wildcards: `*.example.com` matches `foo.example.com`.
 * Does NOT match `example.com` or `foo.bar.example.com` (single-level wildcard).
 *
 * @param hostname  - The hostname to check (e.g. 'api.example.com').
 * @param pattern   - The DNS name pattern from the certificate (e.g. '*.example.com').
 * @returns true if the hostname matches the pattern.
 */
export function matchHostname(hostname: string, pattern: string): boolean {
  if (!hostname || !pattern) return false;

  const normalizedHost = hostname.toLowerCase();
  const normalizedPattern = pattern.toLowerCase();

  // Exact match
  if (normalizedHost === normalizedPattern) return true;

  // Wildcard: single level only
  if (normalizedPattern.startsWith('*.')) {
    const suffix = normalizedPattern.slice(1); // remove the '*'
    if (normalizedHost.endsWith(suffix) && !normalizedHost.slice(0, -suffix.length).includes('.')) {
      return true;
    }
  }

  return false;
}
