/**
 * VulnTrace In-Browser Cryptographic Evidence Verification Engine (Spec §4.11 / §6 AC4).
 * 
 * Verifies authentic RFC 8032 Ed25519 digital signatures and deterministic canonical payloads
 * using standard W3C Web Cryptography API (`crypto.subtle`).
 * 
 * Security Guarantees:
 * 1. Strict Fail-Closed Execution: Any missing attribute, tampered byte, or corrupted signature fails immediately.
 * 2. Trust Anchor Enforcement: Merely possessing a valid mathematical signature is insufficient;
 *    the signer public-key fingerprint must match an approved, trusted release authority.
 * 3. Single-Byte Tamper Detection: Recomputes canonical payload SHA-256 digest and compares bitwise against declared hash.
 */

export type VerificationStatus =
  | 'TRUSTED_VERIFIED'
  | 'UNTRUSTED_SIGNER'
  | 'PAYLOAD_TAMPERED'
  | 'INVALID_SIGNATURE'
  | 'FINGERPRINT_MISMATCH'
  | 'MALFORMED_BUNDLE'
  | 'UNSUPPORTED_ENV';

export interface VerificationResult {
  status: VerificationStatus;
  isValid: boolean;
  signerFingerprint?: string;
  signerLabel?: string;
  computedSha256?: string;
  declaredSha256?: string;
  isTrustedSigner: boolean;
  message: string;
  verifiedAt: string;
}

/**
 * Approved Trust Anchors:
 * Canonical release keys authorized to seal VulnTrace forensic evidence.
 */
export const TRUSTED_TRUST_ANCHORS = new Map<string, { label: string; keyHex: string }>([
  [
    'fe9efb08b8882c91e7946d56bf0ab2ba7ac3e998d015470ccebb8fe5bcca7ce3',
    {
      label: 'VulnTrace Studio Official Release Authority (Canonical Release Key)',
      keyHex: '16c6d4fa9d637049065ae3b68b2a29bcb808c053c72ca1e56a3a7014f313d08b'
    }
  ]
]);

/**
 * Deterministically serializes a clean evidence payload into canonical JSON bytes,
 * mirroring Python's `vulntrace.evidence.canonical.canonical_json_bytes` and RFC 8785 conventions.
 */
export function canonicalJsonString(obj: unknown, path = ''): string {
  if (obj === null) return 'null';
  if (typeof obj === 'boolean') return obj ? 'true' : 'false';
  if (typeof obj === 'number') {
    // Preserve float formatting for schema fields that Python outputs with trailing .0
    if (Number.isInteger(obj) && (path.endsWith('timeout_sec') || path.endsWith('latency_ms'))) {
      return obj.toFixed(1);
    }
    return String(obj);
  }
  if (typeof obj === 'string') return JSON.stringify(obj);
  if (Array.isArray(obj)) {
    return '[' + obj.map((item, idx) => canonicalJsonString(item, `${path}[${idx}]`)).join(',') + ']';
  }
  if (typeof obj === 'object') {
    const sortedKeys = Object.keys(obj as Record<string, unknown>).sort();
    const pairs = sortedKeys.map(
      k => `${JSON.stringify(k)}:${canonicalJsonString((obj as Record<string, unknown>)[k], path ? `${path}.${k}` : k)}`
    );
    return '{' + pairs.join(',') + '}';
  }
  return JSON.stringify(obj);
}

/**
 * Converts a hex string to Uint8Array.
 */
export function hexToBytes(hex: string): Uint8Array {
  if (typeof hex !== 'string' || hex.length % 2 !== 0) {
    throw new Error('Invalid hex string format: must have even length.');
  }
  const cleanHex = hex.trim().toLowerCase();
  const bytes = new Uint8Array(cleanHex.length / 2);
  for (let i = 0; i < cleanHex.length; i += 2) {
    const val = parseInt(cleanHex.substring(i, i + 2), 16);
    if (isNaN(val)) {
      throw new Error(`Invalid hex character at index ${i}: ${cleanHex.substring(i, i + 2)}`);
    }
    bytes[i / 2] = val;
  }
  return bytes;
}

/**
 * Converts a Uint8Array or ArrayBuffer to a lowercase hex string.
 */
export function bytesToHex(buffer: ArrayBuffer | Uint8Array): string {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Verifies an evidence bundle's cryptographic seal and trust anchor in-browser.
 */
export async function verifyEvidenceBundle(
  bundle: Record<string, unknown>,
  options: {
    rawCanonicalText?: string;
    subtleCrypto?: SubtleCrypto;
  } = {}
): Promise<VerificationResult> {
  const verifiedAt = new Date().toISOString();

  // 1. Detect Web Crypto support
  const cryptoSubtle =
    options.subtleCrypto ||
    (typeof window !== 'undefined' && window.crypto && window.crypto.subtle
      ? window.crypto.subtle
      : (typeof globalThis !== 'undefined' && (globalThis as any).crypto && (globalThis as any).crypto.subtle
          ? (globalThis as any).crypto.subtle
          : null));

  if (!cryptoSubtle) {
    return {
      status: 'UNSUPPORTED_ENV',
      isValid: false,
      isTrustedSigner: false,
      message: 'Web Crypto API (crypto.subtle) is not available in this environment.',
      verifiedAt
    };
  }

  // 2. Validate signature block schema
  const sigBlock = bundle.signature as Record<string, unknown> | undefined;
  if (!sigBlock || typeof sigBlock !== 'object') {
    return {
      status: 'MALFORMED_BUNDLE',
      isValid: false,
      isTrustedSigner: false,
      message: "Evidence bundle is missing required 'signature' block.",
      verifiedAt
    };
  }

  const alg = sigBlock.alg;
  if (alg !== 'Ed25519') {
    return {
      status: 'MALFORMED_BUNDLE',
      isValid: false,
      isTrustedSigner: false,
      message: `Unsupported signature algorithm '${String(alg)}'. Expected 'Ed25519'.`,
      verifiedAt
    };
  }

  const pubKeyHex = sigBlock.public_key;
  const declaredFp = sigBlock.public_key_fingerprint;
  const declaredSha256 = sigBlock.canonical_sha256;
  const sigHex = sigBlock.sig;

  if (
    typeof pubKeyHex !== 'string' ||
    typeof declaredFp !== 'string' ||
    typeof declaredSha256 !== 'string' ||
    typeof sigHex !== 'string'
  ) {
    return {
      status: 'MALFORMED_BUNDLE',
      isValid: false,
      isTrustedSigner: false,
      message: 'Malformed signature block: missing or invalid string types for public_key, fingerprint, hash, or sig.',
      verifiedAt
    };
  }

  let pubKeyBytes: Uint8Array;
  let sigBytes: Uint8Array;
  try {
    pubKeyBytes = hexToBytes(pubKeyHex);
    sigBytes = hexToBytes(sigHex);
  } catch (err: any) {
    return {
      status: 'MALFORMED_BUNDLE',
      isValid: false,
      isTrustedSigner: false,
      message: `Hex decode failure in signature block: ${err.message}`,
      verifiedAt
    };
  }

  if (pubKeyBytes.length !== 32) {
    return {
      status: 'MALFORMED_BUNDLE',
      isValid: false,
      isTrustedSigner: false,
      message: `Invalid Ed25519 public key length (${pubKeyBytes.length} bytes, expected 32 bytes).`,
      verifiedAt
    };
  }

  if (sigBytes.length !== 64) {
    return {
      status: 'MALFORMED_BUNDLE',
      isValid: false,
      isTrustedSigner: false,
      message: `Invalid Ed25519 signature length (${sigBytes.length} bytes, expected 64 bytes).`,
      verifiedAt
    };
  }

  // 3. Verify public key fingerprint
  let computedFp: string;
  try {
    const fpDigest = await cryptoSubtle.digest('SHA-256', pubKeyBytes);
    computedFp = bytesToHex(fpDigest);
  } catch (err: any) {
    return {
      status: 'UNSUPPORTED_ENV',
      isValid: false,
      isTrustedSigner: false,
      message: `SHA-256 digest failure during fingerprint computation: ${err.message}`,
      verifiedAt
    };
  }

  if (computedFp.toLowerCase() !== declaredFp.toLowerCase()) {
    return {
      status: 'FINGERPRINT_MISMATCH',
      isValid: false,
      signerFingerprint: declaredFp,
      isTrustedSigner: false,
      message: `Public key fingerprint mismatch: declared '${declaredFp}' != computed '${computedFp}'.`,
      verifiedAt
    };
  }

  // 4. Construct canonical payload without signature
  const cleanBundle: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(bundle)) {
    if (k !== 'signature') {
      cleanBundle[k] = v;
    }
  }

  const canonicalPayloadStr = options.rawCanonicalText || canonicalJsonString(cleanBundle);
  const canonicalBytes = new TextEncoder().encode(canonicalPayloadStr);

  // 5. Recompute canonical SHA-256 hash & verify single-byte integrity
  let computedSha256: string;
  try {
    const digestBuf = await cryptoSubtle.digest('SHA-256', canonicalBytes);
    computedSha256 = bytesToHex(digestBuf);
  } catch (err: any) {
    return {
      status: 'UNSUPPORTED_ENV',
      isValid: false,
      isTrustedSigner: false,
      message: `SHA-256 digest calculation error: ${err.message}`,
      verifiedAt
    };
  }

  if (computedSha256.toLowerCase() !== declaredSha256.toLowerCase()) {
    return {
      status: 'PAYLOAD_TAMPERED',
      isValid: false,
      signerFingerprint: declaredFp,
      computedSha256,
      declaredSha256,
      isTrustedSigner: false,
      message: `Canonical SHA-256 mismatch: payload has been modified. Declared '${declaredSha256}', computed '${computedSha256}'.`,
      verifiedAt
    };
  }

  // 6. Cryptographic Ed25519 verification via Web Crypto
  let isCryptoValid = false;
  try {
    const cryptoKey = await cryptoSubtle.importKey(
      'raw',
      pubKeyBytes,
      { name: 'Ed25519' },
      false,
      ['verify']
    );

    isCryptoValid = await cryptoSubtle.verify(
      { name: 'Ed25519' },
      cryptoKey,
      sigBytes,
      canonicalBytes
    );
  } catch (err: any) {
    return {
      status: 'UNSUPPORTED_ENV',
      isValid: false,
      signerFingerprint: declaredFp,
      computedSha256,
      declaredSha256,
      isTrustedSigner: false,
      message: `Web Crypto Ed25519 verification error: ${err.message}`,
      verifiedAt
    };
  }

  if (!isCryptoValid) {
    return {
      status: 'INVALID_SIGNATURE',
      isValid: false,
      signerFingerprint: declaredFp,
      computedSha256,
      declaredSha256,
      isTrustedSigner: false,
      message: 'Ed25519 cryptographic signature verification failed: signature does not match canonical payload.',
      verifiedAt
    };
  }

  // 7. Evaluate Trust Anchor Whitelist
  const trustAnchor = TRUSTED_TRUST_ANCHORS.get(declaredFp.toLowerCase());
  const isTrusted = !!trustAnchor;

  if (!isTrusted) {
    return {
      status: 'UNTRUSTED_SIGNER',
      isValid: false, // Fail closed: valid crypto signature, but untrusted authority
      signerFingerprint: declaredFp,
      signerLabel: 'Unknown / Untrusted Key',
      computedSha256,
      declaredSha256,
      isTrustedSigner: false,
      message: `Cryptographic signature is mathematically valid, but public key fingerprint (${declaredFp}) is not in trusted authority whitelist.`,
      verifiedAt
    };
  }

  return {
    status: 'TRUSTED_VERIFIED',
    isValid: true,
    signerFingerprint: declaredFp,
    signerLabel: trustAnchor.label,
    computedSha256,
    declaredSha256,
    isTrustedSigner: true,
    message: 'RFC 8032 Ed25519 Cryptographic Signature & RFC 8785 Canonical Payload successfully verified by trusted authority.',
    verifiedAt
  };
}
