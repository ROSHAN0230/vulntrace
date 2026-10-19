import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const sampleBundlePath = path.resolve(__dirname, '../../../docs/evidence/sample_m6_bundle.json');

// Dynamically import compiled or transpile-ready module
import {
  verifyEvidenceBundle,
  canonicalJsonString,
  TRUSTED_TRUST_ANCHORS,
} from '../utils/cryptoVerification.ts';

const authenticBundle = JSON.parse(fs.readFileSync(sampleBundlePath, 'utf8'));

test('1. Authentic bundle verifies cleanly as TRUSTED_VERIFIED', async () => {
  const bundleCopy = JSON.parse(JSON.stringify(authenticBundle));
  const result = await verifyEvidenceBundle(bundleCopy);

  assert.equal(result.status, 'TRUSTED_VERIFIED');
  assert.equal(result.isValid, true);
  assert.equal(result.isTrustedSigner, true);
  assert.equal(result.signerFingerprint, 'fe9efb08b8882c91e7946d56bf0ab2ba7ac3e998d015470ccebb8fe5bcca7ce3');
  assert.equal(result.computedSha256, '094ddb468af8e311b1e8391bcf6a2e7af231dc3ff0b0501b6c49dc4adcf1ef40');
  assert.match(result.message, /successfully verified/i);
});

test('2. Single-byte tampering of tokens used immediately triggers PAYLOAD_TAMPERED', async () => {
  const tampered = JSON.parse(JSON.stringify(authenticBundle));
  // Mutate token count by +1
  tampered.llm.calls[0].prompt_tokens = 1847;

  const result = await verifyEvidenceBundle(tampered);

  assert.equal(result.status, 'PAYLOAD_TAMPERED');
  assert.equal(result.isValid, false);
  assert.notEqual(result.computedSha256, authenticBundle.signature.canonical_sha256);
  assert.match(result.message, /Canonical SHA-256 mismatch/i);
});

test('3. Single-character tampering of unified diff triggers PAYLOAD_TAMPERED', async () => {
  const tampered = JSON.parse(JSON.stringify(authenticBundle));
  // Append whitespace or modify diff
  tampered.attempts[0].diff += '\n# tampered';

  const result = await verifyEvidenceBundle(tampered);

  assert.equal(result.status, 'PAYLOAD_TAMPERED');
  assert.equal(result.isValid, false);
  assert.match(result.message, /payload has been modified/i);
});

test('4. Corrupted signature hex bytes triggers INVALID_SIGNATURE', async () => {
  const tampered = JSON.parse(JSON.stringify(authenticBundle));
  // Flip the first two hex characters of the signature
  const originalSig = tampered.signature.sig;
  tampered.signature.sig = (originalSig.startsWith('00') ? 'ff' : '00') + originalSig.substring(2);

  const result = await verifyEvidenceBundle(tampered);

  assert.equal(result.status, 'INVALID_SIGNATURE');
  assert.equal(result.isValid, false);
  assert.match(result.message, /Ed25519 cryptographic signature verification failed/i);
});

test('5. Public key fingerprint mismatch triggers FINGERPRINT_MISMATCH', async () => {
  const tampered = JSON.parse(JSON.stringify(authenticBundle));
  // Provide wrong fingerprint for the valid public key
  tampered.signature.public_key_fingerprint = '0000000000000000000000000000000000000000000000000000000000000000';

  const result = await verifyEvidenceBundle(tampered);

  assert.equal(result.status, 'FINGERPRINT_MISMATCH');
  assert.equal(result.isValid, false);
  assert.match(result.message, /fingerprint mismatch/i);
});

test('6. Missing signature block triggers MALFORMED_BUNDLE', async () => {
  const tampered = JSON.parse(JSON.stringify(authenticBundle));
  delete tampered.signature;

  const result = await verifyEvidenceBundle(tampered);

  assert.equal(result.status, 'MALFORMED_BUNDLE');
  assert.equal(result.isValid, false);
  assert.match(result.message, /Missing required 'signature' block/i);
});

test('7. Untrusted authority key fails closed as UNTRUSTED_SIGNER', async () => {
  const bundleCopy = JSON.parse(JSON.stringify(authenticBundle));
  // Temporarily clear trust anchor whitelist
  const originalEntry = TRUSTED_TRUST_ANCHORS.get('fe9efb08b8882c91e7946d56bf0ab2ba7ac3e998d015470ccebb8fe5bcca7ce3');
  try {
    TRUSTED_TRUST_ANCHORS.clear();
    const result = await verifyEvidenceBundle(bundleCopy);

    assert.equal(result.status, 'UNTRUSTED_SIGNER');
    assert.equal(result.isValid, false); // Strict Zero-Trust fail closed!
    assert.equal(result.isTrustedSigner, false);
    assert.match(result.message, /not in trusted authority whitelist/i);
  } finally {
    if (originalEntry) {
      TRUSTED_TRUST_ANCHORS.set('fe9efb08b8882c91e7946d56bf0ab2ba7ac3e998d015470ccebb8fe5bcca7ce3', originalEntry);
    }
  }
});
