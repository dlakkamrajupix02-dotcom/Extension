/**
 * Unit tests for client-sdk/src/crypto.ts
 */

import { describe, it, expect } from 'vitest';
import { x25519 } from '@noble/curves/ed25519';
import {
  bytesToBase64,
  base64ToBytes,
  generateClientKeyPair,
  getSessionInfoBytes,
} from '../src/crypto';

describe('Client SDK Crypto Unit Tests', () => {
  it('should encode and decode base64 bytes symmetrically', () => {
    const originalBytes = new Uint8Array([1, 2, 3, 4, 5, 255, 128, 64]);
    const b64 = bytesToBase64(originalBytes);
    expect(typeof b64).toBe('string');

    const decoded = base64ToBytes(b64);
    expect(decoded).toEqual(originalBytes);
  });

  it('should generate valid X25519 client key pair', () => {
    const { privateKeyBytes, publicKeyB64 } = generateClientKeyPair();
    expect(privateKeyBytes.length).toBe(32);

    const pubBytes = base64ToBytes(publicKeyB64);
    expect(pubBytes.length).toBe(32);

    const reDerivedPub = x25519.getPublicKey(privateKeyBytes);
    expect(pubBytes).toEqual(reDerivedPub);
  });

  it('should format session info bytes correctly', () => {
    const info = getSessionInfoBytes('sess_abc123');
    const text = new TextDecoder().decode(info);
    expect(text).toBe('payload-shield-v1:sess_abc123');
  });
});
