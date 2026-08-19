/**
 * Client-side Crypto Implementation for Payload Shield SDK.
 *
 * Cryptographic Architecture:
 * - Uses `@noble/curves/x25519` for cross-browser X25519 ECDH key generation & agreement.
 * - Uses WebCrypto (`crypto.subtle`) for HKDF-SHA256 key derivation and AES-256-GCM encryption/decryption.
 * - Nonce: 12-byte (96-bit) cryptographically secure random values via `crypto.getRandomValues()`.
 * - HKDF Info: `payload-shield-v1:<session_id>` UTF-8 encoded bytes.
 *
 * Threat Model & Security Notice:
 * Protects JSON API payloads against casual Network tab inspection, naive direct scraping scripts,
 * and proxy log harvesting over TLS.
 * DOES NOT protect against local browser DevTools inspection by authenticated users or in-page XSS.
 * MUST be layered on top of HTTPS/TLS.
 */

import { x25519 } from '@noble/curves/ed25519';
import { EncryptedPayload } from './types';


/**
 * Ensure WebCrypto API is available in the execution environment.
 */
function assertWebCryptoAvailable(): void {
  if (
    typeof globalThis === 'undefined' ||
    !globalThis.crypto ||
    !globalThis.crypto.subtle
  ) {
    throw new Error(
      'Payload Shield Error: WebCrypto API (crypto.subtle) is unavailable in this browser environment. ' +
      'Ensure the application is served over HTTPS/TLS in a secure context.'
    );
  }
}

/**
 * Base64 encoding helper for Uint8Array.
 */
export function bytesToBase64(bytes: Uint8Array): string {
  let binary = '';
  const len = bytes.byteLength;
  for (let i = 0; i < len; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

/**
 * Base64 decoding helper returning Uint8Array.
 */
export function base64ToBytes(b64: string): Uint8Array {
  const binary = atob(b64);
  const len = binary.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

export interface KeyPairB64 {
  privateKeyBytes: Uint8Array;
  publicKeyB64: string;
}

/**
 * Generate an ephemeral X25519 private/public key pair.
 */
export function generateClientKeyPair(): KeyPairB64 {
  const privateKeyBytes = x25519.utils.randomPrivateKey();
  const publicKeyBytes = x25519.getPublicKey(privateKeyBytes);
  return {
    privateKeyBytes,
    publicKeyB64: bytesToBase64(publicKeyBytes),
  };
}

/**
 * Construct HKDF context info byte array bound to session ID.
 * Matches Python `get_session_info(session_id)`.
 */
export function getSessionInfoBytes(sessionId: string): Uint8Array {
  return new TextEncoder().encode(`payload-shield-v1:${sessionId}`);
}

/**
 * Perform X25519 ECDH key agreement and derive a 256-bit AES-GCM CryptoKey using WebCrypto HKDF-SHA256.
 *
 * @param clientPrivateKeyBytes 32-byte client X25519 private key.
 * @param serverPublicKeyB64 Base64-encoded server X25519 public key.
 * @param sessionId Server-issued session ID bound to this key agreement.
 */
export async function deriveSessionCryptoKey(
  clientPrivateKeyBytes: Uint8Array,
  serverPublicKeyB64: string,
  sessionId: string
): Promise<CryptoKey> {
  assertWebCryptoAvailable();

  const serverPublicKeyBytes = base64ToBytes(serverPublicKeyB64);
  if (serverPublicKeyBytes.length !== 32) {
    throw new Error(`Invalid server X25519 public key length: ${serverPublicKeyBytes.length} bytes (expected 32)`);
  }

  // 1. Calculate raw X25519 shared secret (32 bytes)
  const rawSharedSecret = x25519.getSharedSecret(clientPrivateKeyBytes, serverPublicKeyBytes);

  // 2. Import raw shared secret as HKDF Input Key Material (IKM)
  const ikmKey = await globalThis.crypto.subtle.importKey(
    'raw',
    rawSharedSecret.buffer as ArrayBuffer,
    { name: 'HKDF' },
    false,
    ['deriveKey']
  );

  // 3. Derive 256-bit AES-GCM CryptoKey using HKDF-SHA256 with session-bound info
  const infoBytes = getSessionInfoBytes(sessionId);

  const aesGcmKey = await globalThis.crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: new Uint8Array(32).buffer as ArrayBuffer, // 32 zero bytes matching Python cryptography library's salt=None (RFC 5869 HashLen zeros)
      info: infoBytes.buffer as ArrayBuffer,
    },
    ikmKey,
    {
      name: 'AES-GCM',
      length: 256,
    },
    true, // extractable for testing/storage
    ['encrypt', 'decrypt']
  );

  return aesGcmKey;
}

/**
 * Encrypt a plaintext string or byte array using AES-256-GCM with a fresh 12-byte random nonce.
 */
export async function encryptPayloadClient(
  key: CryptoKey,
  plaintext: string | Uint8Array
): Promise<EncryptedPayload> {
  assertWebCryptoAvailable();

  const plaintextBytes =
    typeof plaintext === 'string'
      ? new TextEncoder().encode(plaintext)
      : plaintext;

  // Generate fresh 12-byte (96-bit) cryptographically secure random nonce
  const nonce = globalThis.crypto.getRandomValues(new Uint8Array(12));

  const encryptedBuffer = await globalThis.crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: nonce.buffer as ArrayBuffer,
    },
    key,
    plaintextBytes.buffer as ArrayBuffer
  );


  const ciphertextBytes = new Uint8Array(encryptedBuffer);

  return {
    nonce: bytesToBase64(nonce),
    ciphertext: bytesToBase64(ciphertextBytes),
  };
}

/**
 * Decrypt an AES-256-GCM encrypted payload and return plaintext bytes.
 */
export async function decryptPayloadClient(
  key: CryptoKey,
  nonceB64: string,
  ciphertextB64: string
): Promise<Uint8Array> {
  assertWebCryptoAvailable();

  const nonce = base64ToBytes(nonceB64);
  if (nonce.length !== 12) {
    throw new Error(`Invalid GCM nonce length: ${nonce.length} bytes (expected 12)`);
  }

  const ciphertext = base64ToBytes(ciphertextB64);

  try {
    const decryptedBuffer = await globalThis.crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: nonce.buffer as ArrayBuffer,
      },
      key,
      ciphertext.buffer as ArrayBuffer
    );


    return new Uint8Array(decryptedBuffer);
  } catch (err: any) {
    throw new Error(
      `Payload Shield Decryption Failed: Authentication tag validation failed or ciphertext corrupted (${err?.message || err})`
    );
  }
}


