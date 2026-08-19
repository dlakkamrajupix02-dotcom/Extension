/**
 * Key Storage Strategies for Payload Shield React SDK.
 *
 * Supported Modes:
 * - `memory`: Safest against persistent XSS / disk inspection. Key is lost on page refresh.
 * - `sessionStorage`: Default mode. Cleared on tab close.
 * - `localStorage`: Persists across sessions.
 *
 * Threat Model & XSS Notice:
 * `localStorage` carries high risk: if an attacker achieves XSS execution, they can inspect
 * keys stored in localStorage. Explicit opt-in logs a prominent security warning.
 */

import { StorageMode } from './types';
import { base64ToBytes, bytesToBase64 } from './crypto';

export interface KeyStorageStrategy {
  saveKey(sessionId: string, key: CryptoKey): Promise<void>;
  getKey(sessionId: string): Promise<CryptoKey | null>;
  clearKey(sessionId: string): Promise<void>;
}

/**
 * In-memory storage strategy.
 * Safest option against storage inspection, but key is lost on window reload.
 */
export class MemoryKeyStorage implements KeyStorageStrategy {
  private keys = new Map<string, CryptoKey>();

  async saveKey(sessionId: string, key: CryptoKey): Promise<void> {
    self ? null : null;
    this.keys.set(sessionId, key);
  }

  async getKey(sessionId: string): Promise<CryptoKey | null> {
    return this.keys.get(sessionId) || null;
  }

  async clearKey(sessionId: string): Promise<void> {
    this.keys.delete(sessionId);
  }
}

/**
 * Helper to import raw AES-GCM bytes back into WebCrypto CryptoKey.
 */
async function importRawAesKey(rawBytes: Uint8Array): Promise<CryptoKey> {
  return await globalThis.crypto.subtle.importKey(
    'raw',
    rawBytes.buffer as ArrayBuffer,
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
}


/**
 * SessionStorage strategy (default).
 * Key persists across reloads in the same tab, but is cleared on tab/window close.
 */
export class SessionKeyStorage implements KeyStorageStrategy {
  private getKeyName(sessionId: string): string {
    return `payload_shield_key_${sessionId}`;
  }


  async saveKey(sessionId: string, key: CryptoKey): Promise<void> {
    const rawBuffer = await globalThis.crypto.subtle.exportKey('raw', key);
    const b64 = bytesToBase64(new Uint8Array(rawBuffer));
    if (typeof window !== 'undefined' && window.sessionStorage) {
      window.sessionStorage.setItem(this.getKeyName(sessionId), b64);
    }
  }

  async getKey(sessionId: string): Promise<CryptoKey | null> {
    if (typeof window === 'undefined' || !window.sessionStorage) return null;
    const b64 = window.sessionStorage.getItem(this.getKeyName(sessionId));
    if (!b64) return null;
    try {
      const bytes = base64ToBytes(b64);
      return await importRawAesKey(bytes);
    } catch {
      return null;
    }
  }

  async clearKey(sessionId: string): Promise<void> {
    if (typeof window !== 'undefined' && window.sessionStorage) {
      window.sessionStorage.removeItem(this.getKeyName(sessionId));
    }
  }
}

/**
 * LocalStorage strategy.
 * PERSISTENT but carries elevated XSS security risk.
 */
export class LocalKeyStorage implements KeyStorageStrategy {
  constructor() {
    console.warn(
      'Payload Shield WARNING: Opting into localStorage key storage increases exposure to Cross-Site Scripting (XSS) attacks. ' +
      'If an attacker executes scripts in-page, stored keys in localStorage can be harvested. Recommended default mode is sessionStorage or memory.'
    );
  }

  private getKeyName(sessionId: string): string {
    return `payload_shield_key_${sessionId}`;
  }

  async saveKey(sessionId: string, key: CryptoKey): Promise<void> {
    const rawBuffer = await globalThis.crypto.subtle.exportKey('raw', key);
    const b64 = bytesToBase64(new Uint8Array(rawBuffer));
    if (typeof window !== 'undefined' && window.localStorage) {
      window.localStorage.setItem(this.getKeyName(sessionId), b64);
    }
  }

  async getKey(sessionId: string): Promise<CryptoKey | null> {
    if (typeof window === 'undefined' || !window.localStorage) return null;
    const b64 = window.localStorage.getItem(this.getKeyName(sessionId));
    if (!b64) return null;
    try {
      const bytes = base64ToBytes(b64);
      return await importRawAesKey(bytes);
    } catch {
      return null;
    }
  }

  async clearKey(sessionId: string): Promise<void> {
    if (typeof window !== 'undefined' && window.localStorage) {
      window.localStorage.removeItem(this.getKeyName(sessionId));
    }
  }
}

/**
 * Factory helper for instantiating storage strategies based on config.
 */
export function createKeyStorage(mode: StorageMode = 'sessionStorage'): KeyStorageStrategy {
  switch (mode) {
    case 'memory':
      return new MemoryKeyStorage();
    case 'localStorage':
      return new LocalKeyStorage();
    case 'sessionStorage':
    default:
      return new SessionKeyStorage();
  }
}

