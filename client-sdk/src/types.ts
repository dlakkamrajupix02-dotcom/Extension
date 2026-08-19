/**
 * Types and interfaces for Payload Shield Client SDK.
 *
 * Threat Model Warning:
 * Key storage in sessionStorage or localStorage carries trade-offs.
 * localStorage persists across sessions but increases XSS exposure risk.
 */

export type StorageMode = 'memory' | 'sessionStorage' | 'localStorage';

export interface PayloadShieldConfig {
  baseUrl: string;
  handshakeEndpoint?: string;
  storageMode?: StorageMode;
}

export interface HandshakeRequest {
  client_public_key: string;
  session_id: string;
}

export interface HandshakeResponse {
  server_public_key: string;
  session_id: string;
}

export interface EncryptedPayload {
  nonce: string;
  ciphertext: string;
}
