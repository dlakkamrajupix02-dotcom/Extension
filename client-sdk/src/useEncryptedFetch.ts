/**
 * Custom React Hook providing an encrypted/decrypted fetch wrapper.
 *
 * Automatically injects the session ID header and decrypts AES-256-GCM response payloads.
 *
 * Threat Model Note:
 * Decryption happens in browser application memory just prior to rendering.
 * Network tab observers will see only base64 ciphertext and nonce.
 */

import { useCallback } from 'react';
import { usePayloadShield } from './PayloadShieldProvider';
import { decryptPayloadClient } from './crypto';

export interface UseEncryptedFetchOptions {
  headerName?: string;
}

export function useEncryptedFetch(options: UseEncryptedFetchOptions = {}) {
  const { sessionKey, sessionId, logout } = usePayloadShield();
  const headerName = options.headerName || 'X-Payload-Shield-Session';

  const encryptedFetch = useCallback(
    async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      if (!sessionKey || !sessionId) {
        throw new Error('Encrypted fetch failed: No active Payload Shield session or key. Perform handshake first.');
      }

      const headers = new Headers(init?.headers || {});
      headers.set(headerName, sessionId);

      const modifiedInit: RequestInit = {
        ...init,
        headers,
      };

      const response = await fetch(input, modifiedInit);

      // Handle 401 Unauthorized (session key expired or invalidated server-side)
      if (response.status === 401) {
        // Clear local state so application is alerted to re-authenticate or re-handshake
        await logout();
        return response;
      }

      // Clone response to inspect body without consuming original stream
      const contentType = response.headers.get('content-type') || '';
      if (response.ok && contentType.includes('application/json')) {

        const clonedRes = response.clone();
        try {
          const bodyJson = await clonedRes.json();
          // Check if payload matches EncryptedPayload schema { nonce, ciphertext }
          if (bodyJson && typeof bodyJson.nonce === 'string' && typeof bodyJson.ciphertext === 'string') {
            const decryptedBytes = await decryptPayloadClient(
              sessionKey,
              bodyJson.nonce,
              bodyJson.ciphertext
            );

            // Construct synthetic Response with decrypted JSON body
            const decryptedBlob = new Blob([decryptedBytes.buffer as ArrayBuffer], { type: 'application/json' });
            return new Response(decryptedBlob, {
              status: response.status,
              statusText: response.statusText,
              headers: response.headers,
            });

          }
        } catch {
          // If body is not encrypted JSON or parsing fails, return original response
        }
      }

      return response;
    },
    [sessionKey, sessionId, headerName]
  );

  return {
    fetch: encryptedFetch,
  };
}

