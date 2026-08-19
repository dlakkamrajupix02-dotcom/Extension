/**
 * React Context Provider for Payload Shield SDK.
 *
 * Manages client key generation, handshake with FastAPI backend, key storage strategy,
 * and key destruction on logout.
 *
 * Threat Model & Security Notice:
 * Keys are scoped to active server sessions. Logging out destroys the key client-side and
 * invalidates it server-side.
 */

import React, { createContext, useContext, useEffect, useState, useMemo, useCallback } from 'react';
import { StorageMode, HandshakeRequest, HandshakeResponse } from './types';
import { generateClientKeyPair, deriveSessionCryptoKey } from './crypto';
import { createKeyStorage, KeyStorageStrategy } from './storage';

export interface PayloadShieldContextValue {
  sessionKey: CryptoKey | null;
  sessionId: string | null;
  isHandshakeDone: boolean;
  handshakeError: Error | null;
  performHandshake: (sessionId: string) => Promise<void>;
  logout: () => Promise<void>;
}

const PayloadShieldContext = createContext<PayloadShieldContextValue | null>(null);

export interface PayloadShieldProviderProps {
  baseUrl: string;
  handshakeEndpoint?: string;
  logoutEndpoint?: string;
  storageMode?: StorageMode;
  sessionId?: string | null;
  children: React.ReactNode;
}

export const PayloadShieldProvider: React.FC<PayloadShieldProviderProps> = ({
  baseUrl,
  handshakeEndpoint = '/api/handshake',
  logoutEndpoint = '/api/logout',
  storageMode = 'sessionStorage',
  sessionId: propSessionId = null,
  children,
}) => {
  const [activeSessionId, setActiveSessionId] = useState<string | null>(propSessionId);
  const [sessionKey, setSessionKey] = useState<CryptoKey | null>(null);
  const [isHandshakeDone, setIsHandshakeDone] = useState<boolean>(false);
  const [handshakeError, setHandshakeError] = useState<Error | null>(null);

  const storage: KeyStorageStrategy = useMemo(
    () => createKeyStorage(storageMode),
    [storageMode]
  );

  const fullHandshakeUrl = `${baseUrl.replace(/\/+$/, '')}/${handshakeEndpoint.replace(/^\/+/, '')}`;
  const fullLogoutUrl = `${baseUrl.replace(/\/+$/, '')}/${logoutEndpoint.replace(/^\/+/, '')}`;

  const performHandshake = useCallback(
    async (sessionIdToUse: string) => {
      setIsHandshakeDone(false);
      setHandshakeError(null);
      try {
        // 1. Check if key already exists in storage for this session
        const existingKey = await storage.getKey(sessionIdToUse);
        if (existingKey) {
          setSessionKey(existingKey);
          setActiveSessionId(sessionIdToUse);
          setIsHandshakeDone(true);
          return;
        }

        // 2. Generate client ephemeral X25519 key pair
        const { privateKeyBytes, publicKeyB64 } = generateClientKeyPair();

        // 3. Initiate handshake request with backend
        const handshakeReq: HandshakeRequest = {
          client_public_key: publicKeyB64,
          session_id: sessionIdToUse,
        };

        const res = await fetch(fullHandshakeUrl, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(handshakeReq),
        });

        if (!res.ok) {
          throw new Error(`Handshake failed with status ${res.status}: ${res.statusText}`);
        }

        const data: HandshakeResponse = await res.json();

        // 4. Derive symmetric key bound to session ID
        const derivedKey = await deriveSessionCryptoKey(
          privateKeyBytes,
          data.server_public_key,
          sessionIdToUse
        );

        // 5. Store key using active storage strategy
        await storage.saveKey(sessionIdToUse, derivedKey);

        setSessionKey(derivedKey);
        setActiveSessionId(sessionIdToUse);
        setIsHandshakeDone(true);
      } catch (err: any) {
        const error = err instanceof Error ? err : new Error(String(err));
        setHandshakeError(error);
        setIsHandshakeDone(true);
        throw error;
      }
    },
    [fullHandshakeUrl, storage]
  );

  const logout = useCallback(async () => {
    if (activeSessionId) {
      // 1. Send logout signal to backend to trigger server-side key invalidation in SessionStore
      try {
        await fetch(fullLogoutUrl, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-Payload-Shield-Session': activeSessionId,
          },
          body: JSON.stringify({ session_id: activeSessionId }),
        });
      } catch {
        // Ignore network errors during logout request; proceed to destroy client key locally
      }

      // 2. Delete key from local client storage
      await storage.clearKey(activeSessionId);
    }

    // 3. Reset React Context key state
    setSessionKey(null);
    setActiveSessionId(null);
    setIsHandshakeDone(false);
  }, [activeSessionId, fullLogoutUrl, storage]);


  useEffect(() => {
    if (propSessionId) {
      performHandshake(propSessionId).catch(() => {});
    }
  }, [propSessionId, performHandshake]);

  const value: PayloadShieldContextValue = useMemo(
    () => ({
      sessionKey,
      sessionId: activeSessionId,
      isHandshakeDone,
      handshakeError,
      performHandshake,
      logout,
    }),
    [sessionKey, activeSessionId, isHandshakeDone, handshakeError, performHandshake, logout]
  );

  return (
    <PayloadShieldContext.Provider value={value}>
      {children}
    </PayloadShieldContext.Provider>
  );
};

export function usePayloadShield(): PayloadShieldContextValue {
  const context = useContext(PayloadShieldContext);
  if (!context) {
    throw new Error('usePayloadShield must be used within a <PayloadShieldProvider>.');
  }
  return context;
}

