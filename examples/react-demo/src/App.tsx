/**
 * React Demo Application consuming Payload Shield SDK.
 *
 * Demonstrates:
 * 1. Login & session issuance.
 * 2. Automatic ECDH key exchange handshake on mount.
 * 3. Network Tab vs Rendered Component UI side-by-side comparison.
 * 4. Full Logout invalidating keys client-side AND server-side.
 */

import React, { useState } from 'react';
import { PayloadShieldProvider, usePayloadShield, useEncryptedFetch } from '../../../client-sdk/src';

const BASE_URL = 'http://localhost:8000';

function UserProfileView({ onLogout }: { onLogout: () => void }) {
  const { sessionId, isHandshakeDone, handshakeError, logout } = usePayloadShield();
  const { fetch: encryptedFetch } = useEncryptedFetch();

  const [rawNetworkResponse, setRawNetworkResponse] = useState<string | null>(null);
  const [decryptedData, setDecryptedData] = useState<any>(null);
  const [fetchError, setFetchError] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(false);

  const fetchProfile = async () => {
    setIsLoading(true);
    setFetchError(null);
    setRawNetworkResponse(null);
    setDecryptedData(null);

    try {
      // 1. Raw fetch simulating what Network tab sniffer sees
      const rawRes = await fetch(`${BASE_URL}/api/user-profile`, {
        headers: { 'X-Payload-Shield-Session': sessionId || '' },
      });
      const rawJson = await rawRes.json();
      setRawNetworkResponse(JSON.stringify(rawJson, null, 2));

      // 2. Encrypted fetch using SDK auto-decryption wrapper
      const encRes = await encryptedFetch(`${BASE_URL}/api/user-profile`);
      if (encRes.ok) {
        const decryptedJson = await encRes.json();
        setDecryptedData(decryptedJson);
      } else {
        setFetchError(`Request failed with status ${encRes.status}`);
      }
    } catch (err: any) {
      setFetchError(err.message || String(err));
    } finally {
      setIsLoading(false);
    }
  };

  const handleLogoutClick = async () => {
    // Triggers client-side key destruction AND server-side SessionStore invalidation
    await logout();
    onLogout();
  };

  return (
    <div style={{ padding: 20, fontFamily: 'sans-serif', maxWidth: 900, margin: '0 auto' }}>
      <h2>Payload Shield Protected Dashboard</h2>
      <p><strong>Active Session ID:</strong> <code>{sessionId}</code></p>

      {handshakeError && (
        <div style={{ color: 'red', background: '#ffe6e6', padding: 10, borderRadius: 5 }}>
          Handshake Error: {handshakeError.message}
        </div>
      )}

      <div style={{ display: 'flex', gap: 10, margin: '20px 0' }}>
        <button
          onClick={fetchProfile}
          disabled={!isHandshakeDone || isLoading}
          style={{ padding: '10px 20px', background: '#0066cc', color: '#fff', border: 'none', borderRadius: 4, cursor: 'pointer' }}
        >
          {isLoading ? 'Fetching & Decrypting...' : 'Fetch User Profile Data'}
        </button>

        <button
          onClick={handleLogoutClick}
          style={{ padding: '10px 20px', background: '#cc0000', color: '#fff', border: 'none', borderRadius: 4, cursor: 'pointer' }}
        >
          Logout & Invalidate Key (Server + Client)
        </button>
      </div>

      {fetchError && (
        <div style={{ color: 'red', margin: '10px 0' }}>
          Fetch Error: {fetchError}
        </div>
      )}

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 20, marginTop: 20 }}>
        {/* Left Side: What the Network Tab Sees */}
        <div style={{ background: '#1e1e1e', color: '#00ff66', padding: 15, borderRadius: 8 }}>
          <h3 style={{ color: '#fff', marginTop: 0 }}>Network Tab Inspection (Raw JSON)</h3>
          <p style={{ color: '#aaa', fontSize: 13 }}>What casual scrapers or network sniffers see:</p>
          <pre style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-all', fontSize: 12 }}>
            {rawNetworkResponse || '// Click "Fetch User Profile Data" to inspect payload'}
          </pre>
        </div>

        {/* Right Side: Decrypted UI Rendered */}
        <div style={{ background: '#f5f5f5', border: '1px solid #ddd', padding: 15, borderRadius: 8 }}>
          <h3 style={{ marginTop: 0 }}>Rendered UI (Decrypted in React)</h3>
          <p style={{ color: '#666', fontSize: 13 }}>Decrypted in memory just before rendering:</p>
          {decryptedData ? (
            <div>
              <p><strong>Username:</strong> {decryptedData.username}</p>
              <p><strong>Email:</strong> {decryptedData.email}</p>
              <p><strong>Role:</strong> {decryptedData.role}</p>
              <p><strong>Balance:</strong> {decryptedData.sensitive_data?.account_balance}</p>
              <p><strong>Secret Key:</strong> <code>{decryptedData.sensitive_data?.api_key_secret}</code></p>
            </div>
          ) : (
            <p style={{ color: '#999' }}>// No decrypted data loaded yet</p>
          )}
        </div>
      </div>
    </div>
  );
}

export function App() {
  const [sessionId, setSessionId] = useState<string | null>(null);
  const [username, setUsername] = useState<string>('alice_admin');
  const [loginError, setLoginError] = useState<string | null>(null);

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoginError(null);
    try {
      const res = await fetch(`${BASE_URL}/api/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username }),
      });
      if (!res.ok) throw new Error('Login failed');
      const data = await res.json();
      setSessionId(data.session_id);
    } catch (err: any) {
      setLoginError(err.message || 'Login failed');
    }
  };

  if (!sessionId) {
    return (
      <div style={{ padding: 40, fontFamily: 'sans-serif', maxWidth: 400, margin: '100px auto', border: '1px solid #ccc', borderRadius: 8 }}>
        <h2>Payload Shield Demo</h2>
        <p>Step 1: Authenticate to issue a server-side session.</p>
        <form onSubmit={handleLogin}>
          <div style={{ marginBottom: 15 }}>
            <label style={{ display: 'block', marginBottom: 5 }}>Username:</label>
            <input
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              style={{ width: '100%', padding: 8, boxSizing: 'border-box' }}
            />
          </div>
          {loginError && <p style={{ color: 'red' }}>{loginError}</p>}
          <button type="submit" style={{ width: '100%', padding: 10, background: '#0066cc', color: '#fff', border: 'none', borderRadius: 4 }}>
            Log In & Issue Session
          </button>
        </form>
      </div>
    );
  }

  return (
    <PayloadShieldProvider baseUrl={BASE_URL} sessionId={sessionId}>
      <UserProfileView onLogout={() => setSessionId(null)} />
    </PayloadShieldProvider>
  );
}

export default App;

