# Payload Shield: Technical Threat Model & Security Policy

## 1. Executive Summary

Payload Shield provides application-layer HTTP payload encryption for FastAPI and React applications. Its explicit primary objective is to **raise the cost of casual web scraping, unauthenticated bot scraping, and passive network log harvesting** over TLS connections.

It is **NOT** a silver bullet or an "unbreakable" DRM solution. End users with authenticated browser access, local DevTools privilege, or in-page code execution capabilities can ultimately access unencrypted data.

---

## 2. In-Scope Security Protections (What Payload Shield DOES Protect Against)

1. **Casual Network Inspection**:
   - Prevents non-technical users or automated proxy dumpers from copying structured JSON data directly from browser Network tabs or HTTP proxy logs.
2. **Naive Automated API Bots**:
   - Blocks automated scripts (e.g. `curl`, `requests`, simple Python scrapers) that attempt to invoke API endpoints directly without completing the ECDH handshake or executing JavaScript.
3. **Passive Network-Log Harvesting**:
   - Obscures response payload bodies captured in intermediary proxy logs, CDN debug dumps, or server access logs.
4. **Competitor Data Scraping**:
   - Deters low-effort automated data harvesters that do not perform full browser emulation or reverse-engineer the client cryptographic handshake.

---

## 3. Out-of-Scope Security Risks (What Payload Shield DOES NOT Protect Against)

1. **Authenticated DevTools User**:
   - An authenticated end user with browser console access can inspect memory variables, view the derived AES key, or inspect the DOM tree after React renders the decrypted data.
2. **Cross-Site Scripting (XSS)**:
   - If an attacker achieves arbitrary JavaScript execution in the client origin context, they can hook into `window.crypto.subtle`, inspect storage keys, or intercept `fetch` calls.
3. **Motivated Reverse Engineers**:
   - An attacker can inspect bundled JavaScript, reverse-engineer the X25519 ECDH handshake and HKDF parameters, and construct a custom client script to perform handshakes.

---

## 4. Cryptographic Primitives & Guarantees

- **Key Agreement**: X25519 ECDH (`cryptography` in Python, `@noble/curves/ed25519` in TypeScript).
- **Key Derivation**: HKDF-SHA256 with 32 zero-bytes salt (RFC 5869) and session-bound `info` (`payload-shield-v1:<session_id>`).
- **Symmetric Encryption**: AES-256-GCM with fresh cryptographically secure 12-byte random nonces generated per encryption call.
- **Session Revocation**: Server-side invalidation via `SessionStore.invalidate(session_id)` immediately revokes payload decryption capability on logout.

---

## 5. Transport Layer Security Requirement

Payload Shield **MUST** be deployed on top of HTTPS/TLS. It relies on secure contexts in modern browsers to access WebCrypto (`crypto.subtle`). It serves as an additional layer of payload obscurity on top of TLS, not a replacement.
