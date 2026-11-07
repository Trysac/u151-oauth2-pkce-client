# Security Policy & Threat Model

## Threat Model

### Defended
1. **Authorization Code Interception**: PKCE S256 is enforced by design; 'plain' method is not supported.
2. **Login CSRF**: State parameter is required and checked in constant time against the initial request.
3. **Token & Secret Leakage**: `TokenSet`, `OAuthConfig`, and `AuthRequest` mask tokens (`***`) in `__repr__`. Events emitted through `on_event` omit sensitive tokens and codes.
4. **Insecure Endpoints**: Rejects cleartext HTTP for endpoints unless using RFC 8252 loopback addresses (`127.0.0.1`, `::1`, `localhost`).
5. **Denial of Service**: Enforces maximum input sizes: 8 KiB for callback queries, 64 KiB for token responses.

### Not Defended
- **Token Storage**: Security of persistent token storage is the responsibility of the calling application.
- **Redirect Handling**: The application's local HTTP listener is outside this library's scope.
- **OIDC Features**: ID token signature verification and OIDC discovery are not implemented.
- **Advanced Protocols**: RFC 9207 (Issuer identification) and DPoP (Proof-of-possession) are out of scope.