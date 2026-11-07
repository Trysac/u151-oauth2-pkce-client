# Architecture

`trysac-oauth2-pkce-client` is a zero-dependency OAuth 2.0 PKCE client implementing the client side of RFC 6749 and RFC 7636.

## Architecture Overview

```
+-----------------------------------------------------------+
|                    Application Layer                      |
+-----------------------------------------------------------+
       | start_authorization()            | get_access_token()
       v                                  v
+-----------------------------------------------------------+
|                      OAuthClient                          |
|  - PKCE S256 Generation & Validation                      |
|  - Constant-time State Check                              |
|  - Single-flight Thread-safe Token Refresh                |
|  - Masked Credentials in repr()                           |
+-----------------------------------------------------------+
       |                                  |
       v Transport.post_form(...)          v
+-----------------------+      +----------------------------+
| User-Injected Transport|      | TokenSet (immutable)       |
| (e.g. urllib / httpx) |      | access_token, expires_at   |
+-----------------------+      +----------------------------+
```

## Key Design Decisions
- **Injected Transport Protocol**: Decouples network I/O from protocol validation, preventing dependency conflicts.
- **Single-Flight Refresh**: Thread lock with expiration re-checks prevents token endpoint stampedes when concurrent workers see an expired token.
- **Strict Parsing Limits**: Rejects payloads over 64 KiB and callback queries over 8 KiB.
