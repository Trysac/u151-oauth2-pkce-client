# oauth2-pkce-client

OAuth 2.0 authorization code client with PKCE S256, constant-time state check, bounded token parsing, and thread-safe token renewal over an injected transport.

## The Problem

Hand-rolled OAuth 2.0 clients often introduce critical vulnerabilities by skipping state checks, supporting the insecure 'plain' PKCE method, leaking credentials into logs, or stampeding the token endpoint when multiple threads attempt to refresh an expired token. Existing full-featured frameworks are often heavy, carry significant dependencies, and force a specific HTTP client stack on the user.

## Installation

```bash
pip install oauth2-pkce-client
```

## Usage Example

```python
from oauth2_pkce_client import OAuthConfig, OAuthClient, HttpResponse


class MyTransport:
    def post_form(self, url, form, *, timeout_s):  # Implement your HTTP client
        return HttpResponse(200, b'{"access_token":"t","token_type":"Bearer"}')


cfg = OAuthConfig(
    "app", "https://auth.example/auth", "https://auth.example/token", "http://127.0.0.1:8765/cb"
)
client = OAuthClient(cfg, MyTransport())
req = client.start_authorization()
# After redirect, exchange code for tokens:
tokens = client.complete_authorization(req, f"code=abc&state={req.state}")
```

## Public API Summary

### Classes & Objects
- `OAuthClient`: The primary client interface.
- `OAuthConfig`: Client configuration (immutable).
- `Pkce`: Data class for verifier/challenge pairs.
- `AuthRequest`: Represents an in-flight authorization.
- `TokenSet`: Immutable container for access and refresh tokens.

### Limits & Options
- `refresh_skew_s` (default 60): Time before expiration to trigger refresh.
- `timeout_s` (default 10.0): Network timeout for transport calls.
- `on_event`: Callback for monitoring (`token_request`, `token_refreshed`, `refresh_failed`).
- Strict limits: Callback queries capped at 8 KiB, token endpoint responses capped at 64 KiB.

### Errors
- `OAuthError` (Base), `PkceError`, `AuthorizationError`, `TokenEndpointError`.

## Why not Authlib?

Authlib is a heavy dependency that often forces specific HTTP clients on the user. `oauth2-pkce-client` is a zero-dependency, transport-agnostic library that allows users to inject any HTTP client while enforcing security (PKCE S256, state checks) by default.

## Security

See [docs/SECURITY.md](docs/SECURITY.md) for the threat model and defense limits.