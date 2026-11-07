# Project record

## Objective

Implement a secure, lightweight OAuth 2.0 authorization code client that enforces PKCE S256, performs constant-time state validation, and manages token lifecycle via a single-flight mechanism.

## Scope

- **PKCE S256 Enforcement**: Only allows SHA-256 challenges; refuses 'plain' method.
- **State Validation**: Constant-time comparison using `hmac.compare_digest`.
- **Single-Flight Refresh**: Thread-safe coordination to prevent token stampedes.
- **Injected Transport**: Network I/O is delegated via a simple protocol interface.
- **Security Hardening**: Masked sensitive data in `__repr__`, strict input/output length boundaries.

## Out of Scope

- Persistent token storage at rest.
- Local HTTP redirect listener implementation.
- OIDC ID token signature verification.
- RFC 9207 Issuer identification.
- DPoP (RFC 9449) support.

## Timeline

| Date | Event |
|---|---|
| 2026 | Repository created from factory utility template. |

## Effort metrics

| Metric | Value |
|---|---|
| Tokens (input / output) | 2310656 / 27908 |
| Hours (human) | pending measurement |
| Cost (USD) | 0.4364 |

## Factory run u151 (measured from API usage)

| Phase | Model | Batch | Input | Output | Cache write | Cache read | Cost (USD) |
|---|---|---|---|---|---|---|---|
| generation | gemini-3.8-flash | yes | 5146 | 15027 | 0 | 0 | 0.0301 |
| fix-1 | gemini-3.8-flash | no | 96818 | 8034 | 0 | 831768 | 0.1651 |
| fix-2 | gemini-3.8-flash | no | 36639 | 626 | 0 | 83601 | 0.0361 |
| fix-3 | gemini-3.8-flash | no | 24031 | 979 | 0 | 38394 | 0.0246 |
| fix-4 | gemini-3.8-flash | no | 50974 | 566 | 0 | 230498 | 0.0576 |
| fix-1 | gemini-3.8-flash | no | 21659 | 318 | 0 | 37751 | 0.0203 |
| fix-2 | gemini-3.8-flash | no | 17692 | 333 | 0 | 22510 | 0.0162 |
| audit | gemini-3.1-flash-lite | no | 103840 | 408 | 0 | 533241 | 0.0399 |
| docs | gemini-3.1-flash-lite | no | 176094 | 1617 | 0 | 0 | 0.0464 |

Total: $0.4364. Prices: Anthropic list prices.
