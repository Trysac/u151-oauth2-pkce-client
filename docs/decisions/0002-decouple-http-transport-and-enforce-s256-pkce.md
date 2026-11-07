# Decouple HTTP Transport and Enforce S256 PKCE

Status: accepted (generated, pending human review)

## Context

OAuth 2.0 clients often embed a specific HTTP client (such as requests or httpx) or make PKCE optional. When multiple threads share a client, concurrent access to an expired token can stampede the token endpoint.

## Decision

Define a minimal Transport protocol for token endpoint POST requests, enforce PKCE S256 exclusively with constant-time state validation, and guard token renewal with a single-flight threading lock.

## Consequences

Users can use any HTTP client library without runtime dependencies. Token stampedes and login CSRF are mitigated, while tokens and secrets are protected against log leakage.
