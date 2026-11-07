"""OAuth 2.0 authorization code client with PKCE S256.

RFC 6749 and RFC 7636 compliant client with strict input boundaries, safe representations
(no token leakage), constant-time state verification, loopback HTTP support (RFC 8252),
and thread-safe single-flight token refresh.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import re
import secrets
import threading
import time
import urllib.parse
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, Literal, Protocol, runtime_checkable

__all__ = [
    "AuthRequest",
    "AuthorizationError",
    "HttpResponse",
    "OAuthClient",
    "OAuthConfig",
    "OAuthError",
    "OAuthErrorCode",
    "Pkce",
    "PkceError",
    "TokenEndpointError",
    "TokenSet",
    "Transport",
    "__version__",
    "generate_pkce",
    "s256_challenge",
]

__version__ = "0.1.0"

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

OAuthErrorCode = Literal[
    "invalid_verifier",
    "insecure_endpoint",
    "invalid_callback",
    "authorization_denied",
    "state_mismatch",
    "missing_code",
    "token_error",
    "invalid_token_response",
    "unsupported_token_type",
    "response_too_large",
    "no_refresh_token",
]

MAX_CALLBACK_QUERY_BYTES = 8192
MAX_RESPONSE_BYTES = 65536
MAX_MESSAGE_INPUT_LEN = 200
_VERIFIER_PATTERN = re.compile(r"^[A-Za-z0-9._~-]{43,128}$")
_ALLOWED_LOOPBACK_HOSTS = {"127.0.0.1", "::1", "[::1]", "localhost"}


def _truncate_msg(val: str) -> str:
    if len(val) <= MAX_MESSAGE_INPUT_LEN:
        return val
    return val[:MAX_MESSAGE_INPUT_LEN] + "..."


def _base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


class OAuthError(Exception):
    """Base error for all OAuth client operations."""

    def __init__(self, code: OAuthErrorCode, message: str = "") -> None:
        super().__init__(message or code)
        self.code: OAuthErrorCode = code


class PkceError(OAuthError):
    """Raised when PKCE generation or verification fails."""


class AuthorizationError(OAuthError):
    """Raised during callback handling and authorization validation."""

    def __init__(self, code: OAuthErrorCode, message: str = "", error: str | None = None) -> None:
        super().__init__(code, message)
        self.error: str | None = error


class TokenEndpointError(OAuthError):
    """Raised when token endpoint exchanges fail."""

    def __init__(self, code: OAuthErrorCode, message: str = "", error: str | None = None) -> None:
        super().__init__(code, message)
        self.error: str | None = error


@dataclass(frozen=True)
class Pkce:
    """PKCE verifier and code challenge pair."""

    verifier: str
    challenge: str
    method: str = "S256"


def s256_challenge(verifier: str) -> str:
    """Compute the RFC 7636 S256 code challenge for a given code verifier."""
    if not isinstance(verifier, str) or not _VERIFIER_PATTERN.fullmatch(verifier):
        raise PkceError("invalid_verifier", "Code verifier must be 43-128 unreserved characters")
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return _base64url_encode(digest)


def generate_pkce(rng: Callable[[int], bytes] = secrets.token_bytes) -> Pkce:
    """Generate a PKCE verifier and SHA-256 challenge using 32 random bytes."""
    raw = rng(32)
    verifier = _base64url_encode(raw)
    challenge = s256_challenge(verifier)
    return Pkce(verifier=verifier, challenge=challenge, method="S256")


def _validate_endpoint(url: str) -> None:
    parsed = urllib.parse.urlsplit(url)
    scheme = parsed.scheme.lower()
    host = (parsed.hostname or "").lower()
    if scheme == "https":
        return
    if scheme == "http" and host in _ALLOWED_LOOPBACK_HOSTS:
        return
    raise OAuthError("insecure_endpoint", f"Insecure endpoint URL: {_truncate_msg(url)}")


@dataclass(frozen=True)
class OAuthConfig:
    """OAuth 2.0 client configuration with endpoint validation and masked secret repr."""

    client_id: str
    authorization_endpoint: str
    token_endpoint: str
    redirect_uri: str
    scopes: tuple[str, ...] = ()
    client_secret: str | None = None

    def __post_init__(self) -> None:
        if not self.client_id:
            raise OAuthError("insecure_endpoint", "client_id must not be empty")
        _validate_endpoint(self.authorization_endpoint)
        _validate_endpoint(self.token_endpoint)
        _validate_endpoint(self.redirect_uri)
        if isinstance(self.scopes, list):
            object.__setattr__(self, "scopes", tuple(self.scopes))

    def __repr__(self) -> str:
        secret_repr = "'***'" if self.client_secret is not None else "None"
        return (
            f"OAuthConfig(client_id={self.client_id!r}, "
            f"authorization_endpoint={self.authorization_endpoint!r}, "
            f"token_endpoint={self.token_endpoint!r}, "
            f"redirect_uri={self.redirect_uri!r}, "
            f"scopes={self.scopes!r}, client_secret={secret_repr})"
        )


@dataclass(frozen=True)
class AuthRequest:
    """In-flight authorization request details."""

    url: str
    state: str
    verifier: str

    def __repr__(self) -> str:
        return f"AuthRequest(url={self.url!r}, state={self.state!r}, verifier='***')"


@dataclass(frozen=True)
class TokenSet:
    """OAuth 2.0 token set with masked token repr."""

    access_token: str
    token_type: str
    expires_at: float | None
    refresh_token: str | None
    scope: str | None

    def __repr__(self) -> str:
        ref_masked = "'***'" if self.refresh_token is not None else "None"
        return (
            f"TokenSet(access_token='***', token_type={self.token_type!r}, "
            f"expires_at={self.expires_at!r}, refresh_token={ref_masked}, "
            f"scope={self.scope!r})"
        )


@dataclass(frozen=True)
class HttpResponse:
    """HTTP response returned by the Transport."""

    status: int
    body: bytes


@runtime_checkable
class Transport(Protocol):
    """HTTP transport protocol for token endpoint requests."""

    def post_form(self, url: str, form: Mapping[str, str], *, timeout_s: float) -> HttpResponse:
        """Send an application/x-www-form-urlencoded POST request."""
        ...


class OAuthClient:
    """OAuth 2.0 client supporting PKCE authorization code grant and automatic refresh."""

    def __init__(
        self,
        config: OAuthConfig,
        transport: Transport,
        *,
        clock: Callable[[], float] = time.time,
        rng: Callable[[int], bytes] = secrets.token_bytes,
        refresh_skew_s: int = 60,
        timeout_s: float = 10.0,
        on_event: Callable[[dict[str, Any]], None] | None = None,
    ) -> None:
        self._config = config
        self._transport = transport
        self._clock = clock
        self._rng = rng
        self._refresh_skew_s = refresh_skew_s
        self._timeout_s = timeout_s
        self._on_event = on_event
        self._lock = threading.Lock()
        self._tokens: TokenSet | None = None

    def _emit_event(self, event: str, grant_type: str, status: int | None) -> None:
        if self._on_event is not None:
            self._on_event({"event": event, "grant_type": grant_type, "status": status})

    def start_authorization(self) -> AuthRequest:
        """Generate the PKCE authorization URL and state."""
        pkce = generate_pkce(self._rng)
        raw_state = self._rng(16)
        state = _base64url_encode(raw_state)

        params: list[tuple[str, str]] = [
            ("response_type", "code"),
            ("client_id", self._config.client_id),
            ("redirect_uri", self._config.redirect_uri),
        ]
        if self._config.scopes:
            params.append(("scope", " ".join(self._config.scopes)))
        params.extend(
            [
                ("state", state),
                ("code_challenge", pkce.challenge),
                ("code_challenge_method", "S256"),
            ]
        )

        query_string = urllib.parse.urlencode(params, quote_via=urllib.parse.quote, safe="")
        separator = "&" if "?" in self._config.authorization_endpoint else "?"
        auth_url = f"{self._config.authorization_endpoint}{separator}{query_string}"
        return AuthRequest(url=auth_url, state=state, verifier=pkce.verifier)

    def complete_authorization(self, request: AuthRequest, callback_query: str) -> TokenSet:
        """Parse callback query parameters, verify state, and exchange code for tokens."""
        if len(callback_query.encode("utf-8")) > MAX_CALLBACK_QUERY_BYTES:
            raise AuthorizationError("invalid_callback", "Callback query exceeds maximum size")

        cleaned_query = callback_query.lstrip("?")
        parsed = urllib.parse.parse_qs(cleaned_query, keep_blank_values=True)

        if "error" in parsed:
            err_vals = parsed["error"]
            err_code = err_vals[0] if err_vals else "unknown"
            raise AuthorizationError(
                "authorization_denied", f"Authorization failed: {err_code}", error=err_code
            )

        cb_state = parsed.get("state", [""])[0]
        if not hmac.compare_digest(cb_state, request.state):
            raise AuthorizationError("state_mismatch", "State parameter mismatch")

        code_vals = parsed.get("code")
        if not code_vals or not code_vals[0]:
            raise AuthorizationError("missing_code", "Authorization code missing in callback")
        code = code_vals[0]

        form: dict[str, str] = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self._config.redirect_uri,
            "client_id": self._config.client_id,
            "code_verifier": request.verifier,
        }
        if self._config.client_secret is not None:
            form["client_secret"] = self._config.client_secret

        token_set = self._exchange_token(form, "authorization_code")
        with self._lock:
            self._tokens = token_set
        return token_set

    def _parse_token_response(
        self, resp: HttpResponse, fallback_refresh_token: str | None = None
    ) -> TokenSet:
        if len(resp.body) > MAX_RESPONSE_BYTES:
            raise OAuthError("response_too_large", "Token response exceeded maximum size limit")

        try:
            payload = json.loads(resp.body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise OAuthError("invalid_token_response", "Token response is not valid JSON") from exc

        if not isinstance(payload, dict):
            raise OAuthError("invalid_token_response", "Token response must be a JSON object")

        if resp.status in (400, 401):
            err_val = payload.get("error")
            err_str = str(err_val) if err_val is not None else None
            raise TokenEndpointError(
                "token_error",
                f"Token endpoint returned error: {err_str or resp.status}",
                error=err_str,
            )
        if resp.status != 200:
            raise TokenEndpointError(
                "token_error",
                f"Token endpoint returned status {resp.status}",
                error=None,
            )

        access_token = payload.get("access_token")
        if not isinstance(access_token, str) or not access_token:
            raise OAuthError("invalid_token_response", "access_token missing or empty")

        token_type = payload.get("token_type")
        if not isinstance(token_type, str) or token_type.lower() != "bearer":
            raise OAuthError("unsupported_token_type", "Unsupported token type")

        expires_at: float | None = None
        if "expires_in" in payload:
            expires_in = payload["expires_in"]
            if isinstance(expires_in, bool) or not isinstance(expires_in, int) or expires_in < 0:
                raise OAuthError(
                    "invalid_token_response", "expires_in must be a non-negative integer"
                )
            expires_at = self._clock() + float(expires_in)

        refresh_token = payload.get("refresh_token")
        if refresh_token is not None:
            if not isinstance(refresh_token, str) or not refresh_token:
                raise OAuthError(
                    "invalid_token_response", "refresh_token must be a non-empty string"
                )
        else:
            refresh_token = fallback_refresh_token

        scope = payload.get("scope")
        if scope is not None and not isinstance(scope, str):
            raise OAuthError("invalid_token_response", "scope must be a string")

        return TokenSet(
            access_token=access_token,
            token_type=token_type,
            expires_at=expires_at,
            refresh_token=refresh_token,
            scope=scope,
        )

    def _exchange_token(
        self, form: dict[str, str], grant_type: str, fallback_refresh: str | None = None
    ) -> TokenSet:
        self._emit_event("token_request", grant_type, None)
        resp = self._transport.post_form(
            self._config.token_endpoint, form, timeout_s=self._timeout_s
        )
        try:
            token_set = self._parse_token_response(resp, fallback_refresh_token=fallback_refresh)
        except Exception:
            if grant_type == "refresh_token":
                self._emit_event("refresh_failed", grant_type, resp.status)
            raise

        if grant_type == "refresh_token":
            self._emit_event("token_refreshed", grant_type, resp.status)
        return token_set

    def get_access_token(self) -> str:
        """Return a valid access token, refreshing it if expired or nearing expiry."""
        with self._lock:
            if self._tokens is None:
                raise OAuthError("no_refresh_token", "No tokens present")
            if self._tokens.expires_at is None:
                return self._tokens.access_token
            if self._clock() < (self._tokens.expires_at - self._refresh_skew_s):
                return self._tokens.access_token

            # Token is expired or nearing expiry; refresh under lock
            refresh_tok = self._tokens.refresh_token
            if not refresh_tok:
                raise OAuthError("no_refresh_token", "Cannot refresh: no refresh_token")

            form: dict[str, str] = {
                "grant_type": "refresh_token",
                "refresh_token": refresh_tok,
                "client_id": self._config.client_id,
            }
            if self._config.client_secret is not None:
                form["client_secret"] = self._config.client_secret

            new_tokens = self._exchange_token(form, "refresh_token", fallback_refresh=refresh_tok)
            self._tokens = new_tokens
            return new_tokens.access_token
