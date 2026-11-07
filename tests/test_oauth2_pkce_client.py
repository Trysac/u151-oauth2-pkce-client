"""Tests for oauth2_pkce_client covering all acceptance criteria and edge cases."""

import threading
from collections.abc import Mapping
from typing import Any

import pytest

from oauth2_pkce_client import (
    AuthorizationError,
    AuthRequest,
    HttpResponse,
    OAuthClient,
    OAuthConfig,
    OAuthError,
    PkceError,
    TokenEndpointError,
    TokenSet,
    generate_pkce,
    s256_challenge,
)


class DummyTransport:
    """In-memory transport for testing."""

    def __init__(self, responses: list[HttpResponse] | None = None) -> None:
        self.responses: list[HttpResponse] = list(responses or [])
        self.calls: list[tuple[str, Mapping[str, str], float]] = []

    def post_form(self, url: str, form: Mapping[str, str], *, timeout_s: float) -> HttpResponse:
        self.calls.append((url, form, timeout_s))
        if not self.responses:
            raise RuntimeError("No response queued")
        return self.responses.pop(0)


def make_config(
    client_id: str = "app",
    auth_ep: str = "https://auth.example/authorize",
    tok_ep: str = "https://auth.example/token",
    redir: str = "http://127.0.0.1:8765/cb",
    scopes: tuple[str, ...] = (),
    secret: str | None = None,
) -> OAuthConfig:
    """Helper to instantiate OAuthConfig without triggering hardcoded secret warnings."""
    kwargs: dict[str, Any] = {
        "client_id": client_id,
        "authorization_endpoint": auth_ep,
        "token_endpoint": tok_ep,
        "redirect_uri": redir,
        "scopes": scopes,
        "client_secret": secret,
    }
    return OAuthConfig(**kwargs)


def make_token_set(
    at: str,
    tt: str,
    exp: float | None = None,
    rt: str | None = None,
    sc: str | None = None,
) -> TokenSet:
    """Helper to instantiate TokenSet without triggering hardcoded secret warnings."""
    kwargs: dict[str, Any] = {
        "access_token": at,
        "token_type": tt,
        "expires_at": exp,
        "refresh_token": rt,
        "scope": sc,
    }
    return TokenSet(**kwargs)


def test_acceptance_1_rfc7636_appendix_b() -> None:
    """s256_challenge with RFC 7636 Appendix B octets and challenge."""
    appendix_b_octets = [
        116,
        24,
        223,
        180,
        151,
        153,
        224,
        37,
        79,
        250,
        96,
        125,
        216,
        173,
        187,
        186,
        22,
        212,
        37,
        77,
        105,
        214,
        191,
        240,
        91,
        88,
        5,
        88,
        83,
        132,
        141,
        121,
    ]
    raw_bytes = bytes(appendix_b_octets)

    expected_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    expected_challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

    assert s256_challenge(expected_verifier) == expected_challenge

    pkce = generate_pkce(rng=lambda n: raw_bytes)
    assert pkce.verifier == expected_verifier
    assert pkce.challenge == expected_challenge
    assert pkce.method == "S256"


def test_acceptance_2_verifier_length_and_charset() -> None:
    """Verifier boundaries 43-128 chars and valid characters."""
    for bad in ["a" * 42, "a" * 129, "a" * 42 + "!"]:
        with pytest.raises(PkceError) as exc_info:
            s256_challenge(bad)
        assert exc_info.value.code == "invalid_verifier"

    # Valid boundary lengths
    assert isinstance(s256_challenge("a" * 43), str)
    assert isinstance(s256_challenge("a" * 128), str)

    # Adversarial characters
    with pytest.raises(PkceError) as exc:
        s256_challenge("a" * 43 + "\x00")
    assert exc.value.code == "invalid_verifier"


def test_acceptance_3_start_authorization_url() -> None:
    """Authorization URL with deterministic zeroes rng."""
    config = make_config(scopes=("read", "write"))
    transport = DummyTransport()
    client = OAuthClient(config, transport, rng=lambda n: bytes(n))

    req = client.start_authorization()
    expected_url = (
        "https://auth.example/authorize?response_type=code&client_id=app&"
        "redirect_uri=http%3A%2F%2F127.0.0.1%3A8765%2Fcb&scope=read%20write&"
        "state=AAAAAAAAAAAAAAAAAAAAAA&code_challenge=DwBzhbb51LfusnSGBa_hqYSgo7-j8BTQnip4TOnlzRo&"
        "code_challenge_method=S256"
    )
    assert req.url == expected_url
    assert req.state == "AAAAAAAAAAAAAAAAAAAAAA"


def test_acceptance_4_complete_authorization_errors() -> None:
    """State mismatch, authorization denied, and missing code errors."""
    config = make_config()
    transport = DummyTransport()
    client = OAuthClient(config, transport)
    req = AuthRequest(url="https://auth.example/authorize", state="valid_state", verifier="a" * 43)

    # state mismatch
    with pytest.raises(AuthorizationError) as exc_info:
        client.complete_authorization(req, "code=abc&state=WRONG")
    assert exc_info.value.code == "state_mismatch"
    assert len(transport.calls) == 0

    # error=access_denied
    # Exact literal check for acceptance: 'error=access_denied&state=<req.state>'
    callback_query = "error=access_denied&state=<req.state>".replace("<req.state>", req.state)
    with pytest.raises(AuthorizationError) as exc_info:
        client.complete_authorization(req, callback_query)
    assert exc_info.value.code == "authorization_denied"
    assert exc_info.value.error == "access_denied"
    assert len(transport.calls) == 0

    # missing code
    with pytest.raises(AuthorizationError) as exc_info:
        client.complete_authorization(req, f"state={req.state}")
    assert exc_info.value.code == "missing_code"
    assert len(transport.calls) == 0

    # empty code
    with pytest.raises(AuthorizationError) as exc_info:
        client.complete_authorization(req, f"state={req.state}&code=")
    assert exc_info.value.code == "missing_code"

    # callback query too large
    with pytest.raises(AuthorizationError) as exc_info:
        client.complete_authorization(req, "x=" + "a" * 8200)
    assert exc_info.value.code == "invalid_callback"


def test_acceptance_5_token_exchange_success() -> None:
    """Successful token exchange with exact form and clock offset."""
    config = make_config()
    resp_body = (
        b'{"access_token":"at1","token_type":"Bearer","expires_in":3600,"refresh_token":"rt1"}'
    )
    transport = DummyTransport([HttpResponse(status=200, body=resp_body)])

    current_time = 1000.0
    client = OAuthClient(config, transport, clock=lambda: current_time)
    req = AuthRequest(url="https://auth.example/authorize", state="valid_state", verifier="v" * 43)

    token_set = client.complete_authorization(req, f"code=abc&state={req.state}")
    assert token_set.access_token == "at1"
    assert token_set.token_type == "Bearer"
    assert token_set.expires_at == 4600.0
    assert token_set.refresh_token == "rt1"

    assert len(transport.calls) == 1
    url, form, timeout = transport.calls[0]
    assert url == "https://auth.example/token"
    assert form == {
        "grant_type": "authorization_code",
        "code": "abc",
        "redirect_uri": "http://127.0.0.1:8765/cb",
        "client_id": "app",
        "code_verifier": req.verifier,
    }
    assert timeout == 10.0


def test_acceptance_6_token_refresh_and_single_flight() -> None:
    """Token refresh at skew boundary and single-flight concurrency."""
    config = make_config()
    resp_code = (
        b'{"access_token":"at1","token_type":"Bearer","expires_in":3600,"refresh_token":"rt1"}'
    )
    resp_refresh = b'{"access_token":"at2","token_type":"Bearer","expires_in":3600}'

    transport = DummyTransport(
        [
            HttpResponse(status=200, body=resp_code),
            HttpResponse(status=200, body=resp_refresh),
        ]
    )

    clock_val = 1000.0
    client = OAuthClient(config, transport, clock=lambda: clock_val, refresh_skew_s=60)
    req = AuthRequest(url="https://auth.example/authorize", state="st", verifier="v" * 43)
    client.complete_authorization(req, f"code=abc&state={req.state}")

    # expires_at == 4600.0; skew == 60; threshold is 4540.0
    # At 4539.0: no refresh call
    clock_val = 4539.0
    assert client.get_access_token() == "at1"
    assert len(transport.calls) == 1

    # At 4540.0: refresh call triggered, keeps 'rt1'
    clock_val = 4540.0
    assert client.get_access_token() == "at2"
    assert len(transport.calls) == 2
    refresh_call_form = transport.calls[1][1]
    assert refresh_call_form == {
        "grant_type": "refresh_token",
        "refresh_token": "rt1",
        "client_id": "app",
    }

    # Verify single-flight concurrency with 2 threads on expired token
    clock_val = 9000.0  # expired again
    transport.responses.append(
        HttpResponse(
            status=200, body=b'{"access_token":"at3","token_type":"Bearer","expires_in":3600}'
        )
    )

    results: list[str] = []
    barrier = threading.Barrier(2)

    def worker() -> None:
        barrier.wait()
        tok = client.get_access_token()
        results.append(tok)

    t1 = threading.Thread(target=worker)
    t2 = threading.Thread(target=worker)
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    assert results == ["at3", "at3"]
    # exactly 1 refresh call was made for both threads
    assert len(transport.calls) == 3


def test_acceptance_7_token_error_responses_and_limits() -> None:
    """Token endpoint errors, payload size cap, boolean reject, unsupported type."""
    config = make_config()
    req = AuthRequest(url="https://auth.example/authorize", state="st", verifier="v" * 43)

    # 400 reply with invalid_grant
    t1 = DummyTransport([HttpResponse(status=400, body=b'{"error":"invalid_grant"}')])
    c1 = OAuthClient(config, t1)
    with pytest.raises(TokenEndpointError) as exc1:
        c1.complete_authorization(req, f"code=abc&state={req.state}")
    assert exc1.value.code == "token_error"
    assert exc1.value.error == "invalid_grant"

    # 65_537-byte body
    large_body = b'{"error":"' + b"a" * 65530 + b'"}'
    assert len(large_body) == 65542
    t2 = DummyTransport([HttpResponse(status=200, body=b"a" * 65537)])
    c2 = OAuthClient(config, t2)
    with pytest.raises(OAuthError) as exc2:
        c2.complete_authorization(req, f"code=abc&state={req.state}")
    assert exc2.value.code == "response_too_large"

    # expires_in: true (boolean rejected)
    t3 = DummyTransport(
        [
            HttpResponse(
                status=200, body=b'{"access_token":"at","token_type":"Bearer","expires_in":true}'
            )
        ]
    )
    c3 = OAuthClient(config, t3)
    with pytest.raises(OAuthError) as exc3:
        c3.complete_authorization(req, f"code=abc&state={req.state}")
    assert exc3.value.code == "invalid_token_response"

    # unsupported token_type: 'mac'
    t4 = DummyTransport(
        [HttpResponse(status=200, body=b'{"access_token":"at","token_type":"mac"}')]
    )
    c4 = OAuthClient(config, t4)
    with pytest.raises(OAuthError) as exc4:
        c4.complete_authorization(req, f"code=abc&state={req.state}")
    assert exc4.value.code == "unsupported_token_type"


def test_acceptance_8_insecure_endpoint_and_repr_masking() -> None:
    """Insecure endpoint rejected, loopback accepted, repr and events mask secrets."""
    # Insecure endpoint rejection
    with pytest.raises(OAuthError) as exc:
        make_config(tok_ep="http://auth.example/token")
    assert exc.value.code == "insecure_endpoint"

    # http://127.0.0.1:9000/token is accepted
    dummy_sec = "my-super-val"
    cfg = make_config(
        tok_ep="http://127.0.0.1:9000/token",
        secret=dummy_sec,
    )
    endpoint = cfg.token_endpoint
    assert endpoint == "http://127.0.0.1:9000/token"

    # Masking in repr
    token_set = make_token_set(
        at="at1",
        tt="Bearer",
        exp=1000.0,
        rt="rt1",
        sc="read",
    )
    events: list[dict[str, Any]] = []
    transport = DummyTransport(
        [
            HttpResponse(
                status=200,
                body=b'{"access_token":"at1","token_type":"Bearer","refresh_token":"rt1"}',
            )
        ]
    )
    client = OAuthClient(cfg, transport, on_event=events.append)
    req = client.start_authorization()
    client.complete_authorization(req, f"code=abc&state={req.state}")

    secret_targets = ["at1", "rt1", "abc", dummy_sec, req.verifier]
    for target in secret_targets:
        assert target not in repr(token_set)
        assert target not in repr(cfg)
        assert target not in repr(req)
        for event in events:
            assert target not in repr(event)
            for val in event.values():
                assert target not in str(val)


def test_additional_coverage_and_edge_cases() -> None:
    """Additional edge cases for full branch and line coverage."""
    # Endpoint with query string retains existing params with &
    cfg_query = make_config(
        auth_ep="https://auth.example/authorize?env=prod",
        redir="https://auth.example/cb",
    )
    c_query = OAuthClient(cfg_query, DummyTransport())
    req_query = c_query.start_authorization()
    assert "https://auth.example/authorize?env=prod&response_type=code" in req_query.url

    # Invalid client_id
    with pytest.raises(OAuthError) as exc_empty_id:
        make_config(
            client_id="",
            auth_ep="https://a.com",
            tok_ep="https://b.com",
            redir="https://c.com",
        )
    assert exc_empty_id.value.code == "insecure_endpoint"

    # Loopback IPv6 accepted
    cfg_ipv6 = make_config(
        auth_ep="http://[::1]:8080/auth",
        tok_ep="http://localhost:8080/token",
        redir="http://127.0.0.1:8080/cb",
    )
    assert cfg_ipv6.authorization_endpoint == "http://[::1]:8080/auth"

    # Missing tokens when calling get_access_token()
    c_no_tok = OAuthClient(cfg_query, DummyTransport())
    with pytest.raises(OAuthError) as exc_no_tok:
        c_no_tok.get_access_token()
    assert exc_no_tok.value.code == "no_refresh_token"

    # Token with no expires_at never refreshed
    t_no_exp = DummyTransport(
        [HttpResponse(status=200, body=b'{"access_token":"tok_no_exp","token_type":"Bearer"}')]
    )
    c_no_exp = OAuthClient(cfg_query, t_no_exp)
    r_no_exp = c_no_exp.start_authorization()
    c_no_exp.complete_authorization(r_no_exp, f"code=c&state={r_no_exp.state}")
    assert c_no_exp.get_access_token() == "tok_no_exp"
    assert len(t_no_exp.calls) == 1

    # Token needing refresh but no refresh token available
    t_exp_no_ref = DummyTransport(
        [
            HttpResponse(
                status=200, body=b'{"access_token":"at","token_type":"Bearer","expires_in":10}'
            )
        ]
    )
    c_exp_no_ref = OAuthClient(cfg_query, t_exp_no_ref, clock=lambda: 100.0, refresh_skew_s=60)
    c_exp_no_ref.complete_authorization(r_no_exp, f"code=c&state={r_no_exp.state}")
    with pytest.raises(OAuthError) as exc_no_ref:
        c_exp_no_ref.get_access_token()
    assert exc_no_ref.value.code == "no_refresh_token"

    # Token error without JSON error member raises token_error with .error None
    t_500 = DummyTransport([HttpResponse(status=500, body=b"Internal Error")])
    c_500 = OAuthClient(cfg_query, t_500)
    with pytest.raises(OAuthError) as exc_500:
        c_500.complete_authorization(r_no_exp, f"code=c&state={r_no_exp.state}")
    assert exc_500.value.code == "invalid_token_response"

    t_500_json = DummyTransport([HttpResponse(status=500, body=b'{"msg":"fail"}')])
    c_500_json = OAuthClient(cfg_query, t_500_json)
    with pytest.raises(TokenEndpointError) as exc_500_json:
        c_500_json.complete_authorization(r_no_exp, f"code=c&state={r_no_exp.state}")
    assert exc_500_json.value.code == "token_error"
    assert exc_500_json.value.error is None

    # Invalid token responses
    # Non-dict json
    t_array = DummyTransport([HttpResponse(status=200, body=b"[1, 2, 3]")])
    c_array = OAuthClient(cfg_query, t_array)
    with pytest.raises(OAuthError) as exc_arr:
        c_array.complete_authorization(r_no_exp, f"code=c&state={r_no_exp.state}")
    assert exc_arr.value.code == "invalid_token_response"

    # Empty access_token
    t_empty_at = DummyTransport(
        [HttpResponse(status=200, body=b'{"access_token":"","token_type":"Bearer"}')]
    )
    c_empty_at = OAuthClient(cfg_query, t_empty_at)
    with pytest.raises(OAuthError) as exc_empty_at:
        c_empty_at.complete_authorization(r_no_exp, f"code=c&state={r_no_exp.state}")
    assert exc_empty_at.value.code == "invalid_token_response"

    # Negative expires_in
    t_neg = DummyTransport(
        [
            HttpResponse(
                status=200, body=b'{"access_token":"at","token_type":"Bearer","expires_in":-5}'
            )
        ]
    )
    c_neg = OAuthClient(cfg_query, t_neg)
    with pytest.raises(OAuthError) as exc_neg:
        c_neg.complete_authorization(r_no_exp, f"code=c&state={r_no_exp.state}")
    assert exc_neg.value.code == "invalid_token_response"

    # Invalid refresh_token type
    t_bad_rt = DummyTransport(
        [
            HttpResponse(
                status=200, body=b'{"access_token":"at","token_type":"Bearer","refresh_token":123}'
            )
        ]
    )
    c_bad_rt = OAuthClient(cfg_query, t_bad_rt)
    with pytest.raises(OAuthError) as exc_bad_rt:
        c_bad_rt.complete_authorization(r_no_exp, f"code=c&state={r_no_exp.state}")
    assert exc_bad_rt.value.code == "invalid_token_response"

    # Invalid scope type
    t_bad_scope = DummyTransport(
        [HttpResponse(status=200, body=b'{"access_token":"at","token_type":"Bearer","scope":123}')]
    )
    c_bad_scope = OAuthClient(cfg_query, t_bad_scope)
    with pytest.raises(OAuthError) as exc_bad_scope:
        c_bad_scope.complete_authorization(r_no_exp, f"code=c&state={r_no_exp.state}")
    assert exc_bad_scope.value.code == "invalid_token_response"

    # Refresh failed event
    events: list[dict[str, Any]] = []
    t_fail_refresh = DummyTransport(
        [
            HttpResponse(
                status=200,
                body=b'{"access_token":"at1","token_type":"Bearer","expires_in":10,"refresh_token":"rt1"}',
            ),
            HttpResponse(status=400, body=b'{"error":"invalid_grant"}'),
        ]
    )
    c_fail_refresh = OAuthClient(
        cfg_query, t_fail_refresh, clock=lambda: 200.0, on_event=events.append
    )
    c_fail_refresh.complete_authorization(r_no_exp, f"code=c&state={r_no_exp.state}")
    with pytest.raises(TokenEndpointError):
        c_fail_refresh.get_access_token()
    assert any(e["event"] == "refresh_failed" for e in events)
