# Testing

## Test Suite

The test suite is located in `tests/test_oauth2_pkce_client.py`. It uses `pytest` to cover the public API and all acceptance criteria.

### Coverage
- **RFC 7636 Appendix B**: Verification of SHA-256 octets, challenge generation, and method usage.
- **Input Boundaries**: Tests for 43-128 character verifier lengths, character set restrictions, and oversized callback/response handling.
- **Error Handling**: Validates specific `OAuthErrorCode` raising for state mismatches, authorization denial, missing codes, token errors, and insecure endpoints.
- **Token Logic**: Validates token set parsing, expiry calculation, and refresh logic, including thread safety and single-flight request behavior.
- **Security & Masking**: Ensures no tokens or secrets appear in `__repr__` or event payloads.

## Running Tests

```sh
uv run pytest --cov=oauth2_pkce_client
```