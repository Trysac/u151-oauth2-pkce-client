# oauth2-pkce-client

[![PyPI version](https://img.shields.io/pypi/v/trysac-oauth2-pkce-client)](https://pypi.org/project/trysac-oauth2-pkce-client/)
[![License: MIT](https://img.shields.io/pypi/l/trysac-oauth2-pkce-client)](LICENSE)
[![CI](https://github.com/Trysac/u151-oauth2-pkce-client/actions/workflows/ci.yml/badge.svg)](https://github.com/Trysac/u151-oauth2-pkce-client/actions/workflows/ci.yml)

OAuth 2.0 authorization code client with PKCE S256, constant-time state check, bounded token parsing and single-refresh token renewal over an injected transport

## Problem

Describe in two or three sentences the concrete problem this utility solves, who hits it, and what
they do today without it. Replace this paragraph when the first real feature lands.

## Install

```sh
pip install trysac-oauth2-pkce-client
# or
uv add trysac-oauth2-pkce-client
```

Requires Python 3.10 or newer. No runtime dependencies.

## Usage

```python
import oauth2_pkce_client

# normalize() trims surrounding whitespace and lower-cases the text.
print(oauth2_pkce_client.normalize("  Hello World "))  # -> "hello world"

# Blank input is rejected explicitly instead of returning an empty string.
try:
    oauth2_pkce_client.normalize("   ")
except ValueError as exc:
    print(f"rejected: {exc}")
```

## Documentation

- [Architecture](docs/ARCHITECTURE.md) and [decisions](docs/decisions/)
- [Testing](docs/TESTING.md) and [security](docs/SECURITY.md)
- [Project record](docs/PROJECT.md) and [stack](docs/STACK.md)
- [Changelog](CHANGELOG.md) and [contributing guide](CONTRIBUTING.md)

## License

[MIT](LICENSE) (c) 2026 Miguel Gomez
