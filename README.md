# Orbit Auth JWT

`orbit-auth-jwt` is a separately installable JWT verification adapter for `orbit-auth`. It implements
the capability's provider-neutral `TokenVerifier` contract using PyJWT; neither Core nor
`orbit-auth` depends on PyJWT.

```bash
pip install orbit-core orbit-auth orbit-auth-jwt
```

This base installation supports HMAC algorithms. For RSA, ECDSA, PSS, or EdDSA verification,
install the optional cryptography dependency:

```bash
pip install 'orbit-auth-jwt[asymmetric]'
```

Configuring one of those algorithm families without the extra fails immediately with an
installation hint instead of looking like an invalid end-user token at request time.

Compose it with `orbit-auth`'s bearer authenticator:

```python
from orbit_auth import BearerAuthenticator
from orbit_auth_jwt import PyJWTVerifier

authenticator = BearerAuthenticator(
    PyJWTVerifier(
        key="load-this-from-a-secret-manager",
        algorithms=("HS256",),
        issuer="https://identity.example",
        audience="my-service",
    ),
    provider="jwt",
)
```

The verifier requires an explicit algorithm allowlist, an expected issuer, and one or more intended
audiences. It rejects `none`, requires subject, token ID, issued-at, and expiry claims, bounds input
and policy metadata, validates scopes, and returns `orbit-auth`'s payload-safe `Token` model. PyJWT
validates the configured issuer, audience, expiry, and not-before claim when present; applications
should issue tokens with a short expiry and only the claims required by their access policy.

Use a separate verifier for each issuer/audience trust policy. A tuple of audiences means every
listed audience is trusted by that verifier, so include only audiences intended for the same
application boundary. One verifier may allow multiple algorithms from the same key family for
controlled key rotation, but it rejects allowlists that mix HMAC (`HS*`) with asymmetric algorithms
to prevent algorithm-confusion configurations. Keep the allowlist narrow.

HMAC verification uses a shared secret that can also mint tokens. Prefer asymmetric signing for
distributed services; give verifiers public keys only and protect signing private keys separately.
Load key material from a secret manager and never commit production keys. This package does not
issue tokens, fetch or refresh JWKS keys, rotate keys, store credentials, or check revocation. Compose
it with an appropriate key-distribution and revocation strategy where those are required. Revocation
and authorization policy are separate concerns from signature verification.

## Documentation

The package-specific guides cover [architecture](docs/architecture/overview.md), [operations and security](docs/operations/README.md), and [development](docs/development/README.md), with [security guidance](docs/security/overview.md). The [documentation index](docs/README.md) links to the full package overview and project policies.

## Development

```bash
python -m pip install -e '.[dev]'
pytest
ruff check .
mypy
```

## Status

This is a **v0.1.0-alpha review candidate**. On CPython 3.11.14, 3.12.14, 3.13.15, and 3.14.7,
all 31 tests, Ruff lint and format checks, strict mypy, dependency audits, and wheel/sdist builds pass
locally. Hosted CI, external key rotation/JWKS behavior, and identity-provider interoperability
remain release gates. The local source is not a published release; its API may change before stable
release.

Licensed under Apache-2.0.

