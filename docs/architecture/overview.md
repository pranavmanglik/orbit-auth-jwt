# Orbit Auth JWT: architecture and boundaries

## Responsibility

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

The verifier requires an explicit algorithm allowlist, expected issuer, and intended audience. It
rejects `none`, requires subject, token ID, issued-at, and expiry claims, bounds input and policy
metadata, validates scopes, and returns `orbit-auth`'s payload-safe `Token` model. PyJWT checks the
configured issuer, audience, expiration, and not-before claim when present. Keep token lifetimes
short and define authorization and revocation policy at the application boundary.

Use separate verifier instances for distinct issuer/audience trust policies. Every value in an
audience tuple is accepted by that verifier; do not combine unrelated services in one tuple. One
verifier may allow multiple algorithms from the same key family for controlled key rotation, but it
rejects allowlists that mix HMAC (`HS*`) with asymmetric algorithms to prevent algorithm-confusion
configurations. Keep the allowlist narrow.

HMAC verification uses a shared secret that can also sign tokens. Prefer asymmetric signing for
distributed services, give verifiers public keys only, and protect signing private keys in a secret
manager. This package does not issue tokens, fetch or refresh JWKS keys, rotate keys, store
credentials, or check revocation. Use a separate key-distribution and revocation strategy where
those capabilities are needed.

## Declared dependencies

The following dependency declarations come from the checked-in manifests. Optional groups and development dependencies are called out separately.

### `pyproject.toml`
- `orbit-auth>=0.1.0a1,<0.2`
- `PyJWT>=2.9,<3`
- Optional `asymmetric` group: `PyJWT[crypto]>=2.9,<3`.
- Optional `dev` group: `pytest>=8,<10`, `pytest-asyncio>=0.24,<2`, `ruff>=0.8,<1`, `mypy>=1.13,<2`, `PyJWT[crypto]>=2.9,<3`.

Declared dependencies do not mean that optional providers or services are bundled with this package.

## Implementation layout

Representative implementation files in this checkout:

- `src/orbit_auth_jwt/__init__.py`
- `src/orbit_auth_jwt/verifier.py`

## Public contract and scope

## Status

This package is a v0.1.0-alpha review candidate. Its local Python 3.11–3.14 test, lint, type,
dependency-audit, and build matrix passes; hosted CI, external key rotation/JWKS behavior, and
identity-provider interoperability remain separate release gates. The API may change before stable
release.

Licensed under Apache-2.0.

## Boundary rules

Keep provider SDKs, credentials, transports, and provider-specific error translation in provider adapters. Keep reusable capability contracts in the matching capability package and lifecycle orchestration in Core. Apply the relevant layer for this repository and preserve the dependency direction shown above.
