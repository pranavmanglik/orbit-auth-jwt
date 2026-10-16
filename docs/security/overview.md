# Orbit Auth JWT: security

## Verification policy

`PyJWTVerifier` requires a fixed expected issuer and audience when it is constructed. Configure
one verifier per trust boundary and allow only the algorithms and audiences actually issued for
that service. The verifier requires `sub`, `jti`, `iat`, and `exp`; PyJWT checks the configured
issuer, audience, expiry, and `nbf` when provided. The optional leeway is bounded to one day; keep
production clock leeway small and synchronize host clocks.

Signature verification does not establish authorization, session state, or revocation status. A
valid token still needs application policy for scopes/roles, tenant access, token type, and revoked
credentials. Use short-lived access tokens and do not treat a scope claim as sufficient for
resource-level authorization without checking the requested resource.

## Signing keys

HMAC verifiers hold the same secret used by issuers to sign tokens. Any service with that secret can
mint credentials. For service-to-service verification, prefer asymmetric algorithms and distribute
only public keys to verifiers. Load secrets and private keys from a secret manager, restrict access,
plan rotation, and never include credentials in logs or support bundles. This package accepts a
static key; it does not perform JWKS discovery, key rotation, or credential revocation. HMAC keys
must be at least 32, 48, or 64 bytes for HS256, HS384, or HS512 respectively, following [RFC 7518
§3.2](https://www.rfc-editor.org/rfc/rfc7518.html#section-3.2). Length alone does not establish
randomness: generate keys with a cryptographically secure random source, never use a
human-memorable password directly as recommended by [RFC 8725 §3.5](https://www.rfc-editor.org/rfc/rfc8725.html#section-3.5),
and protect shared keys as signing secrets.

## Credentials and sensitive data

Use least-privilege credentials and a secret manager for provider secrets. Do not commit secrets, tokens, private keys, personal data, request bodies, raw provider errors, or opaque cursors. Enable TLS certificate verification for remote services unless package documentation gives a narrowly scoped local-development exception.

## Vulnerability disclosure

Follow the repository [security policy](../../SECURITY.md). Do not post vulnerability details in public issues. The policy describes private reporting alternatives without claiming that a hosting-platform setting is enabled.

## Limits

This page records source and package documentation, not an independent security audit. Validate the package, its provider SDKs, and its deployment configuration before production use.
