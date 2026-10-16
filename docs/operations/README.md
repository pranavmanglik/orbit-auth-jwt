# Orbit Auth JWT: operations

This guide covers runtime configuration and deployment practices for the PyJWT verification
adapter. The package validates a signed token against a configured policy; it does not manage
signing keys, discover identity providers, issue credentials, or establish user authorization.

## Configure the trust boundary

Construct one `PyJWTVerifier` with all of the following:

- A key loaded from a secret manager or trusted public-key source.
- An explicit, narrow algorithm tuple.
- The exact expected issuer.
- One audience, or a tuple containing only audiences that share the same service trust boundary.
- A small clock-skew allowance only when deployment clock behavior requires it.

Do not share a verifier between unrelated issuers or services. Use asymmetric algorithms for
distributed verification where possible. A verifier using HMAC holds signing-equivalent material:
every process with the secret can mint tokens. Asymmetric verifiers should receive public keys only.
Never pass a signing private key to a verification service.

## Token and request handling

Verification requires `sub`, `jti`, `iat`, and `exp`; the configured issuer and audience are also
validated. PyJWT validates `nbf` when present. Keep access-token lifetimes short, synchronize host
clocks, and avoid putting credentials in URLs, logs, error messages, telemetry, or exception
reports. `verify()` returns an `orbit-auth.Token` containing validated claims and metadata, not the
original compact credential.

Signature validity does not imply authorization or current session validity. Apply role, scope,
tenant, and resource checks for each operation. Add a revocation strategy when immediate
credential invalidation is required. This adapter does not fetch JWKS, refresh keys, rotate keys,
or check token revocation; configure those systems separately and plan key rollover before it is
needed.

## Failure behavior and limits

Malformed tokens, invalid signatures, expired tokens, issuer/audience mismatches, and invalid
claim shapes all fail as `ValueError("JWT credential is invalid.")`. Backend exception details are
not included in the public error, reducing accidental disclosure. Treat every verification failure
as an authentication failure and do not retry with a weaker algorithm, an unpinned issuer, or a
different audience.

Input is limited to 16 KiB. Policy strings, algorithm count, audience count, leeway, and scope
cardinality are bounded in the implementation. The verifier is synchronous and performs local
cryptographic work; applications integrating it into async request handling should account for
the selected key algorithm and request rate. It performs no network calls or key caching.

## Production validation

Before rollout, verify issuer and audience values against tokens from the actual identity system,
test key rotation and revocation procedures, measure verification latency at expected concurrency,
and confirm secrets/public keys are distributed with least privilege. Local unit tests use generated
keys and synthetic tokens; they do not validate an identity provider, hosted CI, deployment wiring,
or production key custody.
