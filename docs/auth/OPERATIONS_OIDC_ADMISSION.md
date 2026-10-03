# Operations OIDC callback and current workforce admission

The Operations BFF retains the original ID token, access token and authorization
nonce only server-side. It validates its callback state, PKCE, signature, issuer,
audience and nonce. The owning Operations API independently submits those exact
proofs to Login; neither a subject header nor the old local `is_ops_admin` flag is
admission or an Operations permission. Operations owns its current capabilities,
resource relationships, maker-checker rules and action decisions separately.

## Pinned callback provenance

The ZITADEL **v4.15.3** custom Session API path links a real provider session to
the OIDC request. This is supported source behavior, not a guessed JWT claim:

- [CreateCallback](https://github.com/zitadel/zitadel/blob/v4.15.3/internal/api/grpc/oidc/v2/oidc.go)
  calls `LinkSessionToAuthRequest` with the authenticated Session API ID/token.
- [LinkSessionToAuthRequest](https://github.com/zitadel/zitadel/blob/v4.15.3/internal/command/auth_request.go)
  verifies that provider session token and records its exact session ID.
- [OIDC session creation](https://github.com/zitadel/zitadel/blob/v4.15.3/internal/command/oidc_session.go)
  copies the authorization request's SessionID into the OIDC session.
- [ID-token construction](https://github.com/zitadel/zitadel/blob/v4.15.3/internal/api/oidc/token.go)
  emits this SessionID as signed `sid`, the original `nonce`, and the paired
  access token's `at_hash`. The access token's `jti` is a different identifier.
- [Native introspection](https://github.com/zitadel/zitadel/blob/v4.15.3/internal/api/oidc/introspect.go)
  authenticates a registered resource client, checks its audience and current
  provider token/user status. No subject-only lookup substitutes for this check.

The producer requires a currently valid RS256 ID token from the fixed issuer's
JWKS, exact client `aud`/`azp`, exact original nonce and SHA-256 `at_hash` pairing.
It forbids caller-selected key URLs, delegated actor tokens and missing `sid`.
Native access-token introspection must return the same issuer, subject/client,
Bearer token type, current times and actual `jti`; its absolute token lifetime
must be at most **300 seconds**. ID-token time never establishes action freshness.

## Private contract

`POST /api/internal/v1/operations/admissions/check` uses the separate purpose
credential `Authorization: Bearer PAYPM_OPERATIONS_ADMISSION_READER_TOKEN`.
The exact JSON request is `{idToken,accessToken,nonce,clientId}`; extra properties,
invalid proof, unavailable provider/Identity, current logout or absent policy
return `403 {active:false}`. All responses use `Cache-Control: no-store`.

The success response has exactly these 22 properties:

```text
{active:true,issuer,providerSubject,baseSessionId,clientId,tokenId,
 idTokenHash,accessTokenHash,nonceHash,personId,plane:'workforce',
 appId,deploymentId,environment,contextId,requestId,challengeId,
 authenticationClass:'workforce_limited',verifiedAt,absoluteExpiresAt,
 checkedAt,revocationVersion}
```

Hashes are lowercase SHA-256 hex of the exact UTF-8 input strings. `tokenId` is
the current access-token `jti`; `baseSessionId` is the authenticated signed ID
token's real Session API `sid`. `contextId` is the configured opaque numeric
ZITADEL OPS organization ID (`PAYPM_WORKFORCE_ORGANIZATION_ID`), checked against
the provider session, current human's resource owner and current Identity staff
eligibility. It is not a Business UUID or a product permission. Person is the
canonical Identity UUID. App, deployment and environment are server-registered.
The epoch is a decimal string. ISO timestamps come from current admission; only
`checkedAt` is generated at this read. No tokens, credentials or capabilities are
returned.

Login checks current durable admission, the exact current provider session and
accepted email factor timestamp, active provider human/verified email and current
Identity invitation/eligibility. Only verified use advances the 30-minute idle
clock. A final durable epoch check makes local logout take effect before provider
revocation completes. The existing eight-hour absolute bound never slides.

The backend independently validates its original access JWT and compares this
strict response to its original raw ID/access/nonce hashes, client, subject,
token ID, fixed app and Manifest deployment/environment. Its server-only proof
transport is the original access Bearer plus `X-PayPM-Workforce-Id-Token` and
`X-PayPM-Workforce-Nonce`; these headers never establish permission themselves.

## Required configuration and release gates

### Server-side refresh

The pinned [v2 refresh handler](https://github.com/zitadel/zitadel/blob/v4.15.3/internal/api/oidc/token_refresh.go)
retains `openid` scope and calls the same token response constructor. Its
[session exchange](https://github.com/zitadel/zitadel/blob/v4.15.3/internal/command/oidc_session.go)
rotates access/refresh tokens while returning the original SessionID, Nonce and
AuthTime. The new signed ID token therefore preserves the real `sid` and original
authorization nonce and recomputes `at_hash` for the new access token. The BFF
must serialize refresh rotation and replace the entire pair atomically only after
current admission validation, while preserving its original nonce/Person/session
and local logout epoch. Missing new ID/access proof or mismatch denies. The v1
fallback supplies empty nonce/session values and cannot enter this contract.
Refresh never extends Login's eight-hour absolute or 30-minute idle limit or
provides action freshness. Provider client clock skew must be qualified so actual
access `exp-iat` remains at most 300 seconds; zero skew is the intended setting.

- `PAYPM_OPERATIONS_OIDC_CLIENT_POLICIES_JSON` is an exact nonempty array of
  `{clientId,appId,deploymentId,environment}` for registered workforce clients.
  Missing/duplicate/unclassified clients deny. Deployment preserves the current
  `[a-z0-9_]{1,128}` Manifest ID; environment is explicitly production, staging or
  sandbox. No legacy environment default or generated mapping is allowed.
- The existing workforce client mode registry still governs limited versus
  fresh-passkey callback admission. This endpoint always returns limited
  authentication and grants no infrastructure/native or Operations role.
- `PAYPM_OPERATIONS_INTROSPECTION_CLIENT_ID` and
  `PAYPM_OPERATIONS_INTROSPECTION_CLIENT_SECRET` are a distinct registered
  ZITADEL resource client's native introspection credentials. Its audience must
  be qualified for the actual Operations tokens. The reader token is separate
  from this secret, Identity admission/reader, flow and encryption purposes.
- The route stays private. The BFF and backend each receive only the intended
  purpose credential. Current Identity eligibility uses the existing narrow
  Login service adapter, not a newly invented Operations Identity grant.
- Workforce OTP readiness stays off until the actual provider client/session,
  five-minute token settings, private network boundary, DB migration/restore,
  machine roles/secret references, BFF and Operations owners are qualified.

Actual RSA-signed synthetic tokens prove signature/nonce/at_hash handling and
denial boundaries. Disposable PostgreSQL proves session/client binding and
immediate logout; transport/provider mocks prove fail-closed dependency handling.
These are source proofs. Real deployed provider callbacks, independent staff
actors, native console roles, per-action passkeys and direct API protection remain
separate release gates. Identity action receipts are not Operations receipts.
