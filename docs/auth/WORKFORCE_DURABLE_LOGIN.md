# Workforce OTP and current session admission

The existing ZITADEL Login owns workforce OTP challenge orchestration and durable
session admission. ZITADEL generates and verifies codes and passkey assertions.
Identity owns canonical people, invitations, current staff eligibility and exact
action capabilities; it consumes current Login admission before issuing or using
workforce action receipts.

## Server contracts and persistence

`startWorkforceEmailOtp({email,requestId,operationKey})`,
`resendWorkforceEmailOtp({sessionId,requestId,operationKey})` and
`verifyWorkforceEmailOtp({sessionId,requestId,operationKey,code})` require a fresh
UUIDv4 operation key per new operation; retries retain the same key and exact
body. Issue returns only session/challenge IDs, expiry, truthful resend time and
`workforce_limited`. Provider session tokens stay encrypted server-side and in
existing protected HttpOnly session cookies. Codes are never returned or stored
in Login plaintext.

The pinned postgres.js 3.4.7 runtime supports the existing production Node runtime.
No CI or production package-manager migration is included. Apply
the ordered `apps/login/migrations/001_workforce_auth.sql`,
`002_legacy_recovery_retirements.sql` and `003_workforce_action_intents.sql` with
the dedicated migration role using `bun apps/login/scripts/migrate-workforce.mjs` and
`PAYPM_WORKFORCE_MIGRATION_DATABASE_URL`. The runner locks and verifies its applied
checksum; production TLS verifies certificates. Package the migration source
with that operator artifact before release. The serving role uses
`PAYPM_WORKFORCE_DATABASE_URL`, table-level permissions, and an independent
canonical 32-byte `PAYPM_WORKFORCE_STORE_KEY_BASE64`.

SQL reservations precede provider writes. Contact HMAC quota applies across all
registered workforce clients: three sends/reservations per ten minutes,
60-second resend interval, five verification attempts per five-minute challenge.
A resend retires the prior flow before issuing another. A request whose provider
result is unknown must read the exact stored provider metadata/user/session;
it never blindly recreates a session, resends a code, or repeats a verification.
An uncertain create whose exact metadata cannot be found stays unavailable.
Metadata and factor acceptance are atomic in the
[pinned ZITADEL Session implementation](https://github.com/zitadel/zitadel/blob/v4.15.3/internal/command/session.go).
Generic legacy Session helpers reject workforce email OTP operations when the
new readiness flag is on, preventing quota bypass.

Public staff self-registration is disabled. Entry requires Identity-owned current
approved invitation/eligibility, active provider human, real verified email,
registered client, local-auth policy and enrolled email OTP. The nonproduction
qualification subject list remains a fixture/bootstrap gate.

## Session and callback policy

Provider and local admission have an eight-hour absolute cap. Durable admission
has a 30-minute idle limit. It binds exact issuer, provider subject, provider
session, OIDC client/request and logout epoch. A signed browser flow alone is
insufficient. Current OIDC callback and action initiation consult SQL admission.
Timestamps and factors come from the provider; missing policy/timestamps deny.

`PAYPM_WORKFORCE_OIDC_ADMISSION_POLICIES_JSON` must exhaustively classify the
registered `PAYPM_WORKFORCE_OIDC_CLIENT_IDS` as
`[{"clientId":"registered ID","mode":"limited|fresh_passkey"}]`.
Unknown, missing, duplicate or unrecognized entries deny when OTP readiness is
on. `limited` permits the admitted email OTP session. `fresh_passkey` additionally
requires actual provider UV verification within 60 seconds and at/after the exact
OIDC request creation. Readiness off retains the incumbent privileged admission.
`PAYPM_WORKFORCE_EMAIL_OTP_READY` stays off until the owning applications and
native infrastructure restricted/privileged client and role configuration are
qualified. This registry does not enforce a console's native action permissions
or protect its direct API; those remain separate operating proof gates.

Logout writes a durable tombstone/epoch before external deletion. Logout-all
requires the current exact admitted subject and revokes all Login-owned sessions.
Pending provider deletion cannot restore a local session; a late create is queued
for revocation. Browser BFF owners must coordinate their own OIDC token/provider
logout. This Login contract does not claim revocation of independent OAuth tokens
that it never holds.

## Private current admission and fresh action proof

`POST /api/internal/v1/workforce/admissions/check` accepts only the distinct
`Authorization: Bearer PAYPM_WORKFORCE_ADMISSION_READER_TOKEN` purpose credential
and exact `{issuer,providerSubject,baseSessionId,clientId}`. It rechecks durable
admission before and after actual provider validation and returns no credentials:

```
{active:true,issuer,providerSubject,baseSessionId,clientId,requestId,challengeId,
 authenticationClass:'workforce_limited',verifiedAt,absoluteExpiresAt,checkedAt,
 revocationVersion}
```

Wrong credentials, arbitrary actor fields, revoked/idle/expired admission,
provider outage and late logout return `403 {active:false}`. Deploy this route
behind the private service boundary. Identity requires the exact endpoint and
matching separate `IDENTITY_WORKFORCE_LOGIN_ADMISSION_URL/TOKEN`; unavailable
or stale/mismatched responses deny receipt issuance and consumption immediately,
even before provider deletion completes.

The existing fresh workforce action producer binds its exact assertion hash in
SQL before forwarding the assertion. Provider acceptance atomically retains that
marker. Lost responses read the marker and verified UP/UV/provider freshness
without repeating the assertion. Identity retains an immutable completion hash;
identical completion readback returns the original receipt and expiry. A changed
assertion, consumed/expired receipt, missing marker or current admission/role
revocation denies. Receipts remain action/payload/context-bound, 60 seconds and
single use. Generic login time/AMR never substitutes for this ceremony.

`startWorkforceAction({operationKey,action,payloadHash,appId,deploymentId,environment})`
also requires a retained UUIDv4 operation key. Login reserves the exact server-derived
base session, subject, client, OIDC request, logout epoch and requested action in SQL
before creating the provider ceremony. The challenge options and provider token are
sealed using the store key. The same command resumes that original ceremony and
expiry after a lost Identity registration response; changed commands conflict.
Identity's registration readback returns the original unexpired request only for
the identical challenge and current admission/capability. Completed or expired
ceremonies cannot be restarted.

An in-flight provider creation is not repeated. After its five-second request
deadline and ten-second settlement interval, a retry locates the exact subject and
operation metadata, queues that ceremony for retirement, and requires a new operation.
It cannot reconstruct lost public challenge options. Unknown, duplicate or truncated
provider readback stays unavailable. Logout retires intents and queues known ceremony
sessions immediately; a late provider response is queued without restoring admission.
The action UI must retain one operation key during retries, then use a new key only
for an explicitly new ceremony.

## Qualification and remaining delivery gates

Owned source tests cover quotas, concurrent reservations, immutable attempts,
resend retirement, expiry/idle, exact callback categories, late logout and
uncertain provider outcomes. Disposable real PostgreSQL qualification is separate
from provider mock tests. Release still requires shared durable DB/backup restore,
private reader credential rotation, current Session API machine grants, SMTP,
client/role policies, browser/BFF integration, fresh passkey behavior and real
independent authorized staff/recovery actors. Existing presentation changes are
preserved; this slice introduces no visible UI.
