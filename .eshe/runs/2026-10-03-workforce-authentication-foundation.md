# Workforce authentication foundation

- Protocol 0.2; owner identity_implementation; state verify.
- Authorized direction: commercial credentials move to Ory; this Login keeps ZITADEL workforce authentication. The current user direction supersedes older universal-ZITADEL commercial assumptions.
- Plane: workforce authentication orchestration. Authorized actor: exact invited, active, verified-email workforce subject under a registered OIDC client. Denied actors: commercial profile, public staff signup, unapproved subject, absent policy/eligibility, account discovery without provider credential proof, missing or stale factors.
- Sources of truth: ZITADEL verifies credentials and provider sessions; Identity owns canonical Person links, invitations and staff eligibility; product/infrastructure APIs own capabilities and action approval. Login creates no role, company membership, money authority or second identity.
- Visible work: none. Root owns Tier B email/code presentation and French/English copy. Existing presentation/locales/style and other Eshe records are preserved.
- State model: provider contact/invite proof -> protected credential enrollment proof; email challenge -> provider-verified limited admission; failure remains denial. No financial success is inferred.

## Implemented source behavior

1. The predictable SHA(userId:fingerprint) compatibility check always denies. New registration requires provider contact proof; unauthenticated password setup requires a real provider reset code. Actual provider registration proof is encrypted in a five-minute HttpOnly cookie bound to provider session and user, sent to ZITADEL server-side, and removed after accepted registration options. Codes are absent from Login redirect URLs.
2. Current provider Login policy is fetched without the old 15-minute presentation cache. Missing policy denies session validation. Finite provider creation/expiration and valid non-future, session-bound factor timestamps are required; effective absolute web lifetime is eight hours. Cookie metadata cannot extend it. Updates read current provider lifetime and replace cookie timestamps from the provider response.
3. OIDC and SAML finalizers cannot fall through from invalid session to callback. OIDC respects max_age and prompt=login using verified primary factors. Email-primary is a separate explicit workforce_limited class, never the same code counted as MFA.
4. Headless startWorkforceEmailOtp/verifyWorkforceEmailOtp use an existing active, verified-email, enrolled OTP_EMAIL provider account, exact workforce client and organization, and current Identity eligibility. Initiation cannot create accounts or enroll OTP methods. Signed flow state binds session/user/client/OIDC request and expires after five minutes; accepted admission stays within provider absolute lifetime. No provider token/code is returned.
5. The Identity eligibility adapter denies absent config, malformed response and outage. A provider-subject invitation allowlist exists only under explicit non-production qualification mode; production cannot activate it.
6. Public password/social staff signup is denied. Old workforce password-only credential mutation and implicit privileged passkey registration links deny until governed credential/recovery proof or a dedicated action-receipt path exists. The fresh-passkey evidence helper checks provider acceptance timestamps, exact subject, fresh ceremony start and provider userVerified; it is authentication evidence, not an executable action receipt.

## Configuration and integration contract

- PAYPM_WORKFORCE_ORGANIZATION_ID, PAYPM_WORKFORCE_ISSUER, PAYPM_WORKFORCE_OIDC_CLIENT_IDS: exact server category registry.
- PAYPM_WORKFORCE_EMAIL_OTP_READY defaults off and must stay off until the remaining gates below are qualified.
- PAYPM_WORKFORCE_FLOW_KEY_BASE64: canonical 32-byte secret for signed flow state. PAYPM_LOGIN_ENROLLMENT_KEY_BASE64: canonical 32-byte source for HKDF-separated encrypted enrollment proof; the flow key may supply the source when a separate key is absent. No real key is checked in.
- PAYPM_WORKFORCE_IDENTITY_URL, PAYPM_WORKFORCE_IDENTITY_TOKEN_URL, PAYPM_WORKFORCE_IDENTITY_CLIENT_ID, PAYPM_WORKFORCE_IDENTITY_CLIENT_SECRET, PAYPM_WORKFORCE_IDENTITY_SCOPES: separate retained ZITADEL machine client for Identity admission, never a forwarded human token.
- Production adapter contract: POST /internal/v1/authentication-subjects/workforce-eligibility with issuer, subject, clientId, purpose login|enrollment; response personId, organizationId, eligible. Exact service admission and durable invitation/current-eligibility persistence are the next owned Identity follow-on.

## Evidence

- Bun direct Vitest CLI replaces the checked-in pnpm script only for local execution. All 72 Login unit files and 911 tests pass; the final session-provider unavailable denial adjustment also passes the three affected files (74 tests). Includes signed-state tamper/expiry/key denial, provider factor/expiry boundaries, OTP enrollment/eligibility, no returned secrets, denied request/session/user swap, callback fallthrough regressions, provider policy refresh and cookie write lifetime checks.
- Production TypeScript source passes with original next-env-vars declarations and tests excluded. The whole-repository typecheck retains pre-existing test-only errors in ready-route/form/api/loginname tests; no changed production diagnostics. This is not a successful full Next build.
- Changed source/tests pass ESLint and Prettier. Offline secret scan is a checkpoint gate; no Sonar upload or external source scan was performed.
- Homelab workers are unavailable due untolerated taints; root authorized the smallest local fallback. No shared job configuration changed.

## Remaining release gates

- Identity-owned approved invitation/current eligibility endpoint and dedicated machine-client configuration; existing staff need governed canonical Person linkage and enrollment of OTP_EMAIL after approved invitation.
- Tier B bilingual email/code UI, real browser callback/logout/retry/recovery proof and callback-state cleanup.
- Shared durable per-contact delivery/verification quotas, resend retirement, provider expiry/lockout configuration, delivery failure/abuse monitoring and sender readiness. Source initiation is not ready for public release merely because the readiness flag exists.
- Workforce fresh REQUIRED-UV action ceremony plus durable, action/payload/context/session-bound single-use receipts, Identity/Operations/infrastructure capability gates and privileged session revocation. Commercial Kratos receipts cannot validate workforce ZITADEL evidence.
- Eight-hour/30-minute-idle application BFF behavior, five-minute access tokens, provider coordinated logout/revocation and direct native API authorization proof.
- Reviewed workforce credential recovery, old-contact notification, canonical maker-checker comparisons and 24-hour money-release hold where strong proof is unavailable.
- Established CI/full build, pinned deployed image, runtime health, live provider API qualification and authorized/denied actor proof remain separate gates. No push, merge or deployment occurred in this source checkpoint.
