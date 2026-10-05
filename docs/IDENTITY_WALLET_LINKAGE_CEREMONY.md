# Identity Wallet legacy-linkage ceremony (headless source)

This is a Login ceremony transport for Identity Administration. Identity owns the canonical Person, current staff capability, independent maker/checker decision and one-use `paypm-wf1` proof. Login cannot bind a Wallet, alter a PIN, activate a hold, grant staff permissions or consume the proof. Only `wallet_legacy_linkage` and `identity.wallet.legacy.linkage.intake` / `identity.wallet.legacy.linkage.review` are accepted.

## Current authority and original command

Login validates the existing Identity ID/access-token pair and current limited workforce admission, then calls Identity's fixed current-action reader. The strict expected tuple binds canonical Person, HTTPS issuer, decimal provider subject/base SID/OPS context, client, Identity app, deployment, environment, action and payload hash. The strict command carries the original case UUID and immutable intake material hash or review decision. Identity independently denies affected-Person intake, same-Person checking, wrong capability, stale material and unavailable current ownership.

A five-minute reservation is committed before the sole ZITADEL session-create dispatch. Caller tokens/callback capability, provider session material, assertion and receipt use separate AEAD purposes and a dedicated HKDF domain derived from the existing workforce store key. The Identity proof's actual deadline is stored independently; it cannot extend the original Login deadline. One assertion hash is durable before provider verification. A lost verification response permits only actual original provider readback and the named Identity proof completion; no second verification dispatch.

UP and UV, current exact RP/origin/challenge and the signed authenticator RP hash are required before dispatch. Actual provider subject/organization/intent/proof metadata, verified timestamp, live base admission and current Identity authority are checked before settling an exact structurally qualified Identity receipt. Identity alone signs and consumes that receipt. Operations receipts are rejected.

## Finite routes and purpose credentials

The private prefix is `/ui/v2/login/api/internal/v1/identity/actions/requests`. Every route uses POST and rejects a query, Origin or cookie. `PAYPM_IDENTITY_ACTION_BFF_TOKEN` admits start, `/:requestId/status` and `/:previousRequestId/continue`; `PAYPM_IDENTITY_ACTION_CONSUMER_TOKEN` admits only `/:requestId/readback`. These credentials must remain distinct from each other and all applicable existing transport/store credentials. Absence is fail-closed.

Start takes only `{requestId, operationKey, expected, command, callbackState, idToken, accessToken, nonce, clientId}`. The callback is derived from optional `PAYPM_IDENTITY_ACTION_CLIENT_POLICIES_JSON`, not from browser input: at most16 unique exact client policies with an HTTPS callback ending `/api/v1/auth/browser/actions/callback`, no userinfo/query/fragment. An unconfigured client is denied. The returned capability-only redirect is `/ui/v2/login/identity/step-up`; **that hosted page is intentionally absent and remains a later presentation/actor gate**.

Public finite routes are `/ui/v2/login/api/identity/actions/:requestId/challenge` (GET with `X-PayPM-Ceremony-Capability`), `/complete` and `/cancel` (POST, exact configured Origin, capability in the body). Challenge exposes public credential options only. Complete returns only the configured callback with original request/state; readback delivers a receipt solely to the Identity consumer. No public consume route exists.

## Retirement and continuation

Logout, subject epoch changes, base revocation, cancellation and expiry retire capability custody and queue the actual provider SID while preserving immutable request/command/audit. A late known create response may add its first SID only as terminal audit metadata, with provider/assertion/receipt material absent; it cannot resurrect authorization. Named provider NotFound or actual provider expiry can establish retirement. Missing metadata after an uncertain create, an outage or an ambiguous provider response cannot.

A returned or metadata-discovered SID is adopted/queued only after an actual read from the pinned provider confirms the original subject, organization, intent, client and base-session metadata. A known conflicting provider-owned SID commits revocation custody for both SIDs, preserves the original SID/tuple, wipes every capability/material/receipt and sets a monotonic `provider_conflicted` audit/denial flag. Neither partial first-SID NotFound nor a retry may clear it or authorize a successor. This slice has no automatic conflict-reconciliation authority. A retired row with destroyed caller ciphertext cannot authenticate even terminal capability readback.

A renewed same-owner admission may only observe status of the immutable original SID. It cannot complete that original ceremony. A successor retains the case/command and predecessor UUID, requires confirmed original provider retirement plus Identity's exact expired-unconsumed continuation decision, and uses current fresh admission. Login never claims Identity has consumed a proof.

## Qualification boundary

Migration007 is additive and separate from Operations journals. Runtime table grants, the new image/standalone artifact, hosted page and actual staff/provider UP+UV are not qualified by this source slice. The opt-in SQL fixture accepts only an explicit generated loopback `TEST_IDENTITY_ACTION_DATABASE_URL` for database `login_identity_action_tests`; it creates a UUID schema and runs all001–007 with max1. ROOT owns its eventual execution. Existing workforce email-OTP readiness and client eligibility remain unchanged/default held.

The renewed-admission SQL scenario exercises the real same-contact60-second quota: immediate renewal must be denied, then a bounded61-second real wait precedes a distinct admission. It uses no fake clocks or database timestamp adjustment. Initial actual ROOT runs exposed fixture mistakes. ROOT's fresh V4 run passed all seven cases with max1, additive001–007, real cooldown and confirmed generated-fixture cleanup at2026-10-05T20:15:53.501377Z (receipt SHA256 `6c58386e678eac18ec7bd90c4263e49f92b6d6fecbca671ac8910b979d05fa72`). External providers/admissions were synthetic; actual provider, human and runtime007 grant/image proof remain separate.
