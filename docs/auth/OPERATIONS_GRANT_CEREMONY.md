# Operations access grant ceremonies

Operations owns independently governed review, approval and revocation of its
product capabilities. Identity proves the exact current invited canonical
workforce target; Login proves the admitted reviewer's fresh provider passkey.
No native OPS membership, Identity staff capability, local administrator flag or
Login ceremony grants an Operations permission.

## Separate purpose and wire

The grant family uses private POST routes under
`/api/internal/v1/operations/grants/actions`:

- `/requests`: distinct `PAYPM_OPERATIONS_GRANT_BFF_TOKEN` and exact
  `{requestId,idToken,accessToken,nonce,clientId,callbackState,action,payloadHash,command}`.
- `/requests/:id/readback`: the same BFF purpose and exact `{expected,command}`.
- `/consume`: distinct `PAYPM_OPERATIONS_GRANT_CONSUMER_TOKEN` and exact
  `{receipt,expected,command}`.
- `/consumed/readback`: the same consumer purpose and original exact tuple after
  a single uncertain consume outcome. No repeated consume after an unknown effect.

Both purpose credentials require at least 32 characters and must differ from
settlement, admission, owner readers, logout, encryption, introspection and
Identity-purpose credentials. There are no default credentials. Existing
settlement routes reject grant actions/commands and the grant routes reject
settlement actions/commands or crossed credentials.

Grant actions are exactly `operations.access.grant.review`,
`operations.access.grant.approve` and `operations.access.grant.revoke`. Expected
binding remains the exact eleven fields in OPERATIONS_ACTION_CEREMONY.md.
The exact nine-field command is
`{operationKey,policyId,targetPersonId,targetAuthentication:{issuer,subject},capability,merchantBusinessId,organizationId,expiresAt,reason}`.
The original owning operation UUID remains unchanged across independent phases.
The capability is one registered settlement read/review/approve/execute
capability. Target subject is the actual workforce provider subject; client,
deployment, environment and OPS context preserve their existing identifiers.

`PAYPM_OPERATIONS_GRANT_AUTHORITY_URL` is fixed to the owning API's HTTPS
`/api/v1/internal/operations/authority/grants/actions/current`. Its independent
`PAYPM_OPERATIONS_GRANT_AUTHORITY_KEY_ID` preserves the existing opaque key ID
and `PAYPM_OPERATIONS_GRANT_AUTHORITY_API_KEY` supplies the separate Plane B
HMACv2 caller. The owner permits only `operations.grant.authority.read` and its
exact configured reader key. Raw signed JSON and original paired OIDC proof
headers follow the existing owner protocol; there are no actor headers or
body-only grants.

Owner readback must echo the exact current tuple and command and return
`capabilityDecisionId = policyId` and exact resource
`{policyId,policyHash,targetPersonId,targetAuthentication,capability,merchantBusinessId,organizationId}`.
Login independently recomputes the v1 canonical hash with this resource as
`target` and `{expiresAt,reason}` as `input`. All resource fields, current policy
hash, target contact/profile eligibility and reviewer authority remain owning
API checks. Login rereads the same current owner and base admission before and
after provider completion and at consumption/readback. A changed/revoked policy
or target denies even after a provider has accepted the assertion.

The bounded public passkey page, fixed callback, actual required-UV ZITADEL
challenge, immutable assertion readback, encrypted SQL evidence, cancellation
epoch and cleanup are the same proven ceremony mechanics. The receipt remains
54 characters matching `^paypm-ops1\.[A-Za-z0-9_-]{43}$`; the action discriminator
and exact private purpose prevent cross-family consumption. The proof response
remains exactly twenty fields, with actual fresh separate provider proof session,
`paypm_fresh_operations_passkey`, expiry no later than verifiedAt + 60 seconds
and single consumption. No generic AMR/login timestamp replaces provider proof.

## Evidence and release gates

The independently generated owning backend fixture is copied verbatim to
apps/login/test-fixtures/operations-governed-grant.json. Login independently
qualifies its policy hash, canonical command hash, signed raw HMAC bytes, exact
owner echoes and twenty-field proof. It is synthetic wire evidence, not a live
grant or account. Focused scenarios cover crossed routes/credentials, altered
target/policy/expiry/reason, unavailable owner and revocation after provider
acceptance. Actual production Login SQL supports concurrent reservations,
immutable target/policy evidence, once-only consumption, exact uncertain
readback and immediate logout denial for this discriminator.

The incumbent component receives only three English/French descriptions. Tier C
before/after actual component review is recorded in
../design-research/2026-10-03-operations-grant-descriptions.md. Verification does
not display or imply access success. No provider or grant writes occur in local
previews.

Local Bun qualification: 81 focused assertions and nine actual PostgreSQL
ceremony scenarios pass, including concurrent grant reservation, target/policy
immutability, single consume and logout denial. The full incumbent Login suite
passes 1,176 assertions (31 database-dependent checks skipped in the unit run);
production TypeScript, owned ESLint and the established Webpack production build
pass. The actual component was reviewed before and after at 1280px English and
402px French, including a failed cancellation with no false success/handoff.
Temporary preview tabs/viewport/server were removed. Offline staged scan is a
separate checkpoint gate. Homelab workers remain unavailable due taints; these
are parent-authorized focused local checks, not CI or provider actor proof.

Release requires separately configured grant BFF/consumer/owner purposes, the
Identity target reader, finite current canonical Operations owner policies,
registered callback and RP, actual provider permissions, database migrations and
cleanup, independent real reviewer/target proof and immutable deployment. No
production user, credential, permission or cluster was changed here.
