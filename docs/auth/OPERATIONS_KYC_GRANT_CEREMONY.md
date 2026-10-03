# Governed Operations KYC access grants

This is a separate owner-bound Operations ceremony family. The shared backend
owns its finite reviewer policy, current approved workforce target, independent
review/approval, expiry and persisted KYC permissions. Login supplies the exact
fresh provider action proof. Neither workforce admission, Identity staff access,
deployment read access nor company settlement grants imply KYC review or decision
permission. No individual KYC case is decided by this grant ceremony.

Registered actions are `operations.access.kyc-grant.review`,
`operations.access.kyc-grant.approve` and `operations.access.kyc-grant.revoke`.
The strict command has seven keys:

```typescript
{
  operationKey: string; // original UUIDv4 across independent phases
  policyId: string;
  targetPersonId: string;
  targetAuthentication: { issuer: string; subject: string };
  capability: 'operations.kyc.review' | 'operations.kyc.decide';
  expiresAt: string;
  reason: string;
}
```

The strict resource has five keys: `policyId`, current owner-derived `policyHash`,
`targetPersonId`, `targetAuthentication`, and `capability`. Policy ID equals the
owning capability-decision ID. The expected tuple remains exactly eleven fields
from [the settlement contract](OPERATIONS_ACTION_CEREMONY.md). Deployment,
environment, application, client and current OPS context are bound there.
Canonical v1 action hash uses the resource as `target`, the original operation
UUID as `idempotencyKey`, and `{expiresAt,reason}` as `input`.

Private routes use `/api/internal/v1/operations/kyc-grants/actions`:

| Route suffix | Credential | Strict body |
| --- | --- | --- |
| `/requests` | `PAYPM_OPERATIONS_KYC_GRANT_BFF_TOKEN` | Existing nine-field paired-proof start |
| `/requests/:id/readback` | Same BFF purpose | `{expected,command}` |
| `/requests/:id/status` | Same BFF purpose | Existing six-field current paired-proof observation |
| `/consume` | `PAYPM_OPERATIONS_KYC_GRANT_CONSUMER_TOKEN` | `{receipt,expected,command}` |
| `/consumed/readback` | Same consumer purpose | Same exact body after one uncertain consume |

Missing or colliding purpose secrets deny before provider effects. Owner access
uses distinct `PAYPM_OPERATIONS_KYC_GRANT_AUTHORITY_URL`, `_KEY_ID`, `_API_KEY`,
the exact HTTPS path `/api/v1/internal/operations/authority/kyc-grants/actions/current`,
dedicated HMACv2 scope `operations.kyc-grant.authority.read` and the configured
owning backend key ID. Login forwards only the original server-held proof pair,
checks the strict fifteen-field owner response and recomputes its exact hash.
No settlement, company or deployment reader fallback exists.

Consume/readback keeps exactly twenty fields, command7/resource5, and
`^paypm-ops1\.[A-Za-z0-9_-]{43}$` receipts (54 characters). Expiry is actual
provider verified time plus 60 seconds, capped by the request deadline. Signed
UP/UV and the expected identity are required. Current base admission and owning
target/policy are checked before and after provider verification and consumption.
The SQL receipt is consumed once. Identical uncertain readback can recover only
the same bound operation; altered target, policy, reason, expiry, plane or session
denies. Status is the existing strict nine-field pure observation, with no
challenge, secret, receipt, credential replay or invented provider retirement.

The public passkey component inherits its existing capability binding, explicit
prompt, callback state, cancellation epoch, quiet errors and light bilingual
presentation. Only three EN/FR descriptions were added after Tier C incumbent
inspection. The callback remains `/auth/workforce/actions/callback`; receipts
and provider tokens do not enter browser URLs or JavaScript.

Qualification: the actual backend fixture was copied verbatim to
`apps/login/test-fixtures/operations-kyc-grant.json` and independently checked for
policy hash, canonical action hash, raw HMACv2 and strict twenty-field proof.
183 focused cases, 16 real PostgreSQL cases and 1,273 full Login cases pass;
38 database/opt-in cases are intentionally skipped in the default full suite.
Production type checks, owned lint and the Next Webpack production build pass. The actual component was inspected
in English at desktop and French at 402px, including truthful cancellation
failure. All fixtures are synthetic. No deployed policy, invitation, credential,
native passkey actor or final owning grant has been created. Current provider/RP,
secret custody, independent authorized reviewers/target eligibility, CI/image
and deployed effect remain distinct release gates. Homelab worker taints require
the authorized local checks.
