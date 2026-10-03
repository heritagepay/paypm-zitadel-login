# Governed Operations deployment read grants

This is a third owner-bound Operations ceremony family. It reuses the existing
durable provider challenge, fresh signed UP/UV verification, original paired
OIDC admission, callback capability, immutable operation journal and 60-second
receipt. It does not grant permissions in Login. The owning shared backend
holds the finite independent reviewer policy, current invited workforce target,
exact deployment/environment, review/approve/revoke state and grant persistence.
No OPS organization, Identity staff capability or local admin flag grants these
permissions. Company settlement grants cannot substitute for this family.

The registered actions are `operations.access.deployment-grant.review`,
`operations.access.deployment-grant.approve` and
`operations.access.deployment-grant.revoke`. The strict command has seven keys:

```typescript
{
  operationKey: string; // original UUIDv4, preserved across independent phases
  policyId: string;
  targetPersonId: string;
  targetAuthentication: { issuer: string; subject: string };
  capability: 'operations.transactions.read' | 'operations.kyc.read' | 'operations.audit.read';
  expiresAt: string;
  reason: string;
}
```

The strict resource has five keys: `policyId`, current owner-derived `policyHash`,
`targetPersonId`, `targetAuthentication`, and `capability`. Its policy ID must
equal the owner capability-decision ID. The expected tuple remains exactly the
eleven fields in [the settlement contract](OPERATIONS_ACTION_CEREMONY.md).
Deployment, environment, client, application and actual OPS context are bound
there, not caller-selected company identifiers. Canonical v1 action hash uses
the five-field resource as `target` and `{expiresAt,reason}` as `input`.

Private requests use the separate prefix
`/api/internal/v1/operations/deployment-grants/actions`:

| Route suffix | Credential | Body |
| --- | --- | --- |
| `/requests` | `PAYPM_OPERATIONS_DEPLOYMENT_GRANT_BFF_TOKEN` | Same nine-field paired-proof start contract |
| `/requests/:id/readback` | Same BFF purpose | `{expected,command}` |
| `/consume` | `PAYPM_OPERATIONS_DEPLOYMENT_GRANT_CONSUMER_TOKEN` | `{receipt,expected,command}` |
| `/consumed/readback` | Same consumer purpose | Same exact body after one uncertain consume |

Both tokens are distinct from every other Operations/Identity purpose and
encryption key. Missing/colliding configuration denies before provider effects.
The owner uses separate `PAYPM_OPERATIONS_DEPLOYMENT_GRANT_AUTHORITY_URL`,
`_KEY_ID`, and `_API_KEY`, exact HTTPS path
`/api/v1/internal/operations/authority/deployment-grants/actions/current`,
dedicated Plane B/HMACv2 scope `operations.deployment-grant.authority.read` and
exact configured backend key ID. Login forwards the original server-only proof
pair. It validates the exact fifteen-field active owner response and recomputes
the command/hash/resource; it never uses company or settlement reader fallback.

The terminal consume/readback remains exactly twenty fields, with the five-key
resource and seven-key command. Receipt syntax remains
`^paypm-ops1\.[A-Za-z0-9_-]{43}$` (54 characters). Actual provider verification
time plus 60 seconds bounds expiry, capped by the request deadline. SQL consumes
once; uncertain readback accepts only the same exact command/current base and
current owning policy/target. Provider subject, base session, independent proof
session and canonical Person retain distinct meanings. The registered callback
stays `/auth/workforce/actions/callback` with request UUID and one-use state;
receipts/tokens never enter the browser URL or JavaScript.

Evidence: the actual backend frozen fixture was copied verbatim to
`apps/login/test-fixtures/operations-deployment-grant.json` and independently
validated for policy hash, canonical action hash, raw HMACv2 and twenty-field
proof. Seven focused files pass 134 cases; full Login passes 1,210 cases with
32 intentional opt-in/database skips. Ten real PostgreSQL cases include both
grant discriminators, concurrent immutable reservations, one-use consumption,
uncertain readback, altered target/policy denial and logout. Production type
checks and owned lint pass. EN/FR actual-component desktop/402px preview and
truthful cancellation failure were inspected after Tier C incumbent research.
All fixtures are synthetic; no policy, actor grant, provider credential or
deployment was configured. Exact RP/provider/browser/actor, current independent
reviewers/target invitation, secret custody and final owning grant effects
remain rollout gates. Homelab worker taints require the authorized local checks.
