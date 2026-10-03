# Operations KYC case reauthentication

Operations owns the affected Wallet account, current KYC documents and state,
governed reviewer permissions, independent review/decision and durable effect.
Login owns the fresh ZITADEL ceremony. KYC access grants and case decisions are
separate authority families. Workforce admission or a grant receipt cannot
decide an individual case.

Registered actions are `operations.kyc.review` and `operations.kyc.decide`.
The strict command has five fields:

```typescript
{
  operationKey: string; // original UUIDv4, retained by the owning operation
  verificationId: string;
  decision: 'manual_review' | 'approved' | 'rejected';
  reasons: string[]; // 1–10 bounded source reason codes
  reviewOperationKey: string | null;
}
```

`manual_review` requires a null review reference and the review action. A terminal
decision requires its actual original review UUID and the decide action. The
strict six-field resource is `{verificationId,walletEndUserId,affectedPersonId,
level,stateHash,reviewOperationKey}`. Its account, Person, finite tier, document
snapshot hash and review reference come from the current owner. Self-review is
denied. Login independently recomputes the canonical v1 action hash using that
resource as `target`, `{decision,reasons}` as `input`, and the unchanged original
operation UUID as `idempotencyKey`. No contact text establishes ownership.

Private routes use `/api/internal/v1/operations/kyc/actions`:

| Route suffix | Credential | Strict body |
| --- | --- | --- |
| `/requests` | `PAYPM_OPERATIONS_KYC_ACTION_BFF_TOKEN` | Existing nine-field paired-proof start |
| `/requests/:id/readback` | Same BFF purpose | `{expected,command}` |
| `/requests/:id/status` | Same BFF purpose | Existing six-field current paired-proof observation |
| `/consume` | `PAYPM_OPERATIONS_KYC_ACTION_CONSUMER_TOKEN` | `{receipt,expected,command}` |
| `/consumed/readback` | Same consumer purpose | Same exact body after one uncertain consume |

The eleven-field `expected` tuple and twenty-field successful proof retain
[the Operations action contract](OPERATIONS_ACTION_CEREMONY.md), with this
command5/resource6. Receipts are 54 characters matching
`^paypm-ops1\.[A-Za-z0-9_-]{43}$`. Expiry is actual provider verified time plus
60 seconds, capped by the original request deadline. Signed UP/UV, exact issued
challenge and provider acceptance are required. Current paired base admission,
logout epoch and owner capability/resource/state are checked before and after
verification and consumption. SQL consumes the receipt once. Uncertain readback
recovers only the identical operation; changed documents, state, reasons,
review reference, actor or session deny. Pure nine-field status exposes neither
challenge nor receipt and cannot invent provider retirement.

The fixed owner reader is HTTPS
`/api/v1/internal/operations/authority/kyc/actions/current`, with separate
`PAYPM_OPERATIONS_KYC_ACTION_AUTHORITY_URL`, `_KEY_ID`, `_API_KEY` configuration,
sole native scope `operations.kyc.action.authority.read` and exact registered
key ID. HMACv2 binds the raw body and path, while original raw OIDC proofs travel
only server to server. The strict fifteen-field response echoes the expected
tuple, exact command, capability decision and six-field owner resource.
Missing, colliding or wrong-purpose secrets deny before provider effects. No
grant, settlement or deployment reader fallback exists.

The public passkey page inherits explicit native prompt, callback state,
cancellation epoch, quiet pending/errors and bilingual light presentation.
Only two EN/FR action descriptions were added after Tier C incumbent inspection.
The registered callback remains `/auth/workforce/actions/callback` with only
original `requestId` and `state`; raw tokens and receipts never enter its URL.

The frozen actual backend checkpoint `820f7ee` fixture is copied verbatim to
`apps/login/test-fixtures/operations-kyc-case.json`. Independent tests recompute
the document snapshot, action hash, raw HMAC and strict twenty-field proof.
207 focused checks, 18 real PostgreSQL checks and 1,306 full Login checks pass;
40 database/opt-in cases are intentionally skipped in the default suite.
Production types, owned lint and Next Webpack build are separate source gates.
Actual component English desktop, French 402px and quiet cancellation failure
were inspected using an owned loopback fixture. All identifiers are synthetic.
Current provider/RP, machine secret custody, actual independent authorized
actors, deployed image and final owning case effect remain release gates.
Homelab worker taints require the authorized local fallback.
