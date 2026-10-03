# Operations original request observation

This private read observes an immutable request after an uncertain result. It
does not issue a provider challenge, renew a credential, replay an assertion,
retire a provider session, or expose/consume an action receipt. Login remains
the provider ceremony owner; Operations remains the permission and effect owner.

Each family has its own endpoint and existing BFF purpose credential:

| Family | POST endpoint | Credential |
| --- | --- | --- |
| Settlement | `/api/internal/v1/operations/actions/requests/:id/status` | `PAYPM_OPERATIONS_ACTION_BFF_TOKEN` |
| Company grant | `/api/internal/v1/operations/grants/actions/requests/:id/status` | `PAYPM_OPERATIONS_GRANT_BFF_TOKEN` |
| Deployment read grant | `/api/internal/v1/operations/deployment-grants/actions/requests/:id/status` | `PAYPM_OPERATIONS_DEPLOYMENT_GRANT_BFF_TOKEN` |
| KYC access grant | `/api/internal/v1/operations/kyc-grants/actions/requests/:id/status` | `PAYPM_OPERATIONS_KYC_GRANT_BFF_TOKEN` |
| KYC case | `/api/internal/v1/operations/kyc/actions/requests/:id/status` | `PAYPM_OPERATIONS_KYC_ACTION_BFF_TOKEN` |

Exact six-key request: `{idToken,accessToken,nonce,clientId,expected,command}`.
`expected` is the existing eleven-key action binding; `command` is the strict
family command. The BFF retains the original UUID request and operation. The
raw pair is validated through current provider introspection, signed ID-token
nonce/SID, canonical invited workforce eligibility, and durable Login admission.
A refreshed pair may observe only the same original base, client, OIDC request
and logout epoch. A different login cannot resurrect the old request.

Exact nine-key HTTP200 response, always `Cache-Control: no-store`:

```json
{
  "requestId": "original-request-UUID",
  "state": "pending",
  "expected": "exact eleven-key object",
  "command": "exact family command object",
  "capabilityDecisionId": "current owning decision UUID",
  "requestExpiresAt": "ISO timestamp or null",
  "receiptExpiresAt": "ISO timestamp or null",
  "providerRetirement": "pending",
  "checkedAt": "ISO timestamp"
}
```

`state` is exactly `not_started`, `pending`, `verified`, `consumed`, `cancelled`,
`expired` or `retired`. `providerRetirement` is exactly `not_started`, `pending`
or `confirmed`. No challenge, capability, raw token or receipt appears here.

- `not_started` means no immutable row and no conflicting original operation,
  or an existing reservation with no durable provider creation claim. Observation
  never takes that claim. Only the same UUID and original body may be retried;
  this response is a point-in-time observation and can race an original POST.
- `pending` includes actual live provider sessions and unknown claimed creation.
  A complete bounded provider search with no result does not prove an in-flight
  request failed. Local expiry or a queued revocation alone cannot establish
  provider retirement. Provider outage/malformed/truncated evidence denies the
  read; it never becomes a successful retirement result.
- `verified` requires the exact provider-accepted challenge/assertion marker,
  actual fresh UP/UV acceptance and the still-live sixty-second receipt interval.
  Fetching its secret remains the separate terminal readback contract.
- `consumed` and `cancelled` are durable local facts. Cancellation prevents local
  use even while actual provider retirement remains pending. Financial outcomes
  remain the owning Operations immutable command readback.
- `expired` or `retired` requires known lack of a creation claim, or an actually
  bound provider session with classified NotFound or a verified bounded provider
  expiration that has passed. A local retired tombstone with unresolved provider
  effect reports `pending`, preserving the original reservation.

The service rereads current owner policy/resource and current exact original
admission before and after provider inspection. Changed semantic hash, command,
policy, resource, original UUID, action family or canonical actor denies. SQL
observation can read tombstones after credential erasure but requires the original
epoch/current base; logout denies immediately. It makes no persistent change.

Source evidence:66 focused strict-family/provider checks,14 actual PostgreSQL
scenarios,1238 full unit checks with36 intentional skips, production TS, owned
lint and Next Webpack build. The synthetic exact wire is frozen in
`apps/login/test-fixtures/operations-original-status.json`. Offline staged scan
is a separate checkpoint receipt. No live provider effects or authority grants
were made. Deployment, configured machine-purpose custody, actual provider
outage/retirement and owning BFF callback proof remain separate gates.
