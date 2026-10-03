# Operations current workforce admission producer

Authorized scope: Login-owned private authentication admission for the existing
Operations plane. Admitted actor: currently eligible canonical workforce Person
with an exact registered OIDC token pair and current Login admission. Denied:
commercial identity, disabled/uninvited staff, mismatched client/context, stale or
revoked session, arbitrary actor fields and unavailable dependencies. Identity
owns canonical staff/eligibility; Login/ZITADEL own provider authentication and
durable admission; Operations owns all product permissions and decisions.

Server-only slice; no presentation edit or additional UI research tier is needed.
French/English entry remains the separately qualified incumbent workforce flow.
No provider credentials, roles, deployment or runtime configuration were changed.

The pinned v4.15.3 callback SessionID provenance and strict private 22-field
contract are recorded in `docs/auth/OPERATIONS_OIDC_ADMISSION.md`. Existing
eight-hour/30-minute durable session policy and immediate logout epochs remain
authoritative. Five-minute native access-token validation is mandatory.

Qualification: 50 focused actual-signature/admission boundary cases; production
TypeScript and owned ESLint pass. Full unit suite: 88 suites / 1082 tests pass;
12 database tests are deliberately skipped there and pass separately against
disposable real PostgreSQL, including actual session ID versus access-token ID
and immediate logout. Next's supported Webpack production build passes compile,
full Next TypeScript, 29 static pages and final build traces. Webpack remains the
narrow local fallback for the documented Turbopack external postgres-store
symlink limitation; no CI/runtime package-manager change. Staged offline secret
scan and whitespace checks are required for this checkpoint. No Sonar upload or
live cutover.

Release gates: actual registered clients/resource introspection audience,
separate purpose credentials/private route, current DB migrations/restore,
provider callback and staff actor behavior, BFF/Operations owning permissions and
separate sensitive-action broker. OTP readiness remains off until qualification.
