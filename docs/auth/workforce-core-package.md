# Workforce CORE migration package

This slice belongs to the shared workforce Login plane. ZITADEL remains the
credential and provider-session owner; Identity remains the Person, staff
eligibility and capability owner. It introduces no invitation, grant, UI,
credential, provider registration or commercial-product behavior. Workforce
email-OTP readiness remains disabled until separate release and actor gates pass.

## Artifact contract

The existing `apps/login` build now packages its owned migration runner, SQL and
the exact `postgres` 3.4.7 package before the existing server-wrapper moves.
The unchanged Dockerfile copies `.next/standalone` to `/app` and runs as UID 1001.

| Final image path                                                            | Contract                                                                         |
| --------------------------------------------------------------------------- | -------------------------------------------------------------------------------- |
| `/app/scripts/migrate-workforce.mjs`                                        | Existing transaction/advisory-lock/checksum runner; versions001–006 exactly once |
| `/app/migrations/001_workforce_auth.sql` through `006_identity_logouts.sql` | Byte-identical owned source SQL; runner-relative lookup                          |
| `/app/node_modules/postgres`                                                | Exact pinned 3.4.7 package, no transitive package dependencies                   |

An operator-controlled migration job must run `node /app/scripts/migrate-workforce.mjs`
with its dedicated `PAYPM_WORKFORCE_MIGRATION_DATABASE_URL`. The application does
not run this script automatically. Production connections retain certificate
verification; a development fixture is not production TLS qualification.

The packaging helper rejects linked artifact `scripts` or root `node_modules`
before writing, requires the exact declared PostgreSQL version, and checks that
the runner resolves its dependency inside the artifact. It removes the generic
flattened runner and build-only helper. Existing build managers, dependency
versions, lockfile, Dockerfile and server wrappers remain unchanged. The existing
environment-file removal becomes idempotent for builds where Next did not trace
the file.

## Source qualification and its limits

The local profile uses Bun1.4.0 and existing installed dependency payloads whose
generating workspace source is unchanged from the authorized release. The
repository `bun run test-unit` script invokes Vitest's Node child. Real PostgreSQL
tests require an explicitly supplied `PAYPM_WORKFORCE_TEST_DATABASE_URL`; the new
runner cases create and remove their own random databases. Never point that
variable at a production or retained rehearsal database.

The complete established unit suite passed **97 files /1,387 tests**, including
**52 real PostgreSQL tests** against a new empty PostgreSQL16 fixture. The new
three SQL cases prove serialized initial001–006 application, one populated
001–005 epoch row preserved on expansion, unchanged replay timestamps, and
changed006-checksum rejection without rewriting committed fixture rows. This is
bounded fixture preservation, not a complete populated workforce restore proof.
Focused enumeration/packaging tests passed **8 tests**; complete ESLint passed
with the existing single `security-settings.ts` console warning.

Next16.2.6 compiled the production source, type-checked it and generated29 static
pages using the previously documented local **Webpack** exception. Default
Turbopack cannot resolve dependency links outside its filesystem root. The
production build script still selects its unchanged default bundler. The new
migration package was actually placed in that Next standalone output; all six
SQL and runner bytes matched source. Its final runner executed under the
Dockerfile's Node24.21.0 Linux/arm64 runtime, as UID1001 with a read-only artifact
mount and dropped capabilities, applied six checksums once, left the006 journal
empty, and preserved the ledger on replay. This does not qualify Linux/amd64
image boot or production database roles/TLS.

The local Next artifact retains **nine external links for existing Next,
Winston and OpenTelemetry server dependencies** from the reused dependency
payload. Those are outside the migration dependency closure. **The whole Login
image is not qualified for publication by this local artifact.** The supported
release dependency build must produce a contained standalone server tree and
prove its production image boot before publication. Do not dereference arbitrary
external payloads or claim the migration proof settles that gate.

Standalone `tsc --noEmit --incremental false` still reports **30 existing errors**
in unrelated tests. Removing only the two new tests from a temporary local
baseline configuration produced the identical30 diagnostic lines. There are no
new migration-test type errors; Next's production source type check passed. No
test assertion, TypeScript baseline, UI or dependency was changed to hide this.

The complete `lint-check-prettier` script retains three unchanged baseline
files: `operations-logout-store.test.ts`, `server/idp-intent.test.ts` and
`server/idp-intent.ts`. They are byte-identical to the authorized base. Focused
formatting for every owned code path passes; the full formatting gate is not
reported green and these unrelated files are not restyled in this slice.

A trial frozen Bun import was unsuitable for this repository: it created
temporary migration metadata despite `--no-save`, and isolated store peer
resolution failed Vitest and ThemeProvider typing. That metadata was restored,
the generated lock removed, and the trial dependency links preserved privately.
No Bun migration is part of this source slice. Public font-fetch sandbox denial
and loopback PostgreSQL sandbox denial were rerun with appropriate network
permission; neither failed attempt is a passed gate. Homelab's Bun profile
requires a Bun lockfile, so it cannot run the unchanged pnpm-lock repository.

## Separate deployment/configuration gates

1. Build the exact reviewed source with the supported release dependency profile;
   verify the whole standalone tree, Node24 Linux/amd64 image, non-root boot and
   readiness-off behavior. Source tests are not hosted CI or native actor proof.
2. Establish separate DDL migration and application database roles. The migration
   role owns the001–006 schema and checksummed ledger; the application must not
   own DDL or write that ledger. Grant only the actual store statements per table.
   In particular `login_identity_logouts` needs runtime **SELECT/INSERT only**;
   migration006 has no mutation trigger, so role-level denial of UPDATE, DELETE
   and TRUNCATE is a required gate. Qualify production schema/search path and TLS.
3. Run001–006 in the owning migration job before enabling consumers; preserve and
   compare the actual existing workforce data/ledger and independently read back
   the006 schema. Neither the fixture nor `CREATE TABLE IF NOT EXISTS` proves an
   existing production table has the expected contract.
4. Supply the existing workforce configuration: exact ZITADEL OPS organization,
   issuer, approved OIDC client IDs and finite limited/fresh-passkey admission
   policies; distinct store/flow keys, runtime database connection and provider
   service identity. The eligibility machine consumer calls
   `/internal/v1/authentication-subjects/workforce-eligibility`; qualify its
   dedicated current Identity capability scope and exact subject/client policy.
5. Separately qualify Identity/Operations confidential browser clients, paired
   current-token admission readers, distinct logout/read purpose credentials,
   introspection policies and private routes. Do not reuse a broad commercial
   machine or an unrelated existing OIDC browser client.
6. Prove invited workforce enrollment, actual email delivery, identified active
   verified provider human and OTP_EMAIL enrollment, current Identity staff
   eligibility, limited login, revocation, then a fresh UP/UV passkey for each
   registered risky action. No staff actor or privileged grant is established by
   this slice. Missing Identity action producers and unmerged007/008 backlog are
   held later slices; adding their capabilities is not a packaging repair.

Only after those gates may the owner set
`PAYPM_WORKFORCE_EMAIL_OTP_READY=true`. This document contains configuration
names and contracts only, not credentials or a grant procedure.
