# PayPM Login V2 light-only correction

- State: implementing. Work track: standard (shared auth surface and external release).
- Locked request: continue PayPM delivery; fix the proven light-only defect in hosted Login V2 without weakening authentication or inventing Merchant membership.
- Repository baseline: clean sparse clone of upstream ZITADEL `v4.15.3` at `e2886a61670ca8fd41c9434f87036546e5620bcc`; `heritagepay/paypm-zitadel-login` is the fork remote; GitHub Actions disabled.
- Product/plane: shared authentication plane. Authorized actor: legitimate Wallet/Merchant/operator subject completing the requesting client's OIDC ceremony. Denied actor: subject without Identity membership or product permission; the target app/API must deny.
- Truth/dependencies: ZITADEL owns auth, session and token; PayPM Identity owns person/Business/membership; product APIs own authorization. No new API, data model or financial state. Provider is deployed v4.15.3.
- State model: first paint, login, pending authentication, MFA/passkey/password/reset, error/recovery, callback/return. This slice changes only light presentation, not ceremony transitions.
- Copy: no string changes; retain upstream FR and EN. Full PayPM branded copy/design is Tier A later.
- Design tier: C for enforcing an existing approved light-only invariant. Actual before state is the Honor tablet screenshot and GitOps verification record from 2026-09-30; PayPM Vision and visual system govern. Full auth visual replacement is a separately gated Tier A slice.
- UI-kit: existing Login components/themes; use their light branch, do not create a second kit. Beyond-the-object: deliberate quiet for this correction; no new motion/haptic/sound requirement is earned by suppressing an invalid theme state.
- Non-goals: changing self-registration, org discovery, staff grants, Wallet signup, or the security ceremony; no CSS overlay.

## Acceptance

| ID | Observable outcome | Proof | State |
| --- | --- | --- | --- |
| L1 | Login stays light when device/system is dark and provider policy reads AUTO or LIGHT | Source test and real-device capture | open |
| L2 | No theme selector in login, skeleton, error and return states | Source test and rendered routes | open |
| L3 | FR/EN and existing authentication/callback semantics are preserved | Tests/build and OIDC actor/denial checks | open |
| L4 | Immutable image promoted only after canary, with source/runtime/actor proof kept separate | Image digest, GitOps, Argo and device evidence | open |

## Progress

- Fork setup and Actions-off readback complete.
- Source and runtime baseline inspected. A provider LIGHT setting alone did not enforce the intended device state and was rolled back.
- The Login provider now forces light, the route layout no longer renders a theme chooser, and the branding wrapper no longer applies provider dark/auto mode. Authentication actions and strings were untouched.
- Local proof: new saved-dark/system-dark regression passed; all 53 Login unit-test files passed (793 tests); changed-file ESLint and Prettier passed; Next production compilation, TypeScript and standalone packaging passed after pinning the repository root in `next.config.mjs`; a local image was built. These are not device or actor proof.
- Whole-login lint remains red only for upstream, untouched `src/lib/server/idp-intent.ts` and `idp-intent.test.ts` Prettier output. Do not reformat unrelated vendor files to hide this baseline; changed-file lint is clean.
- Bun 1.4 could not migrate this sparse pnpm workspace: `pnpm-lock.yaml` named absent `apps/docs/package.json`, then Bun ignored the lock and matched no Login workspace. The version-pinned upstream pnpm 10.30.3 path was used as a repository-specific exception, without changing checked-in CI/package-manager files.
- Next: publish the exact source commit, push an immutable image derived from it, then run a controlled no-user-traffic canary and dark-mode device check before any Login V2 production route or policy change. Actor login and all flows remain unproved.
