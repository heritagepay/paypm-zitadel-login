# PayPM Login V2 light-only correction

- State: deployed invariant/copy correction; full branded design and authenticated callback/authorization proof remain open. Work track: standard (shared auth surface and external release).
- Locked request: continue PayPM delivery; fix the proven light-only defect in hosted Login V2 without weakening authentication or inventing Merchant membership.
- Repository baseline: clean sparse clone of upstream ZITADEL `v4.15.3` at `e2886a61670ca8fd41c9434f87036546e5620bcc`; `heritagepay/paypm-zitadel-login` is the fork remote; GitHub Actions disabled.
- Product/plane: shared authentication plane. Authorized actor: legitimate Wallet/Merchant/operator subject completing the requesting client's OIDC ceremony. Denied actor: subject without Identity membership or product permission; the target app/API must deny.
- Truth/dependencies: ZITADEL owns auth, session and token; PayPM Identity owns person/Business/membership; product APIs own authorization. No new API, data model or financial state. Provider is deployed v4.15.3.
- State model: first paint, login, pending authentication, MFA/passkey/password/reset, error/recovery, callback/return. This slice changes only light presentation, not ceremony transitions.
- Copy: no string changes; retain upstream FR and EN. ZITADEL's inherited system hosted-login response was found to return English even for `fr`, overriding the bundled French copy. Only explicit instance and organization customizations may override the bundled locale, in that order. Full PayPM branded copy/design is Tier A later.
- Design tier: C for enforcing an existing approved light-only invariant. Actual before state is the Honor tablet screenshot and GitOps verification record from 2026-09-30; PayPM Vision and visual system govern. Full auth visual replacement is a separately gated Tier A slice.
- UI-kit: existing Login components/themes; use their light branch, do not create a second kit. Beyond-the-object: deliberate quiet for this correction; no new motion/haptic/sound requirement is earned by suppressing an invalid theme state.
- Non-goals: changing self-registration, org discovery, staff grants, Wallet signup, or the security ceremony; no CSS overlay.

## Acceptance

| ID | Observable outcome | Proof | State |
| --- | --- | --- | --- |
| L1 | Login stays light when device/system is dark and provider policy reads AUTO or LIGHT | Public `auth.paypm.net` on Honor tablet with Android night mode enabled rendered light in EN and FR under AUTO; night mode restored after proof | pass |
| L2 | No theme selector in login, skeleton, error and return states | Source/layout regression and public account, login-name and password routes omit the chooser; error/return states still need actor coverage | partial |
| L3 | FR/EN and existing authentication/callback semantics are preserved | Public Server Actions switch account/password copy between FR/EN, and account selection reaches the password step; no browser errors observed. Password/MFA, callback and target-app authority remain unproved | partial |
| L4 | Immutable image promoted only after canary, with source/runtime/actor proof kept separate | Source `a9f170b`, Harbor digest, canary, GitOps `69e3933`, Argo Synced/Healthy, sole ready public pod/image ID and physical-device proof are recorded separately from pending actor gates | pass for promotion/trace |

## Progress

- Fork setup and Actions-off readback complete.
- Source and runtime baseline inspected. A provider LIGHT setting alone did not enforce the intended device state and was rolled back.
- The Login provider now forces light, the route layout no longer renders a theme chooser, and the branding wrapper no longer applies provider dark/auto mode. Authentication actions and strings were untouched.
- Local proof: new saved-dark/system-dark regression passed; all 53 Login unit-test files passed (793 tests); changed-file ESLint and Prettier passed; Next production compilation, TypeScript and standalone packaging passed after pinning the repository root in `next.config.mjs`; a local image was built. These are not device or actor proof.
- Whole-login lint remains red only for upstream, untouched `src/lib/server/idp-intent.ts` and `idp-intent.test.ts` Prettier output. Do not reformat unrelated vendor files to hide this baseline; changed-file lint is clean.
- Bun 1.4 could not migrate this sparse pnpm workspace: `pnpm-lock.yaml` named absent `apps/docs/package.json`, then Bun ignored the lock and matched no Login workspace. The version-pinned upstream pnpm 10.30.3 path was used as a repository-specific exception, without changing checked-in CI/package-manager files.
- Next: complete authenticated actor/callback and denied-authority checks through normal sign-in, then replace the stock visual shell using separately recorded PayPM Tier A research and target-geometry proof. Do not describe the stock light shell as the completed C3 design.

## Internal canary and localization finding

- Published source `ac3dab5`, Harbor AMD64 digest `sha256:5127ec985e83a2203fa90dcdbdb67732482cd73c1c9f36ce998a800563f6e247`, and GitOps `7a77099` internal-only canary. Argo read back Synced/Healthy at that GitOps revision; the canary Deployment was 1/1 available, with no matching public Service or Ingress. The live Login Service still selected the upstream `ghcr.io/zitadel/zitadel-login:v4.15.3` pod.
- The canary's first cold start exceeded the inherited liveness window and restarted once, then its ready and healthy endpoints returned 200. This startup margin needs release review; 200 health is not sign-in proof.
- Through a temporary host-correct proxy, an actual Merchant OIDC request rendered the canary login form. On the Honor tablet with Android night mode set to yes, the form remained light and omitted the theme controls; Android night mode was restored after capture. The local proxy does not prove server actions or callback semantics, so it cannot authorize live promotion by itself.
- Both upstream live and first canary rendered English login copy while the language chooser could show Français. Read-only Settings V2 checks proved `GetHostedLoginTranslation` at system level returns English `loginname.title` for both `fr` and `fr-FR`; the instance level has no explicit translations. This is inherited-provider fallback, not an explicit PayPM customization.
- The source now excludes inherited system translations from locale-message precedence, while preserving explicit instance and organization overrides. New regression tests cover the RPC inheritance flag, French local copy and override order; all 55 Login test files / 797 tests passed.
- The corrected source also passed changed-file ESLint/Prettier and the production build, including TypeScript and standalone packaging. This is ready for the second immutable canary image.

## Public promotion and real-medium proof

- Corrected source `a9f170b` was published to the Actions-disabled fork. Harbor image `v4.15.3-paypm.a9f170b` resolves to `sha256:249ae78cf58d685e416db38d68920c5588730f7a7aea4017125a025ae99746e8` for `linux/amd64`.
- GitOps `e599e50` deployed the second isolated canary. It started ready with zero restarts; host-correct French/English Login GETs returned the corresponding locale without inherited English overriding French.
- GitOps `69e39337d0c6204b9267e4cd133b20e5e47a3b09` promoted the exact image to the existing public Login Deployment. Helm resource comparison changed only that Deployment and its existing service account; the ZITADEL core pod template, configuration, grants and Identity services were untouched. Full GitOps validation, deploy readiness, strict known-kind schema checks and secret scan passed. No paid GitHub Actions were run.
- Argo `heritagepay-identity` read back Synced/Healthy at `69e3933`; the sole ready Login pod and public endpoint resolve to the new immutable image with zero restarts. Public Login readiness and Identity health returned HTTP 200.
- Real Chrome public-origin language actions translated the account chooser to `Comptes`, preserved French into `Mot de passe`, then switched it back to English `Password`. The normal existing-account action reached the password route. The field was empty; no password, OTP, grant, callback or account creation was fabricated, and none is claimed.
- Honor tablet `AJ5EJK6808C02336`, 800x1340, Android night mode enabled: public English and French forms remained light, no theme chooser. Individually inspected before/after captures and a compact continuation are retained under `docs/verification/2026-09-30-login-v2/`. Night mode restored to its original `no` state.
- This corrects two defects, not the visual direction. The current gray stock composition, provider terminology and loose layout still need the branded PayPM design slice. Full sign-in and Merchant/Identity authority proof remain open.
- Native Merchant `net.paypm.merchant` 1.0.0 on the Honor tablet was cold-launched; its Sign in action opened its own public `auth.paypm.net` Custom Tab, rendered the corrected French form, accepted the owner-supplied existing account identifier, and reached the ordinary empty password step. The owner was asked to finish password/MFA privately on-device. No full callback or Merchant permissions are claimed; no credential was reset or new account inserted. The phone was no longer connected at the final USB inventory.
