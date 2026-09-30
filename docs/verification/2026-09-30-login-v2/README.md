# Public Login V2 correction — 30 September 2026

These are real public-origin Honor tablet captures, not generated proposals or
authenticated-flow proof. They prove the light-only and translated login-name
state. The stock visual shell remains an unfinished design surface.

| Capture | Environment | Result |
| --- | --- | --- |
| `login-name/honor-tablet-before-dark-en.png` | Upstream v4.15.3, Android night mode yes, EN | Dark form and theme selector: failed PayPM invariant |
| `login-name/honor-tablet-after-dark-en.png` | PayPM source `a9f170b`, Android night mode yes, EN | Light form; no theme selector |
| `login-name/honor-tablet-after-dark-fr.png` | Same deployed revision, Android night mode yes, FR | Light form with French copy; no theme selector |

- Device: Honor JMS-W09, `AJ5EJK6808C02336`, physical 800x1340. All three
  images were opened individually; original night-mode setting `no` restored.
- Public host: `https://auth.paypm.net/ui/v2/login`. ZITADEL theme policy remains
  AUTO; the source enforces the PayPM light-only invariant.
- Source `a9f170b`, image
  `sha256:249ae78cf58d685e416db38d68920c5588730f7a7aea4017125a025ae99746e8`,
  GitOps promotion `69e39337d0c6204b9267e4cd133b20e5e47a3b09`; Argo
  Synced/Healthy and sole public Login pod ready, zero restarts at readback.
- Public Chrome account/password language switches and account selection
  passed; the account's password field remained empty. No completed sign-in,
  MFA, OIDC callback, money flow or target-app permission is claimed.
- Source proof: 797 tests, changed-file lint/format, TypeScript and production
  build passed. Upstream unrelated whole-lint formatting failures remain
  disclosed in the [run record](../../../.eshe/runs/2026-09-30-light-only-login-v2.md).

## Continue from here

1. Finish ordinary existing-account sign-in and callback proof; then verify
   authorized Merchant/Identity and denied cross-organization behavior. Never
   fabricate memberships, credentials or success to pass this gate.
2. Replace the stock hosted-auth visuals with the approved PayPM identity.
   Complete Tier A research and target-geometry compositions first; carry
   FR/EN, light-only, accessibility and actual device evidence through every
   auth state. This correction did not approve the gray stock composition.
3. Keep registration of an authentication account separate from Business
   onboarding and Merchant/staff authority; resolve that flow through the
   owning Identity and product interfaces, not global provider policy changes.

For a fresh chat, read the run record and this page first, then the workspace
AGENTS contract and product constitution. The broader PayPM delivery goal is
still active; these captures close only the two specified login defects.
