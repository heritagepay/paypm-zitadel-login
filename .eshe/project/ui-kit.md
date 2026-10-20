# UI-kit register

- Applicability: interface-bearing hosted authentication plane.
- Governing design authority: PayPM `deploy/docs/VISION.md` and `deploy/docs/VISUAL_SYSTEM.md`; light-only, bilingual, sans-serif, accessible.
- Incumbent implementation: `apps/login/src/lib/theme.ts`, `apps/login/src/styles/globals.scss`, and `apps/login/src/components/` at upstream `v4.15.3`. This is a partial incumbent kit, not a validated PayPM kit.
- Current Tier C slice: lock the existing UI to its light branch and remove the unowned theme chooser while preserving existing component geometry and auth semantics.
- Full PayPM adoption: Tier A research and three target-geometry compositions completed in `docs/design-research/2026-09-30-hosted-auth.md`; the owner-pinned C3 arrival seam is now being implemented. Do not call the run finished before render/review/runtime proof.
- Shared kit owners: DynamicTheme (all ceremony sections), PaypmBrand (canonical vector), DM Sans local faces, TextInput (linked labels and feedback), Button (native variants), Alert (persistent alert/status), LanguageSwitcher (server-confirmed locale), SessionItem/SessionsList (semantic account actions). `globals.scss` carries the scoped light composition and target sizes.
- Provider boundary: supported organization logo/font/colors remain provider-owned. PayPM defaults do not silently discard explicit branding; a guarded provider palette reconciliation is a separate configuration receipt.
- State inventory: identifier/account/password, recovery, MFA/passkey/OTP/U2F, registration/verification, IDP/device consent, sign-out and recoverable boundaries. Shared layout/build coverage is not completed actor coverage of every state.
- Proof: local tests/build and the real Login V2 flow on the Honor tablet with Android dark mode, then FR/EN and desktop/browser states.
