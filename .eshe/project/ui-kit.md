# UI-kit register

- Applicability: interface-bearing hosted authentication plane.
- Governing design authority: PayPM `deploy/docs/VISION.md` and `deploy/docs/VISUAL_SYSTEM.md`; light-only, bilingual, sans-serif, accessible.
- Incumbent implementation: `apps/login/src/lib/theme.ts`, `apps/login/src/styles/globals.scss`, and `apps/login/src/components/` at upstream `v4.15.3`. This is a partial incumbent kit, not a validated PayPM kit.
- Current Tier C slice: lock the existing UI to its light branch and remove the unowned theme chooser while preserving existing component geometry and auth semantics.
- Full PayPM adoption: deferred Tier A research and target-geometry proof. Do not claim the upstream stock UI is the finished PayPM visual system.
- Proof: local tests/build and the real Login V2 flow on the Honor tablet with Android dark mode, then FR/EN and desktop/browser states.
