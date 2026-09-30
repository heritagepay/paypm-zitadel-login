# Authority map

- Installed protocol: Eshe 0.2, mechanically copied from `/Users/macbook/.config/eshe/protocol` on 2026-09-30; target records are project-specific.
- User request: continue the active PayPM delivery goal, make all surfaces bilingual and light-only, fix hosted sign-in, ship quickly without paid GitHub Actions, and preserve ZITADEL as authentication authority.
- Product: [`deploy/docs/VISION.md`](../../../deploy/docs/VISION.md) and [`deploy/docs/VISUAL_SYSTEM.md`](../../../deploy/docs/VISUAL_SYSTEM.md) in the PayPM deployment repository; this fork cannot redefine the portfolio.
- Source: `apps/login/AGENTS.md`, upstream tag `v4.15.3`, and official ZITADEL Login App/fork guidance. The current app code is observation, not PayPM product authority.
- Delivery: `heritagepay-gitops/identity/Chart.yaml` and `values.yaml`, immutable image digest, ArgoCD, ZITADEL Login V2 settings, and real phone/tablet OIDC behavior. GitHub Actions on this fork were verified disabled to avoid paid workflows.
- Secrets: the cluster-held login service key and cookie-signing secret stay in the existing Kubernetes/Vault path; never copy values into this source tree or tests.
- UI kit: upstream Login themes/components are incumbent implementation; PayPM visual rules are governing authority. See [UI-kit register](ui-kit.md). No separate UI-kit package is created by the narrow theme fix.
- Current evidence: GitOps `docs/verification/2026-09-30-login-v2-theme-policy.md` records LIGHT policy readback failing on an Honor tablet in Android dark mode, followed by exact rollback.
- Current run: [light-only correction](../runs/2026-09-30-light-only-login-v2.md). Full redesign and actor proof remain separate gates.
