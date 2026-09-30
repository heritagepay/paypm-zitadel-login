# Decision register

| ID | Question | Observed | Accepted target / source | Status | Gate |
| --- | --- | --- | --- | --- | --- |
| PROD-01 | Product/plane | Upstream Login V2 is a separate Next.js app | Shared authentication plane only; no fourth PayPM product (Vision) | accepted | Preserve |
| AUTH-01 | Ceremony owner | ZITADEL v4.15.3 supplies OIDC, sessions, and Login V2 | Keep authentication and tokens in ZITADEL; retain PKCE, MFA and verification. PayPM apps do not collect credentials | accepted | Source and actor proof |
| TENANT-01 | Business scope | Merchant mobile currently requests no fixed Business org scope | Each PayPM Business has its own ZITADEL org; trusted discovery/mapping, never browser-chosen org ID (Vision) | deferred | Before changing org-specific login behavior |
| DOMAIN-01 | Identity records | Login UI can register a generic subject | PayPM Identity owns person, Business, and membership; sign-in never grants product/staff access | accepted | Preserve denials |
| DESIGN-01 | Theme | Provider LIGHT readback still rendered dark/selector on Honor Android dark | PayPM hosted Login must be light-only, with no theme selector (Vision) | accepted correction | Before GitOps promotion |
| DESIGN-02 | Full PayPM visual composition | Stock Login V2 uses upstream UI | Tier A redesign with PRD/personas, live-product research, geometry proof and response grammar | deferred | Before claiming complete visual acceptance |
| CLIENT-01 | Languages | Upstream Login has multiple locales | Keep French and English states; no translation regression | accepted | Build/device proof |
| DELIVERY-01 | CI cost | Fork has upstream workflow files | GitHub Actions disabled; local or approved runner checks must be reported separately from absent CI | accepted exception | Verify before push |
| INFRA-01 | Release path | GitOps chart can pin Login image | Immutable custom image, canary, then source-controlled chart promotion and Argo/device readback; no live Kubernetes patch | accepted | Before runtime claim |
| ASSURANCE-01 | Proof | Source tag and provider readback exist; no custom image yet | Test, build, image, GitOps, runtime, real-device, and authorized actor evidence are distinct | accepted | Per slice |

Next ready action: implement and test the narrow light-only source correction. Registration/invitation policy and complete auth redesign remain held until their respective contract and research gates.
