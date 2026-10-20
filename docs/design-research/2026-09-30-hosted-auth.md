# Hosted authentication — Tier A, 2026-09-30

Authority: [PRODUCT.md](../../apps/login/PRODUCT.md), PayPM VISION.md and VISUAL_SYSTEM.md. This adopts the owner's approved C3 identity rather than selecting a new brand. Primary job/question and actor boundaries are defined in PRODUCT.md before these visual decisions.

## Live reference observations

These are direct browser observations on September 30, not evidence of successful external authentication. No credentials were entered into reference products.

| Work | Observed useful convention | Adopt / reject |
| --- | --- | --- |
| [Wise sign-in](https://wise.com/login) | Explicit labels, one primary submission, recovery and passkey options within one compact column | Adopt hierarchy, not lime palette or its equal-weight social buttons |
| [Stripe sign-in](https://dashboard.stripe.com/login) | Password recovery next to its field; SSO switches the same form from two fields to one, retains focus on identifier and offers Password to return | Adopt stable form context and reversible method selection; reject decorative gradients |
| [Shopify account entry](https://accounts.shopify.com/store-login) | Identifier first, disabled Continue until entry, passkey as existing alternate, account creation subordinate | Adopt clear progression; reject dark ambient page and irrelevant marketing consent |
| [Djamo Côte d'Ivoire](https://www.djamo.com/fr-ci) | Strong localized audience, direct money-use vocabulary, confident brand region and a plainly separated action | Craft reference only; public site was seen, not Djamo's private authentication app. Do not copy its blue identity, advertised capabilities or customer claims |
| [GOV.UK error summary](https://design-system.service.gov.uk/components/error-summary/) — cross-domain public-service forms | Persistent error region, recovery tied to affected fields; guidance names focus management | Adopt clear persistent actionable error semantics, not government graphic identity |
| [IBM Carbon notifications](https://carbondesignsystem.com/components/notification/usage/) — cross-domain operational tools | Inline status close to task, distinct information/warning/error roles, nondismissed critical messages | Adopt proportional inline feedback; reject transient error toasts and blanket success styling |

In-time observation: Stripe SSO action removed the password field, retained the sign-in frame and identifier focus, changed the primary verb, and offered Password as a reversible return. This was a method switch only, not sign-in proof.

## Incumbent evidence and defects

Public PayPM Merchant Console → hosted accounts/loginname was inspected through normal sign-in. Stock Login V2 is gray/white Lato, provider-blue controls, a detached language menu and no reliable PayPM brand anchor. The shared DynamicTheme/layout own ceremony composition; source investigation found that more than two children can be dropped. Fonts and colors can be overwritten by provider branding; preserve those supported boundaries, supply PayPM defaults, and do not invent organizations. Existing real Honor entry captures are available in docs/verification/2026-09-30-login-v2.

## Identity nucleus and signature

1. A person temporarily leaves their Wallet, counter or staff task for one shared authentication ceremony.
2. The selected account is the continuity artifact; authentication must not be mistaken for company permission.
3. Approved PayPM C3 uses a confident teal arrival region and warm light working region, brass accent and readable sans-serif, without excessive empty space.

Familiarity: ordinary labeled fields, primary Continue, legitimate Back/recovery, account selection, existing provider-enabled alternate methods. Owned divergence: a compact PayPM arrival seam framing the current ceremony—not a marketing hero, fake dashboard or progress checklist. Signature rule: “The teal arrival region hands the person to a warm, left-aligned working region; account context and recovery stay beside that work.” Desktop uses a bounded frame, not an empty full-width promotional split; mobile stacks the same regions and allows natural page/keyboard scroll.

Palette inherits existing approved brand roles (#FAF6EE warm ground, #2C5F66 teal, #C9A675 brass, #173D3A ink). Default type is bundled DM Sans; no serif, no financial numbers on this plane. Controls 8px web radius, frame 12px, flat accent, gentle offset elevation only for an actual overlay. Live content determines height. No fake shield guarantee, completed account status or fabricated provider readiness.

## Response requirements (beyond-the-object)

| Moment | Truth/response | Interruption, repetition, accessibility |
| --- | --- | --- |
| Press/commit | Focus ring and immediate disabled/pending primary action are driven by existing form/provider request state | No decorative progress percentage; repeat cannot fabricate a second result. Reduced-motion path has identical labels and semantics |
| Rejected attempt | Persistent inline explanation remains attached to the form; no shake, celebration or disappearing toast | Account and recovery remain available; announce existing error with alert semantics. No auto-dismiss |
| Account/method/locale return | Stable shell and existing URL/cookie/task behavior retain context | No extra account chooser or role inference. Locale action acknowledges pending and failure; layout adapts without a scripted entrance |

Quiet moments: reading instructions, account rows and branding remain still. No sound/haptic requirement is added to hosted web. Existing spinners may acknowledge pending but cannot imply success; reduced motion replaces rotation with static pending indication.

## Composition/proof gate

Generate and inspect three phone-geometry compositions within the pinned C3 world: stacked arrival seam, inset working panel, compact header/flat working region. Select under the owner's explicit delegated best-feature/best-beauty instruction. Every option preserves identifier, Continue, existing register/back and locale controls. Record the selected path/prompt, three states, logo-off, neighbor-swap, grayscale silhouette and response tests before code. Static mock text is illustrative; actual provider-controlled states and policies are implementation truth.

No presentation code changed before this gate. Source, tests, artifact, runtime and private authenticated actor proof stay separate.

## Selected composition and pre-code checks

Selected: `.impeccable/mocks/hosted-auth/login-name/arrival-seam.png`, with exact embedded prompt and sibling JSON. The owner delegated selection within the already selected C3 direction. Inset-work was rejected for nested panels; compact-arrival was rejected for losing the meaningful arrival region while increasing unused space. The selected 851×1848 PNG represents approximately 402×874 logical geometry. It is composition evidence, not shipping raster UI.

- Logo-off: the angled teal-to-cream handoff, compact action column and brass return cue retain C3 continuity with Wallet even without the mark. This is an inherited identity, not a claim that login mechanics are original.
- Neighbor-swap: replacing teal/brass with Wise lime or Djamo blue breaks PayPM's cross-surface nucleus; ordinary field/action conventions remain intentionally familiar.
- Grayscale silhouette: the short arrival band, angled handoff and single working column remain legible without the color distinction. Controls stay below the seam, never inside clipped content.
- Three states: identifier entry uses the full primary action and subordinate creation/back; account/password uses the same frame with actual selected-account context and recovery beside the field; rejected/MFA states keep persistent feedback and all existing ceremony children. These are state-composition decisions; rendered state and interaction proof still follow implementation.
- Response: stable layout, existing pending disablement, persistent inline errors, visible keyboard focus, no shake/entrance/sound. Native locale selection must retain the server-confirmed locale until refresh, serialize writes and expose a retryable failure.

Asset review: no raster-native content exists. Ground, seam, mark, text and controls ship as CSS/SVG/React. Generated purple logo dot, texture, sheen and sampled palette drift are explicitly rejected; pinned #C9A675/#2C5F66/#FAF6EE values govern. Desktop/tablet retain a bounded frame and natural scroll, not an unrelated marketing split.
