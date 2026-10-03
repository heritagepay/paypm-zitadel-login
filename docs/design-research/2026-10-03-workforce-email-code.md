# Workforce email-code entry — Tier B — 2026-10-03

Authority: the approved PayPM commercial/workforce category plan, the PayPM
constitution, and the inherited [hosted-auth direction](2026-09-30-hosted-auth.md).
The current PRODUCT.md describes the earlier shared hosted ceremony; this extension
applies only to registered workforce clients. Identity owns current invited staff
eligibility/capabilities; ZITADEL owns verified contacts, codes, passkeys and sessions;
Login owns challenge quotas and durable admission. No commercial admission, role,
account creation, provider setting or money state is granted by this surface.

Primary persona: an invited staff member returning to an Identity, Operations or
infrastructure task after expiry. Their job is to recognize PayPM, use their existing
verified work email, complete the required factors, and return to the requesting
client. The governing question is “Which account am I using, and what is needed
before I can continue?” Recovery is the same person after delay, rejected code or
lost email access. A reviewer/admin responsibility does not create a new persona.

## Observed incumbent and focused references

- Current source preview inspected in the browser at a loopback-only ephemeral
  URL: actual Button, TextInput, PaypmBrand and compiled SCSS/Tailwind; identifier
  anatomy inherited from UsernameForm. The bounded C3 teal arrival region, warm
  working column, readable labels, 48px field and primary/subordinate controls
  remain. Keyboard Tab moved from identifier to Continue without changing account
  or context. This is a source preview, not a provider route/actor pass. The deployed
  auth.paypm.net navigation timed out; existing September30 deployed captures remain
  historical evidence only.
- [Notion email entry](https://app.notion.com/login), inspected live: a labeled
  identifier and one primary progression. Entering a synthetic incomplete value
  exposed Clear Input; clearing restored input focus within the same frame. Adopt
  reversible identifier correction and quiet focus continuity, not Notion's six
  provider alternatives, legal copy or palette. No form submission/account access.
- [GOV.UK security-code recovery example](https://design-system.service.gov.uk/patterns/confirm-a-phone-number/resend/),
  inspected live: explicit resend wording and a lost-access disclosure. Expanding
  the disclosure retained the resend action and revealed the supported help route
  in place. Adopt visible recovery beside the task. Its phone/password policy,
  code length, validity and concurrently valid prior codes are not PayPM policy.
  [The published input pattern](https://design-system.service.gov.uk/patterns/confirm-a-phone-number/)
  supports one text input with numeric keyboard and one-time-code autofill. PayPM
  retains its six-digit/five-minute/server-retired-prior-attempt policy.

## Required composition and state additions

Inherit DynamicTheme, existing light C3 tokens, TextInput, Button, Spinner, Alert,
French/English locale ownership and protected cookie/callback behavior. Add one
registered workforce form within the incumbent column. No CSS rebrand or alternate
staff account selector. Readiness-off clients retain the incumbent flow.

Wireframe/state sequence:

```
teal arrival: PayPM | existing language control
              Staff sign-in / existing verified work email
warm work:    Email [                         ]
              [ Send code                    ]
              invitation/help guidance

same frame:   Check your email
warm work:    selected email | Change email
              Code [                          ]
              [ Verify and continue           ]
              Resend in server-derived Ns / Resend code
              lost-access help disclosure; Cancel

accepted code -> limited client callback, or existing native passkey ceremony
expired/rejected/unavailable -> persistent explanation, retained account,
                               truthful retry/resend/new flow; no protected content
```

Use a single paste/autofill-friendly text input; strip formatting spaces/hyphens
before submitting exactly six digits. Keep OTP out of URL/storage/analytics. No
auto-submit after paste and no client success animation. A retained operation key
means a retry reads the same operation; changed code and explicit new ceremony
use new operation keys. Resend/expiry labels derive from server timestamps; the
UI cannot increase quota, extend validity or declare provider delivery.

## Response requirements and proof

Commit: immediate pending label and serialized disabled controls driven by the
actual request; no progress percentage. Transition: preserve the chosen email
while replacing the form and focus the code field only after confirmed bounded
challenge data. Rejection: persistent alert attached to the form; code remains
editable and account/recovery remain reachable. Cancellation increments the client
epoch and retires the exact server challenge, so a late result cannot restore a
visible active flow. Passkey cancellation preserves an explicit retry; it grants
no privilege. Reading, countdown, branding and successful redirects remain quiet.
No sound/haptics/entrance effect; reduced motion keeps the same controls/status.

Proof gates: component tests for serialized retries, lost results, resend timing,
expiry, cancellation/late responses and callback categories; current provider
factor/SQL admission tests separately; rendered French/English at320/390/1280px,
keyboard/200% text and native passkey prompt. Source previews are not SMTP,
deployed image, provider revocation or independent staff/privileged actor proof.

Implemented source experience was then inspected in a separate loopback fixture
using the actual form, current DynamicTheme/C3 controls/styles and an explicitly
synthetic transport. English/French email/code states, focus, keyboard Tab/Enter,
quiet denied result, cancellation and expanded recovery were observed at402×874
and1280×900; French code/recovery was also inspected at320×768 and390×844.
At320px, document width/scroll width both measured320: no horizontal overflow.
Recovery expansion scrolls naturally below the current actions. Source tests cover
expiry, retry keys, cancellation failure and late success. Inline tool screenshots
were observed, not saved as an artifact. This is experience proof only; actual SMTP,
native passkey, 200% text, deployed category/actor and provider revocation remain gates.
