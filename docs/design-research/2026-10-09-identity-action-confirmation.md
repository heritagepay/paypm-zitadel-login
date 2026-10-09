# Identity original-action confirmation — Tier B

Authority: PayPM VISION shared Identity plane and existing guarded original-action contract. Primary persona: an invited Identity organization administrator adding an existing canonical Person to a Business. Governing question: can I confirm the request I just initiated, or safely return without granting access?

Observed before: live Identity membership form rejects its legacy mutation with 403; published Login has private Identity action routes but no public identity/step-up page. Focused rendered reference: existing https://auth.paypm.net/ui/v2/login/operations/step-up, observed loading then unavailable/retry. Incumbent components: DynamicTheme, Button, Alert, Spinner, locale selector and browser-native passkey prompt. No brand replacement.

Inherit the centered light confirmation card, clear heading, ordinary action description, quiet progress, single primary verify button, secondary cancellation and return guidance. Add Identity-specific French/English wording and exact action/callback matching. No success celebration: verifying is not membership success. The owning Identity page shows the recorded membership only after execution. Invalid/expired requests keep a fixed return to Identity available; cancellation aborts the native prompt. Never display credential material or payload hashes.

Composition: existing card, title → purpose → request state → verify/cancel → return. No new shell, navigation or illustration. Native passkey feedback remains platform-owned. Actual browser proof follows deployment; automated checks deferred until the full demo is usable.
