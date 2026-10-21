# Staff sign-in: review and plain-language correction

Direct goal (Ben, 2026-10-21): "review and change whatever doesn't make sense" on the workforce sign-in surfaces of this login fork. ZITADEL keeps credentials, sessions, OTP delivery, passkeys and callbacks; Identity keeps staff admission. Nothing in `src/lib/server`, cookies, rate limits or redirects changes. Builds on PR #26 (C3 port, quota countdown, visible login name).

Design tier: C, correction inside the approved PayPM C3 composition. The before state was rendered first: the real `WorkforceEmailForm`, `UsernameForm`, `LoginOTP`, `LoginPasskey`, `ChooseSecondFactorToSetup` and the route error page, mounted in the real layout shell with the compiled `globals.scss`, with only the server actions faked. FR/EN, 390 px and 1280 px, 124 states.

Found and corrected:

- Code step stacked three full-width buttons; resend was as loud as the primary. Now one primary, quiet resend-with-countdown and quiet "change address"; the resend control leaves the page when the code has expired (it was disabled anyway). The destination is labelled ("Code envoyé à …"), the code field is large with tabular digits.
- "patientez 0 min 05 s": ICU plural now gives "5 s" / "2 min 5 s".
- French had no `passkey.verify.errors` at all, so a failed passkey ceremony would have shown the raw key path. Added, and rewrote the English set without "challenge"/"redirect".
- `LoginPasskey` could surface a raw browser exception message; `LoginOTP` had two hard-coded English sentences and an English-only `aria-label` on the resend control. All go through the bundled locales now.
- `error.unknownContext` told people to "provide a loginName as searchParam"; `loginname.errors.*` were system phrases ("Utilisateur non trouvé dans le système"). Rewritten as plain sentences in both languages.
- French typography: no-break space before `?` and `:`; curly apostrophes in the sign-in namespaces; "Vérification en deux étapes" / "Two-step verification" instead of "Verify 2-Factor".
- "Changer d’adresse e-mail ou annuler" → "Changer d’adresse e-mail"; recovery hint no longer says "récupération examinée".

Not changed, by design: the server action still collapses every non-quota failure to one "could not complete this step" sentence (a wrong code and an outage read the same); the first-step "Retour" button on `/loginname` (stock behaviour); enrollment, device and IdP pages outside the sign-in path.

Proof: 124 after-states captured with the same harness; the three affected unit tests had their expectations updated for the new resend label and the hidden expired resend. Evidence lives in the task scratchpad (`access-signin/staff-login/{before,after}`), not in the repository.
