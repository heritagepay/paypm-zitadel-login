# Workforce enrollment — 7 October 2026

## Authority and research

Tier B: extend the existing hosted workforce Login inside the accepted PayPM family. This is a shared operating plane, separate from Wallet, Merchant and Marketplace. The invited human proves ownership of the approved email; an uninvited or changed owner remains denied. ZITADEL owns credential verification and native Sessions, Identity owns the reviewed profile and eventual capabilities. Enrollment completion does not create application admission, roles or a protected session.

The incumbent `(login)/layout.tsx`, global Lato typography, forced-light ThemeProvider, background, layout and language control remain intact. The new route inherits the established warm light / navy / restrained teal family. DM Sans is scoped to this route using the canonical Merchant mobile assets from commit `71626ed6b5c19101b336d64d98efac7615ccb849`, with the SIL OFL preserved. Real 400/500/600 weights avoid synthetic bold.

Research inspected the actual anonymous ZITADEL hosted Login, its focus and French/English language interaction, plus the GOV.UK email ownership and confirmation-code patterns. The primary examples establish that contact ownership is separate from identity or permission, one accessible paste/autofill input is preferable to eight focus traps, and resend follows an observed deadline. The narrow example input was insufficient for PayPM's eight digits. Its example five-digit code and fifteen-minute copy are not inherited.

Accepted private evidence: `workforce-enrollment-design-v3/reference-fr-v3.png` and `reference-en-v3.png`, with root review; `workforce-enrollment-design-live-v4/ROOT_PRIMARY_LIVE_INTERACTION.json` records the actual inert code-example type / Tab-focus / clear interaction without submission or delivery. The design references compose three states at a narrow browser geometry. They are design and synthetic interaction evidence, not proof of delivery or an authorized staff login.

## State and copy requirements

- Server-derived `ready_to_start`: display the approved email, require an explicit Continue action. Initial render and language changes never send mail or create a Session.
- `oidc_request_required`: explain that the original application sign-in request is needed; do not guess a redirect or choose roles.
- `profile_email_verification_pending`: six uppercase A–Z letters or digits. The native profile generator has a one-hour default, but the original browser purpose remains bounded by its own shorter authority. No invented one-hour browser countdown.
- `profile_email_verified`: verified email is truthful; request a separate fresh sign-in code deliberately.
- `otp_pending`: eight digits, one input, numeric keyboard, one-time-code autofill. Use the actual server challenge and expiry/resend timestamps; formatted paste may remove spaces and hyphens only. An expired or unconfirmed result disables verification and resend.
- `identity_link_pending`: the code proof is complete; complete enrollment explicitly. Lost responses use readback of the original operation, not a new enrollment or fabricated success.
- `enrollment_completed_access_pending`: email and code are verified; gold clock and plain text communicate pending access. No role chooser, admission promise, redirect, protected content or success check for access.
- Cancellation must be confirmed by the owner. Late responses cannot reopen a cancelled or unmounted UI. Unknown responses remain neutral and expose no provider payloads.

French and English live in the new `workforceEnrollment` locale namespace. Existing workforce email login copy and eight-digit corrections remain untouched. No support contact, review deadline or permission policy is invented.

The native profile email link carries `operationId` in its query and `code` in its fragment. The UI removes the fragment before bounded parsing, accepts only the original eligible profile state, and requires explicit verification. A fragment never establishes a recipient, OIDC request, subject, role or Session proof. The server owns the registered base path and private reader route; the component builds neither.

## Response grammar and accessibility

State headings settle with a restrained 160 ms opacity transition; focus moves to the relevant single input or heading. Reduced motion removes transitions. No sound, confetti or biometric cue. Quiet verification cannot imply application admission. Controls retain at least 48 px targets, visible focus, disabled-state contrast, long-email wrapping, and a full-width eight-digit input at compact widths. Flat fills and one verified-email label avoid redundant badge decoration.

The pending state uses gold with an explicit clock and text; color is supplementary. Error messages describe uncertainty, not an unproven wrong code or completed cancellation. The existing global language selector is the sole locale control.

## Proof and remaining gates

Focused component tests cover explicit issuance, profile versus Session code formats, fragment removal and rejection, timer/resend retirement, original-request readback, cancellation/late response, language preservation and terminal access-pending truth. Page tests cover bounded query parsing and read-only initialization. Scoped formatting, lint, types, the established unit gate and build are separate source checks.

A local inert browser rehearsal must inspect real fonts, responsive geometry, zoom, keyboard/paste, disabled states and reduced motion without adding a production fixture route. It does not prove native email delivery, a live enrollment, Identity linkage, roles or infrastructure admission. Parent-owned provider and authorized-actor qualification remains required before release. No backend, configuration, provider or credential mutation is part of this presentation slice.
