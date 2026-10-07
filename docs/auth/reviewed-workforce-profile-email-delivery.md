# Reviewed workforce profile email delivery

This additive Login repair belongs to the shared Workforce plane. The original reviewed invitation selects the canonical Person, exact ZITADEL OPS subject, client, organization and verified contact target. The browser cannot choose another recipient or grant a role. Identity remains the canonical Person/contact/subject authority; ZITADEL generates and verifies credentials; Login owns delivery custody and the original browser ceremony. Commercial authentication and existing ACTIVE workforce admission are unchanged. New enrollment remains default OFF and completion still reports access pending.

## Original request and native command

A deliberate start of an original unverified enrollment reserves an immutable profile-delivery row under the existing contact quota and original-enrollment locks. It then claims that exact row before resolving the existing native UserService credential. Only the claimant can issue `SendEmailCode` with `sendCode.urlTemplate`; neither `returnCode` nor an application-generated code is permitted. The recipient is the current native subject’s email, whose exact current Identity invitation projection is rechecked immediately before dispatch. Template origin, `/ui/v2/login/workforce-enrollment`, original operation and actual registered OIDC request are fixed and bounded to the native 200-character limit. The fragment can prefill the six-character input; it never submits verification.

The complete native command has an eight-second deadline and AbortSignal, including credential resolution and the final owner check. A late credential/owner result cannot dispatch a new send. The original epoch, immutable binding, browser purpose, current registered client and native subject are checked again before retaining the command outcome. Cancellation, expiry, changed ownership and retired originals deny new commands. A network acknowledgement can still be lost after native execution; no automatic retry occurs.

## Public projection and truthful feedback

`profile_email_verification_pending` carries the server-owned invited email and original request ID, browser `expiresAt`, and optional `profileDelivery`:

| Field           | Meaning                                                                                                                                               |
| --------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- |
| `state`         | `pending` before a claim, `unknown` after a claim without a retained accepted acknowledgement, or `accepted` after a validated native acknowledgement |
| `attemptId`     | Current opaque UUID delivery attempt, used only for explicit replacement                                                                              |
| `resendAt`      | Server-created attempt time plus 60 seconds                                                                                                           |
| `codeExpiresAt` | Conservative reservation horizon of 3600 seconds; not a provider-returned expiry and never an extension of the original browser ceremony              |

Accepted means the native send command was acknowledged, not that the mailbox received the email. Unknown means delivery is unconfirmed, not absent. A received six-character uppercase letter/digit code can still be deliberately verified while delivery is unknown. Only an in-flight command, invalid original/input or expired original disables that task. Read-only inspection returns retained custody and current owning facts; it cannot reconstruct a missing native operation-specific send acknowledgement. No code, native handle, credential, email-provider payload or token enters this projection.

## Replacement and shared quota

`replaceReviewedWorkforceProfileEmail({operationId, operationKey, attemptId})` reserves a successor of the exact current attempt under the same locks. Reusing the same operation reads the same original reservation; changed arguments conflict. A foreign or superseded attempt is denied. The native new code replaces the previous native code; the application records the immutable predecessor relation and never claims the old code remains valid after replacement.

Profile sends and Session email-OTP sends share one issuer/normalized-contact HMAC quota: a 60-second minimum interval and at most three reservations per ten minutes. Reservations count even when the native outcome is unknown. The quota crosses clients and enrollment/session stages; a verified profile cannot send another profile-stage code. No automatic resend, stage fallback or timer-triggered send exists. A lost replacement response preserves received-code verification and requires original readback before another replacement.

## Native truth and deployment prerequisites

The qualified native v4.15.3 profile generator is six uppercase letters/digits with 3600-second validity. The later fresh Session email OTP remains eight digits with 300-second validity. The original reviewed browser ceremony remains at most five minutes; native code lifetime cannot extend it. Profile verification and fresh Session verification remain separate proofs, and neither produces a role, protected application session or permission by itself.

Migration `009_reviewed_workforce_profile_delivery.sql` adds only immutable delivery/claim/outcome journals and reuses the existing immutability trigger function. SQL001–008 bytes and order remain exact. Migration009 must complete before deploying the shared quota reader; no missing-table fallback is allowed. The runtime store role needs SELECT and INSERT on the new tables and no UPDATE/DELETE/TRUNCATE. Synthetic migration tests cover empty009, populated008→009, exact prior microsecond ledger/row preservation and repeat execution. Real deployed role grants, native configuration, SMTP acceptance, mailbox delivery and original actor ceremonies remain separate ROOT release gates.

French and English presentation reuse the established warm, flat PayPM family and existing component tokens. Generation precedes implementation; accepted FR/EN v2 compositions and source-bound before evidence are recorded in the design-research note. Local browser evidence is synthetic transport proof and does not claim provider delivery, real invitation ownership or deployed admission.
