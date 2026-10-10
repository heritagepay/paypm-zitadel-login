# Workforce starts at the owned email-OTP flow

Shared workforce authentication for already registered clients. The authorized
actor is a currently eligible invited/active workforce Person; commercial-only,
revoked or uninvited users remain denied. ZITADEL owns email proof/sessions;
Identity owns current eligibility; the owning operating plane owns capabilities.

Actual Operations browser use showed that choosing an OTP-only remembered Ben
account routed into the generic username flow and `/verify?invite=true`, although
his provider account was already active and email verified. The category registry
repair alone did not fix the remembered-account branch.

Registered, email-ready workforce OIDC requests now start at the existing email
form before generic remembered-session/IDP discovery. Reviewed invitation-return
continuation keeps precedence. A stale account-selector action returns to the
same email form before generic username discovery/session creation. The normal
email form/provider/durable OTP coordinator still performs all current policy
checks and finalizes no OIDC response without fresh verified provider proof.

No UI styling, translations, credential handling, schema, passkey/action policy,
capability, domain ownership or commercial authentication is changed. The existing
French/English email/code interface owns copy and feedback. No new visual direction.
Build/package and actual browser flow follow implementation; application automated
checks are deferred until final project validation under the owner policy.
