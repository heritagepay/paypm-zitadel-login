# PayPM hosted authentication

<!-- impeccable:product-schema 1 -->

## Platform

web

## Product authority

This is a scoped reader of [PayPM's constitution](../../../deploy/docs/VISION.md), not a fourth product or a new requirements authority. The owner's existing direction and implementation request govern this work; no new product facts were inferred from an unanswered interview.

## Users

- Primary: a returning PayPM customer or workplace member, arriving from the requesting application. Job: recognize the trusted sign-in, identify the correct account, complete the required authentication ceremony, and return to the interrupted task. Frequency follows session expiry, account changes and recovery; no usage frequency is assumed. Governing question: “Am I signing in to PayPM with the right account, and what do I need to do next?”
- Recovery actor: the same person after a forgotten credential, expired request, unavailable authenticator or rejected attempt. Needs a clear explanation and the existing legitimate recovery route, not an invented bypass.
- Organization-specific actor: a person covered by ZITADEL organization discovery and branding. The application and backend own Business mapping and permissions. Branding and an authenticated session do not grant access.

## Product purpose and constraints

ZITADEL owns credentials, passkeys, verification, MFA, sessions and token issuance. PayPM Identity owns people, businesses, membership and subject links. The requesting product owns authorization. This app presents the existing ceremonies and returns through the existing OIDC/SAML behavior. It never awards roles or changes financial state.

## Brand commitments

PayPM, French and English together, light-only under OS dark settings, sans-serif DM Sans, compact purposeful whitespace, approved cream/teal/brass identity. The owner selected C3 blended with useful existing elements, requested visual proposals before building, and delegated selection of the most functional and beautiful variants. This slice inherits that direction; it does not reopen the portfolio or rebrand PayPM.

## Evidence and inclusion

Existing route/provider contracts and tests, deployed blank Login V2 captures, Merchant native entry capture, and the shared visual system provide evidence. Successful sign-in and product authority still require a real actor; screenshots do not provide them. Preserve keyboard focus, assistive technology semantics, 44px controls, long French copy, narrow viewports and reduced motion. Do not enter, invent, reset or retain the user's password for visual proof.
