# Reviewed workforce enrollment return

An expired verification needs a fresh native OIDC request from the owning application. The Login UI must not construct an authorize request, replace application PKCE/state/nonce, reuse expired proof, or grant ordinary admission.

## Operator registration

`PAYPM_WORKFORCE_ENROLLMENT_RETURN_TARGETS_JSON` is a server-only optional catalogue of exact entry points. Each row contains only `clientId`, `application`, and `url`. `application` is one of `identity`, `operations`, or `super-admin`; the client must already belong to the workforce policy. URLs are canonical HTTPS URLs without credentials, query, fragment, wildcard, or backslash. Duplicate/unregistered/malformed rows disable the catalogue. No arbitrary URL is accepted from a browser command.

Example using synthetic values only:

```json
[
  {
    "clientId": "registered-staff-client",
    "application": "identity",
    "url": "https://identity.example.test/"
  }
]
```

The initial deployed registration must be verified against the actual Identity Administration OIDC client and entry URL. A registration does not enable ordinary workforce admission. Login must use its registered `/ui/v2/login` base path.

## Flow and authority

1. On a deliberate Return click, re-read the current Identity projection, active invited provider user and pending original outcome. Inspect immutable original/current attempt custody, canonical contact binding, invitation expiry, provider epoch and retirement using a read-only database transaction. A still-current attempt cannot be replaced through this path.
2. Store a five-minute encrypted HttpOnly routing cookie using a key derived from the existing flow key under a separate purpose. Bind projection, durable attempt/epoch, exact target and predecessor request. Its expiry cannot exceed the invitation expiry. There is no code, provider token, session proof or permission in it.
3. Return to the registered application entry. The user chooses Sign in; the application owns the fresh native OIDC request and callback proof.
4. At native Login initiation, before account selection, provider redirect or old-session callback, re-read the actual request/client, provider/Identity projection, pending outcome and durable custody. Missing cookie preserves ordinary entry. Present invalid/stale/wrong-client/custody-changed cookies fail closed. Return only to the same invitation with the new actual request.
5. Duplicate native GETs do not consume authentication or send a code. A deliberate enrollment start still follows the existing restart owner: retire exact prior sessions, confirm their absence, re-read Identity, activate the fresh attempt and issue new proof. Successful transition into the current flow clears its own routing hint. Completion and cancellation also clear the matching hint.

No invitation lifetime extension, canonical merge, role grant, financial mutation, PIN change or ordinary-admission activation occurs through Return or its readback. Email proof and passkey requirements remain unchanged.

## Evidence boundaries

Focused and full source tests, synthetic isolated PostgreSQL custody checks and native-browser actual-component rehearsals are separate from release artifact, GitOps convergence, actual runtime and named-person proof. The preview is synthetic and cannot qualify provider login or profile linking. Existing inherited typecheck failures remain reported.
