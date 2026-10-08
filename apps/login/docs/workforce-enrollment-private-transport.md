# Reviewed workforce enrollment private transport

Login's server-only enrollment client may use exactly `http://heritagepay-identity-api.identity.svc.cluster.local:3000/api` as its configured Identity base. The raw string must match exactly; no alternate HTTP host, alias, port, path, spelling, userinfo, query, fragment, whitespace or trailing slash is admitted. HTTPS bases retain the existing URL validation and resolution behavior.

Identity owns the global `/api` prefix (`src/main.ts`) and `internal/v1/reviewed-workforce-enrollments` controller. The only existing client operations remain POST `/api/internal/v1/reviewed-workforce-enrollments/{original-id}/current` with `{}` and POST `/api/internal/v1/reviewed-workforce-enrollments/{original-id}/complete` with the original challenge/session body. The private URL is a transport binding, never identity, enrollment, membership or admission evidence.

The token endpoint remains HTTPS-only, including when the Identity base uses the canonical private exception. The separately registered enrollment machine credential, existing client/scopes separation, closed runtime/projection/completion validation, shared eight-second deadline,16384-byte response cap, no-store and redirect denial remain unchanged. No browser receives the token or chooses the authority.

This correction does not expose an ingress, change desired/live configuration, create credentials, call a provider, mutate SQL, grant roles or enable enrollment. Source tests use only synthetic intercepted fetch responses. Image, cluster transport, provider and original actor proof remain subsequent owner-controlled gates.
