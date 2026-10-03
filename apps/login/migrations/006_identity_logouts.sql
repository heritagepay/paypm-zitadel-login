-- Only retirement of an exact previously admitted Identity paired credential.
CREATE TABLE IF NOT EXISTS login_identity_logouts (
 request_hash text PRIMARY KEY CHECK(request_hash ~ '^[a-f0-9]{64}$'),
 admission jsonb NOT NULL,
 provider_session_ids text[] NOT NULL,
 revoked_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
