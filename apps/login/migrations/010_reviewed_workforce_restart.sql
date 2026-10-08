-- Original enrollment/invitation and delivery evidence are retained verbatim.
CREATE TABLE login_reviewed_workforce_restart_intents (
 operation_key uuid PRIMARY KEY, enrollment_id uuid NOT NULL REFERENCES login_reviewed_workforce_enrollments(enrollment_id),
 previous_id uuid NOT NULL, previous_binding_hash char(64) NOT NULL CHECK(previous_binding_hash ~ '^[a-f0-9]{64}$'),
 binding jsonb NOT NULL,binding_hash char(64) NOT NULL CHECK(binding_hash ~ '^[a-f0-9]{64}$'),epoch bigint NOT NULL,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),expires_at timestamptz NOT NULL,
 UNIQUE(enrollment_id,previous_id),CHECK(expires_at>created_at AND expires_at<=created_at+interval '5 minutes')
);
CREATE TABLE login_reviewed_workforce_enrollment_attempts (
 id uuid PRIMARY KEY REFERENCES login_reviewed_workforce_restart_intents(operation_key),
 enrollment_id uuid NOT NULL REFERENCES login_reviewed_workforce_enrollments(enrollment_id),previous_id uuid NOT NULL,
 binding_hash char(64) NOT NULL CHECK(binding_hash ~ '^[a-f0-9]{64}$'),binding jsonb NOT NULL,
 issuer text NOT NULL,provider_subject text NOT NULL,client_id text NOT NULL,request_id text NOT NULL,epoch bigint NOT NULL,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),expires_at timestamptz NOT NULL,
 UNIQUE(enrollment_id,previous_id),CHECK(id<>previous_id),CHECK(expires_at>created_at AND expires_at<=created_at+interval '5 minutes')
);
CREATE TABLE login_reviewed_workforce_challenge_custody (
 challenge_id uuid PRIMARY KEY REFERENCES login_workforce_challenges(id),
 enrollment_id uuid NOT NULL REFERENCES login_reviewed_workforce_enrollments(enrollment_id),attempt_id uuid NOT NULL,
 binding_hash char(64) NOT NULL CHECK(binding_hash ~ '^[a-f0-9]{64}$'),created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE login_reviewed_workforce_restart_session_observations (
 operation_key uuid NOT NULL REFERENCES login_reviewed_workforce_restart_intents(operation_key),
 challenge_id uuid NOT NULL REFERENCES login_workforce_challenges(id),provider_session_id text,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),PRIMARY KEY(operation_key,challenge_id)
);
CREATE TABLE login_reviewed_workforce_restart_session_evidence (
 operation_key uuid NOT NULL REFERENCES login_reviewed_workforce_restart_intents(operation_key),
 challenge_id uuid NOT NULL REFERENCES login_workforce_challenges(id),provider_session_id text,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),PRIMARY KEY(operation_key,challenge_id)
);
CREATE TRIGGER immutable_reviewed_restart_intent BEFORE UPDATE OR DELETE OR TRUNCATE ON login_reviewed_workforce_restart_intents FOR EACH STATEMENT EXECUTE FUNCTION login_reviewed_enrollment_immutable();
CREATE TRIGGER immutable_reviewed_enrollment_attempts BEFORE UPDATE OR DELETE OR TRUNCATE ON login_reviewed_workforce_enrollment_attempts FOR EACH STATEMENT EXECUTE FUNCTION login_reviewed_enrollment_immutable();
CREATE TRIGGER immutable_reviewed_challenge_custody BEFORE UPDATE OR DELETE OR TRUNCATE ON login_reviewed_workforce_challenge_custody FOR EACH STATEMENT EXECUTE FUNCTION login_reviewed_enrollment_immutable();
CREATE TRIGGER immutable_reviewed_restart_session_evidence BEFORE UPDATE OR DELETE OR TRUNCATE ON login_reviewed_workforce_restart_session_evidence FOR EACH STATEMENT EXECUTE FUNCTION login_reviewed_enrollment_immutable();
CREATE TRIGGER immutable_reviewed_restart_session_observations BEFORE UPDATE OR DELETE OR TRUNCATE ON login_reviewed_workforce_restart_session_observations FOR EACH STATEMENT EXECUTE FUNCTION login_reviewed_enrollment_immutable();
