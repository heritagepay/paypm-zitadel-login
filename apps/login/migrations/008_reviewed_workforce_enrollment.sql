ALTER TABLE login_workforce_challenges ADD COLUMN purpose text NOT NULL DEFAULT 'login' CHECK(purpose IN ('login','reviewed_enrollment'));
CREATE TABLE login_reviewed_workforce_enrollments (
 enrollment_id uuid PRIMARY KEY, binding_hash char(64) NOT NULL CHECK(binding_hash ~ '^[a-f0-9]{64}$'), binding jsonb NOT NULL,
 issuer text NOT NULL, provider_subject text NOT NULL, client_id text NOT NULL, request_id text NOT NULL, epoch bigint NOT NULL,
 operation_key uuid UNIQUE NOT NULL, created_at timestamptz NOT NULL DEFAULT clock_timestamp(),expires_at timestamptz NOT NULL,
 CHECK(expires_at<=created_at+interval '5 minutes')
);
CREATE TABLE login_reviewed_workforce_enrollment_challenges (
 challenge_id uuid PRIMARY KEY REFERENCES login_workforce_challenges(id), enrollment_id uuid NOT NULL REFERENCES login_reviewed_workforce_enrollments(enrollment_id),
 ceremony jsonb NOT NULL, ceremony_hash char(64) NOT NULL CHECK(ceremony_hash ~ '^[a-f0-9]{64}$'), created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE login_reviewed_workforce_profile_attempts (
 id uuid PRIMARY KEY, operation_key uuid UNIQUE NOT NULL,enrollment_id uuid NOT NULL REFERENCES login_reviewed_workforce_enrollments(enrollment_id),
 code_hash char(64) NOT NULL CHECK(code_hash ~ '^[a-f0-9]{64}$'), created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE login_reviewed_workforce_enrollment_retirements (
 enrollment_id uuid PRIMARY KEY REFERENCES login_reviewed_workforce_enrollments(enrollment_id), reason text NOT NULL CHECK(reason IN ('cancelled','completed')),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE FUNCTION login_reviewed_enrollment_immutable() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'Reviewed enrollment custody evidence retained'; END $$;
CREATE FUNCTION login_reviewed_enrollment_no_admission() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
 IF EXISTS(SELECT 1 FROM login_workforce_challenges WHERE id=NEW.challenge_id AND purpose<>'login') THEN RAISE EXCEPTION 'Enrollment cannot grant login admission'; END IF; RETURN NEW; END $$;
CREATE TRIGGER reviewed_enrollment_no_admission BEFORE INSERT ON login_workforce_admissions FOR EACH ROW EXECUTE FUNCTION login_reviewed_enrollment_no_admission();
CREATE TRIGGER immutable_reviewed_enrollment BEFORE UPDATE OR DELETE OR TRUNCATE ON login_reviewed_workforce_enrollments FOR EACH STATEMENT EXECUTE FUNCTION login_reviewed_enrollment_immutable();
CREATE TRIGGER immutable_reviewed_enrollment_challenge BEFORE UPDATE OR DELETE OR TRUNCATE ON login_reviewed_workforce_enrollment_challenges FOR EACH STATEMENT EXECUTE FUNCTION login_reviewed_enrollment_immutable();
CREATE TRIGGER immutable_reviewed_enrollment_attempt BEFORE UPDATE OR DELETE OR TRUNCATE ON login_reviewed_workforce_profile_attempts FOR EACH STATEMENT EXECUTE FUNCTION login_reviewed_enrollment_immutable();
CREATE TRIGGER immutable_reviewed_enrollment_retirement BEFORE UPDATE OR DELETE OR TRUNCATE ON login_reviewed_workforce_enrollment_retirements FOR EACH STATEMENT EXECUTE FUNCTION login_reviewed_enrollment_immutable();
