CREATE TABLE login_reviewed_workforce_profile_deliveries (
 id uuid PRIMARY KEY, enrollment_id uuid NOT NULL REFERENCES login_reviewed_workforce_enrollments(enrollment_id),
 operation_key uuid UNIQUE NOT NULL, binding_hash char(64) NOT NULL CHECK(binding_hash ~ '^[a-f0-9]{64}$'),
 epoch bigint NOT NULL, contact_hash char(64) NOT NULL CHECK(contact_hash ~ '^[a-f0-9]{64}$'),
 request_hash char(64) NOT NULL CHECK(request_hash ~ '^[a-f0-9]{64}$'),
 previous_id uuid UNIQUE REFERENCES login_reviewed_workforce_profile_deliveries(id),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 code_expires_at timestamptz NOT NULL DEFAULT clock_timestamp()+interval '3600 seconds',
 CHECK(previous_id IS NULL OR previous_id<>id),
 CHECK(code_expires_at>created_at AND code_expires_at<=created_at+interval '3601 seconds')
);
CREATE UNIQUE INDEX reviewed_profile_initial_delivery ON login_reviewed_workforce_profile_deliveries(enrollment_id) WHERE previous_id IS NULL;
CREATE INDEX reviewed_profile_contact_quota ON login_reviewed_workforce_profile_deliveries(contact_hash,created_at);
CREATE TABLE login_reviewed_workforce_profile_delivery_claims (
 delivery_id uuid PRIMARY KEY REFERENCES login_reviewed_workforce_profile_deliveries(id),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE login_reviewed_workforce_profile_delivery_outcomes (
 delivery_id uuid PRIMARY KEY REFERENCES login_reviewed_workforce_profile_delivery_claims(delivery_id),
 outcome text NOT NULL CHECK(outcome IN ('accepted','unknown')),
 native_sequence text, native_change_at timestamptz, native_resource_owner text,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 CHECK((outcome='accepted' AND native_sequence IS NOT NULL AND native_sequence ~ '^[1-9][0-9]{0,39}$' AND native_change_at IS NOT NULL AND native_resource_owner IS NOT NULL)
    OR (outcome='unknown' AND native_sequence IS NULL AND native_change_at IS NULL AND native_resource_owner IS NULL))
);
CREATE TRIGGER immutable_reviewed_profile_delivery BEFORE UPDATE OR DELETE OR TRUNCATE ON login_reviewed_workforce_profile_deliveries FOR EACH STATEMENT EXECUTE FUNCTION login_reviewed_enrollment_immutable();
CREATE TRIGGER immutable_reviewed_profile_delivery_claim BEFORE UPDATE OR DELETE OR TRUNCATE ON login_reviewed_workforce_profile_delivery_claims FOR EACH STATEMENT EXECUTE FUNCTION login_reviewed_enrollment_immutable();
CREATE TRIGGER immutable_reviewed_profile_delivery_outcome BEFORE UPDATE OR DELETE OR TRUNCATE ON login_reviewed_workforce_profile_delivery_outcomes FOR EACH STATEMENT EXECUTE FUNCTION login_reviewed_enrollment_immutable();
