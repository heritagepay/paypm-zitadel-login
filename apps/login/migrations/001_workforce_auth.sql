CREATE TABLE login_workforce_epochs (
  issuer text NOT NULL, provider_subject text NOT NULL,
  epoch bigint NOT NULL DEFAULT 0, PRIMARY KEY(issuer,provider_subject)
);
CREATE TABLE login_workforce_challenges (
  id uuid PRIMARY KEY, operation_key uuid NOT NULL UNIQUE,
  issuer text NOT NULL, provider_subject text NOT NULL, client_id text NOT NULL, request_id text NOT NULL,
  contact_hash char(64) NOT NULL, request_hash char(64) NOT NULL, epoch bigint NOT NULL,
  state text NOT NULL DEFAULT 'session_pending' CHECK(state IN ('session_pending','delivery_pending','issued','verified','retired')),
  provider_session_id text UNIQUE, provider_token_sealed text,
  created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
  expires_at timestamptz NOT NULL DEFAULT statement_timestamp()+interval '5 minutes',
  issued_at timestamptz, verified_at timestamptz,
  session_started_at timestamptz, delivery_started_at timestamptz,
  CHECK(contact_hash ~ '^[a-f0-9]{64}$' AND request_hash ~ '^[a-f0-9]{64}$'),
  CHECK(expires_at<=created_at+interval '5 minutes'),
  CHECK(state NOT IN ('delivery_pending','issued','verified') OR provider_session_id IS NOT NULL),
  CHECK(state<>'verified' OR verified_at IS NOT NULL)
);
CREATE INDEX login_workforce_contact_quota ON login_workforce_challenges(contact_hash,created_at);
CREATE TABLE login_workforce_attempts (
  id uuid PRIMARY KEY, operation_key uuid NOT NULL UNIQUE,
  challenge_id uuid NOT NULL REFERENCES login_workforce_challenges(id),
  code_hash char(64) NOT NULL, state text NOT NULL DEFAULT 'pending' CHECK(state IN ('pending','verified','failed')),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(), completed_at timestamptz
);
CREATE TABLE login_workforce_admissions (
  provider_session_id text PRIMARY KEY,
  challenge_id uuid NOT NULL UNIQUE REFERENCES login_workforce_challenges(id),
  issuer text NOT NULL, provider_subject text NOT NULL, client_id text NOT NULL, request_id text NOT NULL,
  epoch bigint NOT NULL, authentication_class text NOT NULL CHECK(authentication_class='workforce_limited'),
  verified_at timestamptz NOT NULL, absolute_expires_at timestamptz NOT NULL,
  last_seen_at timestamptz NOT NULL DEFAULT clock_timestamp(), revoked_at timestamptz
);
CREATE TABLE login_workforce_revocations (
  provider_session_id text PRIMARY KEY,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(), completed_at timestamptz
);
CREATE FUNCTION login_workforce_immutable_binding() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
  IF TG_OP IN ('DELETE','TRUNCATE') THEN RAISE EXCEPTION 'workforce authentication evidence retained'; END IF;
  IF TG_TABLE_NAME='login_workforce_challenges' THEN
    IF (to_jsonb(OLD)-ARRAY['state','provider_session_id','provider_token_sealed','issued_at','verified_at','session_started_at','delivery_started_at']) IS DISTINCT FROM
       (to_jsonb(NEW)-ARRAY['state','provider_session_id','provider_token_sealed','issued_at','verified_at','session_started_at','delivery_started_at']) OR
       (OLD.session_started_at IS NOT NULL AND OLD.session_started_at IS DISTINCT FROM NEW.session_started_at) OR
       (OLD.delivery_started_at IS NOT NULL AND OLD.delivery_started_at IS DISTINCT FROM NEW.delivery_started_at) OR
       (OLD.provider_session_id IS NOT NULL AND OLD.provider_session_id IS DISTINCT FROM NEW.provider_session_id) OR
       (OLD.issued_at IS NOT NULL AND OLD.issued_at IS DISTINCT FROM NEW.issued_at) OR
       (OLD.verified_at IS NOT NULL AND OLD.verified_at IS DISTINCT FROM NEW.verified_at) OR
       NOT (NEW.state=OLD.state OR NEW.state='retired' OR (OLD.state='session_pending' AND NEW.state='delivery_pending') OR (OLD.state='delivery_pending' AND NEW.state='issued') OR (OLD.state='issued' AND NEW.state='verified')) THEN RAISE EXCEPTION 'workforce challenge binding immutable'; END IF;
  ELSIF TG_TABLE_NAME='login_workforce_admissions' THEN
    IF (to_jsonb(OLD)-ARRAY['last_seen_at','revoked_at']) IS DISTINCT FROM (to_jsonb(NEW)-ARRAY['last_seen_at','revoked_at']) OR
       (OLD.revoked_at IS NOT NULL AND OLD.revoked_at IS DISTINCT FROM NEW.revoked_at) THEN RAISE EXCEPTION 'workforce admission binding immutable'; END IF;
  ELSE
    IF (to_jsonb(OLD)-ARRAY['state','completed_at']) IS DISTINCT FROM (to_jsonb(NEW)-ARRAY['state','completed_at']) OR
       OLD.state<>'pending' THEN RAISE EXCEPTION 'workforce attempt binding immutable'; END IF;
  END IF; RETURN NEW;
END $$;
CREATE TRIGGER protected_workforce_challenge BEFORE UPDATE OR DELETE ON login_workforce_challenges FOR EACH ROW EXECUTE FUNCTION login_workforce_immutable_binding();
CREATE TRIGGER protected_workforce_challenge_truncate BEFORE TRUNCATE ON login_workforce_challenges FOR EACH STATEMENT EXECUTE FUNCTION login_workforce_immutable_binding();
CREATE TRIGGER protected_workforce_admission BEFORE UPDATE OR DELETE ON login_workforce_admissions FOR EACH ROW EXECUTE FUNCTION login_workforce_immutable_binding();
CREATE TRIGGER protected_workforce_admission_truncate BEFORE TRUNCATE ON login_workforce_admissions FOR EACH STATEMENT EXECUTE FUNCTION login_workforce_immutable_binding();
CREATE TRIGGER protected_workforce_attempt BEFORE UPDATE OR DELETE ON login_workforce_attempts FOR EACH ROW EXECUTE FUNCTION login_workforce_immutable_binding();
CREATE TRIGGER protected_workforce_attempt_truncate BEFORE TRUNCATE ON login_workforce_attempts FOR EACH STATEMENT EXECUTE FUNCTION login_workforce_immutable_binding();
CREATE TABLE login_workforce_passkey_attempts (
  request_id uuid PRIMARY KEY, provider_session_id text NOT NULL,
  assertion_hash char(64) NOT NULL CHECK(assertion_hash ~ '^[a-f0-9]{64}$'),
  state text NOT NULL DEFAULT 'pending' CHECK(state IN ('pending','verified','failed')),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(), completed_at timestamptz
);
CREATE TRIGGER protected_workforce_passkey_attempt BEFORE UPDATE OR DELETE ON login_workforce_passkey_attempts FOR EACH ROW EXECUTE FUNCTION login_workforce_immutable_binding();
CREATE TRIGGER protected_workforce_passkey_attempt_truncate BEFORE TRUNCATE ON login_workforce_passkey_attempts FOR EACH STATEMENT EXECUTE FUNCTION login_workforce_immutable_binding();
