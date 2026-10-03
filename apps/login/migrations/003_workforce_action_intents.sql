CREATE TABLE login_workforce_action_intents (
  operation_key uuid PRIMARY KEY, request_hash char(64) NOT NULL,
  issuer text NOT NULL, provider_subject text NOT NULL, base_session_id text NOT NULL,
  client_id text NOT NULL, request_id text NOT NULL, epoch bigint NOT NULL, binding jsonb NOT NULL,
  state text NOT NULL DEFAULT 'reserved' CHECK(state IN ('reserved','created','registered','retired')),
  provider_started_at timestamptz,provider_session_id text UNIQUE,provider_material_sealed text,
  identity_request_id uuid UNIQUE,
  created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
  expires_at timestamptz NOT NULL DEFAULT statement_timestamp()+interval '5 minutes',
  CHECK(request_hash ~ '^[a-f0-9]{64}$'),CHECK(expires_at<=created_at+interval '5 minutes'),
  CHECK(state NOT IN ('created','registered') OR (provider_session_id IS NOT NULL AND provider_material_sealed IS NOT NULL)),
  CHECK(state<>'registered' OR identity_request_id IS NOT NULL)
);
CREATE FUNCTION login_workforce_action_immutable() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
  IF TG_OP IN ('DELETE','TRUNCATE') THEN RAISE EXCEPTION 'workforce action intent evidence retained';END IF;
  IF (to_jsonb(OLD)-ARRAY['state','provider_started_at','provider_session_id','provider_material_sealed','identity_request_id']) IS DISTINCT FROM
     (to_jsonb(NEW)-ARRAY['state','provider_started_at','provider_session_id','provider_material_sealed','identity_request_id']) OR
     (OLD.provider_started_at IS NOT NULL AND OLD.provider_started_at IS DISTINCT FROM NEW.provider_started_at) OR
     (OLD.provider_session_id IS NOT NULL AND OLD.provider_session_id IS DISTINCT FROM NEW.provider_session_id) OR
     (OLD.provider_material_sealed IS NOT NULL AND OLD.provider_material_sealed IS DISTINCT FROM NEW.provider_material_sealed) OR
     (OLD.identity_request_id IS NOT NULL AND OLD.identity_request_id IS DISTINCT FROM NEW.identity_request_id) OR
     NOT(NEW.state=OLD.state OR NEW.state='retired' OR (OLD.state='reserved' AND NEW.state='created') OR (OLD.state='created' AND NEW.state='registered'))
     THEN RAISE EXCEPTION 'workforce action intent binding immutable';END IF;RETURN NEW;
END $$;
CREATE TRIGGER protected_workforce_action_intent BEFORE UPDATE OR DELETE ON login_workforce_action_intents FOR EACH ROW EXECUTE FUNCTION login_workforce_action_immutable();
CREATE TRIGGER protected_workforce_action_intent_truncate BEFORE TRUNCATE ON login_workforce_action_intents FOR EACH STATEMENT EXECUTE FUNCTION login_workforce_action_immutable();
