CREATE TABLE login_operations_logouts (
  request_id uuid PRIMARY KEY,operation_key uuid NOT NULL UNIQUE,
  request_hash char(64) NOT NULL CHECK(request_hash ~ '^[a-f0-9]{64}$'),
  person_id uuid NOT NULL,issuer text NOT NULL,provider_subject text NOT NULL,
  base_session_id text NOT NULL,client_id text NOT NULL,app_id text NOT NULL,
  deployment_id varchar(128) NOT NULL CHECK(deployment_id ~ '^[a-z0-9_]{1,128}$'),
  environment text NOT NULL CHECK(environment IN ('production','staging','sandbox')),
  context_id text NOT NULL,oidc_request_id text NOT NULL,epoch bigint NOT NULL,
  provider_session_ids text[] NOT NULL,
  revoked_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE FUNCTION login_operations_logout_immutable() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
  RAISE EXCEPTION 'operations logout evidence immutable';
END $$;
CREATE TRIGGER protected_operations_logout BEFORE UPDATE OR DELETE ON login_operations_logouts FOR EACH ROW EXECUTE FUNCTION login_operations_logout_immutable();
CREATE TRIGGER protected_operations_logout_truncate BEFORE TRUNCATE ON login_operations_logouts FOR EACH STATEMENT EXECUTE FUNCTION login_operations_logout_immutable();
-- Permit only terminal secret erasure, retaining original operation/provider/Identity evidence.
CREATE OR REPLACE FUNCTION login_workforce_action_immutable() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
  IF TG_OP IN ('DELETE','TRUNCATE') THEN RAISE EXCEPTION 'workforce action intent evidence retained';END IF;
  IF (to_jsonb(OLD)-ARRAY['state','provider_started_at','provider_session_id','provider_material_sealed','identity_request_id']) IS DISTINCT FROM
     (to_jsonb(NEW)-ARRAY['state','provider_started_at','provider_session_id','provider_material_sealed','identity_request_id']) OR
     (OLD.provider_started_at IS NOT NULL AND OLD.provider_started_at IS DISTINCT FROM NEW.provider_started_at) OR
     (OLD.provider_session_id IS NOT NULL AND OLD.provider_session_id IS DISTINCT FROM NEW.provider_session_id) OR
     (OLD.provider_material_sealed IS NOT NULL AND OLD.provider_material_sealed IS DISTINCT FROM NEW.provider_material_sealed AND NOT(NEW.state='retired' AND NEW.provider_material_sealed IS NULL)) OR
     (OLD.provider_material_sealed IS NULL AND NEW.provider_material_sealed IS NOT NULL AND NOT(OLD.state='reserved' AND NEW.state='created')) OR
     (OLD.identity_request_id IS NOT NULL AND OLD.identity_request_id IS DISTINCT FROM NEW.identity_request_id) OR
     NOT(NEW.state=OLD.state OR NEW.state='retired' OR (OLD.state='reserved' AND NEW.state='created') OR (OLD.state='created' AND NEW.state='registered'))
     THEN RAISE EXCEPTION 'workforce action intent binding immutable';END IF;RETURN NEW;
END $$;
