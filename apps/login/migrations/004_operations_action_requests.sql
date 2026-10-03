CREATE TABLE login_operations_action_requests (
  id uuid PRIMARY KEY, operation_key uuid NOT NULL, request_hash char(64) NOT NULL,
  issuer text NOT NULL, provider_subject text NOT NULL, base_session_id text NOT NULL,
  client_id text NOT NULL, request_id text NOT NULL, epoch bigint NOT NULL,
  binding jsonb NOT NULL, capability_hash char(64) NOT NULL, caller_material_sealed text,
  state text NOT NULL DEFAULT 'reserved' CHECK(state IN ('reserved','created','verified','consumed','cancelled','retired')),
  provider_started_at timestamptz,provider_session_id text UNIQUE,provider_material_sealed text,
  assertion_hash char(64),assertion_sealed text,verification_started_at timestamptz,
  verified_at timestamptz,receipt_hash char(64) UNIQUE,receipt_sealed text,receipt_expires_at timestamptz,
  consumed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
  expires_at timestamptz NOT NULL,
  CHECK(request_hash ~ '^[a-f0-9]{64}$'),CHECK(capability_hash ~ '^[a-f0-9]{64}$'),
  CHECK(expires_at>created_at AND expires_at<=created_at+interval '5 minutes'),
  CHECK(state NOT IN ('created','verified','consumed') OR provider_session_id IS NOT NULL),
  CHECK(state NOT IN ('verified','consumed') OR (verified_at IS NOT NULL AND receipt_hash IS NOT NULL AND receipt_expires_at IS NOT NULL)),
  CHECK(receipt_expires_at IS NULL OR (receipt_expires_at<=verified_at+interval '60 seconds' AND receipt_expires_at<=expires_at)),
  CHECK(state<>'consumed' OR consumed_at IS NOT NULL)
);
CREATE UNIQUE INDEX login_operations_action_active_operation ON login_operations_action_requests(operation_key,(binding->'expected'->>'personId'),(binding->'expected'->>'action')) WHERE state IN ('reserved','created','verified','consumed');
CREATE FUNCTION login_operations_action_immutable() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
  IF TG_OP IN ('DELETE','TRUNCATE') THEN RAISE EXCEPTION 'operations action evidence retained';END IF;
  IF (to_jsonb(OLD)-ARRAY['state','caller_material_sealed','provider_started_at','provider_session_id','provider_material_sealed','assertion_hash','assertion_sealed','verification_started_at','verified_at','receipt_hash','receipt_sealed','receipt_expires_at','consumed_at']) IS DISTINCT FROM
     (to_jsonb(NEW)-ARRAY['state','caller_material_sealed','provider_started_at','provider_session_id','provider_material_sealed','assertion_hash','assertion_sealed','verification_started_at','verified_at','receipt_hash','receipt_sealed','receipt_expires_at','consumed_at']) OR
     (OLD.provider_started_at IS NOT NULL AND OLD.provider_started_at IS DISTINCT FROM NEW.provider_started_at) OR
     (OLD.provider_session_id IS NOT NULL AND OLD.provider_session_id IS DISTINCT FROM NEW.provider_session_id) OR
     (OLD.assertion_hash IS NOT NULL AND OLD.assertion_hash IS DISTINCT FROM NEW.assertion_hash) OR
     (OLD.verification_started_at IS NOT NULL AND OLD.verification_started_at IS DISTINCT FROM NEW.verification_started_at) OR
     (OLD.verified_at IS NOT NULL AND OLD.verified_at IS DISTINCT FROM NEW.verified_at) OR
     (OLD.receipt_hash IS NOT NULL AND OLD.receipt_hash IS DISTINCT FROM NEW.receipt_hash) OR
     (OLD.receipt_expires_at IS NOT NULL AND OLD.receipt_expires_at IS DISTINCT FROM NEW.receipt_expires_at) OR
     (OLD.consumed_at IS NOT NULL AND OLD.consumed_at IS DISTINCT FROM NEW.consumed_at) OR
     (OLD.caller_material_sealed IS NOT NULL AND NEW.caller_material_sealed IS NOT NULL AND OLD.caller_material_sealed IS DISTINCT FROM NEW.caller_material_sealed) OR
     (OLD.provider_material_sealed IS NOT NULL AND NEW.provider_material_sealed IS NOT NULL AND OLD.provider_material_sealed IS DISTINCT FROM NEW.provider_material_sealed) OR
     (OLD.assertion_sealed IS NOT NULL AND NEW.assertion_sealed IS NOT NULL AND OLD.assertion_sealed IS DISTINCT FROM NEW.assertion_sealed) OR
     (OLD.receipt_sealed IS NOT NULL AND NEW.receipt_sealed IS NOT NULL AND OLD.receipt_sealed IS DISTINCT FROM NEW.receipt_sealed) OR
     (OLD.caller_material_sealed IS NULL AND NEW.caller_material_sealed IS NOT NULL) OR
     (OLD.provider_material_sealed IS NULL AND NEW.provider_material_sealed IS NOT NULL AND NOT(OLD.state='reserved' AND NEW.state='created')) OR
     (OLD.assertion_sealed IS NULL AND NEW.assertion_sealed IS NOT NULL AND OLD.verification_started_at IS NOT NULL) OR
     (OLD.receipt_sealed IS NULL AND NEW.receipt_sealed IS NOT NULL AND NOT(OLD.state='created' AND NEW.state='verified')) OR
     ((NEW.caller_material_sealed IS NULL OR NEW.provider_material_sealed IS NULL OR NEW.assertion_sealed IS NULL OR NEW.receipt_sealed IS NULL) AND NEW.state NOT IN ('reserved','created','cancelled','retired') AND NEW.expires_at>clock_timestamp() AND NEW.receipt_expires_at>clock_timestamp()) OR
     NOT(NEW.state=OLD.state OR NEW.state='retired' OR (OLD.state IN ('reserved','created','verified') AND NEW.state='cancelled') OR (OLD.state='reserved' AND NEW.state='created') OR (OLD.state='created' AND NEW.state='verified') OR (OLD.state='verified' AND NEW.state='consumed'))
     THEN RAISE EXCEPTION 'operations action binding immutable';END IF;RETURN NEW;
END $$;
CREATE TRIGGER protected_operations_action BEFORE UPDATE OR DELETE ON login_operations_action_requests FOR EACH ROW EXECUTE FUNCTION login_operations_action_immutable();
CREATE TRIGGER protected_operations_action_truncate BEFORE TRUNCATE ON login_operations_action_requests FOR EACH STATEMENT EXECUTE FUNCTION login_operations_action_immutable();
