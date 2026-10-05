CREATE TABLE login_identity_action_requests (
  id uuid PRIMARY KEY, operation_key uuid NOT NULL, request_hash char(64) NOT NULL,
  issuer text NOT NULL, provider_subject text NOT NULL, base_session_id text NOT NULL,
  client_id text NOT NULL, request_id text NOT NULL, epoch bigint NOT NULL,
  binding jsonb NOT NULL, capability_hash char(64) NOT NULL, caller_material_sealed text,
  state text NOT NULL DEFAULT 'reserved' CHECK(state IN ('reserved','created','registered','verified','cancelled','retired')),
  predecessor_request_id uuid UNIQUE REFERENCES login_identity_action_requests(id),
  proof_id uuid UNIQUE,proof_expires_at timestamptz,
  provider_conflicted boolean NOT NULL DEFAULT false,
  provider_started_at timestamptz,provider_session_id text UNIQUE,provider_material_sealed text,
  assertion_hash char(64),assertion_sealed text,verification_started_at timestamptz,
  verified_at timestamptz,receipt_hash char(64) UNIQUE,receipt_sealed text,receipt_expires_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
  expires_at timestamptz NOT NULL,
  CHECK((binding->'command'->>'purpose'='wallet_legacy_linkage' AND binding->'expected'->>'appId'='identity-administration' AND binding->'expected'->>'action' IN ('identity.wallet.legacy.linkage.intake','identity.wallet.legacy.linkage.review')) IS TRUE),
  CHECK((jsonb_typeof(binding)='object' AND binding->>'caseId'=operation_key::text AND binding->'command'->>'operationKey'=operation_key::text AND binding->'expected'->>'issuer'=issuer AND binding->'expected'->>'providerSubject'=provider_subject AND binding->'expected'->>'baseSessionId'=base_session_id AND binding->'expected'->>'clientId'=client_id) IS TRUE),
  CHECK(NOT provider_conflicted OR (state='retired' AND provider_session_id IS NOT NULL AND caller_material_sealed IS NULL AND provider_material_sealed IS NULL AND assertion_sealed IS NULL AND receipt_sealed IS NULL)),
  CHECK(provider_session_id IS NULL OR provider_session_id ~ '^[1-9][0-9]{0,39}$'),
  CHECK(provider_subject ~ '^[1-9][0-9]{0,39}$' AND base_session_id ~ '^[1-9][0-9]{0,39}$'),
  CHECK(request_hash ~ '^[a-f0-9]{64}$'),CHECK(capability_hash ~ '^[a-f0-9]{64}$'),
  CHECK(expires_at>created_at AND expires_at<=created_at+interval '5 minutes'),
  CHECK(state NOT IN ('created','registered','verified') OR provider_session_id IS NOT NULL),
  CHECK(state<>'verified' OR (verified_at IS NOT NULL AND receipt_hash IS NOT NULL AND receipt_expires_at IS NOT NULL)),
  CHECK(receipt_expires_at IS NULL OR (receipt_expires_at<=verified_at+interval '60 seconds' AND receipt_expires_at<=proof_expires_at)),
  CHECK(provider_started_at IS NULL OR (provider_started_at>=created_at AND provider_started_at<expires_at)),
  CHECK(verification_started_at IS NULL OR (provider_started_at IS NOT NULL AND verification_started_at>=provider_started_at AND verification_started_at<expires_at)),
  CHECK(verified_at IS NULL OR (verification_started_at IS NOT NULL AND verified_at>=verification_started_at)),
  CHECK((proof_id IS NULL)=(proof_expires_at IS NULL)),
  CHECK(state NOT IN ('registered','verified') OR (proof_id IS NOT NULL AND proof_expires_at IS NOT NULL)),
  CHECK((assertion_hash IS NULL)=(verification_started_at IS NULL)),
  CHECK(assertion_hash IS NULL OR assertion_hash ~ '^[a-f0-9]{64}$'),
  CHECK(receipt_hash IS NULL OR receipt_hash ~ '^[a-f0-9]{64}$'),
  CHECK(state IN ('cancelled','retired') OR caller_material_sealed IS NOT NULL),
  CHECK(state NOT IN ('created','registered','verified') OR provider_material_sealed IS NOT NULL),
  CHECK(state<>'verified' OR (assertion_sealed IS NOT NULL AND receipt_sealed IS NOT NULL AND proof_id IS NOT NULL)),
  CHECK(proof_expires_at IS NULL OR (proof_expires_at>created_at AND proof_expires_at<=created_at+interval '10 minutes'))
);
CREATE UNIQUE INDEX login_identity_action_active_operation ON login_identity_action_requests(operation_key,(binding->'expected'->>'personId'),(binding->'expected'->>'action')) WHERE state IN ('reserved','created','registered','verified');
CREATE FUNCTION login_identity_action_immutable() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
  IF TG_OP IN ('DELETE','TRUNCATE') THEN RAISE EXCEPTION 'identity action evidence retained';END IF;
  IF (to_jsonb(OLD)-ARRAY['state','provider_conflicted','caller_material_sealed','provider_started_at','provider_session_id','provider_material_sealed','assertion_hash','assertion_sealed','verification_started_at','verified_at','receipt_hash','receipt_sealed','receipt_expires_at','proof_id','proof_expires_at']) IS DISTINCT FROM
     (to_jsonb(NEW)-ARRAY['state','provider_conflicted','caller_material_sealed','provider_started_at','provider_session_id','provider_material_sealed','assertion_hash','assertion_sealed','verification_started_at','verified_at','receipt_hash','receipt_sealed','receipt_expires_at','proof_id','proof_expires_at']) OR
     (OLD.provider_conflicted AND NOT NEW.provider_conflicted) OR
     (NOT OLD.provider_conflicted AND NEW.provider_conflicted AND NOT(OLD.provider_session_id IS NOT NULL AND NEW.provider_session_id=OLD.provider_session_id AND NEW.state='retired')) OR
     (OLD.provider_started_at IS NULL AND NEW.provider_started_at IS NOT NULL AND NOT(OLD.state='reserved' AND NEW.state='reserved')) OR
     (OLD.provider_started_at IS NOT NULL AND OLD.provider_started_at IS DISTINCT FROM NEW.provider_started_at) OR
     (OLD.provider_session_id IS NULL AND NEW.provider_session_id IS NOT NULL AND NOT((OLD.state='reserved' AND NEW.state='created') OR (OLD.provider_started_at IS NOT NULL AND NEW.state IN ('cancelled','retired') AND NEW.provider_material_sealed IS NULL))) OR
     (OLD.provider_session_id IS NOT NULL AND OLD.provider_session_id IS DISTINCT FROM NEW.provider_session_id) OR
     (OLD.assertion_hash IS NULL AND NEW.assertion_hash IS NOT NULL AND NOT(OLD.state='registered' AND NEW.state='registered')) OR
     (OLD.assertion_hash IS NOT NULL AND OLD.assertion_hash IS DISTINCT FROM NEW.assertion_hash) OR
     (OLD.verification_started_at IS NOT NULL AND OLD.verification_started_at IS DISTINCT FROM NEW.verification_started_at) OR
     (OLD.verified_at IS NOT NULL AND OLD.verified_at IS DISTINCT FROM NEW.verified_at) OR
     (OLD.receipt_hash IS NOT NULL AND OLD.receipt_hash IS DISTINCT FROM NEW.receipt_hash) OR
     (OLD.receipt_expires_at IS NOT NULL AND OLD.receipt_expires_at IS DISTINCT FROM NEW.receipt_expires_at) OR
     (OLD.proof_id IS NULL AND NEW.proof_id IS NOT NULL AND NOT(OLD.state='created' AND NEW.state='registered')) OR
     (OLD.proof_id IS NOT NULL AND OLD.proof_id IS DISTINCT FROM NEW.proof_id) OR
     (OLD.proof_expires_at IS NOT NULL AND OLD.proof_expires_at IS DISTINCT FROM NEW.proof_expires_at) OR
     (OLD.caller_material_sealed IS NOT NULL AND NEW.caller_material_sealed IS NOT NULL AND OLD.caller_material_sealed IS DISTINCT FROM NEW.caller_material_sealed) OR
     (OLD.provider_material_sealed IS NOT NULL AND NEW.provider_material_sealed IS NOT NULL AND OLD.provider_material_sealed IS DISTINCT FROM NEW.provider_material_sealed) OR
     (OLD.assertion_sealed IS NOT NULL AND NEW.assertion_sealed IS NOT NULL AND OLD.assertion_sealed IS DISTINCT FROM NEW.assertion_sealed) OR
     (OLD.receipt_sealed IS NOT NULL AND NEW.receipt_sealed IS NOT NULL AND OLD.receipt_sealed IS DISTINCT FROM NEW.receipt_sealed) OR
     (OLD.caller_material_sealed IS NULL AND NEW.caller_material_sealed IS NOT NULL) OR
     (OLD.provider_material_sealed IS NULL AND NEW.provider_material_sealed IS NOT NULL AND NOT(OLD.state='reserved' AND NEW.state='created')) OR
     (OLD.assertion_sealed IS NULL AND NEW.assertion_sealed IS NOT NULL AND OLD.verification_started_at IS NOT NULL) OR
     (OLD.receipt_sealed IS NULL AND NEW.receipt_sealed IS NOT NULL AND NOT(OLD.state='registered' AND NEW.state='verified')) OR
     ((OLD.caller_material_sealed IS NOT NULL AND NEW.caller_material_sealed IS NULL OR OLD.provider_material_sealed IS NOT NULL AND NEW.provider_material_sealed IS NULL OR OLD.assertion_sealed IS NOT NULL AND NEW.assertion_sealed IS NULL OR OLD.receipt_sealed IS NOT NULL AND NEW.receipt_sealed IS NULL) AND NEW.state NOT IN ('cancelled','retired')) OR
     NOT(NEW.state=OLD.state OR NEW.state='retired' OR (OLD.state IN ('reserved','created','registered','verified') AND NEW.state='cancelled') OR (OLD.state='reserved' AND NEW.state='created') OR (OLD.state='created' AND NEW.state='registered') OR (OLD.state='registered' AND NEW.state='verified'))
     THEN RAISE EXCEPTION 'identity action binding immutable';END IF;RETURN NEW;
END $$;
CREATE TRIGGER protected_identity_action BEFORE UPDATE OR DELETE ON login_identity_action_requests FOR EACH ROW EXECUTE FUNCTION login_identity_action_immutable();
CREATE TRIGGER protected_identity_action_truncate BEFORE TRUNCATE ON login_identity_action_requests FOR EACH STATEMENT EXECUTE FUNCTION login_identity_action_immutable();
