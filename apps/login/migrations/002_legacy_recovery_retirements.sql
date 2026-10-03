CREATE TABLE login_legacy_recovery_retirements (
  id uuid PRIMARY KEY, case_id uuid NOT NULL UNIQUE, decision_id uuid NOT NULL,
  case_hash char(64) NOT NULL, binding jsonb NOT NULL,
  provider_subject text NOT NULL, provider_organization_id text NOT NULL,
  state text NOT NULL DEFAULT 'pending' CHECK(state IN ('pending','retired')),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(), attempted_at timestamptz,
  attempts integer NOT NULL DEFAULT 0 CHECK(attempts BETWEEN 0 AND 5), confirmed_at timestamptz,
  CHECK(case_hash ~ '^[a-f0-9]{64}$'),CHECK((state='retired')=(confirmed_at IS NOT NULL))
);
CREATE FUNCTION login_legacy_retirement_immutable() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
  IF TG_OP IN ('DELETE','TRUNCATE') THEN RAISE EXCEPTION 'legacy retirement evidence retained';END IF;
  IF (to_jsonb(OLD)-ARRAY['state','attempted_at','attempts','confirmed_at']) IS DISTINCT FROM (to_jsonb(NEW)-ARRAY['state','attempted_at','attempts','confirmed_at']) OR
    OLD.state='retired' OR NEW.attempts<OLD.attempts OR (NEW.state='retired' AND NEW.confirmed_at IS NULL)
    THEN RAISE EXCEPTION 'legacy retirement binding immutable';END IF;RETURN NEW;
END $$;
CREATE TRIGGER protected_legacy_retirement BEFORE UPDATE OR DELETE ON login_legacy_recovery_retirements FOR EACH ROW EXECUTE FUNCTION login_legacy_retirement_immutable();
CREATE TRIGGER protected_legacy_retirement_truncate BEFORE TRUNCATE ON login_legacy_recovery_retirements FOR EACH STATEMENT EXECUTE FUNCTION login_legacy_retirement_immutable();
