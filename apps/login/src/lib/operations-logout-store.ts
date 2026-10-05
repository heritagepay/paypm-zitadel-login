import type { Sql } from "postgres";
import "server-only";
import { workforceAssertionHash } from "./workforce-assertion";
import { WorkforceStoreError } from "./workforce-store";
export type LogoutInput = {
  requestId: string;
  operationKey: string;
  idToken: string;
  accessToken: string;
  nonce: string;
  clientId: string;
  retirementProof: string;
};
export type LogoutAdmission = {
  personId: string;
  issuer: string;
  providerSubject: string;
  baseSessionId: string;
  clientId: string;
  appId: string;
  deploymentId: string;
  environment: "production" | "staging" | "sandbox";
  contextId: string;
  requestId: string;
  challengeId: string;
  revocationVersion: string;
};
export type LogoutRow = {
  request_id: string;
  operation_key: string;
  request_hash: string;
  person_id: string;
  issuer: string;
  provider_subject: string;
  base_session_id: string;
  client_id: string;
  app_id: string;
  deployment_id: string;
  environment: string;
  context_id: string;
  oidc_request_id: string;
  epoch: string;
  provider_session_ids: string[];
  revoked_at: Date;
};
export class OperationsLogoutStore {
  constructor(readonly sql: Sql) {}
  async read(input: LogoutInput) {
    const [row] = await this.sql<
      LogoutRow[]
    >`SELECT * FROM login_operations_logouts WHERE request_id=${input.requestId} OR operation_key=${input.operationKey}`;
    if (!row) return undefined;
    if (
      row.request_id !== input.requestId ||
      row.operation_key !== input.operationKey ||
      row.request_hash !== workforceAssertionHash(input)
    )
      throw new WorkforceStoreError("operations_logout_conflict");
    return row;
  }
  async revoke(input: LogoutInput, a: LogoutAdmission) {
    return this.sql.begin(async (tx) => {
      await tx`SELECT pg_advisory_xact_lock(hashtextextended(${input.operationKey},0))`;
      const [old] = await tx<
        LogoutRow[]
      >`SELECT * FROM login_operations_logouts WHERE request_id=${input.requestId} OR operation_key=${input.operationKey}`;
      if (old) {
        if (
          old.request_id !== input.requestId ||
          old.operation_key !== input.operationKey ||
          old.request_hash !== workforceAssertionHash(input)
        )
          throw new WorkforceStoreError("operations_logout_conflict");
        return old;
      }
      const [admission] =
        await tx`SELECT a.provider_session_id FROM login_workforce_admissions a WHERE a.provider_session_id=${a.baseSessionId} AND a.issuer=${a.issuer} AND a.provider_subject=${a.providerSubject} AND a.client_id=${a.clientId} AND a.request_id=${a.requestId} AND a.epoch=${a.revocationVersion} AND a.challenge_id=${a.challengeId} FOR UPDATE OF a`;
      if (!admission) throw new WorkforceStoreError("operations_logout_not_admitted");
      const sessions = await tx<
        { id: string }[]
      >`SELECT ${a.baseSessionId}::text AS id UNION SELECT provider_session_id FROM login_workforce_action_intents WHERE base_session_id=${a.baseSessionId} AND provider_session_id IS NOT NULL UNION SELECT provider_session_id FROM login_operations_action_requests WHERE base_session_id=${a.baseSessionId} AND provider_session_id IS NOT NULL UNION SELECT provider_session_id FROM login_identity_action_requests WHERE base_session_id=${a.baseSessionId} AND provider_session_id IS NOT NULL`;
      const ids = sessions.map((v) => v.id);
      await tx`INSERT INTO login_workforce_revocations(provider_session_id) SELECT unnest(${tx.array(ids)}) ON CONFLICT DO NOTHING`;
      await tx`UPDATE login_workforce_admissions SET revoked_at=clock_timestamp() WHERE provider_session_id=${a.baseSessionId} AND revoked_at IS NULL`;
      await tx`UPDATE login_workforce_challenges SET state='retired',provider_token_sealed=NULL WHERE provider_session_id=${a.baseSessionId} AND state<>'retired'`;
      await tx`UPDATE login_workforce_action_intents SET state='retired',provider_material_sealed=NULL WHERE base_session_id=${a.baseSessionId} AND state<>'retired'`;
      await tx`UPDATE login_operations_action_requests SET state='retired',caller_material_sealed=NULL,provider_material_sealed=NULL,assertion_sealed=NULL,receipt_sealed=NULL WHERE base_session_id=${a.baseSessionId} AND state<>'retired'`;
      await tx`UPDATE login_identity_action_requests SET state='retired',caller_material_sealed=NULL,provider_material_sealed=NULL,assertion_sealed=NULL,receipt_sealed=NULL WHERE base_session_id=${a.baseSessionId} AND state<>'retired'`;
      const [row] = await tx<
        LogoutRow[]
      >`INSERT INTO login_operations_logouts(request_id,operation_key,request_hash,person_id,issuer,provider_subject,base_session_id,client_id,app_id,deployment_id,environment,context_id,oidc_request_id,epoch,provider_session_ids) VALUES(${input.requestId},${input.operationKey},${workforceAssertionHash(input)},${a.personId},${a.issuer},${a.providerSubject},${a.baseSessionId},${a.clientId},${a.appId},${a.deploymentId},${a.environment},${a.contextId},${a.requestId},${a.revocationVersion},${tx.array(ids)}) RETURNING *`;
      return row;
    });
  }
  async pending(row: LogoutRow) {
    return this.sql<
      { provider_session_id: string }[]
    >`SELECT provider_session_id FROM login_workforce_revocations WHERE provider_session_id=ANY(${this.sql.array(row.provider_session_ids)}) AND completed_at IS NULL`;
  }
}
