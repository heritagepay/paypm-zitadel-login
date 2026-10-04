import type { Sql } from "postgres";
import "server-only";
import { workforceAssertionHash } from "./workforce-assertion";
export type IdentityProofPair = { idToken: string; accessToken: string; nonce: string; clientId: string };
export type IdentityLogoutAdmission = {
  personId: string;
  issuer: string;
  providerSubject: string;
  baseSessionId: string;
  clientId: string;
  contextId: string;
  appId: string;
  deploymentId: string;
  environment: string;
  requestId: string;
  challengeId: string;
  revocationVersion: string;
};
export type IdentityLogoutRow = {
  request_hash: string;
  admission: IdentityLogoutAdmission;
  provider_session_ids: string[];
  revoked_at: Date;
};
export class IdentityLogoutStore {
  constructor(readonly sql: Sql) {}
  async read(input: IdentityProofPair) {
    const [row] = await this.sql<
      IdentityLogoutRow[]
    >`SELECT * FROM login_identity_logouts WHERE request_hash=${workforceAssertionHash(input)}`;
    return row;
  }
  async revoke(input: IdentityProofPair, a: IdentityLogoutAdmission) {
    const hash = workforceAssertionHash(input);
    return this.sql.begin(async (tx) => {
      await tx`SELECT pg_advisory_xact_lock(hashtextextended(${`identity-logout:${hash}`},0))`;
      const [old] = await tx<IdentityLogoutRow[]>`SELECT * FROM login_identity_logouts WHERE request_hash=${hash}`;
      if (old) return old;
      const [current] =
        await tx`SELECT a.provider_session_id FROM login_workforce_admissions a JOIN login_workforce_epochs e ON a.issuer=e.issuer AND a.provider_subject=e.provider_subject AND a.epoch=e.epoch WHERE a.provider_session_id=${a.baseSessionId} AND a.issuer=${a.issuer} AND a.provider_subject=${a.providerSubject} AND a.client_id=${a.clientId} AND a.request_id=${a.requestId} AND a.epoch=${a.revocationVersion} AND a.challenge_id=${a.challengeId} AND a.revoked_at IS NULL AND a.absolute_expires_at>clock_timestamp() AND a.last_seen_at>clock_timestamp()-interval '30 minutes' FOR UPDATE OF a FOR SHARE OF e`;
      if (!current || a.appId !== "identity-administration") throw new Error("Identity logout not admitted");
      const sessions = await tx<
        { id: string }[]
      >`SELECT ${a.baseSessionId}::text AS id UNION SELECT provider_session_id FROM login_workforce_action_intents WHERE base_session_id=${a.baseSessionId} AND provider_session_id IS NOT NULL UNION SELECT provider_session_id FROM login_operations_action_requests WHERE base_session_id=${a.baseSessionId} AND provider_session_id IS NOT NULL`;
      const ids = sessions.map((row) => row.id);
      await tx`INSERT INTO login_workforce_revocations(provider_session_id) SELECT unnest(${tx.array(ids)}) ON CONFLICT DO NOTHING`;
      await tx`UPDATE login_workforce_admissions SET revoked_at=clock_timestamp() WHERE provider_session_id=${a.baseSessionId} AND revoked_at IS NULL`;
      await tx`UPDATE login_workforce_challenges SET state='retired',provider_token_sealed=NULL WHERE provider_session_id=${a.baseSessionId} AND state<>'retired'`;
      await tx`UPDATE login_workforce_action_intents SET state='retired',provider_material_sealed=NULL WHERE base_session_id=${a.baseSessionId} AND state<>'retired'`;
      await tx`UPDATE login_operations_action_requests SET state='retired',caller_material_sealed=NULL,provider_material_sealed=NULL,assertion_sealed=NULL,receipt_sealed=NULL WHERE base_session_id=${a.baseSessionId} AND state<>'retired'`;
      const [row] = await tx<
        IdentityLogoutRow[]
      >`INSERT INTO login_identity_logouts(request_hash,admission,provider_session_ids) VALUES(${hash},${tx.json(a)},${tx.array(ids)}) RETURNING *`;
      return row;
    });
  }
  async pending(row: IdentityLogoutRow) {
    return this.sql<
      { provider_session_id: string }[]
    >`SELECT provider_session_id FROM login_workforce_revocations WHERE provider_session_id=ANY(${this.sql.array(row.provider_session_ids)}) AND completed_at IS NULL`;
  }
}
