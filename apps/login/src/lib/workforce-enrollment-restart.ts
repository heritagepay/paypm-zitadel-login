import type { TransactionSql } from "postgres";
import "server-only";
import { workforceAssertionHash } from "./workforce-assertion";
import type { EnrollmentProjection } from "./workforce-enrollment-identity-client";
import type { EnrollmentCeremony, EnrollmentOriginal, WorkforceEnrollmentStore } from "./workforce-enrollment-store";
import type { WorkforceProvider } from "./workforce-provider";
import { WorkforceStoreError, type WorkforceChallenge } from "./workforce-store";
type Binding = EnrollmentOriginal["binding"];
interface RestartIntent {
  operation_key: string;
  enrollment_id: string;
  previous_id: string;
  previous_binding_hash: string;
  binding: Binding;
  binding_hash: string;
  epoch: string;
  expires_at: Date;
}
type RetiringChallenge = WorkforceChallenge & { session_started_at: Date | null };
/** An expired authentication attempt never extends the underlying invitation or grants admission. */
export class WorkforceEnrollmentRestart {
  constructor(private readonly store: WorkforceEnrollmentStore) {}
  private identity(previous: Binding, next: Binding) {
    for (const key of [
      "enrollmentId",
      "personId",
      "policyId",
      "issuer",
      "organizationId",
      "clientId",
      "providerSubject",
      "contactHash",
    ] as const)
      if (previous[key] !== next[key]) throw new WorkforceStoreError("enrollment_binding_changed");
    if (Date.parse(next.expiresAt) > Date.parse(previous.expiresAt) || Date.parse(next.expiresAt) <= Date.now())
      throw new WorkforceStoreError("enrollment_invitation_changed");
  }
  private async locked(id: string, tx: TransactionSql) {
    await tx`SELECT pg_advisory_xact_lock(hashtextextended(${id},0))`;
    const previous = await this.store.custody(id, tx);
    const [epoch] = await tx<
      { epoch: string }[]
    >`SELECT epoch FROM login_workforce_epochs WHERE issuer=${previous.issuer} AND provider_subject=${previous.provider_subject} FOR UPDATE`;
    if (!epoch || String(epoch.epoch) !== String(previous.epoch) || previous.retirement)
      throw new WorkforceStoreError("enrollment_not_current");
    return previous;
  }
  async prepare(p: EnrollmentProjection, requestId: string, operationKey: string) {
    const binding = this.store.binding(p, requestId);
    return this.store.base.sql.begin(async (tx) => {
      const previous = await this.locked(p.enrollmentId, tx);
      const [root] = await tx<
        EnrollmentOriginal[]
      >`SELECT * FROM login_reviewed_workforce_enrollments WHERE enrollment_id=${p.enrollmentId}`;
      this.identity(root.binding, binding);
      this.identity(previous.binding, binding);
      const [already] = await tx<
        RestartIntent[]
      >`SELECT * FROM login_reviewed_workforce_restart_intents WHERE operation_key=${operationKey}`;
      if (already) {
        if (
          already.enrollment_id !== p.enrollmentId ||
          already.binding_hash !== workforceAssertionHash(binding) ||
          String(already.epoch) !== String(previous.epoch)
        )
          throw new WorkforceStoreError("idempotency_conflict");
        if (already.expires_at.getTime() <= Date.now()) throw new WorkforceStoreError("enrollment_restart_expired");
        return already;
      }
      if (previous.expires_at.getTime() > Date.now()) throw new WorkforceStoreError("enrollment_attempt_still_current");
      if (requestId === previous.request_id) throw new WorkforceStoreError("fresh_enrollment_request_required");
      const [intent] = await tx<
        RestartIntent[]
      >`INSERT INTO login_reviewed_workforce_restart_intents(operation_key,enrollment_id,previous_id,previous_binding_hash,binding,binding_hash,epoch,expires_at)
        VALUES(${operationKey},${p.enrollmentId},${previous.attempt_id ?? previous.enrollment_id},${previous.binding_hash},${tx.json(binding as never)},${workforceAssertionHash(binding)},${previous.epoch},${new Date(Math.min(Date.now() + 299000, Date.parse(p.expiresAt)))}) ON CONFLICT(enrollment_id,previous_id) DO NOTHING RETURNING *`;
      if (!intent) throw new WorkforceStoreError("enrollment_restart_owned_elsewhere");
      return intent;
    });
  }
  private async challenges(intent: RestartIntent) {
    const previous = await this.store.custody(intent.enrollment_id);
    if (
      (previous.attempt_id ?? previous.enrollment_id) !== intent.previous_id ||
      previous.binding_hash !== intent.previous_binding_hash
    )
      throw new WorkforceStoreError("enrollment_restart_changed");
    const rows = await this.store.base.sql<
      RetiringChallenge[]
    >`SELECT c.* FROM login_workforce_challenges c WHERE c.purpose='reviewed_enrollment' AND c.issuer=${previous.issuer} AND c.provider_subject=${previous.provider_subject} AND c.client_id=${previous.client_id} AND c.request_id=${previous.request_id} AND c.epoch=${previous.epoch}
      AND c.created_at>=${previous.created_at} AND c.created_at<${previous.expires_at}`;
    if (rows.length > 100) throw new WorkforceStoreError("enrollment_restart_unbounded");
    // This includes legacy unbound create claims that predate challenge associations.
    for (const row of rows) {
      await this.store.base
        .sql`INSERT INTO login_reviewed_workforce_challenge_custody(challenge_id,enrollment_id,attempt_id,binding_hash) VALUES(${row.id},${intent.enrollment_id},${intent.previous_id},${intent.previous_binding_hash}) ON CONFLICT DO NOTHING`;
      const [owned] = await this.store.base.sql<
        { enrollment_id: string; attempt_id: string; binding_hash: string }[]
      >`SELECT * FROM login_reviewed_workforce_challenge_custody WHERE challenge_id=${row.id}`;
      if (
        owned.enrollment_id !== intent.enrollment_id ||
        owned.attempt_id !== intent.previous_id ||
        owned.binding_hash !== intent.previous_binding_hash
      )
        throw new WorkforceStoreError("enrollment_challenge_changed");
    }
    return rows;
  }
  async retireSessions(intent: RestartIntent, provider: WorkforceProvider) {
    for (const row of await this.challenges(intent)) {
      // First reject any late callback/claim locally; no provider token is restored.
      await this.store.base.cancelChallenge(row.id);
      const current = (await this.store.base.challenge(row.id)) as RetiringChallenge;
      const [evidence] = await this.store.base.sql<
        { provider_session_id: string | null }[]
      >`SELECT provider_session_id FROM login_reviewed_workforce_restart_session_observations WHERE operation_key=${intent.operation_key} AND challenge_id=${row.id}`;
      let sessionId = current.provider_session_id ?? evidence?.provider_session_id;
      if (!evidence && (current.provider_session_id || current.session_started_at)) {
        const discovered = await provider.inspectActionIntent(row.id, row.provider_subject, "paypm_workforce_challenge");
        if (discovered && sessionId && discovered.id !== sessionId)
          throw new WorkforceStoreError("enrollment_retirement_changed");
        // A complete absent read can confirm an already-bound ID was deleted, but
        // cannot establish that an unbound in-flight create failed.
        if (!discovered && !sessionId) throw new WorkforceStoreError("enrollment_create_unconfirmed");
        sessionId = discovered?.id ?? sessionId;
      }
      await this.store.base
        .sql`INSERT INTO login_reviewed_workforce_restart_session_observations(operation_key,challenge_id,provider_session_id) VALUES(${intent.operation_key},${row.id},${sessionId ?? null}) ON CONFLICT DO NOTHING`;
      const [observed] = await this.store.base.sql<
        { provider_session_id: string | null }[]
      >`SELECT provider_session_id FROM login_reviewed_workforce_restart_session_observations WHERE operation_key=${intent.operation_key} AND challenge_id=${row.id}`;
      if (observed.provider_session_id !== (sessionId ?? null))
        throw new WorkforceStoreError("enrollment_retirement_changed");
      if (sessionId) {
        let retired: boolean;
        try {
          retired = await provider.retireEnrollmentChallenge(sessionId, row);
        } catch (error) {
          if (!(error instanceof WorkforceStoreError) || error.code !== "retirement_provider_binding_changed") throw error;
          const hash = await this.sealedRetirementCeremony(intent, row, sessionId);
          retired = await provider.retireEnrollmentChallenge(sessionId, row, hash);
        }
        if (!retired) throw new WorkforceStoreError("enrollment_retirement_unconfirmed");
      }
      await this.store.base
        .sql`INSERT INTO login_reviewed_workforce_restart_session_evidence(operation_key,challenge_id,provider_session_id) VALUES(${intent.operation_key},${row.id},${sessionId ?? null}) ON CONFLICT DO NOTHING`;
      const [confirmed] = await this.store.base.sql<
        { provider_session_id: string | null }[]
      >`SELECT provider_session_id FROM login_reviewed_workforce_restart_session_evidence WHERE operation_key=${intent.operation_key} AND challenge_id=${row.id}`;
      if (confirmed.provider_session_id !== (sessionId ?? null))
        throw new WorkforceStoreError("enrollment_retirement_changed");
    }
  }
  private async sealedRetirementCeremony(intent: RestartIntent, row: WorkforceChallenge, sessionId: string) {
    const previous = await this.store.custody(intent.enrollment_id);
    if (
      (previous.attempt_id ?? previous.enrollment_id) !== intent.previous_id ||
      previous.binding_hash !== intent.previous_binding_hash ||
      row.provider_session_id !== sessionId ||
      row.purpose !== "reviewed_enrollment" ||
      row.issuer !== previous.issuer ||
      row.provider_subject !== previous.provider_subject ||
      row.client_id !== previous.client_id ||
      row.request_id !== previous.request_id ||
      String(row.epoch) !== String(previous.epoch) ||
      row.created_at.getTime() < previous.created_at.getTime() ||
      row.created_at.getTime() >= previous.expires_at.getTime()
    )
      throw new WorkforceStoreError("enrollment_retirement_changed");
    const b = previous.binding;
    const expected: EnrollmentCeremony = {
      enrollmentId: intent.enrollment_id,
      personId: b.personId,
      policyId: b.policyId,
      issuer: b.issuer,
      organizationId: b.organizationId,
      clientId: b.clientId,
      providerSubject: b.providerSubject,
      sessionId,
      challengeId: row.id,
      epoch: String(row.epoch),
      issuedAt: row.created_at.toISOString(),
      expiresAt: new Date(Math.min(row.expires_at.getTime(), previous.expires_at.getTime())).toISOString(),
      sourceRevision: b.sourceRevision,
      imageDigest: b.imageDigest,
      configurationSha256: b.configurationSha256,
    };
    const rows = await this.store.base.sql<{ ceremony: EnrollmentCeremony; ceremony_hash: string }[]>`
      SELECT ceremony,ceremony_hash FROM login_reviewed_workforce_enrollment_challenges
      WHERE enrollment_id=${intent.enrollment_id} AND challenge_id=${row.id}`;
    const hash = workforceAssertionHash(expected);
    if (rows.length !== 1 || rows[0].ceremony_hash !== hash || workforceAssertionHash(rows[0].ceremony) !== hash)
      throw new WorkforceStoreError("enrollment_retirement_unconfirmed");
    return hash;
  }
  async activate(intent: RestartIntent, p: EnrollmentProjection, requestId: string) {
    const binding = this.store.binding(p, requestId);
    if (intent.binding_hash !== workforceAssertionHash(binding) || intent.expires_at.getTime() <= Date.now())
      throw new WorkforceStoreError("enrollment_restart_changed");
    return this.store.base.sql.begin(async (tx) => {
      const [stored] = await tx<
        RestartIntent[]
      >`SELECT * FROM login_reviewed_workforce_restart_intents WHERE operation_key=${intent.operation_key} AND enrollment_id=${intent.enrollment_id}`;
      if (
        !stored ||
        stored.previous_id !== intent.previous_id ||
        stored.previous_binding_hash !== intent.previous_binding_hash ||
        stored.binding_hash !== intent.binding_hash ||
        workforceAssertionHash(stored.binding) !== intent.binding_hash ||
        String(stored.epoch) !== String(intent.epoch) ||
        stored.expires_at.getTime() !== intent.expires_at.getTime()
      )
        throw new WorkforceStoreError("enrollment_restart_changed");
      const previous = await this.locked(intent.enrollment_id, tx);
      const [already] = await tx<
        { id: string }[]
      >`SELECT id FROM login_reviewed_workforce_enrollment_attempts WHERE id=${intent.operation_key} AND enrollment_id=${intent.enrollment_id}`;
      if (already) {
        this.store.matches(previous, p);
        return this.store.original(intent.enrollment_id, false, false, tx);
      }
      if (
        (previous.attempt_id ?? previous.enrollment_id) !== intent.previous_id ||
        previous.binding_hash !== intent.previous_binding_hash ||
        String(previous.epoch) !== String(intent.epoch) ||
        previous.expires_at.getTime() > Date.now()
      )
        throw new WorkforceStoreError("enrollment_restart_changed");
      this.identity(previous.binding, binding);
      const [unconfirmed] = await tx<
        { count: number }[]
      >`SELECT count(*)::int count FROM login_workforce_challenges c LEFT JOIN login_reviewed_workforce_restart_session_evidence e ON e.challenge_id=c.id AND e.operation_key=${intent.operation_key}
        WHERE c.purpose='reviewed_enrollment' AND c.issuer=${previous.issuer} AND c.provider_subject=${previous.provider_subject} AND c.client_id=${previous.client_id} AND c.request_id=${previous.request_id} AND c.epoch=${previous.epoch} AND c.created_at>=${previous.created_at} AND c.created_at<${previous.expires_at}
        AND (c.state<>'retired' OR e.challenge_id IS NULL OR (c.session_started_at IS NOT NULL AND e.provider_session_id IS NULL) OR (c.provider_session_id IS NOT NULL AND c.provider_session_id IS DISTINCT FROM e.provider_session_id))`;
      if (unconfirmed.count) throw new WorkforceStoreError("enrollment_retirement_unconfirmed");
      const [row] = await tx<
        EnrollmentOriginal[]
      >`INSERT INTO login_reviewed_workforce_enrollment_attempts(id,enrollment_id,previous_id,binding_hash,binding,issuer,provider_subject,client_id,request_id,epoch,expires_at)
        VALUES(${intent.operation_key},${intent.enrollment_id},${intent.previous_id},${intent.binding_hash},${tx.json(binding as never)},${p.issuer},${p.providerSubject},${p.clientId},${requestId},${intent.epoch},${intent.expires_at}) RETURNING *,id attempt_id`;
      return row;
    });
  }
}
