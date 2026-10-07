import { createCipheriv, createDecipheriv, createHash, createHmac, hkdfSync, randomBytes, randomUUID } from "node:crypto";
import postgres, { type Sql, type TransactionSql } from "postgres";
import "server-only";
import { workforceAssertionHash } from "./workforce-assertion";

export interface WorkforceActionIntentBinding {
  operationKey: string;
  issuer: string;
  providerSubject: string;
  baseSessionId: string;
  clientId: string;
  requestId: string;
  contextId: string;
  appId: string;
  deploymentId: string;
  environment: "production" | "staging" | "sandbox";
  action: string;
  payloadHash: string;
}
export interface WorkforceActionIntent {
  operation_key: string;
  request_hash: string;
  issuer: string;
  provider_subject: string;
  base_session_id: string;
  client_id: string;
  request_id: string;
  epoch: string;
  state: "reserved" | "created" | "registered" | "retired";
  created_at: Date;
  expires_at: Date;
  provider_session_id: string | null;
  provider_material_sealed: string | null;
  provider_started_at: Date | null;
  identity_request_id: string | null;
}
export interface WorkforceActionProviderMaterial {
  sessionId: string;
  sessionToken: string;
  publicKey: Record<string, unknown>;
}

export interface WorkforceChallengeBinding {
  operationKey: string;
  issuer: string;
  userId: string;
  clientId: string;
  requestId: string;
  contact: string;
  purpose?: "reviewed_enrollment";
}
export interface WorkforceChallenge {
  id: string;
  purpose?: "login" | "reviewed_enrollment";
  operation_key: string;
  issuer: string;
  provider_subject: string;
  client_id: string;
  request_id: string;
  contact_hash: string;
  request_hash: string;
  epoch: string;
  state: "session_pending" | "delivery_pending" | "issued" | "verified" | "retired";
  provider_session_id: string | null;
  provider_token_sealed: string | null;
  created_at: Date;
  expires_at: Date;
  issued_at: Date | null;
  verified_at: Date | null;
}
export interface WorkforceAttempt {
  id: string;
  operation_key: string;
  challenge_id: string;
  code_hash: string;
  state: "pending" | "verified" | "failed";
  created_at: Date;
  completed_at: Date | null;
}
export class WorkforceStoreError extends Error {
  constructor(readonly code: string) {
    super(code);
  }
}
const hash = (v: string) => createHash("sha256").update(v).digest("hex");
type Connection = Sql | TransactionSql;

export class WorkforceStore {
  constructor(
    readonly sql: Sql,
    private readonly key: Buffer,
  ) {
    if (key.length !== 32) throw new WorkforceStoreError("workforce_store_unavailable");
  }
  private index(domain: string, value: string) {
    return createHmac("sha256", Buffer.from(hkdfSync("sha256", this.key, Buffer.alloc(0), domain, 32)))
      .update(value)
      .digest("hex");
  }
  private tokenKey() {
    return Buffer.from(hkdfSync("sha256", this.key, Buffer.alloc(0), "paypm-workforce-provider-token-v1", 32));
  }
  private seal(id: string, value: string) {
    const iv = randomBytes(12),
      cipher = createCipheriv("aes-256-gcm", this.tokenKey(), iv);
    cipher.setAAD(Buffer.from(id));
    const data = Buffer.concat([cipher.update(value, "utf8"), cipher.final()]);
    return [iv, cipher.getAuthTag(), data].map((v) => v.toString("base64url")).join(".");
  }
  token(row: WorkforceChallenge) {
    if (!row.provider_token_sealed) throw new WorkforceStoreError("provider_session_pending");
    return this.open(row.id, row.provider_token_sealed);
  }
  private open(id: string, sealed: string) {
    const [iv, tag, data] = sealed.split(".").map((v) => Buffer.from(v, "base64url")),
      cipher = createDecipheriv("aes-256-gcm", this.tokenKey(), iv);
    cipher.setAAD(Buffer.from(id));
    cipher.setAuthTag(tag);
    return Buffer.concat([cipher.update(data), cipher.final()]).toString("utf8");
  }
  async reserve(input: WorkforceChallengeBinding, previousId?: string): Promise<WorkforceChallenge> {
    const contactHash = this.index(
        "paypm-workforce-email-quota-v1",
        input.issuer + ":" + input.contact.trim().toLowerCase(),
      ),
      requestHash = hash(JSON.stringify({ ...input, contact: contactHash, previousId: previousId ?? null }));
    return this.sql.begin(async (tx) => {
      await tx`SELECT pg_advisory_xact_lock(hashtextextended(${contactHash},0))`;
      await tx`INSERT INTO login_workforce_epochs(issuer,provider_subject) VALUES(${input.issuer},${input.userId}) ON CONFLICT DO NOTHING`;
      const [epoch] = await tx<
        { epoch: string }[]
      >`SELECT epoch FROM login_workforce_epochs WHERE issuer=${input.issuer} AND provider_subject=${input.userId} FOR UPDATE`;
      const [old] = await tx<
        WorkforceChallenge[]
      >`SELECT * FROM login_workforce_challenges WHERE operation_key=${input.operationKey}`;
      if (old) {
        if (old.request_hash !== requestHash) throw new WorkforceStoreError("idempotency_conflict");
        await this.current(tx, old, false);
        return old;
      }
      const [quota] = await tx<
        { count: number; recent: boolean }[]
      >`SELECT count(*)::int AS count,coalesce(max(created_at)>clock_timestamp()-interval '60 seconds',false) AS recent FROM login_workforce_challenges WHERE contact_hash=${contactHash} AND created_at>clock_timestamp()-interval '10 minutes'`;
      if (quota.count >= 3 || quota.recent) throw new WorkforceStoreError("workforce_delivery_rate_limited");
      if (previousId) {
        const previous = await this.challenge(previousId, tx, true);
        await this.current(tx, previous);
        if (
          previous.contact_hash !== contactHash ||
          previous.issuer !== input.issuer ||
          previous.provider_subject !== input.userId ||
          previous.client_id !== input.clientId ||
          previous.request_id !== input.requestId ||
          (previous.purpose ?? "login") !== (input.purpose ?? "login")
        )
          throw new WorkforceStoreError("challenge_binding_mismatch");
        await this.retire(tx, previous);
      }
      const [row] =
        input.purpose === "reviewed_enrollment"
          ? await tx<
              WorkforceChallenge[]
            >`INSERT INTO login_workforce_challenges(id,operation_key,issuer,provider_subject,client_id,request_id,contact_hash,request_hash,epoch,purpose) VALUES(${randomUUID()},${input.operationKey},${input.issuer},${input.userId},${input.clientId},${input.requestId},${contactHash},${requestHash},${epoch.epoch},'reviewed_enrollment') RETURNING *`
          : await tx<
              WorkforceChallenge[]
            >`INSERT INTO login_workforce_challenges(id,operation_key,issuer,provider_subject,client_id,request_id,contact_hash,request_hash,epoch) VALUES(${randomUUID()},${input.operationKey},${input.issuer},${input.userId},${input.clientId},${input.requestId},${contactHash},${requestHash},${epoch.epoch}) RETURNING *`;
      return row;
    });
  }
  async challenge(id: string, sql: Connection = this.sql, lock = false): Promise<WorkforceChallenge> {
    const rows = lock
      ? await sql<WorkforceChallenge[]>`SELECT * FROM login_workforce_challenges WHERE id=${id} FOR UPDATE`
      : await sql<WorkforceChallenge[]>`SELECT * FROM login_workforce_challenges WHERE id=${id}`;
    if (!rows[0]) throw new WorkforceStoreError("challenge_not_found");
    return rows[0];
  }
  async challengeBySession(input: {
    issuer: string;
    userId: string;
    clientId: string;
    requestId: string;
    sessionId: string;
  }) {
    const [row] = await this.sql<
      WorkforceChallenge[]
    >`SELECT * FROM login_workforce_challenges WHERE issuer=${input.issuer} AND provider_subject=${input.userId} AND client_id=${input.clientId} AND request_id=${input.requestId} AND provider_session_id=${input.sessionId}`;
    if (!row) throw new WorkforceStoreError("challenge_not_found");
    return row;
  }
  async challengeForRequest(input: { issuer: string; clientId: string; requestId: string; sessionId: string }) {
    const [row] = await this.sql<
      WorkforceChallenge[]
    >`SELECT * FROM login_workforce_challenges WHERE issuer=${input.issuer} AND client_id=${input.clientId} AND request_id=${input.requestId} AND provider_session_id=${input.sessionId}`;
    if (!row) throw new WorkforceStoreError("challenge_not_found");
    return row;
  }
  async cancelChallenge(id: string) {
    await this.sql.begin(async (tx) => {
      const row = await this.challenge(id, tx, true);
      await this.retire(tx, row);
      if (row.provider_session_id) {
        await tx`UPDATE login_workforce_admissions SET revoked_at=clock_timestamp() WHERE provider_session_id=${row.provider_session_id} AND revoked_at IS NULL`;
        await tx`INSERT INTO login_workforce_revocations(provider_session_id) SELECT provider_session_id FROM login_workforce_action_intents WHERE base_session_id=${row.provider_session_id} AND provider_session_id IS NOT NULL ON CONFLICT DO NOTHING`;
        await tx`UPDATE login_workforce_action_intents SET state='retired' WHERE base_session_id=${row.provider_session_id} AND state<>'retired'`;
        await tx`INSERT INTO login_workforce_revocations(provider_session_id) SELECT provider_session_id FROM login_identity_action_requests WHERE base_session_id=${row.provider_session_id} AND provider_session_id IS NOT NULL ON CONFLICT DO NOTHING`;
        await tx`UPDATE login_identity_action_requests SET state='retired',caller_material_sealed=NULL,provider_material_sealed=NULL,assertion_sealed=NULL,receipt_sealed=NULL WHERE base_session_id=${row.provider_session_id} AND state<>'retired'`;
      }
    });
  }
  private async current(sql: Connection, row: WorkforceChallenge, requireIssued = true) {
    const [epoch] = await sql<
      { epoch: string }[]
    >`SELECT epoch FROM login_workforce_epochs WHERE issuer=${row.issuer} AND provider_subject=${row.provider_subject}`;
    if (
      !epoch ||
      String(epoch.epoch) !== String(row.epoch) ||
      row.expires_at.getTime() <= Date.now() ||
      row.state === "retired" ||
      (requireIssued && row.state !== "issued")
    )
      throw new WorkforceStoreError("challenge_not_active");
  }
  private async retire(tx: Connection, row: WorkforceChallenge) {
    await tx`UPDATE login_workforce_challenges SET state='retired',provider_token_sealed=NULL WHERE id=${row.id}`;
    if (row.provider_session_id)
      await tx`INSERT INTO login_workforce_revocations(provider_session_id) VALUES(${row.provider_session_id}) ON CONFLICT DO NOTHING`;
  }
  async session(id: string, providerSessionId: string, token: string) {
    return this.sql.begin(async (tx) => {
      const row = await this.challenge(id, tx, true);
      await this.current(tx, row, false);
      if (row.provider_session_id && row.provider_session_id !== providerSessionId)
        throw new WorkforceStoreError("provider_session_changed");
      const [next] = await tx<
        WorkforceChallenge[]
      >`UPDATE login_workforce_challenges SET provider_session_id=${providerSessionId},provider_token_sealed=${this.seal(id, token)},state=${row.state === "session_pending" ? "delivery_pending" : row.state} WHERE id=${id} RETURNING *`;
      return next;
    });
  }
  async issued(id: string) {
    return this.sql.begin(async (tx) => {
      const row = await this.challenge(id, tx, true);
      await this.current(tx, row, false);
      if (row.state === "issued") return row;
      if (row.state !== "delivery_pending") throw new WorkforceStoreError("challenge_not_ready");
      const [next] = await tx<
        WorkforceChallenge[]
      >`UPDATE login_workforce_challenges SET state='issued',issued_at=clock_timestamp() WHERE id=${id} RETURNING *`;
      return next;
    });
  }
  async claimSession(id: string) {
    const rows = await this
      .sql`UPDATE login_workforce_challenges SET session_started_at=clock_timestamp() WHERE id=${id} AND state='session_pending' AND session_started_at IS NULL AND expires_at>clock_timestamp() RETURNING id`;
    return rows.length === 1;
  }
  async claimDelivery(id: string) {
    const rows = await this
      .sql`UPDATE login_workforce_challenges SET delivery_started_at=clock_timestamp() WHERE id=${id} AND state='delivery_pending' AND delivery_started_at IS NULL AND expires_at>clock_timestamp() RETURNING id`;
    return rows.length === 1;
  }
  async orphanedSession(id: string, sessionId: string) {
    await this.sql.begin(async (tx) => {
      const row = await this.challenge(id, tx, true);
      if (row.provider_session_id && row.provider_session_id !== sessionId)
        throw new WorkforceStoreError("provider_session_changed");
      await tx`INSERT INTO login_workforce_revocations(provider_session_id) VALUES(${sessionId}) ON CONFLICT DO NOTHING`;
    });
  }
  async attempt(id: string, operationKey: string, code: string): Promise<WorkforceAttempt & { first: boolean }> {
    const codeHash = this.index("paypm-workforce-otp-attempt-v1", `${id}:${code}`);
    return this.sql.begin(async (tx) => {
      const row = await this.challenge(id, tx, true);
      const [old] = await tx<WorkforceAttempt[]>`SELECT * FROM login_workforce_attempts WHERE operation_key=${operationKey}`;
      if (old) {
        if (old.challenge_id !== id || old.code_hash !== codeHash) throw new WorkforceStoreError("idempotency_conflict");
        await this.current(tx, row, old.state !== "verified");
        return { ...old, first: false };
      }
      await this.current(tx, row);
      const [count] = await tx<
        { count: number }[]
      >`SELECT count(*)::int AS count FROM login_workforce_attempts WHERE challenge_id=${id}`;
      if (count.count >= 5) throw new WorkforceStoreError("workforce_attempts_exhausted");
      const [attempt] = await tx<
        WorkforceAttempt[]
      >`INSERT INTO login_workforce_attempts(id,operation_key,challenge_id,code_hash) VALUES(${randomUUID()},${operationKey},${id},${codeHash}) RETURNING *`;
      return { ...attempt, first: true };
    });
  }
  async failed(attemptId: string) {
    await this
      .sql`UPDATE login_workforce_attempts SET state='failed',completed_at=clock_timestamp() WHERE id=${attemptId} AND state='pending'`;
  }
  async verified(attemptId: string, verifiedAt: Date, absoluteExpiresAt: Date) {
    return this.finishVerification(attemptId, verifiedAt, absoluteExpiresAt, "login");
  }
  async verifiedEnrollment(attemptId: string, verifiedAt: Date, expiresAt: Date) {
    return this.finishVerification(attemptId, verifiedAt, expiresAt, "reviewed_enrollment");
  }
  private async finishVerification(
    attemptId: string,
    verifiedAt: Date,
    absoluteExpiresAt: Date,
    purpose: "login" | "reviewed_enrollment",
  ) {
    return this.sql.begin(async (tx) => {
      const [reference] = await tx<WorkforceAttempt[]>`SELECT * FROM login_workforce_attempts WHERE id=${attemptId}`;
      if (!reference) throw new WorkforceStoreError("attempt_not_found");
      const row = await this.challenge(reference.challenge_id, tx, true);
      if ((row.purpose ?? "login") !== purpose) throw new WorkforceStoreError("verification_purpose_mismatch");
      const [attempt] = await tx<
        WorkforceAttempt[]
      >`SELECT * FROM login_workforce_attempts WHERE id=${attemptId} FOR UPDATE`;
      await this.current(tx, row, attempt.state !== "verified");
      if (
        attempt.state === "failed" ||
        !row.provider_session_id ||
        verifiedAt.getTime() < attempt.created_at.getTime() ||
        verifiedAt.getTime() > Date.now() + 1000 ||
        absoluteExpiresAt.getTime() <= Date.now() ||
        absoluteExpiresAt.getTime() > row.created_at.getTime() + 8 * 3600000
      )
        throw new WorkforceStoreError("provider_verification_mismatch");
      if (attempt.state === "verified") return row;
      await tx`UPDATE login_workforce_attempts SET state='verified',completed_at=clock_timestamp() WHERE id=${attemptId}`;
      const [next] = await tx<
        WorkforceChallenge[]
      >`UPDATE login_workforce_challenges SET state='verified',verified_at=${verifiedAt} WHERE id=${row.id} RETURNING *`;
      if (purpose === "login")
        await tx`INSERT INTO login_workforce_admissions(provider_session_id,challenge_id,issuer,provider_subject,client_id,request_id,epoch,authentication_class,verified_at,absolute_expires_at) VALUES(${row.provider_session_id},${row.id},${row.issuer},${row.provider_subject},${row.client_id},${row.request_id},${row.epoch},'workforce_limited',${verifiedAt},${absoluteExpiresAt})`;
      return next;
    });
  }
  async currentEnrollmentChallenge(id: string) {
    const row = await this.challenge(id);
    await this.current(this.sql, row, false);
    if (
      row.purpose !== "reviewed_enrollment" ||
      !["session_pending", "delivery_pending", "issued", "verified"].includes(row.state)
    )
      throw new WorkforceStoreError("enrollment_purpose_mismatch");
    return row;
  }
  async admission(sessionId: string, userId: string, clientId: string, requestId: string): Promise<boolean> {
    const rows = await this
      .sql`UPDATE login_workforce_admissions a SET last_seen_at=clock_timestamp() FROM login_workforce_epochs e WHERE a.provider_session_id=${sessionId} AND a.provider_subject=${userId} AND a.client_id=${clientId} AND a.request_id=${requestId} AND a.issuer=e.issuer AND a.provider_subject=e.provider_subject AND a.epoch=e.epoch AND a.revoked_at IS NULL AND a.absolute_expires_at>clock_timestamp() AND a.last_seen_at>clock_timestamp()-interval '30 minutes' RETURNING a.provider_session_id`;
    return rows.length === 1;
  }
  async currentAdmission(input: { issuer: string; providerSubject: string; baseSessionId: string; clientId: string }) {
    const [row] = await this.sql<
      { request_id: string; challenge_id: string; epoch: string; verified_at: Date; absolute_expires_at: Date }[]
    >`SELECT a.request_id,a.challenge_id,a.epoch,a.verified_at,a.absolute_expires_at FROM login_workforce_admissions a JOIN login_workforce_epochs e ON a.issuer=e.issuer AND a.provider_subject=e.provider_subject AND a.epoch=e.epoch WHERE a.issuer=${input.issuer} AND a.provider_subject=${input.providerSubject} AND a.provider_session_id=${input.baseSessionId} AND a.client_id=${input.clientId} AND a.revoked_at IS NULL AND a.absolute_expires_at>clock_timestamp() AND a.last_seen_at>clock_timestamp()-interval '30 minutes'`;
    return row;
  }
  async passkeyAttempt(requestId: string, sessionId: string, assertionHash: string) {
    return this.sql.begin(async (tx) => {
      const inserted =
        await tx`INSERT INTO login_workforce_passkey_attempts(request_id,provider_session_id,assertion_hash) VALUES(${requestId},${sessionId},${assertionHash}) ON CONFLICT DO NOTHING RETURNING request_id`;
      const [row] = await tx<
        { provider_session_id: string; assertion_hash: string; state: string }[]
      >`SELECT * FROM login_workforce_passkey_attempts WHERE request_id=${requestId} FOR UPDATE`;
      if (row.provider_session_id !== sessionId || row.assertion_hash !== assertionHash || row.state === "failed")
        throw new WorkforceStoreError("passkey_attempt_conflict");
      return { first: inserted.length === 1 };
    });
  }
  private async currentAction(tx: Connection, row: WorkforceActionIntent) {
    const current =
      await tx`SELECT a.provider_session_id FROM login_workforce_admissions a JOIN login_workforce_epochs e ON a.issuer=e.issuer AND a.provider_subject=e.provider_subject AND a.epoch=e.epoch WHERE a.provider_session_id=${row.base_session_id} AND a.issuer=${row.issuer} AND a.provider_subject=${row.provider_subject} AND a.client_id=${row.client_id} AND a.request_id=${row.request_id} AND a.epoch=${row.epoch} AND a.revoked_at IS NULL AND a.absolute_expires_at>clock_timestamp() AND a.last_seen_at>clock_timestamp()-interval '30 minutes' FOR SHARE OF a,e`;
    return current.length === 1 && row.state !== "retired" && row.expires_at.getTime() > Date.now();
  }
  async reserveAction(input: WorkforceActionIntentBinding) {
    const requestHash = workforceAssertionHash(input);
    return this.sql.begin(async (tx) => {
      await tx`SELECT pg_advisory_xact_lock(hashtextextended(${input.operationKey},0))`;
      const [old] = await tx<
        WorkforceActionIntent[]
      >`SELECT * FROM login_workforce_action_intents WHERE operation_key=${input.operationKey}`;
      if (old) {
        if (old.request_hash !== requestHash) throw new WorkforceStoreError("action_intent_conflict");
        if (!(await this.currentAction(tx, old))) throw new WorkforceStoreError("action_intent_not_active");
        return old;
      }
      const [admission] = await tx<
        { epoch: string }[]
      >`SELECT a.epoch FROM login_workforce_admissions a JOIN login_workforce_epochs e ON a.issuer=e.issuer AND a.provider_subject=e.provider_subject AND a.epoch=e.epoch WHERE a.provider_session_id=${input.baseSessionId} AND a.issuer=${input.issuer} AND a.provider_subject=${input.providerSubject} AND a.client_id=${input.clientId} AND a.request_id=${input.requestId} AND a.revoked_at IS NULL AND a.absolute_expires_at>clock_timestamp() AND a.last_seen_at>clock_timestamp()-interval '30 minutes' FOR SHARE OF a,e`;
      if (!admission) throw new WorkforceStoreError("action_intent_not_active");
      const [row] = await tx<
        WorkforceActionIntent[]
      >`INSERT INTO login_workforce_action_intents(operation_key,request_hash,issuer,provider_subject,base_session_id,client_id,request_id,epoch,binding) VALUES(${input.operationKey},${requestHash},${input.issuer},${input.providerSubject},${input.baseSessionId},${input.clientId},${input.requestId},${admission.epoch},${tx.json({ ...input })}) RETURNING *`;
      return row;
    });
  }
  async claimAction(operationKey: string) {
    return this.sql.begin(async (tx) => {
      const [row] = await tx<
        WorkforceActionIntent[]
      >`SELECT * FROM login_workforce_action_intents WHERE operation_key=${operationKey} FOR UPDATE`;
      if (!row || !(await this.currentAction(tx, row))) throw new WorkforceStoreError("action_intent_not_active");
      const claimed =
        await tx`UPDATE login_workforce_action_intents SET provider_started_at=clock_timestamp() WHERE operation_key=${operationKey} AND state='reserved' AND provider_started_at IS NULL RETURNING operation_key`;
      return claimed.length === 1;
    });
  }
  actionMaterial(row: WorkforceActionIntent): WorkforceActionProviderMaterial {
    if (!row.provider_material_sealed) throw new WorkforceStoreError("action_provider_pending");
    return JSON.parse(
      this.open("action:" + row.operation_key, row.provider_material_sealed),
    ) as WorkforceActionProviderMaterial;
  }
  async actionCreated(operationKey: string, material: WorkforceActionProviderMaterial) {
    const row = await this.sql.begin(async (tx) => {
      const [row] = await tx<
        WorkforceActionIntent[]
      >`SELECT * FROM login_workforce_action_intents WHERE operation_key=${operationKey} FOR UPDATE`;
      if (!row || !(await this.currentAction(tx, row))) {
        await tx`INSERT INTO login_workforce_revocations(provider_session_id) VALUES(${material.sessionId}) ON CONFLICT DO NOTHING`;
        return undefined;
      }
      if (row.state !== "reserved") {
        if (workforceAssertionHash(this.actionMaterial(row)) !== workforceAssertionHash(material))
          throw new WorkforceStoreError("action_intent_conflict");
        return row;
      }
      if (!row.provider_started_at) throw new WorkforceStoreError("action_provider_not_reserved");
      const [saved] = await tx<
        WorkforceActionIntent[]
      >`UPDATE login_workforce_action_intents SET state='created',provider_session_id=${material.sessionId},provider_material_sealed=${this.seal("action:" + operationKey, JSON.stringify(material))} WHERE operation_key=${operationKey} RETURNING *`;
      return saved;
    });
    if (!row) throw new WorkforceStoreError("action_intent_not_active");
    return row;
  }
  async actionRegistered(operationKey: string, requestId: string) {
    return this.sql.begin(async (tx) => {
      const [row] = await tx<
        WorkforceActionIntent[]
      >`SELECT * FROM login_workforce_action_intents WHERE operation_key=${operationKey} FOR UPDATE`;
      if (!row || !(await this.currentAction(tx, row)) || !["created", "registered"].includes(row.state))
        throw new WorkforceStoreError("action_intent_not_active");
      if (row.identity_request_id) {
        if (row.identity_request_id !== requestId) throw new WorkforceStoreError("action_intent_conflict");
        return row;
      }
      const [saved] = await tx<
        WorkforceActionIntent[]
      >`UPDATE login_workforce_action_intents SET state='registered',identity_request_id=${requestId} WHERE operation_key=${operationKey} RETURNING *`;
      return saved;
    });
  }
  async abandonAction(operationKey: string, providerSessionId: string) {
    await this.sql.begin(async (tx) => {
      await tx`INSERT INTO login_workforce_revocations(provider_session_id) VALUES(${providerSessionId}) ON CONFLICT DO NOTHING`;
      await tx`UPDATE login_workforce_action_intents SET state='retired' WHERE operation_key=${operationKey} AND state='reserved'`;
    });
  }
  async reserveLegacyRetirement(
    caseId: string,
    decisionId: string,
    caseHash: string,
    binding: unknown,
    subject: string,
    organizationId: string,
  ) {
    return this.sql.begin(async (tx) => {
      await tx`INSERT INTO login_legacy_recovery_retirements(id,case_id,decision_id,case_hash,binding,provider_subject,provider_organization_id) VALUES(${randomUUID()},${caseId},${decisionId},${caseHash},${tx.json(binding as postgres.JSONValue)},${subject},${organizationId}) ON CONFLICT DO NOTHING`;
      const [row] = await tx<
        {
          id: string;
          decision_id: string;
          case_hash: string;
          provider_subject: string;
          provider_organization_id: string;
          state: "pending" | "retired";
        }[]
      >`SELECT * FROM login_legacy_recovery_retirements WHERE case_id=${caseId} FOR UPDATE`;
      if (
        !row ||
        row.decision_id !== decisionId ||
        row.case_hash !== caseHash ||
        row.provider_subject !== subject ||
        row.provider_organization_id !== organizationId
      )
        throw new WorkforceStoreError("legacy_retirement_binding_changed");
      return row;
    });
  }
  async claimLegacyRetirement(id: string) {
    const rows = await this
      .sql`UPDATE login_legacy_recovery_retirements SET attempted_at=clock_timestamp(),attempts=attempts+1 WHERE id=${id} AND state='pending' AND attempts<5 AND (attempted_at IS NULL OR attempted_at<clock_timestamp()-interval '10 seconds') RETURNING id`;
    return rows.length === 1;
  }
  async legacyRetirementConfirmed(id: string) {
    await this
      .sql`UPDATE login_legacy_recovery_retirements SET state='retired',confirmed_at=clock_timestamp() WHERE id=${id} AND state='pending'`;
  }
  async passkeyAttemptFailed(requestId: string) {
    await this
      .sql`UPDATE login_workforce_passkey_attempts SET state='failed',completed_at=clock_timestamp() WHERE request_id=${requestId} AND state='pending'`;
  }
  async passkeyAttemptVerified(requestId: string) {
    await this
      .sql`UPDATE login_workforce_passkey_attempts SET state='verified',completed_at=clock_timestamp() WHERE request_id=${requestId} AND state='pending'`;
  }
  async revoke(sessionId: string) {
    await this.sql.begin(async (tx) => {
      const [row] = await tx<
        WorkforceChallenge[]
      >`SELECT * FROM login_workforce_challenges WHERE provider_session_id=${sessionId} FOR UPDATE`;
      if (!row) return;
      await this.retire(tx, row);
      await tx`UPDATE login_workforce_admissions SET revoked_at=clock_timestamp() WHERE provider_session_id=${sessionId} AND revoked_at IS NULL`;
      await tx`INSERT INTO login_workforce_revocations(provider_session_id) SELECT provider_session_id FROM login_workforce_action_intents WHERE base_session_id=${sessionId} AND provider_session_id IS NOT NULL ON CONFLICT DO NOTHING`;
      await tx`UPDATE login_workforce_action_intents SET state='retired' WHERE base_session_id=${sessionId} AND state<>'retired'`;
      await tx`INSERT INTO login_workforce_revocations(provider_session_id) SELECT provider_session_id FROM login_identity_action_requests WHERE base_session_id=${sessionId} AND provider_session_id IS NOT NULL ON CONFLICT DO NOTHING`;
      await tx`UPDATE login_identity_action_requests SET state='retired',caller_material_sealed=NULL,provider_material_sealed=NULL,assertion_sealed=NULL,receipt_sealed=NULL WHERE base_session_id=${sessionId} AND state<>'retired'`;
    });
  }
  async revokeUser(issuer: string, userId: string) {
    await this.sql.begin(async (tx) => {
      await tx`UPDATE login_workforce_epochs SET epoch=epoch+1 WHERE issuer=${issuer} AND provider_subject=${userId}`;
      const rows = await tx<
        WorkforceChallenge[]
      >`SELECT * FROM login_workforce_challenges WHERE issuer=${issuer} AND provider_subject=${userId} AND state<>'retired' FOR UPDATE`;
      for (const row of rows) await this.retire(tx, row);
      await tx`UPDATE login_workforce_admissions SET revoked_at=clock_timestamp() WHERE issuer=${issuer} AND provider_subject=${userId} AND revoked_at IS NULL`;
      await tx`INSERT INTO login_workforce_revocations(provider_session_id) SELECT provider_session_id FROM login_workforce_action_intents WHERE issuer=${issuer} AND provider_subject=${userId} AND provider_session_id IS NOT NULL ON CONFLICT DO NOTHING`;
      await tx`UPDATE login_workforce_action_intents SET state='retired' WHERE issuer=${issuer} AND provider_subject=${userId} AND state<>'retired'`;
      await tx`INSERT INTO login_workforce_revocations(provider_session_id) SELECT provider_session_id FROM login_identity_action_requests WHERE issuer=${issuer} AND provider_subject=${userId} AND provider_session_id IS NOT NULL ON CONFLICT DO NOTHING`;
      await tx`UPDATE login_identity_action_requests SET state='retired',caller_material_sealed=NULL,provider_material_sealed=NULL,assertion_sealed=NULL,receipt_sealed=NULL WHERE issuer=${issuer} AND provider_subject=${userId} AND state<>'retired'`;
    });
  }
  async pendingRevocations() {
    return this.sql<
      { provider_session_id: string }[]
    >`SELECT provider_session_id FROM login_workforce_revocations WHERE completed_at IS NULL ORDER BY created_at LIMIT 100`;
  }
  async revocationCompleted(sessionId: string) {
    await this
      .sql`UPDATE login_workforce_revocations SET completed_at=clock_timestamp() WHERE provider_session_id=${sessionId} AND completed_at IS NULL`;
  }
}

let instance: WorkforceStore | undefined;
export function workforceStore(): WorkforceStore {
  if (instance) return instance;
  const encoded = process.env.PAYPM_WORKFORCE_STORE_KEY_BASE64,
    url = process.env.PAYPM_WORKFORCE_DATABASE_URL;
  if (!encoded || !url) throw new WorkforceStoreError("workforce_store_unavailable");
  const key = Buffer.from(encoded, "base64"),
    parsed = new URL(url);
  if (
    key.length !== 32 ||
    key.toString("base64") !== encoded ||
    !["postgres:", "postgresql:"].includes(parsed.protocol) ||
    [process.env.PAYPM_WORKFORCE_FLOW_KEY_BASE64, process.env.PAYPM_LEGACY_MIGRATION_FLOW_KEY_BASE64].includes(encoded)
  )
    throw new WorkforceStoreError("workforce_store_unavailable");
  instance = new WorkforceStore(
    postgres(url, {
      max: 5,
      connect_timeout: 5,
      idle_timeout: 20,
      ssl: process.env.NODE_ENV === "production" ? { rejectUnauthorized: true } : false,
    }),
    key,
  );
  return instance;
}
