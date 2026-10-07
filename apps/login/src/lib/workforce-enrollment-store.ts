import { createHmac, hkdfSync, randomUUID } from "node:crypto";
import type { Sql, TransactionSql } from "postgres";
import "server-only";
import { workforceAssertionHash } from "./workforce-assertion";
import type { EnrollmentProjection } from "./workforce-enrollment-identity-client";
import { workforceStore, WorkforceStore, WorkforceStoreError, type WorkforceChallenge } from "./workforce-store";
export interface EnrollmentCeremony {
  enrollmentId: string;
  personId: string;
  policyId: string;
  issuer: string;
  organizationId: string;
  clientId: string;
  providerSubject: string;
  sessionId: string;
  challengeId: string;
  epoch: string;
  issuedAt: string;
  expiresAt: string;
  sourceRevision: string;
  imageDigest: string;
  configurationSha256: string;
}
type Binding = Omit<EnrollmentProjection, "email" | "emailVerified" | "state"> & { contactHash: string; requestId: string };
export interface EnrollmentOriginal {
  enrollment_id: string;
  binding_hash: string;
  binding: Binding;
  issuer: string;
  provider_subject: string;
  client_id: string;
  request_id: string;
  epoch: string;
  created_at: Date;
  expires_at: Date;
  retirement?: string;
}
export interface ProfileDelivery {
  id: string;
  enrollment_id: string;
  operation_key: string;
  binding_hash: string;
  epoch: string;
  contact_hash: string;
  request_hash: string;
  previous_id: string | null;
  created_at: Date;
  code_expires_at: Date;
  claimed?: boolean;
  outcome?: "accepted" | "unknown";
}
export interface ProfileDeliveryAcknowledgement {
  sequence: string;
  changeAt: string;
  resourceOwner: string;
}
/** Adds only appointment associations; OTP/session/quotas/sealing/epoch remain WorkforceStore-owned. */
export class WorkforceEnrollmentStore {
  constructor(
    readonly base: WorkforceStore,
    private readonly key: Buffer,
  ) {
    if (key.length !== 32) throw new Error("Existing workforce store key required");
  }
  private index(domain: string, value: string) {
    return createHmac("sha256", Buffer.from(hkdfSync("sha256", this.key, Buffer.alloc(0), domain, 32)))
      .update(value)
      .digest("hex");
  }
  async begin(p: EnrollmentProjection, requestId: string, operationKey: string) {
    const { email, emailVerified: _verified, state: _state, ...fields } = p;
    void _verified;
    void _state;
    const binding: Binding = {
      ...fields,
      contactHash: this.index("paypm-workforce-enrollment-contact-v1", email),
      requestId,
    };
    return this.base.sql.begin(async (tx) => {
      await tx`SELECT pg_advisory_xact_lock(hashtextextended(${p.enrollmentId},0))`;
      await tx`INSERT INTO login_workforce_epochs(issuer,provider_subject) VALUES(${p.issuer},${p.providerSubject}) ON CONFLICT DO NOTHING`;
      const [epoch] = await tx<
        { epoch: string }[]
      >`SELECT epoch FROM login_workforce_epochs WHERE issuer=${p.issuer} AND provider_subject=${p.providerSubject} FOR UPDATE`;
      const [old] = await tx<
        EnrollmentOriginal[]
      >`SELECT * FROM login_reviewed_workforce_enrollments WHERE enrollment_id=${p.enrollmentId}`;
      if (old) {
        if (old.binding_hash !== workforceAssertionHash(binding))
          throw new WorkforceStoreError("enrollment_binding_changed");
        return this.original(p.enrollmentId);
      }
      const [row] = await tx<
        EnrollmentOriginal[]
      >`INSERT INTO login_reviewed_workforce_enrollments(enrollment_id,binding_hash,binding,issuer,provider_subject,client_id,request_id,epoch,operation_key,expires_at) VALUES(${p.enrollmentId},${workforceAssertionHash(binding)},${tx.json(binding as never)},${p.issuer},${p.providerSubject},${p.clientId},${requestId},${epoch.epoch},${operationKey},${new Date(Math.min(Date.now() + 299000, Date.parse(p.expiresAt)))}) RETURNING *`;
      return row;
    });
  }
  async original(id: string, allowCompleted = false, allowCancelled = false, sql: Sql | TransactionSql = this.base.sql) {
    const [r] = await sql<
      EnrollmentOriginal[]
    >`SELECT o.*,r.reason retirement FROM login_reviewed_workforce_enrollments o JOIN login_workforce_epochs e ON e.issuer=o.issuer AND e.provider_subject=o.provider_subject AND e.epoch=o.epoch LEFT JOIN login_reviewed_workforce_enrollment_retirements r ON r.enrollment_id=o.enrollment_id WHERE o.enrollment_id=${id} AND o.expires_at>clock_timestamp()`;
    if (
      !r ||
      (r.retirement &&
        !((allowCompleted && r.retirement === "completed") || (allowCancelled && r.retirement === "cancelled")))
    )
      throw new WorkforceStoreError("enrollment_not_current");
    if (r.binding_hash !== workforceAssertionHash(r.binding)) throw new WorkforceStoreError("enrollment_binding_changed");
    return r;
  }
  matches(r: EnrollmentOriginal, p: EnrollmentProjection) {
    const { email, emailVerified: _verified, state: _state, ...fields } = p;
    void _verified;
    void _state;
    if (
      r.binding_hash !==
      workforceAssertionHash({
        ...fields,
        contactHash: this.index("paypm-workforce-enrollment-contact-v1", email),
        requestId: r.request_id,
      })
    )
      throw new WorkforceStoreError("enrollment_binding_changed");
  }
  async attach(id: string, row: WorkforceChallenge) {
    const r = await this.original(id);
    if (
      row.purpose !== "reviewed_enrollment" ||
      row.issuer !== r.issuer ||
      row.provider_subject !== r.provider_subject ||
      row.client_id !== r.client_id ||
      row.request_id !== r.request_id ||
      String(row.epoch) !== String(r.epoch) ||
      !row.provider_session_id ||
      !/^[1-9]\d{0,39}$/.test(row.provider_session_id)
    )
      throw new WorkforceStoreError("enrollment_challenge_changed");
    const b = r.binding,
      ceremony: EnrollmentCeremony = {
        enrollmentId: id,
        personId: b.personId,
        policyId: b.policyId,
        issuer: b.issuer,
        organizationId: b.organizationId,
        clientId: b.clientId,
        providerSubject: b.providerSubject,
        sessionId: row.provider_session_id,
        challengeId: row.id,
        epoch: String(row.epoch),
        issuedAt: row.created_at.toISOString(),
        expiresAt: new Date(Math.min(row.expires_at.getTime(), r.expires_at.getTime())).toISOString(),
        sourceRevision: b.sourceRevision,
        imageDigest: b.imageDigest,
        configurationSha256: b.configurationSha256,
      };
    await this.base
      .sql`INSERT INTO login_reviewed_workforce_enrollment_challenges(challenge_id,enrollment_id,ceremony,ceremony_hash) VALUES(${row.id},${id},${this.base.sql.json(ceremony as never)},${workforceAssertionHash(ceremony)}) ON CONFLICT DO NOTHING`;
    const [old] = await this.base.sql<
      { ceremony_hash: string }[]
    >`SELECT ceremony_hash FROM login_reviewed_workforce_enrollment_challenges WHERE challenge_id=${row.id} AND enrollment_id=${id}`;
    if (old?.ceremony_hash !== workforceAssertionHash(ceremony))
      throw new WorkforceStoreError("enrollment_ceremony_changed");
    return ceremony;
  }
  async ceremony(id: string) {
    await this.original(id);
    const rows = await this.base.sql<
      { ceremony: EnrollmentCeremony; ceremony_hash: string }[]
    >`SELECT b.ceremony,b.ceremony_hash FROM login_reviewed_workforce_enrollment_challenges b JOIN login_workforce_challenges c ON c.id=b.challenge_id WHERE b.enrollment_id=${id} AND c.purpose='reviewed_enrollment' AND c.state='verified' AND c.expires_at>clock_timestamp()`;
    if (rows.length !== 1 || rows[0].ceremony_hash !== workforceAssertionHash(rows[0].ceremony))
      throw new WorkforceStoreError("enrollment_not_verified");
    const row = await this.base.currentEnrollmentChallenge(rows[0].ceremony.challengeId);
    if (
      row.provider_session_id !== rows[0].ceremony.sessionId ||
      String(row.epoch) !== rows[0].ceremony.epoch ||
      Date.parse(rows[0].ceremony.expiresAt) <= Date.now()
    )
      throw new WorkforceStoreError("enrollment_ceremony_changed");
    return rows[0].ceremony;
  }
  /** Immutable native send intent; reservation itself conveys no verification or permission. */
  async reserveProfileDelivery(p: EnrollmentProjection, operationKey: string, template: string, previousId?: string) {
    const contactHash = this.base.emailQuotaHash(p.issuer, p.email);
    return this.base.sql.begin(async (tx) => {
      // Same contact lock/order as Session OTP; prevents cross-stage quota races.
      await tx`SELECT pg_advisory_xact_lock(hashtextextended(${contactHash},0))`;
      await tx`SELECT pg_advisory_xact_lock(hashtextextended(${p.enrollmentId},0))`;
      await tx`SELECT epoch FROM login_workforce_epochs WHERE issuer=${p.issuer} AND provider_subject=${p.providerSubject} FOR UPDATE`;
      const original = await this.original(p.enrollmentId, false, false, tx);
      this.matches(original, p);
      if (p.emailVerified) throw new WorkforceStoreError("profile_already_verified");
      const requestHash = workforceAssertionHash({
        enrollmentId: p.enrollmentId,
        bindingHash: original.binding_hash,
        epoch: String(original.epoch),
        templateHash: workforceAssertionHash(template),
        previousId: previousId ?? null,
      });
      const [old] = await tx<
        ProfileDelivery[]
      >`SELECT * FROM login_reviewed_workforce_profile_deliveries WHERE operation_key=${operationKey}`;
      if (old) {
        if (old.request_hash !== requestHash) throw new WorkforceStoreError("idempotency_conflict");
        await this.currentProfileDelivery(p.enrollmentId, old.id, tx);
        return old;
      }
      const [current] = await tx<
        ProfileDelivery[]
      >`SELECT d.* FROM login_reviewed_workforce_profile_deliveries d WHERE d.enrollment_id=${p.enrollmentId} AND NOT EXISTS(SELECT 1 FROM login_reviewed_workforce_profile_deliveries n WHERE n.previous_id=d.id)`;
      if (previousId) {
        if (!current || current.id !== previousId) throw new WorkforceStoreError("profile_delivery_changed");
        await this.currentProfileDelivery(p.enrollmentId, previousId, tx);
      } else if (current) return current; // repeated original start observes; never creates a new send
      await this.base.assertEmailQuota(tx, contactHash);
      const [row] = await tx<
        ProfileDelivery[]
      >`INSERT INTO login_reviewed_workforce_profile_deliveries(id,enrollment_id,operation_key,binding_hash,epoch,contact_hash,request_hash,previous_id) VALUES(${randomUUID()},${p.enrollmentId},${operationKey},${original.binding_hash},${original.epoch},${contactHash},${requestHash},${previousId ?? null}) RETURNING *`;
      return row;
    });
  }
  async currentProfileDelivery(id: string, deliveryId?: string, sql: Sql | TransactionSql = this.base.sql) {
    const original = await this.original(id, false, false, sql);
    const [row] = await sql<
      ProfileDelivery[]
    >`SELECT d.*,c.delivery_id IS NOT NULL claimed,o.outcome FROM login_reviewed_workforce_profile_deliveries d LEFT JOIN login_reviewed_workforce_profile_delivery_claims c ON c.delivery_id=d.id LEFT JOIN login_reviewed_workforce_profile_delivery_outcomes o ON o.delivery_id=d.id WHERE d.enrollment_id=${id} AND NOT EXISTS(SELECT 1 FROM login_reviewed_workforce_profile_deliveries n WHERE n.previous_id=d.id)`;
    if (deliveryId && row?.id !== deliveryId) throw new WorkforceStoreError("profile_delivery_changed");
    if (row && (row.binding_hash !== original.binding_hash || String(row.epoch) !== String(original.epoch)))
      throw new WorkforceStoreError("profile_delivery_changed");
    return row;
  }
  async claimProfileDelivery(id: string, deliveryId: string) {
    return this.base.sql.begin(async (tx) => {
      await tx`SELECT pg_advisory_xact_lock(hashtextextended(${id},0))`;
      await this.currentProfileDelivery(id, deliveryId, tx);
      const inserted =
        await tx`INSERT INTO login_reviewed_workforce_profile_delivery_claims(delivery_id) VALUES(${deliveryId}) ON CONFLICT DO NOTHING RETURNING delivery_id`;
      return inserted.length === 1;
    });
  }
  async recordProfileDelivery(id: string, deliveryId: string, ack?: ProfileDeliveryAcknowledgement) {
    return this.base.sql.begin(async (tx) => {
      await tx`SELECT pg_advisory_xact_lock(hashtextextended(${id},0))`;
      await this.currentProfileDelivery(id, deliveryId, tx);
      const original = await this.original(id, false, false, tx);
      if (
        ack &&
        (!/^[1-9]\d{0,39}$/.test(ack.sequence) ||
          !Number.isFinite(Date.parse(ack.changeAt)) ||
          ack.resourceOwner !== original.binding.organizationId)
      )
        throw new WorkforceStoreError("profile_delivery_ack_changed");
      await tx`INSERT INTO login_reviewed_workforce_profile_delivery_outcomes(delivery_id,outcome,native_sequence,native_change_at,native_resource_owner) VALUES(${deliveryId},${ack ? "accepted" : "unknown"},${ack?.sequence ?? null},${ack ? new Date(ack.changeAt) : null},${ack?.resourceOwner ?? null}) ON CONFLICT DO NOTHING`;
      const [outcome] = await tx<
        {
          outcome: string;
          native_sequence: string | null;
          native_change_at: Date | null;
          native_resource_owner: string | null;
        }[]
      >`SELECT * FROM login_reviewed_workforce_profile_delivery_outcomes WHERE delivery_id=${deliveryId}`;
      if (
        outcome.outcome !== (ack ? "accepted" : "unknown") ||
        outcome.native_sequence !== (ack?.sequence ?? null) ||
        outcome.native_change_at?.getTime() !== (ack ? Date.parse(ack.changeAt) : undefined) ||
        outcome.native_resource_owner !== (ack?.resourceOwner ?? null)
      )
        throw new WorkforceStoreError("profile_delivery_ack_changed");
    });
  }
  async profileDeliveryProjection(id: string) {
    const row = await this.currentProfileDelivery(id);
    if (!row) return undefined;
    return {
      state: row.outcome ?? (row.claimed ? ("unknown" as const) : ("pending" as const)),
      attemptId: row.id,
      resendAt: new Date(row.created_at.getTime() + 60000).toISOString(),
      codeExpiresAt: row.code_expires_at.toISOString(),
    };
  }
  async profileAttempt(id: string, operationKey: string, code: string) {
    await this.original(id);
    const codeHash = this.index("paypm-workforce-profile-verification-v1", id + ":" + code);
    return this.base.sql.begin(async (tx) => {
      await tx`SELECT pg_advisory_xact_lock(hashtextextended(${id},0))`;
      const [old] = await tx<
        { code_hash: string }[]
      >`SELECT code_hash FROM login_reviewed_workforce_profile_attempts WHERE operation_key=${operationKey}`;
      if (old) {
        if (old.code_hash !== codeHash) throw new WorkforceStoreError("idempotency_conflict");
        return false;
      }
      const [count] = await tx<
        { count: number }[]
      >`SELECT count(*)::int count FROM login_reviewed_workforce_profile_attempts WHERE enrollment_id=${id}`;
      if (count.count >= 5) throw new WorkforceStoreError("profile_attempts_exhausted");
      await tx`INSERT INTO login_reviewed_workforce_profile_attempts(id,enrollment_id,operation_key,code_hash) VALUES(${randomUUID()},${id},${operationKey},${codeHash})`;
      return true;
    });
  }
  async retire(id: string, reason: "cancelled" | "completed") {
    await this.original(id, true, reason === "cancelled");
    await this.base.sql.begin(async (tx) => {
      await tx`SELECT pg_advisory_xact_lock(hashtextextended(${id},0))`;
      await this.original(id, true, reason === "cancelled", tx);
      await tx`INSERT INTO login_reviewed_workforce_enrollment_retirements(enrollment_id,reason) VALUES(${id},${reason}) ON CONFLICT DO NOTHING`;
    });
    const [old] = await this.base.sql<
      { reason: string }[]
    >`SELECT reason FROM login_reviewed_workforce_enrollment_retirements WHERE enrollment_id=${id}`;
    if (old.reason !== reason) throw new WorkforceStoreError("enrollment_retirement_changed");
    if (reason === "cancelled") {
      const rows = await this.base.sql<
        { challenge_id: string }[]
      >`SELECT challenge_id FROM login_reviewed_workforce_enrollment_challenges WHERE enrollment_id=${id}`;
      for (const r of rows) await this.base.cancelChallenge(r.challenge_id);
    }
  }
}
export function workforceEnrollmentStore() {
  const key = Buffer.from(process.env.PAYPM_WORKFORCE_STORE_KEY_BASE64 ?? "", "base64");
  return new WorkforceEnrollmentStore(workforceStore(), key);
}
