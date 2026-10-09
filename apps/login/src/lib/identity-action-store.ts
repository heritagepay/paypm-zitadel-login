import { createCipheriv, createDecipheriv, createHash, hkdfSync, randomBytes } from "node:crypto";
import type { Sql, TransactionSql } from "postgres";
import "server-only";
import {
  sameIdentityBinding,
  sameIdentityOwner,
  type IdentityActionBinding,
  type IdentityActionPair,
} from "./identity-action-contract";
import { workforceAssertionHash } from "./workforce-assertion";
import { workforceStore, WorkforceStoreError, type WorkforceActionProviderMaterial } from "./workforce-store";
export type IdentityCallerMaterial = IdentityActionPair & { capability: string; callbackState: string; callbackUrl: string };
export type IdentityActionRow = {
  id: string;
  operation_key: string;
  request_hash: string;
  issuer: string;
  provider_subject: string;
  base_session_id: string;
  client_id: string;
  request_id: string;
  epoch: string;
  binding: IdentityActionBinding;
  capability_hash: string;
  caller_material_sealed: string | null;
  predecessor_request_id: string | null;
  state: "reserved" | "created" | "registered" | "verified" | "cancelled" | "retired";
  provider_conflicted: boolean;
  provider_started_at: Date | null;
  provider_session_id: string | null;
  provider_material_sealed: string | null;
  proof_id: string | null;
  proof_expires_at: Date | null;
  assertion_hash: string | null;
  assertion_sealed: string | null;
  verification_started_at: Date | null;
  verified_at: Date | null;
  receipt_hash: string | null;
  receipt_sealed: string | null;
  receipt_expires_at: Date | null;
  created_at: Date;
  expires_at: Date;
};
const sha = (v: string) => createHash("sha256").update(v).digest("hex");
type Connection = Sql | TransactionSql;
export class IdentityActionStore {
  private readonly key: Buffer;
  constructor(
    readonly sql: Sql,
    key: Buffer,
  ) {
    if (key.length !== 32) throw new WorkforceStoreError("identity_action_store_unavailable");
    this.key = Buffer.from(hkdfSync("sha256", key, Buffer.alloc(0), Buffer.from("paypm-identity-action-store-v1"), 32));
  }
  private seal(id: string, purpose: string, value: unknown) {
    const iv = randomBytes(12),
      cipher = createCipheriv("aes-256-gcm", this.key, iv);
    cipher.setAAD(Buffer.from(`identity:${purpose}:${id}`));
    const body = Buffer.concat([cipher.update(JSON.stringify(value), "utf8"), cipher.final()]);
    return Buffer.concat([iv, cipher.getAuthTag(), body]).toString("base64url");
  }
  private open<T>(row: IdentityActionRow, purpose: string, value: string | null): T {
    if (!value) throw new WorkforceStoreError("identity_action_material_unavailable");
    const bytes = Buffer.from(value, "base64url"),
      cipher = createDecipheriv("aes-256-gcm", this.key, bytes.subarray(0, 12));
    cipher.setAAD(Buffer.from(`identity:${purpose}:${row.id}`));
    cipher.setAuthTag(bytes.subarray(12, 28));
    return JSON.parse(Buffer.concat([cipher.update(bytes.subarray(28)), cipher.final()]).toString("utf8"));
  }
  caller(row: IdentityActionRow) {
    return this.open<IdentityCallerMaterial>(row, "caller", row.caller_material_sealed);
  }
  provider(row: IdentityActionRow) {
    return this.open<WorkforceActionProviderMaterial>(row, "provider", row.provider_material_sealed);
  }
  assertion(row: IdentityActionRow) {
    return this.open<Record<string, any>>(row, "assertion", row.assertion_sealed);
  }
  receipt(row: IdentityActionRow) {
    return this.open<string>(row, "receipt", row.receipt_sealed);
  }
  private async admission(tx: Connection, binding: IdentityActionBinding, requestId: string) {
    const e = binding.expected;
    const [row] = await tx<
      { epoch: string }[]
    >`SELECT a.epoch FROM login_workforce_admissions a JOIN login_workforce_epochs e ON a.issuer=e.issuer AND a.provider_subject=e.provider_subject AND a.epoch=e.epoch WHERE a.issuer=${e.issuer} AND a.provider_subject=${e.providerSubject} AND a.provider_session_id=${e.baseSessionId} AND a.client_id=${e.clientId} AND a.request_id=${requestId} AND a.revoked_at IS NULL AND a.absolute_expires_at>clock_timestamp() AND a.last_seen_at>clock_timestamp()-interval '30 minutes' FOR SHARE OF a,e`;
    if (!row) throw new WorkforceStoreError("identity_action_not_active");
    return row;
  }
  private async current(tx: Connection, row: IdentityActionRow, terminal = false) {
    if (row.provider_conflicted) throw new WorkforceStoreError("identity_action_conflict");
    if ((!terminal && ["retired", "cancelled"].includes(row.state)) || (!terminal && row.expires_at.getTime() <= Date.now()))
      throw new WorkforceStoreError("identity_action_not_active");
    const admission = await this.admission(tx, row.binding, row.request_id);
    if (String(admission.epoch) !== String(row.epoch)) throw new WorkforceStoreError("identity_action_not_active");
  }
  async reserve(input: {
    id: string;
    binding: IdentityActionBinding;
    requestId: string;
    material: IdentityCallerMaterial;
    predecessor?: IdentityActionRow;
  }) {
    const e = input.binding.expected;
    const hash = workforceAssertionHash({
      id: input.id,
      binding: input.binding,
      callbackState: input.material.callbackState,
      callbackUrl: input.material.callbackUrl,
      idTokenHash: sha(input.material.idToken),
      accessTokenHash: sha(input.material.accessToken),
      nonceHash: sha(input.material.nonce),
      predecessorRequestId: input.predecessor?.id ?? null,
    });
    return this.sql.begin(async (tx) => {
      await tx`SELECT pg_advisory_xact_lock(hashtextextended(${`${input.binding.caseId}:${e.personId}:${e.action}`},0))`;
      const [old] = await tx<
        IdentityActionRow[]
      >`SELECT * FROM login_identity_action_requests WHERE id=${input.id} FOR UPDATE`;
      if (old) {
        if (old.request_hash !== hash) throw new WorkforceStoreError("identity_action_conflict");
        await this.current(tx, old);
        return old;
      }
      const history = await tx<
        IdentityActionRow[]
      >`SELECT * FROM login_identity_action_requests WHERE operation_key=${input.binding.caseId} AND binding->'expected'->>'personId'=${e.personId} AND binding->'expected'->>'action'=${e.action} FOR UPDATE`;
      if (history.length && !input.predecessor) throw new WorkforceStoreError("identity_action_original_required");
      const active = await tx<
        IdentityActionRow[]
      >`SELECT * FROM login_identity_action_requests WHERE operation_key=${input.binding.caseId} AND binding->'expected'->>'personId'=${e.personId} AND binding->'expected'->>'action'=${e.action} AND state IN ('reserved','created','registered','verified') FOR UPDATE`;
      if (active.length) throw new WorkforceStoreError("identity_action_original_required");
      if (input.predecessor) {
        const [p] = await tx<
          IdentityActionRow[]
        >`SELECT * FROM login_identity_action_requests WHERE id=${input.predecessor.id} FOR UPDATE`;
        if (
          !p ||
          p.provider_conflicted ||
          !["cancelled", "retired"].includes(p.state) ||
          (p.receipt_expires_at && p.receipt_expires_at.getTime() > Date.now()) ||
          !sameIdentityOwner(p.binding.expected, e) ||
          !sameIdentityBinding(p.binding.command, input.binding.command)
        )
          throw new WorkforceStoreError("identity_action_continuation_denied");
      }
      const a = await this.admission(tx, input.binding, input.requestId);
      const [row] = await tx<
        IdentityActionRow[]
      >`INSERT INTO login_identity_action_requests(id,operation_key,request_hash,issuer,provider_subject,base_session_id,client_id,request_id,epoch,binding,capability_hash,caller_material_sealed,predecessor_request_id,expires_at) VALUES(${input.id},${input.binding.caseId},${hash},${e.issuer},${e.providerSubject},${e.baseSessionId},${e.clientId},${input.requestId},${a.epoch},${tx.json(input.binding)},${sha(input.material.capability)},${this.seal(input.id, "caller", input.material)},${input.predecessor?.id ?? null},statement_timestamp()+interval '5 minutes') RETURNING *`;
      return row;
    });
  }
  async row(id: string, terminal = false) {
    const [row] = await this.sql<IdentityActionRow[]>`SELECT * FROM login_identity_action_requests WHERE id=${id}`;
    if (!row) throw new WorkforceStoreError("identity_action_not_found");
    await this.current(this.sql, row, terminal);
    return row;
  }
  /** Current same owner may observe an immutable old SID; it may not complete that ceremony. */
  async observe(id: string, binding: IdentityActionBinding, requestId: string) {
    return this.sql.begin(async (tx) => {
      await this.admission(tx, binding, requestId);
      const rows = await tx<
        IdentityActionRow[]
      >`SELECT * FROM login_identity_action_requests WHERE id=${id} OR (operation_key=${binding.caseId} AND binding->'expected'->>'personId'=${binding.expected.personId} AND binding->'expected'->>'action'=${binding.expected.action})`;
      const row = rows.find((r) => r.id === id);
      if (!row && rows.length) throw new WorkforceStoreError("identity_action_original_required");
      if (
        row &&
        (!sameIdentityOwner(row.binding.expected, binding.expected) ||
          !sameIdentityBinding(row.binding.command, binding.command) ||
          row.operation_key !== binding.caseId)
      )
        throw new WorkforceStoreError("identity_action_conflict");
      return row;
    });
  }
  /** An Identity-only successor may never have reached this journal. Resolve only
   * an expired unregistered local ancestor; Identity must still prove the exact
   * missing predecessor and fresh successor before reservation. */
  async observeUnregisteredMembershipContinuation(id: string, binding: IdentityActionBinding, requestId: string) {
    return this.sql.begin(async (tx) => {
      await this.admission(tx, binding, requestId);
      const rows = await tx<IdentityActionRow[]>`SELECT * FROM login_identity_action_requests WHERE id=${id} OR (operation_key=${binding.caseId} AND binding->'expected'->>'personId'=${binding.expected.personId} AND binding->'expected'->>'action'=${binding.expected.action}) FOR SHARE`;
      const exact = rows.find((r) => r.id === id);
      if (exact) {
        if (!sameIdentityOwner(exact.binding.expected, binding.expected) || !sameIdentityBinding(exact.binding.command, binding.command) || exact.operation_key !== binding.caseId)
          throw new WorkforceStoreError("identity_action_conflict");
        return exact;
      }
      if (!rows.length || rows.length > 32 || rows.some((r) =>
        r.operation_key !== binding.caseId || !sameIdentityOwner(r.binding.expected, binding.expected) ||
        !sameIdentityBinding(r.binding.command, binding.command) || !this.closedUnregisteredMembership(r)))
        throw new WorkforceStoreError("identity_action_original_required");
      const leaves = rows.filter((r) => !rows.some((next) => next.predecessor_request_id === r.id));
      if (leaves.length !== 1) throw new WorkforceStoreError("identity_action_conflict");
      return leaves[0];
    });
  }
  closedUnregisteredMembership(row: IdentityActionRow) {
    return row.binding.command.purpose === "commercial_membership" && row.state === "retired" &&
      row.expires_at.getTime() <= Date.now() && !row.provider_conflicted &&
      row.provider_session_id === null && row.proof_id === null && row.assertion_hash === null &&
      row.verification_started_at === null && row.verified_at === null && row.receipt_hash === null &&
      row.caller_material_sealed === null && row.provider_material_sealed === null &&
      row.assertion_sealed === null && row.receipt_sealed === null;
  }
  async capability(id: string, value: string, terminal = false) {
    const row = await this.row(id, terminal);
    if (
      !row.caller_material_sealed ||
      row.provider_conflicted ||
      !/^[A-Za-z0-9_-]{43}$/.test(value) ||
      sha(value) !== row.capability_hash
    )
      throw new WorkforceStoreError("identity_action_not_active");
    return row;
  }
  async claimCreation(id: string) {
    return this.sql.begin(async (tx) => {
      const [row] = await tx<IdentityActionRow[]>`SELECT * FROM login_identity_action_requests WHERE id=${id} FOR UPDATE`;
      if (!row) throw new WorkforceStoreError("identity_action_not_active");
      await this.current(tx, row);
      const rows =
        await tx`UPDATE login_identity_action_requests SET provider_started_at=clock_timestamp() WHERE id=${id} AND state='reserved' AND provider_started_at IS NULL RETURNING id`;
      return rows.length === 1;
    });
  }
  /** Caller supplies only a provider-owned SID already verified by the fixed service. No network in SQL. */
  private async providerConflict(tx: Connection, row: IdentityActionRow, actualSid: string) {
    for (const sid of [row.provider_session_id!, actualSid])
      await tx`INSERT INTO login_workforce_revocations(provider_session_id) VALUES(${sid}) ON CONFLICT DO NOTHING`;
    await tx`UPDATE login_identity_action_requests SET state='retired',provider_conflicted=true,caller_material_sealed=NULL,provider_material_sealed=NULL,assertion_sealed=NULL,receipt_sealed=NULL WHERE id=${row.id}`;
  }
  async created(id: string, material: WorkforceActionProviderMaterial) {
    const result = await this.sql.begin(async (tx) => {
      const [row] = await tx<IdentityActionRow[]>`SELECT * FROM login_identity_action_requests WHERE id=${id} FOR UPDATE`;
      if (!row) throw new WorkforceStoreError("identity_action_not_active");
      if (!row.provider_started_at || !/^[1-9][0-9]{0,39}$/.test(material.sessionId))
        throw new WorkforceStoreError("identity_action_not_reserved");
      if (row.provider_session_id && row.provider_session_id !== material.sessionId) {
        await this.providerConflict(tx, row, material.sessionId);
        return "conflict" as const;
      }
      if (row.provider_conflicted) return "conflict" as const;
      try {
        await this.current(tx, row);
      } catch {
        // The original response supplies a known SID after expiry/cancel/logout. Retain
        // only that audit pointer so named provider retirement can be observed later.
        await tx`INSERT INTO login_workforce_revocations(provider_session_id) VALUES(${material.sessionId}) ON CONFLICT DO NOTHING`;
        if (!row.provider_session_id || row.provider_session_id === material.sessionId) {
          await tx`UPDATE login_identity_action_requests SET state=${row.state === "cancelled" ? "cancelled" : "retired"},provider_session_id=${material.sessionId},caller_material_sealed=${row.state === "cancelled" ? row.caller_material_sealed : null},provider_material_sealed=NULL,assertion_sealed=NULL,receipt_sealed=NULL WHERE id=${id}`;
        }
        return undefined;
      }
      if (row.state !== "reserved") {
        if (!sameIdentityBinding(this.provider(row), material)) throw new WorkforceStoreError("identity_action_conflict");
        return row;
      }
      if (!row.provider_started_at) throw new WorkforceStoreError("identity_action_not_reserved");
      const [saved] = await tx<
        IdentityActionRow[]
      >`UPDATE login_identity_action_requests SET state='created',provider_session_id=${material.sessionId},provider_material_sealed=${this.seal(id, "provider", material)} WHERE id=${id} RETURNING *`;
      return saved;
    });
    if (result === "conflict") throw new WorkforceStoreError("identity_action_conflict");
    return result;
  }
  async registered(id: string, proofId: string, expires: Date) {
    return this.sql.begin(async (tx) => {
      const [row] = await tx<IdentityActionRow[]>`SELECT * FROM login_identity_action_requests WHERE id=${id} FOR UPDATE`;
      if (!row) throw new WorkforceStoreError("identity_action_not_active");
      await this.current(tx, row);
      if (row.proof_id) {
        if (row.proof_id !== proofId || row.proof_expires_at?.getTime() !== expires.getTime())
          throw new WorkforceStoreError("identity_action_conflict");
        return row;
      }
      if (
        row.state !== "created" ||
        !Number.isFinite(expires.getTime()) ||
        expires.getTime() > row.created_at.getTime() + 600000 ||
        expires.getTime() <= Date.now()
      )
        throw new WorkforceStoreError("identity_action_conflict");
      const [saved] = await tx<
        IdentityActionRow[]
      >`UPDATE login_identity_action_requests SET state='registered',proof_id=${proofId},proof_expires_at=${expires} WHERE id=${id} RETURNING *`;
      return saved;
    });
  }
  async attempt(id: string, assertion: Record<string, any>) {
    return this.sql.begin(async (tx) => {
      const [row] = await tx<IdentityActionRow[]>`SELECT * FROM login_identity_action_requests WHERE id=${id} FOR UPDATE`;
      if (!row) throw new WorkforceStoreError("identity_action_not_active");
      await this.current(tx, row);
      const hash = workforceAssertionHash(assertion);
      if (row.assertion_hash) {
        if (row.assertion_hash !== hash) throw new WorkforceStoreError("identity_action_conflict");
        return { row, first: false };
      }
      if (row.state !== "registered" || !row.proof_expires_at || row.proof_expires_at.getTime() <= Date.now())
        throw new WorkforceStoreError("identity_action_not_registered");
      const [saved] = await tx<
        IdentityActionRow[]
      >`UPDATE login_identity_action_requests SET assertion_hash=${hash},assertion_sealed=${this.seal(id, "assertion", assertion)},verification_started_at=clock_timestamp() WHERE id=${id} RETURNING *`;
      return { row: saved, first: true };
    });
  }
  async verified(id: string, verified: Date, receipt: string, expires: Date) {
    return this.sql.begin(async (tx) => {
      const [row] = await tx<IdentityActionRow[]>`SELECT * FROM login_identity_action_requests WHERE id=${id} FOR UPDATE`;
      if (!row) throw new WorkforceStoreError("identity_action_not_active");
      await this.current(tx, row);
      if (row.state === "verified") {
        if (
          row.receipt_hash !== sha(receipt) ||
          row.verified_at?.getTime() !== verified.getTime() ||
          row.receipt_expires_at?.getTime() !== expires.getTime()
        )
          throw new WorkforceStoreError("identity_action_conflict");
        return row;
      }
      if (
        row.state !== "registered" ||
        !row.verification_started_at ||
        verified.getTime() < row.verification_started_at.getTime() ||
        verified.getTime() > Date.now() ||
        Date.now() - verified.getTime() > 60000 ||
        expires.getTime() > verified.getTime() + 60000 ||
        !Number.isFinite(expires.getTime()) ||
        !row.proof_expires_at ||
        expires.getTime() > row.proof_expires_at.getTime() ||
        expires.getTime() <= Date.now()
      )
        throw new WorkforceStoreError("identity_action_invalid_receipt");
      const [saved] = await tx<
        IdentityActionRow[]
      >`UPDATE login_identity_action_requests SET state='verified',verified_at=${verified},receipt_hash=${sha(receipt)},receipt_sealed=${this.seal(id, "receipt", receipt)},receipt_expires_at=${expires} WHERE id=${id} RETURNING *`;
      return saved;
    });
  }
  /** Retire capability custody without replacing immutable request, SID or audit. No network inside SQL. */
  async clearExpired() {
    await this.sql.begin(async (tx) => {
      await tx`INSERT INTO login_workforce_revocations(provider_session_id) SELECT r.provider_session_id FROM login_identity_action_requests r WHERE r.provider_session_id IS NOT NULL AND (r.expires_at<=clock_timestamp() OR r.receipt_expires_at<=clock_timestamp() OR NOT EXISTS(SELECT 1 FROM login_workforce_admissions a JOIN login_workforce_epochs e ON a.issuer=e.issuer AND a.provider_subject=e.provider_subject AND a.epoch=e.epoch WHERE a.issuer=r.issuer AND a.provider_subject=r.provider_subject AND a.provider_session_id=r.base_session_id AND a.client_id=r.client_id AND a.request_id=r.request_id AND a.epoch=r.epoch AND a.revoked_at IS NULL AND a.absolute_expires_at>clock_timestamp() AND a.last_seen_at>clock_timestamp()-interval '30 minutes')) ON CONFLICT DO NOTHING`;
      await tx`UPDATE login_identity_action_requests r SET state='retired',caller_material_sealed=NULL,provider_material_sealed=NULL,assertion_sealed=NULL,receipt_sealed=NULL WHERE state<>'retired' AND (r.expires_at<=clock_timestamp() OR r.receipt_expires_at<=clock_timestamp() OR NOT EXISTS(SELECT 1 FROM login_workforce_admissions a JOIN login_workforce_epochs e ON a.issuer=e.issuer AND a.provider_subject=e.provider_subject AND a.epoch=e.epoch WHERE a.issuer=r.issuer AND a.provider_subject=r.provider_subject AND a.provider_session_id=r.base_session_id AND a.client_id=r.client_id AND a.request_id=r.request_id AND a.epoch=r.epoch AND a.revoked_at IS NULL AND a.absolute_expires_at>clock_timestamp() AND a.last_seen_at>clock_timestamp()-interval '30 minutes'))`;
    });
  }
  async retire(id: string, orphan?: string) {
    const conflict = await this.sql.begin(async (tx) => {
      const [row] = await tx<IdentityActionRow[]>`SELECT * FROM login_identity_action_requests WHERE id=${id} FOR UPDATE`;
      if (!row) throw new WorkforceStoreError("identity_action_not_found");
      if (orphan && (!row.provider_started_at || !/^[1-9][0-9]{0,39}$/.test(orphan)))
        throw new WorkforceStoreError("identity_action_not_reserved");
      if (orphan && row.provider_session_id && row.provider_session_id !== orphan) {
        await this.providerConflict(tx, row, orphan);
        return true;
      }
      if (row.provider_session_id)
        await tx`INSERT INTO login_workforce_revocations(provider_session_id) VALUES(${row.provider_session_id}) ON CONFLICT DO NOTHING`;
      if (orphan)
        await tx`INSERT INTO login_workforce_revocations(provider_session_id) VALUES(${orphan}) ON CONFLICT DO NOTHING`;
      // Never replace an already known SID. An independently discovered exact original
      // intent may fill an absent SID only while retiring every capability/material.
      await tx`UPDATE login_identity_action_requests SET state='retired',provider_session_id=${row.provider_session_id ?? orphan ?? null},caller_material_sealed=NULL,provider_material_sealed=NULL,assertion_sealed=NULL,receipt_sealed=NULL WHERE id=${id}`;
      return false;
    });
    if (conflict) throw new WorkforceStoreError("identity_action_conflict");
  }
  async cancel(id: string) {
    await this.sql.begin(async (tx) => {
      const [row] = await tx<IdentityActionRow[]>`SELECT * FROM login_identity_action_requests WHERE id=${id} FOR UPDATE`;
      if (!row) throw new WorkforceStoreError("identity_action_not_active");
      await this.current(tx, row, true);
      await tx`INSERT INTO login_workforce_revocations(provider_session_id) SELECT provider_session_id FROM login_identity_action_requests WHERE id=${id} AND provider_session_id IS NOT NULL ON CONFLICT DO NOTHING`;
      if (row.state !== "retired")
        await tx`UPDATE login_identity_action_requests SET state='cancelled',provider_material_sealed=NULL,assertion_sealed=NULL,receipt_sealed=NULL WHERE id=${id}`;
    });
  }
}
let instance: IdentityActionStore | undefined;
export function identityActionStore() {
  if (instance) return instance;
  const encoded = process.env.PAYPM_WORKFORCE_STORE_KEY_BASE64,
    key = Buffer.from(encoded ?? "", "base64");
  if (key.length !== 32 || key.toString("base64") !== encoded)
    throw new WorkforceStoreError("identity_action_store_unavailable");
  return (instance = new IdentityActionStore(workforceStore().sql, key));
}
