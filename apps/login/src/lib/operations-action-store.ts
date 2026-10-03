import { createCipheriv, createDecipheriv, createHash, hkdfSync, randomBytes } from "node:crypto";
import type { Sql, TransactionSql } from "postgres";
import "server-only";
import { workforceAssertionHash } from "./workforce-assertion";
import { workforceStore, WorkforceStoreError, type WorkforceActionProviderMaterial } from "./workforce-store";

export type OperationsActionExpected = {
  personId: string;
  issuer: string;
  providerSubject: string;
  baseSessionId: string;
  clientId: string;
  contextId: string;
  appId: string;
  deploymentId: string;
  environment: "production" | "staging" | "sandbox";
  action:
    | "operations.merchant.settlement.review"
    | "operations.merchant.settlement.approve"
    | "operations.merchant.settlement.execute"
    | "operations.access.grant.review"
    | "operations.access.grant.approve"
    | "operations.access.grant.revoke"
    | "operations.access.deployment-grant.review"
    | "operations.access.deployment-grant.approve"
    | "operations.access.deployment-grant.revoke"
    | "operations.access.kyc-grant.review"
    | "operations.access.kyc-grant.approve"
    | "operations.access.kyc-grant.revoke"
    | "operations.kyc.review"
    | "operations.kyc.decide";
  payloadHash: string;
};
export type OperationsSettlementCommand = { operationKey: string; merchantBusinessId: string; organizationId: string };
export type OperationsGrantCommand = OperationsSettlementCommand & {
  policyId: string;
  targetPersonId: string;
  targetAuthentication: { issuer: string; subject: string };
  capability:
    | "operations.merchant.settlement.read"
    | "operations.merchant.settlement.review"
    | "operations.merchant.settlement.approve"
    | "operations.merchant.settlement.execute";
  expiresAt: string;
  reason: string;
};
export type OperationsDeploymentGrantCommand = {
  operationKey: string;
  policyId: string;
  targetPersonId: string;
  targetAuthentication: { issuer: string; subject: string };
  capability: "operations.transactions.read" | "operations.kyc.read" | "operations.audit.read";
  expiresAt: string;
  reason: string;
};
export type OperationsKycGrantCommand = Omit<OperationsDeploymentGrantCommand, "capability"> & {
  capability: "operations.kyc.review" | "operations.kyc.decide";
};
export type OperationsKycCaseCommand = {
  operationKey: string;
  verificationId: string;
  decision: "manual_review" | "approved" | "rejected";
  reasons: string[];
  reviewOperationKey: string | null;
};
export type OperationsKycCaseResource = {
  verificationId: string;
  walletEndUserId: string;
  affectedPersonId: string;
  level: "tier1" | "tier2" | "tier3";
  stateHash: string;
  reviewOperationKey: string | null;
};
export type OperationsActionCommand =
  | OperationsSettlementCommand
  | OperationsGrantCommand
  | OperationsDeploymentGrantCommand
  | OperationsKycGrantCommand
  | OperationsKycCaseCommand;
export type OperationsGrantResource = Omit<OperationsGrantCommand, "operationKey" | "expiresAt" | "reason"> & {
  policyHash: string;
};
export type OperationsDeploymentGrantResource = Omit<
  OperationsDeploymentGrantCommand,
  "operationKey" | "expiresAt" | "reason"
> & {
  policyHash: string;
};
export type OperationsActionBinding = {
  expected: OperationsActionExpected;
  command: OperationsActionCommand;
  capabilityDecisionId: string;
  resource:
    | { merchantBusinessId: string; organizationId: string; currency: string }
    | OperationsGrantResource
    | OperationsDeploymentGrantResource
    | (Omit<OperationsKycGrantCommand, "operationKey" | "expiresAt" | "reason"> & { policyHash: string })
    | OperationsKycCaseResource;
};
export type OperationsCallerMaterial = {
  idToken: string;
  accessToken: string;
  nonce: string;
  clientId: string;
  capability: string;
  callbackState: string;
  callbackUrl: string;
};
export type OperationsActionRow = {
  id: string;
  operation_key: string;
  request_hash: string;
  issuer: string;
  provider_subject: string;
  base_session_id: string;
  client_id: string;
  request_id: string;
  epoch: string;
  binding: OperationsActionBinding;
  capability_hash: string;
  caller_material_sealed: string | null;
  state: "reserved" | "created" | "verified" | "consumed" | "cancelled" | "retired";
  provider_started_at: Date | null;
  provider_session_id: string | null;
  provider_material_sealed: string | null;
  assertion_hash: string | null;
  assertion_sealed: string | null;
  verification_started_at: Date | null;
  verified_at: Date | null;
  receipt_hash: string | null;
  receipt_sealed: string | null;
  receipt_expires_at: Date | null;
  consumed_at: Date | null;
  created_at: Date;
  expires_at: Date;
};
const sha = (value: string) => createHash("sha256").update(value).digest("hex");
type Connection = Sql | TransactionSql;
export class OperationsActionStore {
  private readonly key: Buffer;
  constructor(
    readonly sql: Sql,
    key: Buffer,
  ) {
    if (key.length !== 32) throw new WorkforceStoreError("operations_action_store_unavailable");
    this.key = Buffer.from(hkdfSync("sha256", key, Buffer.alloc(0), Buffer.from("paypm-operations-action-store-v1"), 32));
  }
  private seal(id: string, purpose: string, value: unknown) {
    const iv = randomBytes(12),
      cipher = createCipheriv("aes-256-gcm", this.key, iv);
    cipher.setAAD(Buffer.from(`${purpose}:${id}`));
    const body = Buffer.concat([cipher.update(JSON.stringify(value), "utf8"), cipher.final()]);
    return Buffer.concat([iv, cipher.getAuthTag(), body]).toString("base64url");
  }
  private open<T>(row: OperationsActionRow, purpose: string, value: string | null): T {
    if (!value) throw new WorkforceStoreError("operations_action_material_unavailable");
    const bytes = Buffer.from(value, "base64url"),
      cipher = createDecipheriv("aes-256-gcm", this.key, bytes.subarray(0, 12));
    cipher.setAAD(Buffer.from(`${purpose}:${row.id}`));
    cipher.setAuthTag(bytes.subarray(12, 28));
    return JSON.parse(Buffer.concat([cipher.update(bytes.subarray(28)), cipher.final()]).toString("utf8"));
  }
  caller(row: OperationsActionRow) {
    return this.open<OperationsCallerMaterial>(row, "caller", row.caller_material_sealed);
  }
  provider(row: OperationsActionRow) {
    return this.open<WorkforceActionProviderMaterial>(row, "provider", row.provider_material_sealed);
  }
  assertion(row: OperationsActionRow) {
    return this.open<Record<string, unknown>>(row, "assertion", row.assertion_sealed);
  }
  receipt(row: OperationsActionRow) {
    return this.open<string>(row, "receipt", row.receipt_sealed);
  }
  private async current(tx: Connection, row: OperationsActionRow, allowCancelled = false) {
    if (row.state === "retired" || (row.state === "cancelled" && !allowCancelled) || row.expires_at.getTime() <= Date.now())
      return false;
    const rows =
      await tx`SELECT a.provider_session_id FROM login_workforce_admissions a JOIN login_workforce_epochs e ON a.issuer=e.issuer AND a.provider_subject=e.provider_subject AND a.epoch=e.epoch WHERE a.provider_session_id=${row.base_session_id} AND a.issuer=${row.issuer} AND a.provider_subject=${row.provider_subject} AND a.client_id=${row.client_id} AND a.request_id=${row.request_id} AND a.epoch=${row.epoch} AND a.revoked_at IS NULL AND a.absolute_expires_at>clock_timestamp() AND a.last_seen_at>clock_timestamp()-interval '30 minutes' FOR SHARE OF a,e`;
    return rows.length === 1;
  }
  async reserve(input: {
    id: string;
    binding: OperationsActionBinding;
    requestId: string;
    material: OperationsCallerMaterial;
  }) {
    const e = input.binding.expected,
      hash = workforceAssertionHash({
        id: input.id,
        binding: input.binding,
        callbackState: input.material.callbackState,
        callbackUrl: input.material.callbackUrl,
        idTokenHash: sha(input.material.idToken),
        accessTokenHash: sha(input.material.accessToken),
        nonceHash: sha(input.material.nonce),
      });
    return this.sql.begin(async (tx) => {
      await tx`SELECT pg_advisory_xact_lock(hashtextextended(${input.binding.command.operationKey},0))`;
      const [old] = await tx<
        OperationsActionRow[]
      >`SELECT * FROM login_operations_action_requests WHERE (operation_key=${input.binding.command.operationKey} AND binding->'expected'->>'personId'=${e.personId} AND binding->'expected'->>'action'=${e.action} AND state IN ('reserved','created','verified','consumed')) OR id=${input.id} ORDER BY (id=${input.id}) DESC FOR UPDATE`;
      if (old) {
        if (old.id !== input.id || old.operation_key !== input.binding.command.operationKey || old.request_hash !== hash)
          throw new WorkforceStoreError("operations_action_conflict");
        if (!(await this.current(tx, old))) throw new WorkforceStoreError("operations_action_not_active");
        return old;
      }
      const [admission] = await tx<
        { epoch: string }[]
      >`SELECT a.epoch FROM login_workforce_admissions a JOIN login_workforce_epochs e ON a.issuer=e.issuer AND a.provider_subject=e.provider_subject AND a.epoch=e.epoch WHERE a.provider_session_id=${e.baseSessionId} AND a.issuer=${e.issuer} AND a.provider_subject=${e.providerSubject} AND a.client_id=${e.clientId} AND a.request_id=${input.requestId} AND a.revoked_at IS NULL AND a.absolute_expires_at>clock_timestamp() AND a.last_seen_at>clock_timestamp()-interval '30 minutes' FOR SHARE OF a,e`;
      if (!admission) throw new WorkforceStoreError("operations_action_not_active");
      const [row] = await tx<
        OperationsActionRow[]
      >`INSERT INTO login_operations_action_requests(id,operation_key,request_hash,issuer,provider_subject,base_session_id,client_id,request_id,epoch,binding,capability_hash,caller_material_sealed,expires_at) VALUES(${input.id},${input.binding.command.operationKey},${hash},${e.issuer},${e.providerSubject},${e.baseSessionId},${e.clientId},${input.requestId},${admission.epoch},${tx.json({ ...input.binding })},${sha(input.material.capability)},${this.seal(input.id, "caller", input.material)},statement_timestamp()+interval '5 minutes') RETURNING *`;
      return row;
    });
  }
  async row(id: string, allowCancelled = false) {
    const [row] = await this.sql<OperationsActionRow[]>`SELECT * FROM login_operations_action_requests WHERE id=${id}`;
    if (!row || !(await this.current(this.sql, row, allowCancelled)))
      throw new WorkforceStoreError("operations_action_not_active");
    return row;
  }
  /** Observation retains the original base/epoch even after request material was erased. */
  async observe(id: string, binding: OperationsActionBinding, requestId: string) {
    const e = binding.expected;
    return this.sql.begin(async (tx) => {
      const [admission] = await tx<
        { epoch: string }[]
      >`SELECT a.epoch FROM login_workforce_admissions a JOIN login_workforce_epochs e ON a.issuer=e.issuer AND a.provider_subject=e.provider_subject AND a.epoch=e.epoch WHERE a.provider_session_id=${e.baseSessionId} AND a.issuer=${e.issuer} AND a.provider_subject=${e.providerSubject} AND a.client_id=${e.clientId} AND a.request_id=${requestId} AND a.revoked_at IS NULL AND a.absolute_expires_at>clock_timestamp() AND a.last_seen_at>clock_timestamp()-interval '30 minutes' FOR SHARE OF a,e`;
      if (!admission) throw new WorkforceStoreError("operations_action_not_active");
      const rows = await tx<
        OperationsActionRow[]
      >`SELECT * FROM login_operations_action_requests WHERE id=${id} OR (operation_key=${binding.command.operationKey} AND binding->'expected'->>'personId'=${e.personId} AND binding->'expected'->>'action'=${e.action})`;
      const row = rows.find((v) => v.id === id);
      if (!row) {
        if (rows.length) throw new WorkforceStoreError("operations_action_conflict");
        return undefined;
      }
      if (
        row.operation_key !== binding.command.operationKey ||
        workforceAssertionHash(row.binding) !== workforceAssertionHash(binding) ||
        row.request_id !== requestId ||
        row.epoch !== admission.epoch
      )
        throw new WorkforceStoreError("operations_action_conflict");
      return row;
    });
  }
  async capability(id: string, value: string, allowCancelled = false) {
    const row = await this.row(id, allowCancelled);
    if (!/^[A-Za-z0-9_-]{43}$/.test(value) || sha(value) !== row.capability_hash)
      throw new WorkforceStoreError("operations_action_not_active");
    return row;
  }
  async claimCreation(id: string) {
    return this.sql.begin(async (tx) => {
      const [row] = await tx<
        OperationsActionRow[]
      >`SELECT * FROM login_operations_action_requests WHERE id=${id} FOR UPDATE`;
      if (!row || !(await this.current(tx, row))) throw new WorkforceStoreError("operations_action_not_active");
      const saved =
        await tx`UPDATE login_operations_action_requests SET provider_started_at=clock_timestamp() WHERE id=${id} AND state='reserved' AND provider_started_at IS NULL RETURNING id`;
      return saved.length === 1;
    });
  }
  async created(id: string, material: WorkforceActionProviderMaterial) {
    const row = await this.sql.begin(async (tx) => {
      const [old] = await tx<
        OperationsActionRow[]
      >`SELECT * FROM login_operations_action_requests WHERE id=${id} FOR UPDATE`;
      if (!old || !(await this.current(tx, old))) {
        await tx`INSERT INTO login_workforce_revocations(provider_session_id) VALUES(${material.sessionId}) ON CONFLICT DO NOTHING`;
        return undefined;
      }
      if (old.state !== "reserved") {
        if (workforceAssertionHash(this.provider(old)) !== workforceAssertionHash(material))
          throw new WorkforceStoreError("operations_action_conflict");
        return old;
      }
      if (!old.provider_started_at) throw new WorkforceStoreError("operations_action_not_reserved");
      const [saved] = await tx<
        OperationsActionRow[]
      >`UPDATE login_operations_action_requests SET state='created',provider_session_id=${material.sessionId},provider_material_sealed=${this.seal(id, "provider", material)} WHERE id=${id} RETURNING *`;
      return saved;
    });
    if (!row) throw new WorkforceStoreError("operations_action_not_active");
    return row;
  }
  async attempt(id: string, assertion: Record<string, unknown>) {
    const hash = workforceAssertionHash(assertion);
    return this.sql.begin(async (tx) => {
      const [row] = await tx<
        OperationsActionRow[]
      >`SELECT * FROM login_operations_action_requests WHERE id=${id} FOR UPDATE`;
      if (!row || !(await this.current(tx, row)) || !["created", "verified"].includes(row.state))
        throw new WorkforceStoreError("operations_action_not_active");
      if (row.assertion_hash) {
        if (row.assertion_hash !== hash) throw new WorkforceStoreError("operations_assertion_conflict");
        return { row, first: false };
      }
      const [saved] = await tx<
        OperationsActionRow[]
      >`UPDATE login_operations_action_requests SET assertion_hash=${hash},assertion_sealed=${this.seal(id, "assertion", assertion)},verification_started_at=clock_timestamp() WHERE id=${id} RETURNING *`;
      return { row: saved, first: true };
    });
  }
  async verified(id: string, verifiedAt: Date) {
    return this.sql.begin(async (tx) => {
      const [row] = await tx<
        OperationsActionRow[]
      >`SELECT * FROM login_operations_action_requests WHERE id=${id} FOR UPDATE`;
      if (
        !row ||
        !(await this.current(tx, row)) ||
        !["created", "verified"].includes(row.state) ||
        !row.assertion_hash ||
        !row.verification_started_at ||
        verifiedAt.getTime() < row.verification_started_at.getTime() ||
        Date.now() - verifiedAt.getTime() > 60000 ||
        verifiedAt.getTime() > Date.now() + 1000
      )
        throw new WorkforceStoreError("operations_verification_mismatch");
      if (row.state === "verified") {
        if (
          row.verified_at?.getTime() !== verifiedAt.getTime() ||
          !row.receipt_expires_at ||
          row.receipt_expires_at.getTime() <= Date.now()
        )
          throw new WorkforceStoreError("operations_verification_mismatch");
        return row;
      }
      const receipt = `paypm-ops1.${randomBytes(32).toString("base64url")}`,
        expiry = new Date(Math.min(verifiedAt.getTime() + 60000, row.expires_at.getTime()));
      const [saved] = await tx<
        OperationsActionRow[]
      >`UPDATE login_operations_action_requests SET state='verified',verified_at=${verifiedAt},receipt_hash=${sha(receipt)},receipt_sealed=${this.seal(id, "receipt", receipt)},receipt_expires_at=${expiry} WHERE id=${id} RETURNING *`;
      return saved;
    });
  }
  async consume(receipt: string, binding: OperationsActionBinding, readback = false) {
    return this.sql.begin(async (tx) => {
      const [row] = await tx<
        OperationsActionRow[]
      >`SELECT * FROM login_operations_action_requests WHERE receipt_hash=${sha(receipt)} FOR UPDATE`;
      if (
        !row ||
        workforceAssertionHash(row.binding) !== workforceAssertionHash(binding) ||
        !(await this.current(tx, row)) ||
        !row.receipt_expires_at ||
        row.receipt_expires_at.getTime() <= Date.now() ||
        !row.verified_at ||
        Date.now() - row.verified_at.getTime() > 60000
      )
        throw new WorkforceStoreError("operations_receipt_not_active");
      if (readback) {
        if (row.state !== "consumed") throw new WorkforceStoreError("operations_receipt_not_consumed");
        return row;
      }
      if (row.state !== "verified") throw new WorkforceStoreError("operations_receipt_already_used");
      const [saved] = await tx<
        OperationsActionRow[]
      >`UPDATE login_operations_action_requests SET state='consumed',consumed_at=clock_timestamp() WHERE id=${row.id} RETURNING *`;
      return saved;
    });
  }
  async byReceipt(receipt: string) {
    const [row] = await this.sql<
      OperationsActionRow[]
    >`SELECT * FROM login_operations_action_requests WHERE receipt_hash=${sha(receipt)}`;
    if (!row || !(await this.current(this.sql, row))) throw new WorkforceStoreError("operations_receipt_not_active");
    return row;
  }
  async retire(id: string, orphan?: string) {
    await this.sql.begin(async (tx) => {
      await tx`INSERT INTO login_workforce_revocations(provider_session_id) SELECT provider_session_id FROM login_operations_action_requests WHERE id=${id} AND provider_session_id IS NOT NULL ON CONFLICT DO NOTHING`;
      if (orphan)
        await tx`INSERT INTO login_workforce_revocations(provider_session_id) VALUES(${orphan}) ON CONFLICT DO NOTHING`;
      await tx`UPDATE login_operations_action_requests SET state='retired',caller_material_sealed=NULL,provider_material_sealed=NULL,assertion_sealed=NULL,receipt_sealed=NULL WHERE id=${id} AND state<>'retired'`;
    });
  }
  async cancel(id: string) {
    return this.sql.begin(async (tx) => {
      const [row] = await tx<
        OperationsActionRow[]
      >`SELECT * FROM login_operations_action_requests WHERE id=${id} FOR UPDATE`;
      if (
        !row ||
        !(await this.current(tx, row, true)) ||
        !["reserved", "created", "verified", "cancelled"].includes(row.state)
      )
        throw new WorkforceStoreError("operations_action_not_active");
      if (row.state === "cancelled") return row;
      await tx`INSERT INTO login_workforce_revocations(provider_session_id) SELECT provider_session_id FROM login_operations_action_requests WHERE id=${id} AND provider_session_id IS NOT NULL ON CONFLICT DO NOTHING`;
      const [saved] = await tx<
        OperationsActionRow[]
      >`UPDATE login_operations_action_requests SET state='cancelled',provider_material_sealed=NULL,assertion_sealed=NULL,receipt_sealed=NULL WHERE id=${id} RETURNING *`;
      return saved;
    });
  }
  async clearExpired() {
    await this.sql.begin(async (tx) => {
      await tx`INSERT INTO login_workforce_revocations(provider_session_id) SELECT provider_session_id FROM login_operations_action_requests WHERE (expires_at<=clock_timestamp() OR receipt_expires_at<=clock_timestamp() OR NOT EXISTS(SELECT 1 FROM login_workforce_admissions a JOIN login_workforce_epochs e ON a.issuer=e.issuer AND a.provider_subject=e.provider_subject AND a.epoch=e.epoch WHERE a.provider_session_id=base_session_id AND a.epoch=login_operations_action_requests.epoch AND a.revoked_at IS NULL AND a.absolute_expires_at>clock_timestamp() AND a.last_seen_at>clock_timestamp()-interval '30 minutes')) AND provider_session_id IS NOT NULL ON CONFLICT DO NOTHING`;
      await tx`UPDATE login_operations_action_requests r SET state='retired',caller_material_sealed=NULL,provider_material_sealed=NULL,assertion_sealed=NULL,receipt_sealed=NULL WHERE state<>'retired' AND (expires_at<=clock_timestamp() OR receipt_expires_at<=clock_timestamp() OR NOT EXISTS(SELECT 1 FROM login_workforce_admissions a JOIN login_workforce_epochs e ON a.issuer=e.issuer AND a.provider_subject=e.provider_subject AND a.epoch=e.epoch WHERE a.provider_session_id=r.base_session_id AND a.epoch=r.epoch AND a.revoked_at IS NULL AND a.absolute_expires_at>clock_timestamp() AND a.last_seen_at>clock_timestamp()-interval '30 minutes'))`;
    });
  }
}
let instance: OperationsActionStore | undefined;
export function operationsActionStore() {
  if (instance) return instance;
  const encoded = process.env.PAYPM_OPERATIONS_STORE_KEY_BASE64,
    key = Buffer.from(encoded ?? "", "base64");
  if (
    key.length !== 32 ||
    key.toString("base64") !== encoded ||
    [
      process.env.PAYPM_WORKFORCE_STORE_KEY_BASE64,
      process.env.PAYPM_WORKFORCE_FLOW_KEY_BASE64,
      process.env.PAYPM_LEGACY_MIGRATION_FLOW_KEY_BASE64,
    ].includes(encoded)
  )
    throw new WorkforceStoreError("operations_action_store_unavailable");
  instance = new OperationsActionStore(workforceStore().sql, key);
  return instance;
}
