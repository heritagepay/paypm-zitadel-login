import { createHmac, randomUUID } from "node:crypto";
import "server-only";
import type {
  OperationsActionBinding,
  OperationsActionCommand,
  OperationsActionExpected,
  OperationsCallerMaterial,
  OperationsDeploymentGrantCommand,
  OperationsGrantCommand,
  OperationsKycCaseCommand,
  OperationsKycGrantCommand,
  OperationsSettlementCommand,
} from "./operations-action-store";
import { workforceAssertionHash } from "./workforce-assertion";
const denied = () => new Error("Operations action authority unavailable");
export function canonicalOperationsJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalOperationsJson).join(",")}]`;
  if (value && typeof value === "object")
    return `{${Object.keys(value)
      .sort()
      .map((k) => `${JSON.stringify(k)}:${canonicalOperationsJson((value as Record<string, unknown>)[k])}`)
      .join(",")}}`;
  return JSON.stringify(value);
}
const uuid = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i;
const operationUuid = /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i;
export type OperationsActionFamily = "settlement" | "grant" | "deployment-grant" | "kyc-grant" | "kyc";
export function operationsActionFamily(action: unknown): OperationsActionFamily | undefined {
  if (
    [
      "operations.merchant.settlement.review",
      "operations.merchant.settlement.approve",
      "operations.merchant.settlement.execute",
    ].includes(String(action))
  )
    return "settlement";
  if (
    ["operations.access.grant.review", "operations.access.grant.approve", "operations.access.grant.revoke"].includes(
      String(action),
    )
  )
    return "grant";
  if (
    [
      "operations.access.deployment-grant.review",
      "operations.access.deployment-grant.approve",
      "operations.access.deployment-grant.revoke",
    ].includes(String(action))
  )
    return "deployment-grant";
  if (
    [
      "operations.access.kyc-grant.review",
      "operations.access.kyc-grant.approve",
      "operations.access.kyc-grant.revoke",
    ].includes(String(action))
  )
    return "kyc-grant";
  if (["operations.kyc.review", "operations.kyc.decide"].includes(String(action))) return "kyc";
}
export function operationsCommand(
  value: unknown,
  family: OperationsActionFamily = "settlement",
): value is OperationsActionCommand {
  if (family === "grant") return operationsGrantCommand(value);
  if (family === "deployment-grant") return operationsDeploymentGrantCommand(value);
  if (family === "kyc-grant") return operationsKycGrantCommand(value);
  if (family === "kyc") return operationsKycCaseCommand(value);
  return (
    !!value &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.keys(value).sort().join(",") === "merchantBusinessId,operationKey,organizationId" &&
    Object.values(value).every((v) => typeof v === "string" && uuid.test(v)) &&
    operationUuid.test((value as OperationsActionCommand).operationKey)
  );
}
export function operationsGrantCommand(value: unknown): value is OperationsGrantCommand {
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.keys(value).sort().join(",") !==
      "capability,expiresAt,merchantBusinessId,operationKey,organizationId,policyId,reason,targetAuthentication,targetPersonId"
  )
    return false;
  const c = value as OperationsGrantCommand,
    a = c.targetAuthentication;
  return (
    [c.policyId, c.targetPersonId, c.merchantBusinessId, c.organizationId].every(
      (v) => typeof v === "string" && uuid.test(v),
    ) &&
    typeof c.operationKey === "string" &&
    operationUuid.test(c.operationKey) &&
    !!a &&
    typeof a === "object" &&
    !Array.isArray(a) &&
    Object.keys(a).sort().join(",") === "issuer,subject" &&
    typeof a.issuer === "string" &&
    /^https:\/\/[A-Za-z0-9.-]+(?::\d+)?$/.test(a.issuer) &&
    typeof a.subject === "string" &&
    /^[1-9]\d{0,39}$/.test(a.subject) &&
    [
      "operations.merchant.settlement.read",
      "operations.merchant.settlement.review",
      "operations.merchant.settlement.approve",
      "operations.merchant.settlement.execute",
    ].includes(c.capability) &&
    typeof c.expiresAt === "string" &&
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?(?:Z|[+-]\d{2}:\d{2})$/.test(c.expiresAt) &&
    Number.isFinite(Date.parse(c.expiresAt)) &&
    typeof c.reason === "string" &&
    c.reason.trim() === c.reason &&
    c.reason.length >= 10 &&
    c.reason.length <= 500 &&
    !Array.from(c.reason).some((letter) => letter.charCodeAt(0) < 32 || letter.charCodeAt(0) === 127)
  );
}
export function operationsDeploymentGrantCommand(value: unknown): value is OperationsDeploymentGrantCommand {
  return boundedDeploymentGrantCommand(value, [
    "operations.transactions.read",
    "operations.kyc.read",
    "operations.audit.read",
  ]);
}
export function operationsKycGrantCommand(value: unknown): value is OperationsKycGrantCommand {
  return boundedDeploymentGrantCommand(value, ["operations.kyc.review", "operations.kyc.decide"]);
}
export function operationsKycCaseCommand(value: unknown): value is OperationsKycCaseCommand {
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.keys(value).sort().join(",") !== "decision,operationKey,reasons,reviewOperationKey,verificationId"
  )
    return false;
  const command = value as OperationsKycCaseCommand;
  return (
    typeof command.operationKey === "string" &&
    operationUuid.test(command.operationKey) &&
    typeof command.verificationId === "string" &&
    uuid.test(command.verificationId) &&
    ["manual_review", "approved", "rejected"].includes(command.decision) &&
    Array.isArray(command.reasons) &&
    command.reasons.length >= 1 &&
    command.reasons.length <= 10 &&
    command.reasons.every((reason) => typeof reason === "string" && /^[a-z0-9_.:-]{1,80}$/.test(reason)) &&
    (command.reviewOperationKey === null ||
      (typeof command.reviewOperationKey === "string" && operationUuid.test(command.reviewOperationKey))) &&
    (command.decision === "manual_review") === (command.reviewOperationKey === null)
  );
}
function boundedDeploymentGrantCommand(value: unknown, capabilities: readonly string[]): boolean {
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.keys(value).sort().join(",") !==
      "capability,expiresAt,operationKey,policyId,reason,targetAuthentication,targetPersonId"
  )
    return false;
  const c = value as OperationsDeploymentGrantCommand,
    a = c.targetAuthentication;
  return (
    [c.policyId, c.targetPersonId].every((v) => typeof v === "string" && uuid.test(v)) &&
    typeof c.operationKey === "string" &&
    operationUuid.test(c.operationKey) &&
    !!a &&
    typeof a === "object" &&
    !Array.isArray(a) &&
    Object.keys(a).sort().join(",") === "issuer,subject" &&
    typeof a.issuer === "string" &&
    /^https:\/\/[A-Za-z0-9.-]+(?::\d+)?$/.test(a.issuer) &&
    typeof a.subject === "string" &&
    /^[1-9]\d{0,39}$/.test(a.subject) &&
    capabilities.includes(c.capability) &&
    typeof c.expiresAt === "string" &&
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?(?:Z|[+-]\d{2}:\d{2})$/.test(c.expiresAt) &&
    Number.isFinite(Date.parse(c.expiresAt)) &&
    typeof c.reason === "string" &&
    c.reason.trim() === c.reason &&
    c.reason.length >= 10 &&
    c.reason.length <= 500 &&
    !Array.from(c.reason).some((letter) => letter.charCodeAt(0) < 32 || letter.charCodeAt(0) === 127)
  );
}
export function operationsExpected(
  value: unknown,
  family: OperationsActionFamily = "settlement",
): value is OperationsActionExpected {
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.keys(value).sort().join(",") !==
      "action,appId,baseSessionId,clientId,contextId,deploymentId,environment,issuer,payloadHash,personId,providerSubject"
  )
    return false;
  const e = value as Record<string, unknown>;
  return (
    typeof e.personId === "string" &&
    uuid.test(e.personId) &&
    typeof e.issuer === "string" &&
    /^https:\/\/[A-Za-z0-9.-]+(?::\d+)?$/.test(e.issuer) &&
    typeof e.providerSubject === "string" &&
    /^[1-9]\d{0,39}$/.test(e.providerSubject) &&
    typeof e.baseSessionId === "string" &&
    /^[1-9]\d{0,39}$/.test(e.baseSessionId) &&
    typeof e.clientId === "string" &&
    /^[A-Za-z0-9._:@-]{1,200}$/.test(e.clientId) &&
    typeof e.contextId === "string" &&
    /^[1-9]\d{0,39}$/.test(e.contextId) &&
    typeof e.appId === "string" &&
    /^[a-z][a-z0-9_.-]{0,127}$/.test(e.appId) &&
    typeof e.deploymentId === "string" &&
    /^[a-z0-9_]{1,128}$/.test(e.deploymentId) &&
    ["production", "staging", "sandbox"].includes(String(e.environment)) &&
    operationsActionFamily(e.action) === family &&
    typeof e.payloadHash === "string" &&
    /^[a-f0-9]{64}$/.test(e.payloadHash)
  );
}
export async function readOperationsActionAuthority(
  expected: OperationsActionExpected,
  command: OperationsActionCommand,
  proofs: Pick<OperationsCallerMaterial, "idToken" | "accessToken" | "nonce" | "clientId">,
): Promise<OperationsActionBinding> {
  const family = operationsActionFamily(expected.action);
  if (!family || !operationsExpected(expected, family) || !operationsCommand(command, family)) throw denied();
  const prefixes = {
    settlement: "PAYPM_OPERATIONS_ACTION_AUTHORITY",
    grant: "PAYPM_OPERATIONS_GRANT_AUTHORITY",
    "deployment-grant": "PAYPM_OPERATIONS_DEPLOYMENT_GRANT_AUTHORITY",
    "kyc-grant": "PAYPM_OPERATIONS_KYC_GRANT_AUTHORITY",
    kyc: "PAYPM_OPERATIONS_KYC_ACTION_AUTHORITY",
  };
  const prefix = prefixes[family];
  const url = process.env[prefix + "_URL"],
    keyId = process.env[prefix + "_KEY_ID"],
    secret = process.env[prefix + "_API_KEY"];
  if (
    !url ||
    !keyId ||
    !secret ||
    secret.length < 32 ||
    ![
      process.env.PAYPM_OPERATIONS_ACTION_BFF_TOKEN,
      process.env.PAYPM_OPERATIONS_ACTION_CONSUMER_TOKEN,
      process.env.PAYPM_OPERATIONS_ADMISSION_READER_TOKEN,
      process.env.PAYPM_OPERATIONS_INTROSPECTION_CLIENT_SECRET,
      process.env.PAYPM_OPERATIONS_GRANT_BFF_TOKEN,
      process.env.PAYPM_OPERATIONS_GRANT_CONSUMER_TOKEN,
      process.env.PAYPM_OPERATIONS_DEPLOYMENT_GRANT_BFF_TOKEN,
      process.env.PAYPM_OPERATIONS_DEPLOYMENT_GRANT_CONSUMER_TOKEN,
      process.env.PAYPM_OPERATIONS_KYC_GRANT_BFF_TOKEN,
      process.env.PAYPM_OPERATIONS_KYC_GRANT_CONSUMER_TOKEN,
      process.env.PAYPM_OPERATIONS_KYC_ACTION_BFF_TOKEN,
      process.env.PAYPM_OPERATIONS_KYC_ACTION_CONSUMER_TOKEN,
      process.env.PAYPM_WORKFORCE_ADMISSION_READER_TOKEN,
      process.env.PAYPM_WORKFORCE_IDENTITY_CLIENT_SECRET,
      process.env.PAYPM_WORKFORCE_FLOW_KEY_BASE64,
      process.env.PAYPM_WORKFORCE_STORE_KEY_BASE64,
      process.env.PAYPM_OPERATIONS_STORE_KEY_BASE64,
      process.env.PAYPM_OPERATIONS_RETIREMENT_PROOF_KEY_BASE64,
      process.env.PAYPM_OPERATIONS_LOGOUT_TOKEN,
      ...Object.values(prefixes)
        .filter((value) => value !== prefix)
        .map((value) => process.env[value + "_API_KEY"]),
    ].every((v) => v !== secret)
  )
    throw denied();
  const target = new URL(url);
  if (
    target.protocol !== "https:" ||
    target.username ||
    target.password ||
    target.search ||
    target.hash ||
    target.pathname !==
      {
        settlement: "/api/v1/internal/operations/authority/actions/current",
        grant: "/api/v1/internal/operations/authority/grants/actions/current",
        "deployment-grant": "/api/v1/internal/operations/authority/deployment-grants/actions/current",
        "kyc-grant": "/api/v1/internal/operations/authority/kyc-grants/actions/current",
        kyc: "/api/v1/internal/operations/authority/kyc/actions/current",
      }[family] ||
    !/^[A-Za-z0-9_:-]{1,26}$/.test(keyId)
  )
    throw denied();
  const raw = canonicalOperationsJson({ expected, command }),
    timestamp = String(Math.floor(Date.now() / 1000)),
    nonce = randomUUID();
  const signature = createHmac("sha256", secret)
    .update(`${timestamp}.${nonce}.POST.${target.pathname}.${raw}`)
    .digest("hex");
  const response = await fetch(target, {
    method: "POST",
    redirect: "error",
    cache: "no-store",
    signal: AbortSignal.timeout(5000),
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${proofs.accessToken}`,
      "X-PayPM-Workforce-Id-Token": proofs.idToken,
      "X-PayPM-Workforce-Nonce": proofs.nonce,
      "X-Plug-Wallet-Api-Key": secret,
      "X-Plug-Wallet-Signature": `t=${timestamp},n=${nonce},v2=${signature}`,
    },
    body: raw,
  });
  if (!response.ok) throw denied();
  const text = await response.text();
  if (Buffer.byteLength(text) > 32768) throw denied();
  const result = JSON.parse(text),
    keys = ["active", ...Object.keys(expected), "command", "capabilityDecisionId", "resource"].sort().join(",");
  if (
    !result ||
    typeof result !== "object" ||
    Array.isArray(result) ||
    Object.keys(result).sort().join(",") !== keys ||
    result.active !== true ||
    typeof result.capabilityDecisionId !== "string" ||
    !uuid.test(result.capabilityDecisionId) ||
    workforceAssertionHash(result.command) !== workforceAssertionHash(command) ||
    Object.keys(expected).some((k) => result[k] !== expected[k as keyof OperationsActionExpected])
  )
    throw denied();
  if (family === "kyc") {
    const c = command as OperationsKycCaseCommand,
      r = result.resource;
    if (
      !r ||
      typeof r !== "object" ||
      Array.isArray(r) ||
      Object.keys(r).sort().join(",") !==
        "affectedPersonId,level,reviewOperationKey,stateHash,verificationId,walletEndUserId" ||
      r.verificationId !== c.verificationId ||
      r.reviewOperationKey !== c.reviewOperationKey ||
      typeof r.walletEndUserId !== "string" ||
      !uuid.test(r.walletEndUserId) ||
      typeof r.affectedPersonId !== "string" ||
      !uuid.test(r.affectedPersonId) ||
      r.affectedPersonId === expected.personId ||
      !["tier1", "tier2", "tier3"].includes(r.level) ||
      typeof r.stateHash !== "string" ||
      !/^[a-f0-9]{64}$/.test(r.stateHash) ||
      expected.action !== (c.decision === "manual_review" ? "operations.kyc.review" : "operations.kyc.decide")
    )
      throw denied();
  } else if (family !== "settlement") {
    const c = command as OperationsGrantCommand | OperationsDeploymentGrantCommand | OperationsKycGrantCommand,
      r = result.resource;
    if (
      !r ||
      typeof r !== "object" ||
      Array.isArray(r) ||
      Object.keys(r).sort().join(",") !==
        (family === "grant"
          ? "capability,merchantBusinessId,organizationId,policyHash,policyId,targetAuthentication,targetPersonId"
          : "capability,policyHash,policyId,targetAuthentication,targetPersonId") ||
      r.policyId !== c.policyId ||
      result.capabilityDecisionId !== c.policyId ||
      r.targetPersonId !== c.targetPersonId ||
      r.capability !== c.capability ||
      (family === "grant" &&
        (r.merchantBusinessId !== (c as OperationsGrantCommand).merchantBusinessId ||
          r.organizationId !== (c as OperationsGrantCommand).organizationId)) ||
      typeof r.policyHash !== "string" ||
      !/^[a-f0-9]{64}$/.test(r.policyHash) ||
      workforceAssertionHash(r.targetAuthentication) !== workforceAssertionHash(c.targetAuthentication) ||
      c.targetAuthentication.issuer !== expected.issuer
    )
      throw denied();
  } else if (
    !result.resource ||
    typeof result.resource !== "object" ||
    Array.isArray(result.resource) ||
    Object.keys(result.resource).sort().join(",") !== "currency,merchantBusinessId,organizationId" ||
    result.resource.merchantBusinessId !== (command as OperationsSettlementCommand).merchantBusinessId ||
    result.resource.organizationId !== (command as OperationsSettlementCommand).organizationId ||
    typeof result.resource.currency !== "string" ||
    !/^[A-Z]{3}$/.test(result.resource.currency)
  )
    throw denied();
  const payload = {
    version: 1,
    action: expected.action,
    personId: expected.personId,
    appId: expected.appId,
    deploymentId: expected.deploymentId,
    environment: expected.environment,
    contextId: expected.contextId,
    target: result.resource,
    idempotencyKey: command.operationKey,
    input:
      family === "kyc"
        ? {
            decision: (command as OperationsKycCaseCommand).decision,
            reasons: (command as OperationsKycCaseCommand).reasons,
          }
        : family !== "settlement"
          ? {
              expiresAt: (command as OperationsGrantCommand | OperationsDeploymentGrantCommand | OperationsKycGrantCommand)
                .expiresAt,
              reason: (command as OperationsGrantCommand | OperationsDeploymentGrantCommand | OperationsKycGrantCommand)
                .reason,
            }
          : expected.action === "operations.merchant.settlement.approve"
            ? { decision: "approve" }
            : {},
  };
  if (workforceAssertionHash(payload) !== expected.payloadHash) throw denied();
  return { expected, command, capabilityDecisionId: result.capabilityDecisionId, resource: result.resource };
}
