import { createHmac, randomUUID } from "node:crypto";
import "server-only";
import type {
  OperationsActionBinding,
  OperationsActionCommand,
  OperationsActionExpected,
  OperationsCallerMaterial,
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
export function operationsCommand(value: unknown): value is OperationsActionCommand {
  return (
    !!value &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.keys(value).sort().join(",") === "merchantBusinessId,operationKey,organizationId" &&
    Object.values(value).every((v) => typeof v === "string" && uuid.test(v)) &&
    operationUuid.test((value as OperationsActionCommand).operationKey)
  );
}
export function operationsExpected(value: unknown): value is OperationsActionExpected {
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
    [
      "operations.merchant.settlement.review",
      "operations.merchant.settlement.approve",
      "operations.merchant.settlement.execute",
    ].includes(String(e.action)) &&
    typeof e.payloadHash === "string" &&
    /^[a-f0-9]{64}$/.test(e.payloadHash)
  );
}
export async function readOperationsActionAuthority(
  expected: OperationsActionExpected,
  command: OperationsActionCommand,
  proofs: Pick<OperationsCallerMaterial, "idToken" | "accessToken" | "nonce" | "clientId">,
): Promise<OperationsActionBinding> {
  if (!operationsExpected(expected) || !operationsCommand(command)) throw denied();
  const url = process.env.PAYPM_OPERATIONS_ACTION_AUTHORITY_URL,
    keyId = process.env.PAYPM_OPERATIONS_ACTION_AUTHORITY_KEY_ID,
    secret = process.env.PAYPM_OPERATIONS_ACTION_AUTHORITY_API_KEY;
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
    target.pathname !== "/api/v1/internal/operations/authority/actions/current" ||
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
  if (
    !result.resource ||
    typeof result.resource !== "object" ||
    Array.isArray(result.resource) ||
    Object.keys(result.resource).sort().join(",") !== "currency,merchantBusinessId,organizationId" ||
    result.resource.merchantBusinessId !== command.merchantBusinessId ||
    result.resource.organizationId !== command.organizationId ||
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
    input: expected.action === "operations.merchant.settlement.approve" ? { decision: "approve" } : {},
  };
  if (workforceAssertionHash(payload) !== expected.payloadHash) throw denied();
  return { expected, command, capabilityDecisionId: result.capabilityDecisionId, resource: result.resource };
}
