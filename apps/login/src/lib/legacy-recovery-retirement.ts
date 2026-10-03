import { createHash, timingSafeEqual } from "node:crypto";
import "server-only";
import { canonicalLegacy } from "./legacy-commercial-migration-client";
import { workforceStore } from "./workforce-store";

export interface LegacyRecoveryContext {
  version: 1;
  caseId: string;
  revision: 1;
  decisionId: string;
  personId: string;
  originalAuthentication: { issuer: string; subject: string };
  target: { issuer: string; subject?: string; contactType: "phone" | "email"; contactHash: string };
  appId: string;
  deploymentId: string;
  environment: "production" | "staging" | "sandbox";
  contextId: string;
  reviewerPersonId: string;
  makerPersonId: string;
  proofId: string;
  caseHash: string;
  checkedAt: string;
}
interface RegisteredContext {
  appId: string;
  deploymentId: string;
  environment: string;
  organizationIds: string[];
}
const uuid = (v: unknown): v is string =>
  typeof v === "string" && /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i.test(v);
const exact = (v: unknown, keys: string[]) =>
  !!v && typeof v === "object" && !Array.isArray(v) && Object.keys(v).sort().join(",") === keys.sort().join(",");
const unavailable = () => new Error("Governed legacy recovery retirement unavailable");
function privateUrl(value: string | undefined): URL {
  if (!value) throw unavailable();
  const u = new URL(value);
  if (u.protocol !== "https:" || u.username || u.password || u.hash || u.search) throw unavailable();
  return u;
}
function policy(context: LegacyRecoveryContext): RegisteredContext {
  const issuer = privateUrl(process.env.PAYPM_LEGACY_RECOVERY_ISSUER);
  if (
    issuer.pathname !== "/" ||
    context.originalAuthentication.issuer !== issuer.origin ||
    !/^[1-9][0-9]{0,39}$/.test(context.originalAuthentication.subject)
  )
    throw unavailable();
  const registry: unknown = JSON.parse(process.env.PAYPM_LEGACY_RECOVERY_CONTEXTS_JSON ?? "[]");
  if (!Array.isArray(registry) || registry.length > 32) throw unavailable();
  const excluded = [process.env.PAYPM_WORKFORCE_ORGANIZATION_ID, process.env.PAYPM_LEGACY_RECOVERY_SERVICE_ORGANIZATION_ID];
  if (excluded.some((v) => !v || !/^[1-9][0-9]{0,39}$/.test(v))) throw unavailable();
  for (const value of registry)
    if (
      !exact(value, ["appId", "deploymentId", "environment", "organizationIds"]) ||
      !Array.isArray(value.organizationIds) ||
      !value.organizationIds.length ||
      value.organizationIds.length > 128 ||
      new Set(value.organizationIds).size !== value.organizationIds.length ||
      value.organizationIds.some(
        (v: unknown) => typeof v !== "string" || !/^[1-9][0-9]{0,39}$/.test(v) || excluded.includes(v),
      )
    )
      throw unavailable();
  const matches = registry.filter(
    (v: RegisteredContext) =>
      v.appId === context.appId && v.deploymentId === context.deploymentId && v.environment === context.environment,
  );
  if (matches.length !== 1) throw unavailable();
  return matches[0];
}
async function token(purpose: "IDENTITY" | "PROVIDER") {
  const prefix = "PAYPM_LEGACY_RECOVERY_" + purpose;
  const endpoint = privateUrl(process.env[prefix + "_TOKEN_URL"]),
    clientId = process.env[prefix + "_CLIENT_ID"],
    secret = process.env[prefix + "_CLIENT_SECRET"],
    scopes = process.env[prefix + "_SCOPES"];
  if (
    !clientId ||
    !secret ||
    !scopes ||
    process.env.PAYPM_LEGACY_RECOVERY_IDENTITY_CLIENT_ID === process.env.PAYPM_LEGACY_RECOVERY_PROVIDER_CLIENT_ID ||
    [process.env.PAYPM_WORKFORCE_IDENTITY_CLIENT_ID].includes(clientId) ||
    [process.env.PAYPM_WORKFORCE_IDENTITY_CLIENT_SECRET].includes(secret) ||
    process.env.PAYPM_LEGACY_RECOVERY_IDENTITY_CLIENT_SECRET === process.env.PAYPM_LEGACY_RECOVERY_PROVIDER_CLIENT_SECRET
  )
    throw unavailable();
  if (purpose === "PROVIDER" && endpoint.origin !== privateUrl(process.env.PAYPM_LEGACY_RECOVERY_ISSUER).origin)
    throw unavailable();
  const response = await fetch(endpoint, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "client_credentials",
      client_id: clientId,
      client_secret: secret,
      scope: scopes,
    }),
    cache: "no-store",
    redirect: "error",
    signal: AbortSignal.timeout(5000),
  });
  if (!response.ok) throw unavailable();
  const result = await response.json();
  if (typeof result?.access_token !== "string" || !result.access_token || result.access_token.length > 65536)
    throw unavailable();
  return result.access_token as string;
}
export async function legacyRecoveryContext(caseId: string, decisionId: string): Promise<LegacyRecoveryContext> {
  const base = privateUrl(process.env.PAYPM_LEGACY_RECOVERY_IDENTITY_URL);
  if (base.pathname !== "/") throw unavailable();
  const response = await fetch(new URL(`/internal/v1/recovery-cases/${caseId}/legacy-revocation-context`, base), {
    method: "POST",
    headers: { authorization: `Bearer ${await token("IDENTITY")}`, "content-type": "application/json" },
    body: JSON.stringify({ decisionId }),
    cache: "no-store",
    redirect: "error",
    signal: AbortSignal.timeout(5000),
  });
  if (!response.ok) throw unavailable();
  const raw = await response.text();
  if (Buffer.byteLength(raw) > 8192) throw unavailable();
  const value = JSON.parse(raw) as LegacyRecoveryContext;
  if (
    !exact(value, [
      "version",
      "caseId",
      "revision",
      "decisionId",
      "personId",
      "originalAuthentication",
      "target",
      "appId",
      "deploymentId",
      "environment",
      "contextId",
      "reviewerPersonId",
      "makerPersonId",
      "proofId",
      "caseHash",
      "checkedAt",
    ]) ||
    value.version !== 1 ||
    value.revision !== 1 ||
    value.caseId !== caseId ||
    value.decisionId !== decisionId ||
    ![value.caseId, value.decisionId, value.personId, value.reviewerPersonId, value.makerPersonId, value.proofId].every(
      uuid,
    ) ||
    value.reviewerPersonId === value.personId ||
    value.reviewerPersonId === value.makerPersonId ||
    value.makerPersonId === value.personId ||
    !exact(value.originalAuthentication, ["issuer", "subject"]) ||
    !exact(value.target, [
      "issuer",
      "contactType",
      "contactHash",
      ...(value.target?.subject === undefined ? [] : ["subject"]),
    ]) ||
    !["phone", "email"].includes(value.target.contactType) ||
    !/^[a-f0-9]{64}$/.test(value.target.contactHash) ||
    !/^[a-z][a-z0-9_.-]{0,127}$/.test(value.appId) ||
    !/^[a-z0-9_]{1,128}$/.test(value.deploymentId) ||
    !["production", "staging", "sandbox"].includes(value.environment) ||
    typeof value.contextId !== "string" ||
    !value.contextId ||
    value.contextId.length > 200 ||
    !/^[a-f0-9]{64}$/.test(value.caseHash) ||
    !Number.isFinite(Date.parse(value.checkedAt)) ||
    Math.abs(Date.now() - Date.parse(value.checkedAt)) > 5000 ||
    privateUrl(value.target.issuer).origin === privateUrl(value.originalAuthentication.issuer).origin
  )
    throw unavailable();
  policy(value);
  return value;
}
async function providerUser(context: LegacyRecoveryContext) {
  const bearer = await token("PROVIDER"),
    base = privateUrl(process.env.PAYPM_LEGACY_RECOVERY_ISSUER);
  const response = await fetch(new URL(`/v2/users/${context.originalAuthentication.subject}`, base), {
    headers: { authorization: `Bearer ${bearer}` },
    cache: "no-store",
    redirect: "error",
    signal: AbortSignal.timeout(5000),
  });
  if (!response.ok) throw unavailable();
  const raw = await response.text();
  if (Buffer.byteLength(raw) > 32768) throw unavailable();
  const result = JSON.parse(raw);
  const user = result?.user,
    registered = policy(context);
  if (
    user?.userId !== context.originalAuthentication.subject ||
    !user.human ||
    typeof user.human !== "object" ||
    Array.isArray(user.human) ||
    user.machine ||
    !registered.organizationIds.includes(user.details?.resourceOwner) ||
    !["USER_STATE_ACTIVE", "USER_STATE_INACTIVE"].includes(user.state)
  )
    throw unavailable();
  return { user, bearer, base };
}
export async function retireLegacyRecoveryProfile(request: Request): Promise<Response> {
  const denied = () =>
    Response.json(
      { error: "Governed legacy recovery retirement unavailable" },
      { status: 503, headers: { "cache-control": "no-store" } },
    );
  try {
    const expectedSecret = process.env.PAYPM_LEGACY_RECOVERY_CALLER_TOKEN;
    if (
      !expectedSecret ||
      expectedSecret.length < 32 ||
      [
        process.env.PAYPM_WORKFORCE_ADMISSION_READER_TOKEN,
        process.env.PAYPM_LEGACY_RECOVERY_IDENTITY_CLIENT_SECRET,
        process.env.PAYPM_LEGACY_RECOVERY_PROVIDER_CLIENT_SECRET,
        process.env.PAYPM_WORKFORCE_STORE_KEY_BASE64,
      ].includes(expectedSecret)
    )
      return denied();
    const actual = Buffer.from(request.headers.get("authorization") ?? ""),
      expected = Buffer.from("Bearer " + expectedSecret);
    if (actual.length !== expected.length || !timingSafeEqual(actual, expected)) return denied();
    const raw = await request.text();
    if (Buffer.byteLength(raw) > 1024) return denied();
    const input = JSON.parse(raw);
    if (!exact(input, ["caseId", "decisionId"]) || !uuid(input.caseId) || !uuid(input.decisionId)) return denied();
    const context = await legacyRecoveryContext(input.caseId, input.decisionId),
      current = await providerUser(context);
    const { checkedAt, ...binding } = context;
    void checkedAt;
    const hash = createHash("sha256").update(canonicalLegacy(binding)).digest("hex"),
      store = workforceStore();
    const row = await store.reserveLegacyRetirement(
      context.caseId,
      context.decisionId,
      hash,
      binding,
      context.originalAuthentication.subject,
      current.user.details.resourceOwner,
    );
    if (current.user.state === "USER_STATE_ACTIVE") {
      if (row.state === "retired") return denied(); // A restored old profile violates permanent retirement.
      if (!(await store.claimLegacyRetirement(row.id))) return denied();
      try {
        await fetch(new URL(`/v2/users/${context.originalAuthentication.subject}/deactivate`, current.base), {
          method: "POST",
          headers: { authorization: `Bearer ${current.bearer}`, "content-type": "application/json" },
          body: "{}",
          cache: "no-store",
          redirect: "error",
          signal: AbortSignal.timeout(5000),
        });
      } catch {
        /* Only real current provider readback resolves an uncertain result. */
      }
    }
    const confirmed = await providerUser(context);
    if (confirmed.user.state !== "USER_STATE_INACTIVE") return denied();
    const again = await legacyRecoveryContext(input.caseId, input.decisionId),
      { checkedAt: checkedAgain, ...againBinding } = again;
    if (canonicalLegacy(againBinding) !== canonicalLegacy(binding)) return denied();
    await store.legacyRetirementConfirmed(row.id);
    return Response.json(
      {
        revocationEvidenceId: row.id,
        caseId: context.caseId,
        decisionId: context.decisionId,
        personId: context.personId,
        originalAuthentication: context.originalAuthentication,
        appId: context.appId,
        deploymentId: context.deploymentId,
        environment: context.environment,
        kind: "legacy_profile_retired",
        oldSessionsRevokedAt: checkedAgain,
      },
      { headers: { "cache-control": "no-store" } },
    );
  } catch {
    return denied();
  }
}
