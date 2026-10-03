import { createHash, createHmac, randomUUID } from "crypto";
import "server-only";
export type LegacyMigrationCommand = {
  operationKey: string;
  originalAccessToken: string;
  businessId: string;
  appId: string;
  deploymentId: string;
  environment: "production" | "staging" | "sandbox";
  authentication: { issuer: string; subject: string };
  contactProof: { flowId: string; proofId: string; sessionToken: string };
};
export type LegacyMigrationEligibility = Omit<LegacyMigrationCommand, "originalAccessToken" | "contactProof"> & {
  version: 1;
  eligibilityId: string;
  personId: string;
  legacyAuthentication: { issuer: string; subject: string; clientId: string; tokenId: string; baseSessionId?: string };
  contactProofId: string;
  action: "merchant.auth.migration.approve";
  payloadHash: string;
  issuedAt: string;
  expiresAt: string;
};
export type LegacyMigrationContext = {
  appId: string;
  deploymentId: string;
  environment: string;
  clientIds: string[];
  backendUrl: string;
  backendApiKey: string;
  backendSigningKey: string;
  backendApprovalApiKey: string;
  backendApprovalSigningKey: string;
  rpId: string;
  origin: string;
};
export function canonicalLegacy(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map((x) => canonicalLegacy(x ?? null)).join(",")}]`;
  return `{${Object.keys(value)
    .filter((k) => (value as Record<string, unknown>)[k] !== undefined)
    .sort()
    .map((k) => `${JSON.stringify(k)}:${canonicalLegacy((value as Record<string, unknown>)[k])}`)
    .join(",")}}`;
}
function url(raw: string | undefined) {
  if (!raw) throw new Error("Legacy migration unavailable");
  const u = new URL(raw);
  if (u.protocol !== "https:" || u.username || u.password || u.search || u.hash)
    throw new Error("Legacy migration unavailable");
  return u;
}
export function legacyMigrationContext(scope: {
  appId: string;
  deploymentId: string;
  environment: string;
}): LegacyMigrationContext {
  const registry: unknown = JSON.parse(process.env.PAYPM_LEGACY_MIGRATION_CONTEXTS_JSON ?? "[]");
  if (!Array.isArray(registry)) throw new Error("Legacy migration unavailable");
  const matches = registry.filter(
    (r: LegacyMigrationContext) =>
      r && r.appId === scope.appId && r.deploymentId === scope.deploymentId && r.environment === scope.environment,
  );
  if (matches.length !== 1) throw new Error("Legacy migration unavailable");
  const context = matches[0] as LegacyMigrationContext;
  const origin = url(context.origin);
  url(context.backendUrl);
  if (
    origin.origin !== context.origin ||
    origin.hostname !== context.rpId ||
    !Array.isArray(context.clientIds) ||
    !context.clientIds.length ||
    !context.clientIds.every((id) => /^[A-Za-z0-9_.@:-]{1,255}$/.test(id)) ||
    typeof context.backendApiKey !== "string" ||
    context.backendApiKey.length < 24 ||
    typeof context.backendSigningKey !== "string" ||
    context.backendSigningKey.length < 24
  )
    throw new Error("Legacy migration unavailable");
  return context;
}
export function validLegacyEligibility(
  raw: unknown,
  scope: { appId: string; deploymentId: string; environment: string },
): LegacyMigrationEligibility {
  const e = raw as LegacyMigrationEligibility,
    context = legacyMigrationContext(scope);
  if (!e || typeof e !== "object") throw new Error("Legacy migration denied");
  const fields = [
    "version",
    "eligibilityId",
    "operationKey",
    "personId",
    "legacyAuthentication",
    "authentication",
    "appId",
    "deploymentId",
    "environment",
    "businessId",
    "contactProofId",
    "action",
    "payloadHash",
    "issuedAt",
    "expiresAt",
  ];
  if (
    Object.keys(e).sort().join(",") !== fields.sort().join(",") ||
    e.version !== 1 ||
    e.action !== "merchant.auth.migration.approve" ||
    e.appId !== scope.appId ||
    e.deploymentId !== scope.deploymentId ||
    e.environment !== scope.environment ||
    ![e.eligibilityId, e.operationKey, e.personId, e.businessId, e.contactProofId].every((s) =>
      /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(s),
    )
  )
    throw new Error("Legacy migration denied");
  const old = e.legacyAuthentication;
  if (
    !old ||
    old.issuer !== process.env.PAYPM_LEGACY_MIGRATION_ISSUER ||
    !context.clientIds.includes(old.clientId) ||
    !/^[1-9]\d{0,39}$/.test(old.subject) ||
    typeof old.tokenId !== "string" ||
    !old.tokenId ||
    old.tokenId.length > 255 ||
    Object.keys(old).some((k) => !["issuer", "subject", "clientId", "tokenId", "baseSessionId"].includes(k)) ||
    (old.baseSessionId !== undefined &&
      (typeof old.baseSessionId !== "string" || !old.baseSessionId || old.baseSessionId.length > 255))
  )
    throw new Error("Legacy migration denied");
  if (
    !e.authentication ||
    Object.keys(e.authentication).sort().join(",") !== "issuer,subject" ||
    !e.authentication.subject ||
    e.authentication.subject.length > 255
  )
    throw new Error("Legacy migration denied");
  url(e.authentication.issuer);
  const issued = Date.parse(e.issuedAt),
    expires = Date.parse(e.expiresAt);
  if (
    !Number.isFinite(issued) ||
    !Number.isFinite(expires) ||
    issued > Date.now() + 30000 ||
    expires <= Date.now() ||
    expires <= issued ||
    expires - issued > 300000
  )
    throw new Error("Legacy migration denied");
  const { version: _, eligibilityId: __, payloadHash, issuedAt: ___, expiresAt: ____, ...payload } = e;
  void _;
  void __;
  void ___;
  void ____;
  if (createHash("sha256").update(canonicalLegacy(payload)).digest("hex") !== payloadHash)
    throw new Error("Legacy migration denied");
  return e;
}
export async function obtainLegacyEligibility(input: LegacyMigrationCommand): Promise<LegacyMigrationEligibility> {
  const context = legacyMigrationContext(input);
  const base = url(context.backendUrl),
    endpoint = new URL(
      "api/v1/internal/merchant/migration-proof-eligibility",
      base.href.endsWith("/") ? base : `${base.href}/`,
    ),
    body = JSON.stringify(input),
    timestamp = Math.floor(Date.now() / 1000),
    nonce = randomUUID();
  const signature = createHmac("sha256", context.backendSigningKey)
    .update(`${timestamp}.${nonce}.POST.${endpoint.pathname}.${body}`)
    .digest("hex");
  const response = await fetch(endpoint, {
    method: "POST",
    cache: "no-store",
    redirect: "error",
    signal: AbortSignal.timeout(5000),
    headers: {
      "content-type": "application/json",
      "X-Plug-Wallet-Api-Key": context.backendApiKey,
      "X-Plug-Wallet-Signature": `t=${timestamp},n=${nonce},v2=${signature}`,
    },
    body,
  });
  if (!response.ok) throw new Error("Legacy migration denied");
  const eligibility = validLegacyEligibility(await response.json(), input);
  if (
    eligibility.operationKey !== input.operationKey ||
    eligibility.businessId !== input.businessId ||
    canonicalLegacy(eligibility.authentication) !== canonicalLegacy(input.authentication) ||
    eligibility.contactProofId !== input.contactProof.proofId
  )
    throw new Error("Legacy migration denied");
  return eligibility;
}
export async function legacyIdentityRequest(path: string, body: unknown): Promise<unknown> {
  if (!/^internal\/v1\/legacy-commercial-action-proofs\/(requests|requests\/[0-9a-f-]{36}\/complete)$/.test(path))
    throw new Error("Unregistered legacy proof contract");
  const base = url(process.env.PAYPM_LEGACY_MIGRATION_IDENTITY_URL),
    tokenUrl = url(process.env.PAYPM_LEGACY_MIGRATION_IDENTITY_TOKEN_URL),
    client = process.env.PAYPM_LEGACY_MIGRATION_IDENTITY_CLIENT_ID,
    secret = process.env.PAYPM_LEGACY_MIGRATION_IDENTITY_CLIENT_SECRET,
    scope = process.env.PAYPM_LEGACY_MIGRATION_IDENTITY_SCOPES;
  if (!client || !secret || !scope) throw new Error("Legacy proof machine unavailable");
  const tokenResult = await fetch(tokenUrl, {
    method: "POST",
    cache: "no-store",
    redirect: "error",
    signal: AbortSignal.timeout(5000),
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: "client_credentials", client_id: client, client_secret: secret, scope }),
  });
  if (!tokenResult.ok) throw new Error("Legacy proof machine unavailable");
  const token = (await tokenResult.json()) as { access_token?: unknown; token_type?: unknown };
  if (
    typeof token.access_token !== "string" ||
    !token.access_token ||
    typeof token.token_type !== "string" ||
    token.token_type.toLowerCase() !== "bearer"
  )
    throw new Error("Legacy proof machine unavailable");
  const response = await fetch(new URL(path, base.href.endsWith("/") ? base : `${base.href}/`), {
    method: "POST",
    cache: "no-store",
    redirect: "error",
    signal: AbortSignal.timeout(5000),
    headers: { "content-type": "application/json", authorization: `Bearer ${token.access_token}` },
    body: JSON.stringify(body),
  });
  if (!response.ok) throw new Error("Legacy proof denied");
  return response.json();
}
export async function approveLegacyMigration(receipt: string, expected: LegacyMigrationEligibility): Promise<unknown> {
  const context = legacyMigrationContext(expected);
  if (
    typeof context.backendApprovalApiKey !== "string" ||
    context.backendApprovalApiKey.length < 24 ||
    typeof context.backendApprovalSigningKey !== "string" ||
    context.backendApprovalSigningKey.length < 24 ||
    context.backendApprovalApiKey === context.backendApiKey
  )
    throw new Error("Legacy approval unavailable");
  const base = url(context.backendUrl),
    endpoint = new URL("api/v1/internal/merchant/migration-decisions", base.href.endsWith("/") ? base : `${base.href}/`),
    body = JSON.stringify({ receipt, expected }),
    timestamp = Math.floor(Date.now() / 1000),
    nonce = randomUUID(),
    signature = createHmac("sha256", context.backendApprovalSigningKey)
      .update(`${timestamp}.${nonce}.POST.${endpoint.pathname}.${body}`)
      .digest("hex");
  const response = await fetch(endpoint, {
    method: "POST",
    cache: "no-store",
    redirect: "error",
    signal: AbortSignal.timeout(5000),
    headers: {
      "content-type": "application/json",
      "X-Plug-Wallet-Api-Key": context.backendApprovalApiKey,
      "X-Plug-Wallet-Signature": `t=${timestamp},n=${nonce},v2=${signature}`,
    },
    body,
  });
  if (!response.ok) throw new Error("Legacy approval unavailable");
  const raw: unknown = await response.json();
  if (!raw || typeof raw !== "object") throw new Error("Legacy approval unavailable");
  const d = raw as Record<string, unknown>;
  if (
    d.state !== "approved" ||
    d.eligibilityId !== expected.eligibilityId ||
    d.personId !== expected.personId ||
    d.proofKind !== "legacy_zitadel_passkey" ||
    d.payloadHash !== expected.payloadHash ||
    canonicalLegacy(d.authentication) !== canonicalLegacy(expected.authentication) ||
    d.appId !== expected.appId ||
    d.deploymentId !== expected.deploymentId ||
    d.environment !== expected.environment ||
    d.businessId !== expected.businessId
  )
    throw new Error("Legacy approval unavailable");
  return d;
}
