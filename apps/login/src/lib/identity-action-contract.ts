import { workforceAssertionHash } from "./workforce-assertion";
export const identityWalletActions = {
  intake: "identity.wallet.legacy.linkage.intake",
  review: "identity.wallet.legacy.linkage.review",
} as const;
export const identityUuid = (v: unknown): v is string =>
  typeof v === "string" && /^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i.test(v);
export const exactObject = (v: unknown, keys: string[]): v is Record<string, any> =>
  !!v && typeof v === "object" && !Array.isArray(v) && Object.keys(v).sort().join(",") === [...keys].sort().join(",");
const opaqueId = (v: unknown): v is string => typeof v === "string" && /^[1-9]\d{0,39}$/.test(v);
const hash = (v: unknown): v is string => typeof v === "string" && /^[a-f0-9]{64}$/.test(v);
export type IdentityActionExpected = {
  personId: string;
  issuer: string;
  providerSubject: string;
  baseSessionId: string;
  clientId: string;
  contextId: string;
  appId: "identity-administration";
  deploymentId: string;
  environment: "production" | "staging" | "sandbox";
  action: (typeof identityWalletActions)[keyof typeof identityWalletActions];
  payloadHash: string;
};
export type IdentityActionCommand = {
  purpose: "wallet_legacy_linkage";
  operationKey: string;
} & (
  | { input: { caseId: string; revision: 1; source: { operationId: string; materialHash: string } } }
  | { caseId: string; revision: 1; decision: "approve" | "reject" }
);
export type IdentityActionBinding = { expected: IdentityActionExpected; command: IdentityActionCommand; caseId: string };
export type IdentityActionPair = { idToken: string; accessToken: string; nonce: string; clientId: string };
export function identityActionCommand(v: unknown): v is IdentityActionCommand {
  if (!v || typeof v !== "object" || Array.isArray(v)) return false;
  const c = v as Record<string, any>;
  if (c.purpose !== "wallet_legacy_linkage" || !identityUuid(c.operationKey)) return false;
  if ("input" in c)
    return (
      exactObject(c, ["purpose", "operationKey", "input"]) &&
      exactObject(c.input, ["caseId", "revision", "source"]) &&
      c.input.caseId === c.operationKey &&
      c.input.revision === 1 &&
      exactObject(c.input.source, ["operationId", "materialHash"]) &&
      identityUuid(c.input.source.operationId) &&
      hash(c.input.source.materialHash)
    );
  return (
    exactObject(c, ["purpose", "operationKey", "caseId", "revision", "decision"]) &&
    c.caseId === c.operationKey &&
    c.revision === 1 &&
    ["approve", "reject"].includes(c.decision)
  );
}
export function identityActionExpected(v: unknown): v is IdentityActionExpected {
  if (
    !exactObject(v, [
      "personId",
      "issuer",
      "providerSubject",
      "baseSessionId",
      "clientId",
      "contextId",
      "appId",
      "deploymentId",
      "environment",
      "action",
      "payloadHash",
    ])
  )
    return false;
  try {
    const issuer = new URL(v.issuer);
    return (
      identityUuid(v.personId) &&
      typeof v.issuer === "string" &&
      issuer.protocol === "https:" &&
      issuer.origin === v.issuer &&
      opaqueId(v.providerSubject) &&
      opaqueId(v.baseSessionId) &&
      opaqueId(v.contextId) &&
      typeof v.clientId === "string" &&
      /^[A-Za-z0-9._:@-]{1,200}$/.test(v.clientId) &&
      v.appId === "identity-administration" &&
      typeof v.deploymentId === "string" &&
      /^[a-z0-9_]{1,128}$/.test(v.deploymentId) &&
      ["production", "staging", "sandbox"].includes(v.environment) &&
      Object.values(identityWalletActions).includes(v.action) &&
      hash(v.payloadHash)
    );
  } catch {
    return false;
  }
}
export function identityCommandAction(command: IdentityActionCommand) {
  return "input" in command ? identityWalletActions.intake : identityWalletActions.review;
}
export function identityActionPair(v: Record<string, any>): v is IdentityActionPair & Record<string, any> {
  return (
    ["idToken", "accessToken"].every((k) => typeof v[k] === "string" && v[k].length > 0 && v[k].length <= 16384) &&
    typeof v.nonce === "string" &&
    v.nonce.length > 0 &&
    v.nonce.length <= 200 &&
    typeof v.clientId === "string" &&
    /^[A-Za-z0-9._:@-]{1,200}$/.test(v.clientId)
  );
}
export function assertIdentityCommand(expected: unknown, command: unknown): asserts expected is IdentityActionExpected {
  if (
    !identityActionExpected(expected) ||
    !identityActionCommand(command) ||
    expected.action !== identityCommandAction(command)
  )
    throw new Error("Identity action unavailable");
}
export const sameIdentityBinding = (a: unknown, b: unknown) => workforceAssertionHash(a) === workforceAssertionHash(b);
export function sameIdentityOwner(a: IdentityActionExpected, b: IdentityActionExpected) {
  return (Object.keys(a) as (keyof IdentityActionExpected)[])
    .filter((k) => k !== "baseSessionId")
    .every((k) => a[k] === b[k]);
}

/** Structural owner-wire qualification only; Identity alone verifies/signs/consumes paypm-wf1. */
export function identityActionReceiptMatches(
  receipt: string,
  proofId: string,
  expected: IdentityActionExpected,
  verifiedAt: Date,
  expiresAt: Date,
) {
  try {
    const parts = receipt.split(".");
    if (parts.length !== 3 || parts[0] !== "paypm-wf1" || !/^[A-Za-z0-9_-]{43}$/.test(parts[2]) || receipt.length > 8192)
      return false;
    const bytes = Buffer.from(parts[1], "base64url");
    if (bytes.toString("base64url") !== parts[1]) return false;
    const body: unknown = JSON.parse(bytes.toString("utf8"));
    if (!exactObject(body, ["version", "proofId", "verifiedAt", "expiresAt", ...Object.keys(expected)])) return false;
    return (
      body.version === 1 &&
      body.proofId === proofId &&
      body.verifiedAt === verifiedAt.toISOString() &&
      body.expiresAt === expiresAt.toISOString() &&
      (Object.keys(expected) as (keyof IdentityActionExpected)[]).every((k) => body[k] === expected[k])
    );
  } catch {
    return false;
  }
}
