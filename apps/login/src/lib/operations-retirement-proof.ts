import { createHmac, timingSafeEqual } from "node:crypto";
import "server-only";
export type OperationsRetirementAdmission = {
  issuer: string;
  providerSubject: string;
  baseSessionId: string;
  clientId: string;
  tokenId: string;
  idTokenHash: string;
  accessTokenHash: string;
  nonceHash: string;
  personId: string;
  plane: "workforce";
  appId: string;
  deploymentId: string;
  environment: "production" | "staging" | "sandbox";
  contextId: string;
  requestId: string;
  challengeId: string;
  authenticationClass: "workforce_limited";
  verifiedAt: string;
  absoluteExpiresAt: string;
  checkedAt: string;
  revocationVersion: string;
  active: true;
};
const denied = () => new Error("Operations retirement proof unavailable");
function key() {
  const encoded = process.env.PAYPM_OPERATIONS_RETIREMENT_PROOF_KEY_BASE64;
  if (!encoded) throw denied();
  const k = Buffer.from(encoded, "base64");
  if (
    k.length !== 32 ||
    k.toString("base64") !== encoded ||
    [
      "PAYPM_WORKFORCE_STORE_KEY_BASE64",
      "PAYPM_WORKFORCE_FLOW_KEY_BASE64",
      "PAYPM_OPERATIONS_STORE_KEY_BASE64",
      "PAYPM_OPERATIONS_ADMISSION_READER_TOKEN",
      "PAYPM_OPERATIONS_LOGOUT_TOKEN",
      "PAYPM_OPERATIONS_INTROSPECTION_CLIENT_SECRET",
      "PAYPM_OPERATIONS_ACTION_BFF_TOKEN",
      "PAYPM_OPERATIONS_ACTION_CONSUMER_TOKEN",
      "PAYPM_OPERATIONS_GRANT_BFF_TOKEN",
      "PAYPM_OPERATIONS_GRANT_CONSUMER_TOKEN",
      "PAYPM_OPERATIONS_GRANT_AUTHORITY_API_KEY",
      "PAYPM_OPERATIONS_DEPLOYMENT_GRANT_BFF_TOKEN",
      "PAYPM_OPERATIONS_DEPLOYMENT_GRANT_CONSUMER_TOKEN",
      "PAYPM_OPERATIONS_DEPLOYMENT_GRANT_AUTHORITY_API_KEY",
      "PAYPM_OPERATIONS_KYC_GRANT_BFF_TOKEN",
      "PAYPM_OPERATIONS_KYC_ACTION_BFF_TOKEN",
      "PAYPM_OPERATIONS_KYC_GRANT_CONSUMER_TOKEN",
      "PAYPM_OPERATIONS_KYC_ACTION_CONSUMER_TOKEN",
      "PAYPM_OPERATIONS_KYC_GRANT_AUTHORITY_API_KEY",
      "PAYPM_OPERATIONS_KYC_ACTION_AUTHORITY_API_KEY",
    ].some((n) => process.env[n] === encoded)
  )
    throw denied();
  return k;
}
export function mintOperationsRetirementProof(admission: OperationsRetirementAdmission) {
  const now = Date.now(),
    absolute = Date.parse(admission.absoluteExpiresAt);
  if (
    admission.active !== true ||
    admission.plane !== "workforce" ||
    admission.authenticationClass !== "workforce_limited" ||
    !Number.isFinite(absolute) ||
    absolute <= now ||
    absolute > now + 28801000
  )
    throw denied();
  const value = {
    version: 1,
    purpose: "operations_session_retirement",
    issuedAt: new Date(now).toISOString(),
    expiresAt: new Date(absolute + 7 * 86400000).toISOString(),
    admission,
  };
  const payload = Buffer.from(JSON.stringify(value)).toString("base64url");
  return `paypm-oplogout1.${payload}.${createHmac("sha256", key()).update(payload).digest("base64url")}`;
}
export function verifyOperationsRetirementProof(ticket: string): OperationsRetirementAdmission {
  if (ticket.length > 16384) throw denied();
  const parts = ticket.split(".");
  if (parts.length !== 3 || parts[0] !== "paypm-oplogout1" || !parts.slice(1).every((v) => /^[A-Za-z0-9_-]+$/.test(v)))
    throw denied();
  const actual = Buffer.from(parts[2], "base64url"),
    expected = createHmac("sha256", key()).update(parts[1]).digest();
  if (actual.toString("base64url") !== parts[2] || actual.length !== expected.length || !timingSafeEqual(actual, expected))
    throw denied();
  const raw = Buffer.from(parts[1], "base64url");
  if (raw.toString("base64url") !== parts[1]) throw denied();
  const value = JSON.parse(raw.toString("utf8")),
    a = value.admission,
    now = Date.now();
  if (
    !value ||
    Object.keys(value).sort().join(",") !== "admission,expiresAt,issuedAt,purpose,version" ||
    value.version !== 1 ||
    value.purpose !== "operations_session_retirement" ||
    !a ||
    Object.keys(a).length !== 22 ||
    a.active !== true ||
    a.plane !== "workforce" ||
    a.authenticationClass !== "workforce_limited" ||
    !Number.isFinite(Date.parse(value.issuedAt)) ||
    Date.parse(value.issuedAt) > now + 1000 ||
    Date.parse(value.expiresAt) <= now ||
    Date.parse(value.expiresAt) !== Date.parse(a.absoluteExpiresAt) + 7 * 86400000 ||
    Date.parse(a.absoluteExpiresAt) <= Date.parse(value.issuedAt) ||
    Date.parse(a.absoluteExpiresAt) > Date.parse(value.issuedAt) + 28801000
  )
    throw denied();
  return a;
}
