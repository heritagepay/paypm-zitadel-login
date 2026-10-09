import { cookies } from "next/headers";
import { createCipheriv, createDecipheriv, hkdfSync, randomBytes } from "node:crypto";
import "server-only";
import { enrollmentUuid } from "./workforce-enrollment-identity-client";
import { workforcePolicy } from "./workforce-policy";

export type EnrollmentReturnApplication = "identity" | "operations" | "super-admin";
export type EnrollmentReturnTarget = { clientId: string; application: EnrollmentReturnApplication; url: string };
export interface EnrollmentReturnState {
  enrollmentId: string;
  clientId: string;
  issuer: string;
  projectionHash: string;
  custodyHash: string;
  targetHash: string;
  previousRequestId?: string;
  issuedAt: number;
  expiresAt: number;
}
const name = "paypm_workforce_enrollment_return";

/** Exact operator-registered entry points only. This catalogue supplies navigation, never admission. */
export function enrollmentReturnTarget(clientId: string): EnrollmentReturnTarget | undefined {
  const policy = workforcePolicy();
  if (!policy) return undefined;
  try {
    const rows: unknown = JSON.parse(process.env.PAYPM_WORKFORCE_ENROLLMENT_RETURN_TARGETS_JSON ?? "null");
    if (!Array.isArray(rows) || !rows.length || rows.length > policy.clientIds.length) return undefined;
    const seen = new Set<string>();
    for (const row of rows) {
      if (
        !row ||
        typeof row !== "object" ||
        Array.isArray(row) ||
        Object.keys(row).sort().join(",") !== "application,clientId,url" ||
        !policy.clientIds.includes(row.clientId) ||
        seen.has(row.clientId) ||
        !["identity", "operations", "super-admin"].includes(row.application) ||
        typeof row.url !== "string" ||
        row.url.length > 2048
      )
        return undefined;
      const url = new URL(row.url);
      if (
        url.protocol !== "https:" ||
        url.username ||
        url.password ||
        url.search ||
        url.hash ||
        row.url !== url.href ||
        /[\\*]/.test(row.url)
      )
        return undefined;
      seen.add(row.clientId);
    }
    return rows.find((row) => row.clientId === clientId);
  } catch {
    return undefined;
  }
}
function key() {
  const encoded = process.env.PAYPM_WORKFORCE_FLOW_KEY_BASE64;
  const source = Buffer.from(encoded ?? "", "base64");
  if (source.length !== 32 || source.toString("base64") !== encoded) throw new Error("Enrollment return unavailable");
  return Buffer.from(hkdfSync("sha256", source, Buffer.alloc(0), "paypm-workforce-enrollment-return-v1", 32));
}
function valid(state: EnrollmentReturnState, now: number) {
  return (
    !!state &&
    !Array.isArray(state) &&
    Object.keys(state).sort().join(",") ===
      (state.previousRequestId === undefined
        ? "clientId,custodyHash,enrollmentId,expiresAt,issuedAt,issuer,projectionHash,targetHash"
        : "clientId,custodyHash,enrollmentId,expiresAt,issuedAt,issuer,previousRequestId,projectionHash,targetHash") &&
    enrollmentUuid(state.enrollmentId) &&
    typeof state.clientId === "string" &&
    /^[A-Za-z0-9._:@-]{1,200}$/.test(state.clientId) &&
    typeof state.issuer === "string" &&
    /^https:\/\//.test(state.issuer) &&
    state.issuer.length <= 2048 &&
    [state.projectionHash, state.custodyHash, state.targetHash].every(
      (v) => typeof v === "string" && /^[a-f0-9]{64}$/.test(v),
    ) &&
    (state.previousRequestId === undefined ||
      (typeof state.previousRequestId === "string" && /^oidc_[A-Za-z0-9_-]{1,480}$/.test(state.previousRequestId))) &&
    Number.isSafeInteger(state.issuedAt) &&
    Number.isSafeInteger(state.expiresAt) &&
    state.issuedAt <= now &&
    state.expiresAt > now &&
    state.expiresAt - state.issuedAt <= 300000
  );
}
/** Routing context has a separate cryptographic purpose and contains no token, code or authentication proof. */
export function sealEnrollmentReturn(state: EnrollmentReturnState) {
  if (!valid(state, Date.now())) throw new Error("Enrollment return unavailable");
  const iv = randomBytes(12),
    cipher = createCipheriv("aes-256-gcm", key(), iv);
  cipher.setAAD(Buffer.from(name));
  const body = Buffer.concat([cipher.update(JSON.stringify(state)), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), body]).toString("base64url");
}
export function openEnrollmentReturn(value: string | undefined, now = Date.now()): EnrollmentReturnState | undefined {
  try {
    if (!value || value.length > 4096) return undefined;
    const bytes = Buffer.from(value, "base64url");
    if (bytes.length < 29 || bytes.toString("base64url") !== value) return undefined;
    const decipher = createDecipheriv("aes-256-gcm", key(), bytes.subarray(0, 12));
    decipher.setAAD(Buffer.from(name));
    decipher.setAuthTag(bytes.subarray(12, 28));
    const state = JSON.parse(Buffer.concat([decipher.update(bytes.subarray(28)), decipher.final()]).toString("utf8"));
    return valid(state, now) ? state : undefined;
  } catch {
    return undefined;
  }
}
export async function readEnrollmentReturn() {
  const value = (await cookies()).get(name)?.value;
  return { present: value !== undefined, state: openEnrollmentReturn(value) };
}
export async function writeEnrollmentReturn(state: EnrollmentReturnState) {
  (await cookies()).set({
    name,
    value: sealEnrollmentReturn(state),
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    path: "/",
    maxAge: Math.max(1, Math.ceil((state.expiresAt - Date.now()) / 1000)),
  });
}
export async function clearEnrollmentReturn(enrollmentId: string) {
  const current = await readEnrollmentReturn();
  if (current.state?.enrollmentId === enrollmentId) (await cookies()).delete(name);
}
