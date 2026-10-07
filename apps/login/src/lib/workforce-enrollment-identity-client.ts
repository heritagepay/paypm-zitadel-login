import "server-only";
import { workforcePolicy } from "./workforce-policy";
export interface EnrollmentProjection {
  enrollmentId: string;
  personId: string;
  policyId: string;
  issuer: string;
  organizationId: string;
  clientId: string;
  providerSubject: string;
  email: string;
  emailVerified: boolean;
  sourceRevision: string;
  imageDigest: string;
  configurationSha256: string;
  expiresAt: string;
  state: "qualified_enrollment";
}
export const enrollmentUuid = (s: unknown): s is string =>
  typeof s === "string" && /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(s);
export function enrollmentRuntime() {
  try {
    const v = JSON.parse(process.env.PAYPM_WORKFORCE_ENROLLMENT_RUNTIME_JSON ?? "null");
    if (
      !v ||
      Object.keys(v).sort().join(",") !== "configurationSha256,imageDigest,sourceRevision" ||
      !/^[a-f0-9]{40}$/.test(v.sourceRevision) ||
      !/^[a-f0-9]{64}$/.test(v.imageDigest) ||
      !/^[a-f0-9]{64}$/.test(v.configurationSha256)
    )
      return undefined;
    return v as { sourceRevision: string; imageDigest: string; configurationSha256: string };
  } catch {
    return undefined;
  }
}
export function parseEnrollmentProjection(v: unknown, id: string): EnrollmentProjection {
  const p = v as EnrollmentProjection,
    policy = workforcePolicy(),
    runtime = enrollmentRuntime();
  if (
    !p ||
    Object.keys(p).sort().join(",") !==
      "clientId,configurationSha256,email,emailVerified,enrollmentId,expiresAt,imageDigest,issuer,organizationId,personId,policyId,providerSubject,sourceRevision,state" ||
    !enrollmentUuid(id) ||
    p.enrollmentId !== id ||
    !enrollmentUuid(p.personId) ||
    !enrollmentUuid(p.policyId) ||
    !policy ||
    !runtime ||
    p.issuer !== policy.issuer ||
    p.organizationId !== policy.organizationId ||
    !policy.clientIds.includes(p.clientId) ||
    !/^[1-9]\d{0,39}$/.test(p.providerSubject) ||
    typeof p.email !== "string" ||
    p.email !== p.email.trim().toLowerCase() ||
    p.email.length > 254 ||
    !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(p.email) ||
    typeof p.emailVerified !== "boolean" ||
    p.sourceRevision !== runtime.sourceRevision ||
    p.imageDigest !== runtime.imageDigest ||
    p.configurationSha256 !== runtime.configurationSha256 ||
    !Number.isFinite(Date.parse(p.expiresAt)) ||
    Date.parse(p.expiresAt) <= Date.now() ||
    p.state !== "qualified_enrollment"
  )
    throw new Error("Enrollment projection unavailable");
  return p;
}
export interface EnrollmentCompletion {
  ceremonySha256: string;
  clientId: string;
  contactId: string;
  enrollmentId: string;
  evidenceId: string;
  issuer: string;
  organizationId: string;
  ownerDecisionSha256: string;
  personId: string;
  policyId: string;
  profileClass: "workforce";
  providerSessionId: string;
  reviewedCollisionSha256: string;
  state: "completed";
  subject: string;
  verifiedAt: string;
}
export function parseEnrollmentCompletion(value: unknown, id: string, body: unknown): EnrollmentCompletion {
  const p = value as EnrollmentCompletion,
    b = body as { challengeId: string; sessionId: string },
    policy = workforcePolicy();
  if (
    !p ||
    Array.isArray(p) ||
    Object.keys(p).sort().join(",") !==
      "ceremonySha256,clientId,contactId,enrollmentId,evidenceId,issuer,organizationId,ownerDecisionSha256,personId,policyId,profileClass,providerSessionId,reviewedCollisionSha256,state,subject,verifiedAt" ||
    !policy ||
    p.enrollmentId !== id ||
    !enrollmentUuid(p.personId) ||
    !enrollmentUuid(p.policyId) ||
    !enrollmentUuid(p.contactId) ||
    p.evidenceId !== b.challengeId ||
    p.providerSessionId !== b.sessionId ||
    p.issuer !== policy.issuer ||
    p.organizationId !== policy.organizationId ||
    !policy.clientIds.includes(p.clientId) ||
    typeof p.subject !== "string" ||
    !/^[1-9]\d{0,39}$/.test(p.subject) ||
    p.profileClass !== "workforce" ||
    p.state !== "completed" ||
    [p.ceremonySha256, p.ownerDecisionSha256, p.reviewedCollisionSha256].some(
      (v) => typeof v !== "string" || !/^[a-f0-9]{64}$/.test(v),
    ) ||
    typeof p.verifiedAt !== "string" ||
    !Number.isFinite(Date.parse(p.verifiedAt)) ||
    Date.parse(p.verifiedAt) > Date.now()
  )
    throw new Error("Original enrollment completion unavailable");
  return p;
}
function target(raw: string | undefined) {
  if (!raw) throw new Error("Enrollment authority unavailable");
  const u = new URL(raw);
  if (u.username || u.password || u.search || u.hash || u.protocol !== "https:")
    throw new Error("Registered enrollment authority required");
  return u;
}
/** Separate fixed-route machine authority, never the existing eligibility/action client. */
export async function enrollmentIdentityRequest(operation: "current" | "complete", id: string, body: unknown = {}) {
  if (!enrollmentUuid(id) || !["current", "complete"].includes(operation) || !enrollmentRuntime())
    throw new Error("Enrollment unavailable");
  if (
    !body ||
    typeof body !== "object" ||
    Array.isArray(body) ||
    (operation === "current"
      ? Object.keys(body).length !== 0
      : Object.keys(body).sort().join(",") !== "challengeId,sessionId" ||
        !enrollmentUuid((body as any).challengeId) ||
        typeof (body as any).sessionId !== "string" ||
        !/^[1-9]\d{0,39}$/.test((body as any).sessionId))
  )
    throw new Error("Closed enrollment command required");
  const base = target(process.env.PAYPM_WORKFORCE_IDENTITY_URL),
    tokenUrl = target(process.env.PAYPM_WORKFORCE_IDENTITY_TOKEN_URL);
  const client = process.env.PAYPM_WORKFORCE_ENROLLMENT_IDENTITY_CLIENT_ID,
    secret = process.env.PAYPM_WORKFORCE_ENROLLMENT_IDENTITY_CLIENT_SECRET,
    scopes = process.env.PAYPM_WORKFORCE_ENROLLMENT_IDENTITY_SCOPES;
  if (
    !client ||
    !secret ||
    !scopes ||
    [process.env.PAYPM_WORKFORCE_IDENTITY_CLIENT_ID, process.env.PAYPM_IDENTITY_ACTION_IDENTITY_CLIENT_ID].includes(
      client,
    ) ||
    Object.entries(process.env).some(
      ([k, v]) =>
        k !== "PAYPM_WORKFORCE_ENROLLMENT_IDENTITY_CLIENT_SECRET" && /(?:SECRET|TOKEN|KEY_BASE64)$/.test(k) && v === secret,
    )
  )
    throw new Error("Separate enrollment credential required");
  const signal = AbortSignal.timeout(8000);
  const bounded = <T>(value: Promise<T>): Promise<T> =>
    new Promise((resolve, reject) => {
      if (signal.aborted) {
        reject(new Error("Enrollment authority deadline"));
        return;
      }
      const expired = () => reject(new Error("Enrollment authority deadline"));
      signal.addEventListener("abort", expired, { once: true });
      value.then(resolve, reject).finally(() => signal.removeEventListener("abort", expired));
    });
  const read = async (response: Response) => {
    if (!response.ok || !response.body) throw new Error("Enrollment authority unavailable");
    const reader = response.body.getReader();
    let size = 0;
    const chunks: Uint8Array[] = [];
    try {
      while (true) {
        const p = await bounded(reader.read());
        if (p.done) break;
        size += p.value.byteLength;
        if (size > 16384) throw new Error("Enrollment body exceeds cap");
        chunks.push(p.value);
      }
    } finally {
      void reader.cancel().catch(() => {});
    }
    return JSON.parse(Buffer.concat(chunks).toString("utf8")) as unknown;
  };
  const token = (await read(
    await bounded(
      fetch(tokenUrl, {
        method: "POST",
        cache: "no-store",
        redirect: "error",
        signal,
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          grant_type: "client_credentials",
          client_id: client,
          client_secret: secret,
          scope: scopes,
        }),
      }),
    ),
  )) as { access_token?: unknown; token_type?: unknown };
  if (typeof token.access_token !== "string" || !token.access_token || String(token.token_type).toLowerCase() !== "bearer")
    throw new Error("Enrollment token unavailable");
  const result = await read(
    await bounded(
      fetch(
        new URL(
          "internal/v1/reviewed-workforce-enrollments/" + id + "/" + operation,
          base.href.endsWith("/") ? base.href : base.href + "/",
        ),
        {
          method: "POST",
          cache: "no-store",
          redirect: "error",
          signal,
          headers: { authorization: "Bearer " + token.access_token, "content-type": "application/json" },
          body: JSON.stringify(body),
        },
      ),
    ),
  );
  return operation === "current" ? parseEnrollmentProjection(result, id) : parseEnrollmentCompletion(result, id, body);
}
