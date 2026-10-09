import "server-only";

import type { User } from "@zitadel/proto/zitadel/user/v2/user_pb";
import { UserState } from "@zitadel/proto/zitadel/user/v2/user_pb";
import { getAuthRequest, type ServiceConfig } from "./zitadel";

export type WorkforceEligibility = {
  personId: string;
  organizationId: string;
  eligible: boolean;
};

/** Identity owns invitations and staff admission. Provider organization alone grants nothing. */
export interface WorkforceEligibilityAdapter {
  resolve(input: {
    issuer: string;
    subject: string;
    clientId: string;
    purpose: "login" | "enrollment";
  }): Promise<WorkforceEligibility | undefined>;
}

/** Explicit callback admission only; native resource/action roles remain with each owning console. */
export function workforceClientMode(clientId: string): "limited" | "fresh_passkey" | undefined {
  const policy = workforcePolicy();
  if (!policy) return undefined;
  try {
    const rows: unknown = JSON.parse(process.env.PAYPM_WORKFORCE_OIDC_ADMISSION_POLICIES_JSON ?? "null");
    if (!Array.isArray(rows) || rows.length !== policy.clientIds.length) return undefined;
    const seen = new Set<string>();
    for (const row of rows) {
      if (
        !row ||
        typeof row !== "object" ||
        Array.isArray(row) ||
        Object.keys(row).sort().join(",") !== "clientId,mode" ||
        typeof row.clientId !== "string" ||
        !policy.clientIds.includes(row.clientId) ||
        seen.has(row.clientId) ||
        !["limited", "fresh_passkey"].includes(row.mode)
      )
        return undefined;
      seen.add(row.clientId);
    }
    return rows.find((row) => row.clientId === clientId)?.mode;
  } catch {
    return undefined;
  }
}

export function workforcePolicy() {
  const organizationId = process.env.PAYPM_WORKFORCE_ORGANIZATION_ID;
  const issuer = process.env.PAYPM_WORKFORCE_ISSUER;
  const clientIds = (process.env.PAYPM_WORKFORCE_OIDC_CLIENT_IDS ?? "")
    .split(",")
    .map((id) => id.trim())
    .filter(Boolean);
  if (!organizationId || !issuer || clientIds.length === 0) return undefined;
  if (
    !/^[1-9]\d{0,39}$/.test(organizationId) ||
    clientIds.length > 32 ||
    clientIds.some((id) => !/^[A-Za-z0-9._:@-]{1,200}$/.test(id)) ||
    new Set(clientIds).size !== clientIds.length
  )
    return undefined;
  try {
    const url = new URL(issuer);
    if (url.protocol !== "https:" || url.username || url.password || url.search || url.hash) return undefined;
  } catch {
    return undefined;
  }
  return { organizationId, issuer, clientIds, emailOtpReady: process.env.PAYPM_WORKFORCE_EMAIL_OTP_READY === "true" };
}

export async function workforceRequestClient(serviceConfig: ServiceConfig, requestId: string | undefined) {
  const policy = workforcePolicy();
  if (!policy || !requestId?.startsWith("oidc_")) return undefined;
  const { authRequest } = await getAuthRequest({ serviceConfig, authRequestId: requestId.slice(5) });
  return authRequest && policy.clientIds.includes(authRequest.clientId) ? authRequest.clientId : undefined;
}

export async function workforceSelfRegistrationDenied(
  serviceConfig: ServiceConfig,
  organization: string,
  requestId: string | undefined,
) {
  if (organization === process.env.PAYPM_WORKFORCE_ORGANIZATION_ID) return true;
  if (!process.env.PAYPM_WORKFORCE_OIDC_CLIENT_IDS || !requestId?.startsWith("oidc_")) return false;
  const { authRequest } = await getAuthRequest({ serviceConfig, authRequestId: requestId.slice(5) });
  if (!authRequest) return true;
  return process.env.PAYPM_WORKFORCE_OIDC_CLIENT_IDS.split(",")
    .map((id) => id.trim())
    .includes(authRequest.clientId);
}

function serviceUrl(value: string | undefined, privateIdentityBase = false): URL | undefined {
  if (!value) return undefined;
  try {
    const url = new URL(value);
    if (url.username || url.password || url.search || url.hash) return undefined;
    if (
      url.protocol !== "https:" &&
      !(privateIdentityBase && value === "http://heritagepay-identity-api.identity.svc.cluster.local:3000/api") &&
      !(
        process.env.NODE_ENV !== "production" &&
        url.protocol === "http:" &&
        ["localhost", "127.0.0.1"].includes(url.hostname)
      )
    )
      return undefined;
    return url;
  } catch {
    return undefined;
  }
}

export const identityWorkforceEligibility: WorkforceEligibilityAdapter = {
  async resolve(input) {
    const base = serviceUrl(process.env.PAYPM_WORKFORCE_IDENTITY_URL, true);
    const tokenUrl = serviceUrl(process.env.PAYPM_WORKFORCE_IDENTITY_TOKEN_URL);
    const clientId = process.env.PAYPM_WORKFORCE_IDENTITY_CLIENT_ID;
    const secret = process.env.PAYPM_WORKFORCE_IDENTITY_CLIENT_SECRET;
    const scopes = process.env.PAYPM_WORKFORCE_IDENTITY_SCOPES;
    if (!base || !tokenUrl || !clientId || !secret || !scopes) return undefined;
    try {
      const tokenResponse = await fetch(tokenUrl, {
        method: "POST",
        cache: "no-store",
        redirect: "error",
        signal: AbortSignal.timeout(5000),
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          grant_type: "client_credentials",
          client_id: clientId,
          client_secret: secret,
          scope: scopes,
        }),
      });
      if (!tokenResponse.ok) return undefined;
      const token: unknown = await tokenResponse.json();
      if (
        !token ||
        typeof token !== "object" ||
        !("access_token" in token) ||
        typeof token.access_token !== "string" ||
        !token.access_token
      )
        return undefined;
      const response = await fetch(
        new URL(
          "internal/v1/authentication-subjects/workforce-eligibility",
          base.href.endsWith("/") ? base : `${base.href}/`,
        ),
        {
          method: "POST",
          cache: "no-store",
          redirect: "error",
          signal: AbortSignal.timeout(5000),
          headers: { authorization: `Bearer ${token.access_token}`, "content-type": "application/json" },
          body: JSON.stringify(input),
        },
      );
      if (!response.ok) return undefined;
      const result: unknown = await response.json();
      if (
        !result ||
        typeof result !== "object" ||
        !("personId" in result) ||
        typeof result.personId !== "string" ||
        !("organizationId" in result) ||
        typeof result.organizationId !== "string" ||
        !("eligible" in result) ||
        typeof result.eligible !== "boolean"
      )
        return undefined;
      return { personId: result.personId, organizationId: result.organizationId, eligible: result.eligible };
    } catch {
      return undefined;
    }
  },
};

export async function workforceEligible(user: User, clientId: string, purpose: "login" | "enrollment") {
  const policy = workforcePolicy();
  if (
    !policy ||
    !policy.clientIds.includes(clientId) ||
    user.details?.resourceOwner !== policy.organizationId ||
    user.type.case !== "human"
  )
    return false;
  if (purpose === "login" && (user.state !== UserState.ACTIVE || !user.type.value.email?.isVerified)) return false;
  if (purpose === "enrollment" && user.state !== UserState.ACTIVE && user.state !== UserState.INITIAL) return false;
  if (!user.type.value.email?.email) return false;
  // Fixture/bootstrap gate only. Production cannot enable an invitation allowlist.
  if (process.env.NODE_ENV !== "production" && process.env.PAYPM_WORKFORCE_BOOTSTRAP_MODE === "qualification") {
    const invited = (process.env.PAYPM_WORKFORCE_BOOTSTRAP_INVITED_USER_IDS ?? "").split(",").map((id) => id.trim());
    return invited.includes(user.userId);
  }
  const eligibility = await identityWorkforceEligibility.resolve({
    issuer: policy.issuer,
    subject: user.userId,
    clientId,
    purpose,
  });
  return eligibility?.eligible === true && eligibility.organizationId === policy.organizationId && !!eligibility.personId;
}
