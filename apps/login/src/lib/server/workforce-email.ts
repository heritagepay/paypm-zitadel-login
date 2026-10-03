"use server";

import { create } from "@zitadel/client";
import { RequestChallengesSchema } from "@zitadel/proto/zitadel/session/v2/challenge_pb";
import { ChecksSchema } from "@zitadel/proto/zitadel/session/v2/session_service_pb";
import { AuthenticationMethodType } from "@zitadel/proto/zitadel/user/v2/user_service_pb";
import { headers } from "next/headers";
import { providerTimestampMs, sessionExpiresAt, sessionLifetime, verifiedFactor } from "../authentication-policy";
import { completeFlowOrGetUrl } from "../client";
import { getSessionCookieById } from "../cookies";
import { getServiceConfig } from "../service-url";
import { workforceEligible, workforcePolicy } from "../workforce-policy";
import { encodeWorkforceState, readWorkforceState, writeWorkforceState } from "../workforce-state";
import {
  getAuthRequest,
  getLoginSettings,
  getSession,
  getUserByID,
  listAuthenticationMethodTypes,
  listUsers,
} from "../zitadel";
import { createSessionAndUpdateCookie, setSessionAndUpdateCookie } from "./cookie";

const unavailable = () => ({ error: "Workforce authentication unavailable" });

/** Headless contract for the bilingual Login UI. Never returns a code or provider token. */
export async function startWorkforceEmailOtp(command: { email: string; requestId: string }) {
  const policy = workforcePolicy();
  if (
    !policy?.emailOtpReady ||
    typeof command.requestId !== "string" ||
    command.requestId.length > 500 ||
    !command.requestId.startsWith("oidc_") ||
    typeof command.email !== "string"
  )
    return unavailable();
  try {
    const issuedAt = Date.now();
    // Check signing readiness before generating a provider challenge or delivery.
    encodeWorkforceState({
      purpose: "email-challenge",
      userId: "pending",
      sessionId: "pending",
      clientId: "pending",
      requestId: command.requestId,
      issuedAt,
      expiresAt: issuedAt + 300000,
    });
    const { serviceConfig } = getServiceConfig(await headers());
    const { authRequest } = await getAuthRequest({ serviceConfig, authRequestId: command.requestId.slice(5) });
    if (!authRequest || !policy.clientIds.includes(authRequest.clientId)) return unavailable();
    const email = command.email.trim().toLowerCase();
    if (email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return unavailable();
    const result = await listUsers({ serviceConfig, email, organizationId: policy.organizationId });
    if (result.result.length !== 1) return unavailable();
    const user = result.result[0];
    if (
      user.type.case !== "human" ||
      user.type.value.email?.email.trim().toLowerCase() !== email ||
      !(await workforceEligible(user, authRequest.clientId, "login"))
    )
      return unavailable();
    const settings = await getLoginSettings({ serviceConfig, organization: policy.organizationId });
    if (!settings?.allowLocalAuthentication) return unavailable();
    const methods = await listAuthenticationMethodTypes({ serviceConfig, userId: user.userId });
    // Provisioning after an approved invitation enrolls the provider method.
    // Login initiation cannot enroll it or create a staff account.
    if (!methods.authMethodTypes.includes(AuthenticationMethodType.OTP_EMAIL)) return unavailable();
    const { session } = await createSessionAndUpdateCookie({
      requestId: command.requestId,
      checks: create(ChecksSchema, { user: { search: { case: "userId", value: user.userId } } }),
      challenges: create(RequestChallengesSchema, { otpEmail: { deliveryType: { case: "sendCode", value: {} } } }),
      lifetime: sessionLifetime(),
    });
    if (
      session.factors?.user?.id !== user.userId ||
      session.factors.user.organizationId !== policy.organizationId ||
      sessionExpiresAt(session) === undefined
    )
      return unavailable();
    await writeWorkforceState({
      purpose: "email-challenge",
      sessionId: session.id,
      userId: user.userId,
      clientId: authRequest.clientId,
      requestId: command.requestId,
      issuedAt,
      expiresAt: issuedAt + 300000,
    });
    return {
      sessionId: session.id,
      expiresAt: new Date(issuedAt + 300000).toISOString(),
      authenticationClass: "workforce_limited" as const,
    };
  } catch {
    return unavailable();
  }
}

export async function verifyWorkforceEmailOtp(command: { sessionId: string; requestId: string; code: string }) {
  const policy = workforcePolicy();
  if (
    !policy?.emailOtpReady ||
    typeof command.code !== "string" ||
    !/^\d{6}$/.test(command.code) ||
    typeof command.sessionId !== "string" ||
    command.sessionId.length > 500 ||
    typeof command.requestId !== "string" ||
    command.requestId.length > 500
  )
    return unavailable();
  try {
    const flow = await readWorkforceState();
    if (
      !flow ||
      flow.purpose !== "email-challenge" ||
      flow.sessionId !== command.sessionId ||
      flow.requestId !== command.requestId
    )
      return unavailable();
    const { serviceConfig } = getServiceConfig(await headers());
    const { authRequest } = await getAuthRequest({ serviceConfig, authRequestId: flow.requestId.slice(5) });
    if (authRequest?.clientId !== flow.clientId || !policy.clientIds.includes(flow.clientId)) return unavailable();
    const cookie = await getSessionCookieById({ sessionId: flow.sessionId });
    if (!cookie || cookie.requestId !== flow.requestId) return unavailable();
    const original = await getSession({ serviceConfig, sessionId: cookie.id, sessionToken: cookie.token });
    if (
      original.session?.factors?.user?.id !== flow.userId ||
      original.session.factors.user.organizationId !== policy.organizationId ||
      sessionExpiresAt(original.session) === undefined
    )
      return unavailable();
    const { user } = await getUserByID({ serviceConfig, userId: flow.userId });
    if (!user || !(await workforceEligible(user, flow.clientId, "login"))) return unavailable();
    const settings = await getLoginSettings({ serviceConfig, organization: policy.organizationId });
    if (!settings?.allowLocalAuthentication) return unavailable();
    const session = await setSessionAndUpdateCookie({
      recentCookie: cookie,
      requestId: flow.requestId,
      lifetime: sessionLifetime(undefined, original.session),
      checks: create(ChecksSchema, { otpEmail: { code: command.code } }),
    });
    const verifiedAt = providerTimestampMs(session.factors?.otpEmail?.verifiedAt);
    const expiresAt = sessionExpiresAt(session);
    if (
      session.factors?.user?.id !== flow.userId ||
      session.factors.user.organizationId !== policy.organizationId ||
      !verifiedFactor(session, session.factors.otpEmail?.verifiedAt) ||
      verifiedAt === undefined ||
      verifiedAt < flow.issuedAt ||
      expiresAt === undefined
    )
      return unavailable();
    await writeWorkforceState({
      ...flow,
      purpose: "limited-admission",
      issuedAt: Date.now(),
      expiresAt: Math.floor(expiresAt),
    });
    return completeFlowOrGetUrl(
      { sessionId: session.id, requestId: flow.requestId, organization: policy.organizationId },
      settings.defaultRedirectUri,
    );
  } catch {
    return unavailable();
  }
}
