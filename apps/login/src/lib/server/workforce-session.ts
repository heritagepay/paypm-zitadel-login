"use server";
import { headers } from "next/headers";
import { verifiedFactor } from "../authentication-policy";
import { getSessionCookieById, removeSessionFromCookie } from "../cookies";
import { getServiceConfig } from "../service-url";
import { workforceClientMode, workforceEligible, workforcePolicy } from "../workforce-policy";
import { workforceProvider } from "../workforce-provider";
import { flushWorkforceRevocations } from "../workforce-revocations";
import { deleteWorkforceState, readWorkforceState } from "../workforce-state";
import { workforceStore } from "../workforce-store";
import { getSession, getUserByID } from "../zitadel";
export async function logoutAllWorkforceSessions() {
  try {
    const policy = workforcePolicy(),
      flow = await readWorkforceState();
    if (
      !policy?.emailOtpReady ||
      flow?.purpose !== "limited-admission" ||
      !flow.challengeId ||
      !workforceClientMode(flow.clientId)
    )
      return { error: "Workforce session unavailable" };
    const cookie = await getSessionCookieById({ sessionId: flow.sessionId }),
      { serviceConfig } = getServiceConfig(await headers());
    if (
      !cookie ||
      cookie.requestId !== flow.requestId ||
      new URL(serviceConfig.baseUrl).origin !== new URL(policy.issuer).origin
    )
      return { error: "Workforce session unavailable" };
    const store = workforceStore(),
      { session } = await getSession({ serviceConfig, sessionId: cookie.id, sessionToken: cookie.token }),
      { user } = await getUserByID({ serviceConfig, userId: flow.userId });
    if (
      !session ||
      session.factors?.user?.id !== flow.userId ||
      session.factors.user.organizationId !== policy.organizationId ||
      !verifiedFactor(session, session.factors.otpEmail?.verifiedAt) ||
      !user ||
      !(await workforceEligible(user, flow.clientId, "login")) ||
      !(await store.admission(flow.sessionId, flow.userId, flow.clientId, flow.requestId))
    )
      return { error: "Workforce session unavailable" };
    await store.revokeUser(policy.issuer, flow.userId);
    await deleteWorkforceState();
    await removeSessionFromCookie({ session: cookie });
    await flushWorkforceRevocations(store, await workforceProvider(serviceConfig, policy.organizationId));
    return { revoked: true };
  } catch {
    return { error: "Workforce session revocation pending" };
  }
}
