"use server";

import { timestampMs } from "@zitadel/client";
import type { Session } from "@zitadel/proto/zitadel/session/v2/session_pb";
import { AuthenticationMethodType } from "@zitadel/proto/zitadel/user/v2/user_service_pb";
import { headers } from "next/headers";
import { providerTimestampMs, sessionExpiresAt } from "../authentication-policy";
import { completeFlowOrGetUrl } from "../client";
import { addSessionToCookie, getSessionCookieById, removeSessionFromCookie } from "../cookies";
import { isClassifiedError } from "../grpc/interceptors/error-classification";
import { getServiceConfig } from "../service-url";
import { workforceClientMode, workforceEligible, workforcePolicy } from "../workforce-policy";
import { workforceProvider, type WorkforceProvider } from "../workforce-provider";
import { flushWorkforceRevocations } from "../workforce-revocations";
import { deleteWorkforceState, encodeWorkforceState, readWorkforceState, writeWorkforceState } from "../workforce-state";
import { workforceStore, WorkforceStoreError, type WorkforceChallenge, type WorkforceStore } from "../workforce-store";
import {
  getAuthRequest,
  getLoginSettings,
  getSession,
  getUserByID,
  listAuthenticationMethodTypes,
  listUsers,
} from "../zitadel";

const unavailable = () => ({ error: "Workforce authentication unavailable" });
const operation = (value: string) => /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);

async function cookie(row: WorkforceChallenge, session: Session, token: string) {
  if (!session.factors?.user?.loginName || session.id !== row.provider_session_id)
    throw new WorkforceStoreError("provider_session_mismatch");
  await addSessionToCookie({
    session: {
      id: session.id,
      token,
      loginName: session.factors.user.loginName,
      organization: session.factors.user.organizationId,
      requestId: row.request_id,
      creationTs: String(timestampMs(session.creationDate!)),
      expirationTs: String(timestampMs(session.expirationDate!)),
      changeTs: session.changeDate ? String(timestampMs(session.changeDate)) : "",
    },
  });
}
async function issue(row: WorkforceChallenge, store: WorkforceStore, provider: WorkforceProvider) {
  await flushWorkforceRevocations(store, provider);
  if (row.state === "session_pending") {
    const created = (await store.claimSession(row.id))
      ? await provider.create(row)
      : { session: await provider.find(row), token: "" };
    try {
      row = await store.session(
        row.id,
        created.session.id,
        created.token || (await provider.token({ ...row, provider_session_id: created.session.id })).token,
      );
    } catch (error) {
      await store.orphanedSession(row.id, created.session.id);
      throw error;
    }
  }
  if (row.state === "delivery_pending") {
    let delivered;
    if (await store.claimDelivery(row.id)) delivered = await provider.deliver(row);
    else {
      const current = await provider.read(row);
      if (!provider.deliveryAccepted(current, row)) throw new WorkforceStoreError("provider_delivery_unconfirmed");
      delivered = await provider.token(row);
    }
    row = await store.session(row.id, delivered.session.id, delivered.token);
    if (!provider.deliveryAccepted(delivered.session, row)) throw new WorkforceStoreError("provider_delivery_unconfirmed");
    row = await store.issued(row.id);
  }
  if (row.state !== "issued") throw new WorkforceStoreError("challenge_not_active");
  const session = await provider.read(row);
  await writeWorkforceState({
    purpose: "email-challenge",
    challengeId: row.id,
    sessionId: session.id,
    userId: row.provider_subject,
    clientId: row.client_id,
    requestId: row.request_id,
    issuedAt: row.created_at.getTime(),
    expiresAt: row.expires_at.getTime(),
  });
  await cookie(row, session, store.token(row));
  return {
    sessionId: session.id,
    challengeId: row.id,
    expiresAt: row.expires_at.toISOString(),
    resendAt: new Date(row.created_at.getTime() + 60000).toISOString(),
    authenticationClass: "workforce_limited" as const,
  };
}

/** Headless contract: provider owns codes, Login owns durable quotas/flow/session orchestration. */
export async function startWorkforceEmailOtp(command: { email: string; requestId: string; operationKey: string }) {
  const policy = workforcePolicy();
  if (
    !policy?.emailOtpReady ||
    typeof command.requestId !== "string" ||
    command.requestId.length > 500 ||
    !command.requestId.startsWith("oidc_") ||
    typeof command.email !== "string" ||
    !operation(command.operationKey)
  )
    return unavailable();
  try {
    const now = Date.now();
    encodeWorkforceState({
      purpose: "email-challenge",
      userId: "pending",
      sessionId: "pending",
      clientId: "pending",
      requestId: command.requestId,
      issuedAt: now,
      expiresAt: now + 300000,
    });
    const store = workforceStore(),
      { serviceConfig } = getServiceConfig(await headers());
    if (new URL(serviceConfig.baseUrl).origin !== new URL(policy.issuer).origin) return unavailable();
    const { authRequest } = await getAuthRequest({ serviceConfig, authRequestId: command.requestId.slice(5) });
    if (!authRequest || !workforceClientMode(authRequest.clientId)) return unavailable();
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
    const settings = await getLoginSettings({ serviceConfig, organization: policy.organizationId }),
      methods = await listAuthenticationMethodTypes({ serviceConfig, userId: user.userId });
    if (!settings?.allowLocalAuthentication || !methods.authMethodTypes.includes(AuthenticationMethodType.OTP_EMAIL))
      return unavailable();
    const row = await store.reserve({
      operationKey: command.operationKey,
      issuer: policy.issuer,
      userId: user.userId,
      clientId: authRequest.clientId,
      requestId: command.requestId,
      contact: email,
    });
    return await issue(row, store, await workforceProvider(serviceConfig, policy.organizationId));
  } catch {
    return unavailable();
  }
}

export async function resendWorkforceEmailOtp(command: { sessionId: string; requestId: string; operationKey: string }) {
  const policy = workforcePolicy();
  if (!policy?.emailOtpReady || !operation(command.operationKey)) return unavailable();
  try {
    const flow = await readWorkforceState();
    if (!flow?.challengeId || flow.purpose !== "email-challenge" || flow.requestId !== command.requestId)
      return unavailable();
    const store = workforceStore(),
      current = await store.challenge(flow.challengeId),
      { serviceConfig } = getServiceConfig(await headers());
    if (new URL(serviceConfig.baseUrl).origin !== new URL(policy.issuer).origin) return unavailable();
    if (
      current.issuer !== policy.issuer ||
      current.provider_subject !== flow.userId ||
      current.client_id !== flow.clientId ||
      current.request_id !== flow.requestId ||
      current.provider_session_id !== flow.sessionId
    )
      return unavailable();
    // A resend response can update the HttpOnly flow cookie before the caller sees
    // its body. Resolve the exact original session, then let durable operation
    // readback distinguish an identical retry from a new send on a retired flow.
    const row =
      command.sessionId === flow.sessionId
        ? current
        : await store.challengeBySession({
            issuer: policy.issuer,
            userId: flow.userId,
            clientId: flow.clientId,
            requestId: flow.requestId,
            sessionId: command.sessionId,
          });
    const { authRequest } = await getAuthRequest({ serviceConfig, authRequestId: flow.requestId.slice(5) }),
      { user } = await getUserByID({ serviceConfig, userId: flow.userId });
    if (
      authRequest?.clientId !== flow.clientId ||
      !user ||
      user.type.case !== "human" ||
      !(await workforceEligible(user, flow.clientId, "login"))
    )
      return unavailable();
    const email = user.type.value.email?.email;
    if (!email) return unavailable();
    const settings = await getLoginSettings({ serviceConfig, organization: policy.organizationId }),
      methods = await listAuthenticationMethodTypes({ serviceConfig, userId: flow.userId });
    if (!settings?.allowLocalAuthentication || !methods.authMethodTypes.includes(AuthenticationMethodType.OTP_EMAIL))
      return unavailable();
    const next = await store.reserve(
      {
        operationKey: command.operationKey,
        issuer: policy.issuer,
        userId: flow.userId,
        clientId: flow.clientId,
        requestId: flow.requestId,
        contact: email,
      },
      row.id,
    );
    return await issue(next, store, await workforceProvider(serviceConfig, policy.organizationId));
  } catch {
    return unavailable();
  }
}

export async function verifyWorkforceEmailOtp(command: {
  sessionId: string;
  requestId: string;
  operationKey: string;
  code: string;
}) {
  const policy = workforcePolicy();
  if (
    !policy?.emailOtpReady ||
    !operation(command.operationKey) ||
    typeof command.code !== "string" ||
    !/^\d{8}$/.test(command.code)
  )
    return unavailable();
  try {
    const flow = await readWorkforceState();
    if (
      !flow?.challengeId ||
      !["email-challenge", "limited-admission"].includes(flow.purpose) ||
      flow.sessionId !== command.sessionId ||
      flow.requestId !== command.requestId
    )
      return unavailable();
    const store = workforceStore(),
      row = await store.challenge(flow.challengeId),
      { serviceConfig } = getServiceConfig(await headers());
    if (
      new URL(serviceConfig.baseUrl).origin !== new URL(policy.issuer).origin ||
      row.provider_session_id !== flow.sessionId ||
      row.provider_subject !== flow.userId ||
      row.client_id !== flow.clientId ||
      row.request_id !== flow.requestId
    )
      return unavailable();
    const { authRequest } = await getAuthRequest({ serviceConfig, authRequestId: flow.requestId.slice(5) }),
      provider = await workforceProvider(serviceConfig, policy.organizationId);
    if (authRequest?.clientId !== flow.clientId || !policy.clientIds.includes(flow.clientId)) return unavailable();
    const recent = await getSessionCookieById({ sessionId: flow.sessionId });
    if (!recent || recent.requestId !== flow.requestId) return unavailable();
    const { user } = await getUserByID({ serviceConfig, userId: flow.userId }),
      settings = await getLoginSettings({ serviceConfig, organization: policy.organizationId });
    if (!user || !(await workforceEligible(user, flow.clientId, "login")) || !settings?.allowLocalAuthentication)
      return unavailable();
    const attempt = await store.attempt(row.id, command.operationKey, command.code);
    let result;
    if (attempt.first) {
      try {
        result = await provider.verify(row, attempt, command.code);
      } catch (error) {
        if (isClassifiedError(error) && error.isUserError) {
          await store.failed(attempt.id);
          return unavailable();
        }
        const current = await provider.read(row);
        if (!provider.verificationAccepted(current, row, attempt)) return unavailable();
        result = await provider.token(row);
      }
    } else {
      if (attempt.state === "failed") return unavailable();
      const current = await provider.read(row);
      if (!provider.verificationAccepted(current, row, attempt)) return unavailable();
      result = await provider.token(row);
    }
    if (!provider.verificationAccepted(result.session, row, attempt)) return unavailable();
    const verifiedAt = providerTimestampMs(result.session.factors?.otpEmail?.verifiedAt),
      expiresAt = sessionExpiresAt(result.session);
    if (verifiedAt === undefined || expiresAt === undefined) return unavailable();
    await store.session(row.id, result.session.id, result.token);
    await store.verified(
      attempt.id,
      new Date(verifiedAt),
      new Date(Math.min(expiresAt, row.created_at.getTime() + 8 * 3600000)),
    );
    if (!(await store.admission(result.session.id, row.provider_subject, row.client_id, row.request_id)))
      return unavailable();
    await cookie(row, result.session, result.token);
    await writeWorkforceState({
      purpose: "limited-admission",
      challengeId: row.id,
      sessionId: result.session.id,
      userId: row.provider_subject,
      clientId: row.client_id,
      requestId: row.request_id,
      issuedAt: row.created_at.getTime(),
      expiresAt: Math.min(expiresAt, row.created_at.getTime() + 8 * 3600000),
    });
    const mode = workforceClientMode(row.client_id);
    if (!mode) return unavailable();
    if (mode === "fresh_passkey")
      return {
        redirect: `/passkey?${new URLSearchParams({ sessionId: result.session.id, requestId: row.request_id, organization: policy.organizationId })}`,
      };
    return completeFlowOrGetUrl(
      { sessionId: result.session.id, requestId: row.request_id, organization: policy.organizationId },
      settings.defaultRedirectUri,
    );
  } catch {
    return unavailable();
  }
}

/** Cancellation retires durable admission before best-effort provider deletion. */
export async function cancelWorkforceEmailOtp(command: { requestId: string; sessionId: string }) {
  const policy = workforcePolicy();
  if (!policy?.emailOtpReady) return unavailable();
  try {
    const flow = await readWorkforceState(),
      store = workforceStore(),
      { serviceConfig } = getServiceConfig(await headers());
    if (new URL(serviceConfig.baseUrl).origin !== new URL(policy.issuer).origin || !command.requestId?.startsWith("oidc_"))
      return unavailable();
    let row: WorkforceChallenge;
    if (flow) {
      if (
        !flow.challengeId ||
        !["email-challenge", "limited-admission"].includes(flow.purpose) ||
        flow.requestId !== command.requestId
      )
        return unavailable();
      row = await store.challenge(flow.challengeId);
      if (
        row.issuer !== policy.issuer ||
        row.provider_session_id !== flow.sessionId ||
        row.provider_subject !== flow.userId ||
        row.client_id !== flow.clientId ||
        row.request_id !== flow.requestId
      )
        return unavailable();
    } else {
      // An expired challenge cookie cannot verify a code. Its still-protected
      // provider session cookie may only authorize retirement after real token
      // validation and exact request/subject matching, never new admission.
      const recent = await getSessionCookieById({ sessionId: command.sessionId });
      if (!recent || recent.requestId !== command.requestId) return unavailable();
      const { authRequest } = await getAuthRequest({ serviceConfig, authRequestId: command.requestId.slice(5) });
      if (!authRequest || !workforceClientMode(authRequest.clientId)) return unavailable();
      const { session } = await getSession({ serviceConfig, sessionId: recent.id, sessionToken: recent.token });
      row = await store.challengeForRequest({
        issuer: policy.issuer,
        clientId: authRequest.clientId,
        requestId: command.requestId,
        sessionId: recent.id,
      });
      if (
        !session ||
        session.id !== row.provider_session_id ||
        session.factors?.user?.id !== row.provider_subject ||
        session.factors?.user?.organizationId !== policy.organizationId
      )
        return unavailable();
    }
    await store.cancelChallenge(row.id);
    const recent = await getSessionCookieById({ sessionId: row.provider_session_id! });
    if (recent) await removeSessionFromCookie({ session: recent });
    await deleteWorkforceState();
    // Queue is durable; provider outage cannot restore the cancelled admission.
    await flushWorkforceRevocations(store, await workforceProvider(serviceConfig, policy.organizationId)).catch(
      () => undefined,
    );
    return { cancelled: true as const };
  } catch {
    return unavailable();
  }
}
