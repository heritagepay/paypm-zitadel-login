"use server";
import { UserState } from "@zitadel/proto/zitadel/user/v2/user_pb";
import { AuthenticationMethodType } from "@zitadel/proto/zitadel/user/v2/user_service_pb";
import { headers } from "next/headers";
import { providerTimestampMs, sessionExpiresAt } from "../authentication-policy";
import { isClassifiedError } from "../grpc/interceptors/error-classification";
import { getServiceConfig } from "../service-url";
import { workforceAssertionHash } from "../workforce-assertion";
import {
  enrollmentIdentityRequest,
  enrollmentRuntime,
  enrollmentUuid,
  type EnrollmentProjection,
} from "../workforce-enrollment-identity-client";
import { workforceEnrollmentStore, type EnrollmentOriginal } from "../workforce-enrollment-store";
import { workforcePolicy } from "../workforce-policy";
import { deliverWorkforceProfileEmail } from "../workforce-profile-email-provider";
import { workforceProvider, type WorkforceProvider } from "../workforce-provider";
import { flushWorkforceRevocations } from "../workforce-revocations";
import { deleteWorkforceState, readWorkforceState, writeWorkforceState } from "../workforce-state";
import { type WorkforceChallenge } from "../workforce-store";
import {
  addOTPEmail,
  getAuthRequest,
  getLoginSettings,
  getUserByID,
  listAuthenticationMethodTypes,
  verifyEmail,
} from "../zitadel";
const unavailable = () => ({ error: "Reviewed workforce enrollment unavailable" });
function validOriginalRequestId(value: unknown): value is string {
  return typeof value === "string" && /^oidc_[A-Za-z0-9_-]{1,480}$/.test(value);
}
async function prepared(id: string) {
  const policy = workforcePolicy();
  if (!enrollmentUuid(id) || !enrollmentRuntime() || !policy?.emailOtpReady) throw new Error("Enrollment unavailable");
  const { serviceConfig } = getServiceConfig(await headers());
  if (new URL(serviceConfig.baseUrl).origin !== policy.issuer) throw new Error("Registered issuer required");
  const projection = (await enrollmentIdentityRequest("current", id)) as EnrollmentProjection;
  const { user } = await getUserByID({ serviceConfig, userId: projection.providerSubject });
  if (
    !user ||
    user.state !== UserState.ACTIVE ||
    user.details?.resourceOwner !== policy.organizationId ||
    user.type.case !== "human" ||
    user.type.value.email?.email.trim().toLowerCase() !== projection.email ||
    user.type.value.email.isVerified !== projection.emailVerified
  )
    throw new Error("Current prepared user required");
  return { policy, serviceConfig, projection, user };
}
async function context(id: string, requestId: string) {
  if (!validOriginalRequestId(requestId)) throw new Error("Original native request required");
  const current = await prepared(id);
  const { authRequest } = await getAuthRequest({ serviceConfig: current.serviceConfig, authRequestId: requestId.slice(5) });
  if (authRequest?.clientId !== current.projection.clientId) throw new Error("Original request client changed");
  return current;
}
async function owned(id: string, allowCompleted = false) {
  const flow = await readWorkforceState();
  if (!flow || flow.purpose !== "reviewed-workforce-enrollment" || flow.enrollmentId !== id)
    throw new Error("Original enrollment flow required");
  const store = workforceEnrollmentStore(),
    original = await store.original(id, allowCompleted),
    current = await context(id, flow.requestId);
  store.matches(original, current.projection);
  const after = await store.original(id, allowCompleted);
  if (
    after.epoch !== original.epoch ||
    after.binding_hash !== original.binding_hash ||
    after.retirement !== original.retirement
  )
    throw new Error("Original enrollment changed during read");
  if (
    flow.userId !== original.provider_subject ||
    flow.clientId !== original.client_id ||
    flow.requestId !== original.request_id
  )
    throw new Error("Original browser binding changed");
  return { flow, store, original, ...current };
}
async function flow(original: EnrollmentOriginal, row?: WorkforceChallenge) {
  await writeWorkforceState({
    purpose: "reviewed-workforce-enrollment",
    enrollmentId: original.enrollment_id,
    challengeId: row?.id,
    sessionId: row?.provider_session_id ?? "pending",
    userId: original.provider_subject,
    clientId: original.client_id,
    requestId: original.request_id,
    issuedAt: original.created_at.getTime(),
    expiresAt: original.expires_at.getTime(),
  });
}
async function issue(id: string, row: WorkforceChallenge, provider: WorkforceProvider) {
  const store = workforceEnrollmentStore();
  await flushWorkforceRevocations(store.base, provider);
  await store.original(id);
  if (row.purpose !== "reviewed_enrollment") throw new Error("Original enrollment purpose required");
  if (row.state === "session_pending") {
    const created = (await store.base.claimSession(row.id))
      ? await provider.create(row)
      : { session: await provider.find(row), token: "" };
    try {
      row = await store.base.session(
        row.id,
        created.session.id,
        created.token || (await provider.token({ ...row, provider_session_id: created.session.id })).token,
      );
    } catch (e) {
      await store.base.orphanedSession(row.id, created.session.id);
      throw e;
    }
  }
  const ceremony = await store.attach(id, row);
  await provider.attachEnrollment(row, workforceAssertionHash(ceremony));
  if (row.state === "delivery_pending") {
    let result;
    if (await store.base.claimDelivery(row.id)) result = await provider.deliver(row);
    else {
      if (!provider.deliveryAccepted(await provider.read(row), row)) throw new Error("Original delivery pending");
      result = await provider.token(row);
    }
    row = await store.base.session(row.id, result.session.id, result.token);
    if (!provider.deliveryAccepted(result.session, row)) throw new Error("Native delivery not accepted");
    row = await store.base.issued(row.id);
  }
  if (row.state !== "issued") throw new Error("Original OTP not current");
  const original = await store.original(id);
  await flow(original, row);
  return {
    state: "otp_pending" as const,
    email: (await owned(id)).projection.email,
    challengeId: row.id,
    expiresAt: ceremony.expiresAt,
    resendAt: new Date(row.created_at.getTime() + 60000).toISOString(),
  };
}
async function issueProfile(id: string, operationKey: string, previousId?: string) {
  const c = await owned(id);
  if (c.projection.emailVerified || c.flow.challengeId) throw new Error("Original profile stage required");
  const template = await reviewedWorkforceEmailVerificationTemplate(id, c.flow.requestId);
  const row = await c.store.reserveProfileDelivery(c.projection, operationKey, template, previousId);
  if (await c.store.claimProfileDelivery(id, row.id)) {
    let ack;
    try {
      ack = await deliverWorkforceProfileEmail(
        c.serviceConfig,
        { subject: c.projection.providerSubject, organizationId: c.policy.organizationId, template },
        async () => {
          const current = await owned(id);
          if (current.projection.emailVerified || current.flow.challengeId) throw new Error("Profile stage changed");
          await current.store.currentProfileDelivery(id, row.id);
        },
      );
    } catch {
      /* No operation-specific native readback exists; never retry an unknown claim. */
    }
    await owned(id);
    await c.store.recordProfileDelivery(id, row.id, ack);
  }
  const final = await owned(id);
  if (final.projection.emailVerified || final.flow.challengeId) throw new Error("Profile stage changed");
  await final.store.currentProfileDelivery(id, row.id);
  return {
    state: "profile_email_verification_pending" as const,
    email: final.projection.email,
    requestId: final.flow.requestId,
    expiresAt: final.original.expires_at.toISOString(),
    profileDelivery: await final.store.profileDeliveryProjection(id),
  };
}
/** Deliberate replacement only; exact previous attempt and shared contact quota remain server-owned. */
export async function replaceReviewedWorkforceProfileEmail(command: {
  operationId: string;
  operationKey: string;
  attemptId: string;
}) {
  if (!enrollmentUuid(command.operationId) || !enrollmentUuid(command.operationKey) || !enrollmentUuid(command.attemptId))
    return unavailable();
  try {
    return await issueProfile(command.operationId, command.operationKey, command.attemptId);
  } catch {
    return unavailable();
  }
}
export async function startReviewedWorkforceEnrollment(command: {
  operationId: string;
  requestId: string;
  operationKey: string;
}) {
  if (!enrollmentUuid(command.operationId) || !enrollmentUuid(command.operationKey)) return unavailable();
  try {
    const c = await context(command.operationId, command.requestId),
      store = workforceEnrollmentStore(),
      original = await store.begin(c.projection, command.requestId, command.operationKey);
    const existing = await readWorkforceState();
    if (existing?.purpose === "reviewed-workforce-enrollment" && existing.enrollmentId === command.operationId) {
      if (existing.requestId !== command.requestId) throw new Error("Original browser request changed");
      if (existing.challengeId)
        return await inspectReviewedWorkforceEnrollmentEntry({
          operationId: command.operationId,
          requestId: command.requestId,
        });
      await owned(command.operationId);
    } else await flow(original);
    if (!c.projection.emailVerified) return await issueProfile(command.operationId, command.operationKey);
    const settings = await getLoginSettings({ serviceConfig: c.serviceConfig, organization: c.policy.organizationId }),
      methods = await listAuthenticationMethodTypes({
        serviceConfig: c.serviceConfig,
        userId: c.projection.providerSubject,
      });
    if (!settings?.allowLocalAuthentication || !methods.authMethodTypes.includes(AuthenticationMethodType.OTP_EMAIL))
      throw new Error("Native email method unavailable");
    const row = await store.base.reserve({
      operationKey: command.operationKey,
      issuer: c.policy.issuer,
      userId: c.projection.providerSubject,
      clientId: c.projection.clientId,
      requestId: command.requestId,
      contact: c.projection.email,
      purpose: "reviewed_enrollment",
    });
    return await issue(command.operationId, row, await workforceProvider(c.serviceConfig, c.policy.organizationId));
  } catch {
    return unavailable();
  }
}
export async function verifyReviewedWorkforceProfileEmail(command: {
  operationId: string;
  operationKey: string;
  code: string;
}) {
  if (
    !enrollmentUuid(command.operationId) ||
    !enrollmentUuid(command.operationKey) ||
    typeof command.code !== "string" ||
    !/^([A-Z0-9]{6})$/.test(command.code)
  )
    return unavailable();
  try {
    let c = await owned(command.operationId);
    if (!c.projection.emailVerified) {
      if (!(await c.store.profileAttempt(command.operationId, command.operationKey, command.code))) return unavailable();
      try {
        await verifyEmail({
          serviceConfig: c.serviceConfig,
          userId: c.projection.providerSubject,
          verificationCode: command.code,
        });
      } catch {
        /* Exact readback resolves a lost response; never consume again blindly. */
      }
      c = await owned(command.operationId);
      if (!c.projection.emailVerified) return unavailable();
    }
    const methods = await listAuthenticationMethodTypes({
      serviceConfig: c.serviceConfig,
      userId: c.projection.providerSubject,
    });
    if (!methods.authMethodTypes.includes(AuthenticationMethodType.OTP_EMAIL)) {
      try {
        await addOTPEmail({ serviceConfig: c.serviceConfig, userId: c.projection.providerSubject });
      } catch {
        /* Native current method readback only. */
      }
      const current = await listAuthenticationMethodTypes({
        serviceConfig: c.serviceConfig,
        userId: c.projection.providerSubject,
      });
      if (!current.authMethodTypes.includes(AuthenticationMethodType.OTP_EMAIL)) return unavailable();
    }
    await owned(command.operationId);
    return { state: "profile_email_verified" as const };
  } catch {
    return unavailable();
  }
}
export async function verifyReviewedWorkforceEnrollment(command: {
  operationId: string;
  challengeId: string;
  operationKey: string;
  code: string;
}) {
  if (
    !enrollmentUuid(command.operationId) ||
    !enrollmentUuid(command.challengeId) ||
    !enrollmentUuid(command.operationKey) ||
    !/^\d{8}$/.test(command.code)
  )
    return unavailable();
  try {
    const c = await owned(command.operationId);
    if (c.flow.challengeId !== command.challengeId || !c.projection.emailVerified) return unavailable();
    const row = await c.store.base.currentEnrollmentChallenge(command.challengeId);
    if (row.provider_session_id !== c.flow.sessionId) return unavailable();
    const provider = await workforceProvider(c.serviceConfig, c.policy.organizationId),
      attempt = await c.store.base.attempt(row.id, command.operationKey, command.code);
    let result;
    if (attempt.first) {
      try {
        result = await provider.verify(row, attempt, command.code);
      } catch (error) {
        if (isClassifiedError(error) && error.isUserError) {
          await c.store.base.failed(attempt.id);
          return unavailable();
        }
        if (!provider.verificationAccepted(await provider.read(row), row, attempt)) return unavailable();
        result = await provider.token(row);
      }
    } else {
      if (attempt.state === "failed" || !provider.verificationAccepted(await provider.read(row), row, attempt))
        return unavailable();
      result = await provider.token(row);
    }
    if (!provider.verificationAccepted(result.session, row, attempt)) return unavailable();
    const verifiedAt = providerTimestampMs(result.session.factors?.otpEmail?.verifiedAt),
      expires = sessionExpiresAt(result.session);
    if (verifiedAt === undefined || expires === undefined) return unavailable();
    await owned(command.operationId);
    await c.store.base.session(row.id, result.session.id, result.token);
    await c.store.base.verifiedEnrollment(
      attempt.id,
      new Date(verifiedAt),
      new Date(Math.min(expires, row.expires_at.getTime())),
    );
    await c.store.ceremony(command.operationId);
    return { state: "identity_link_pending" as const };
  } catch {
    return unavailable();
  }
}
export async function resendReviewedWorkforceEnrollment(command: {
  operationId: string;
  challengeId: string;
  operationKey: string;
}) {
  if (!enrollmentUuid(command.operationId) || !enrollmentUuid(command.challengeId) || !enrollmentUuid(command.operationKey))
    return unavailable();
  try {
    const c = await owned(command.operationId);
    if (c.flow.challengeId !== command.challengeId || !c.projection.emailVerified) return unavailable();
    const row = await c.store.base.currentEnrollmentChallenge(command.challengeId),
      next = await c.store.base.reserve(
        {
          operationKey: command.operationKey,
          issuer: c.policy.issuer,
          userId: c.projection.providerSubject,
          clientId: c.projection.clientId,
          requestId: c.flow.requestId,
          contact: c.projection.email,
          purpose: "reviewed_enrollment",
        },
        row.id,
      );
    return await issue(command.operationId, next, await workforceProvider(c.serviceConfig, c.policy.organizationId));
  } catch {
    return unavailable();
  }
}
export async function cancelReviewedWorkforceEnrollment(command: { operationId: string; operationKey: string }) {
  if (!enrollmentUuid(command.operationId) || !enrollmentUuid(command.operationKey)) return unavailable();
  try {
    const c = await owned(command.operationId);
    await c.store.retire(command.operationId, "cancelled");
    await deleteWorkforceState();
    await flushWorkforceRevocations(c.store.base, await workforceProvider(c.serviceConfig, c.policy.organizationId));
    return { state: "cancelled" as const };
  } catch {
    return unavailable();
  }
}
export async function completeReviewedWorkforceEnrollment(command: {
  operationId: string;
  challengeId: string;
  operationKey: string;
}) {
  if (!enrollmentUuid(command.operationId) || !enrollmentUuid(command.challengeId) || !enrollmentUuid(command.operationKey))
    return unavailable();
  try {
    const c = await owned(command.operationId, true);
    if (c.flow.challengeId !== command.challengeId) return unavailable();
    const result = (await enrollmentIdentityRequest("complete", command.operationId, {
      challengeId: command.challengeId,
      sessionId: c.flow.sessionId,
    })) as unknown as Record<string, unknown>;
    if (
      !result ||
      result.enrollmentId !== command.operationId ||
      result.personId !== c.projection.personId ||
      result.policyId !== c.projection.policyId ||
      result.clientId !== c.projection.clientId ||
      result.issuer !== c.projection.issuer ||
      result.organizationId !== c.projection.organizationId ||
      result.evidenceId !== command.challengeId ||
      result.providerSessionId !== c.flow.sessionId ||
      result.subject !== c.projection.providerSubject ||
      result.profileClass !== "workforce" ||
      result.state !== "completed"
    )
      return unavailable();
    await owned(command.operationId, true);
    await c.store.retire(command.operationId, "completed");
    return { state: "enrollment_completed_access_pending" as const };
  } catch {
    return unavailable();
  }
}

/** Read-only presentation facts. Inspection never starts a flow, creates a Session or sends a code. */
export async function inspectReviewedWorkforceEnrollmentEntry(command: { operationId: string; requestId?: string }) {
  if (!enrollmentUuid(command.operationId)) return unavailable();
  try {
    const existing = await readWorkforceState();
    if (existing?.purpose === "reviewed-workforce-enrollment" && existing.enrollmentId === command.operationId) {
      const c = await owned(command.operationId, true);
      if (command.requestId !== undefined && command.requestId !== c.flow.requestId) return unavailable();
      const common = { email: c.projection.email, requestId: c.flow.requestId };
      if (c.original.retirement === "completed") return { ...common, state: "enrollment_completed_access_pending" as const };
      if (!c.flow.challengeId)
        return {
          ...common,
          state: c.projection.emailVerified
            ? ("profile_email_verified" as const)
            : ("profile_email_verification_pending" as const),
          ...(!c.projection.emailVerified
            ? {
                expiresAt: c.original.expires_at.toISOString(),
                profileDelivery: await c.store.profileDeliveryProjection(command.operationId),
              }
            : {}),
        };
      if (!c.projection.emailVerified) return unavailable();
      const row = await c.store.base.currentEnrollmentChallenge(c.flow.challengeId);
      if (!["issued", "verified"].includes(row.state)) return unavailable();
      if (
        row.provider_session_id !== c.flow.sessionId ||
        row.client_id !== c.projection.clientId ||
        row.provider_subject !== c.projection.providerSubject ||
        row.request_id !== c.flow.requestId
      )
        return unavailable();
      const final = await owned(command.operationId);
      if (final.flow.challengeId !== row.id || final.flow.sessionId !== row.provider_session_id) return unavailable();
      return {
        ...common,
        state: row.state === "verified" ? ("identity_link_pending" as const) : ("otp_pending" as const),
        challengeId: row.id,
        expiresAt: new Date(Math.min(row.expires_at.getTime(), c.original.expires_at.getTime())).toISOString(),
        resendAt: new Date(row.created_at.getTime() + 60000).toISOString(),
      };
    }
    if (command.requestId === undefined) {
      const c = await prepared(command.operationId);
      return { email: c.projection.email, state: "oidc_request_required" as const };
    }
    const c = await context(command.operationId, command.requestId);
    return { email: c.projection.email, requestId: command.requestId, state: "ready_to_start" as const };
  } catch {
    return unavailable();
  }
}
/** Recipe only: public landing and exact owning OIDC request must be qualified before delivery. */
export async function reviewedWorkforceEmailVerificationTemplate(operationId: string, requestId: string) {
  const policy = workforcePolicy();
  if (!policy || !enrollmentUuid(operationId) || !validOriginalRequestId(requestId))
    throw new Error("Reviewed original request required");
  const basePath = process.env.NEXT_PUBLIC_BASE_PATH;
  if (basePath !== "/ui/v2/login") throw new Error("Registered Login base path required");
  const { serviceConfig } = getServiceConfig(await headers());
  if (new URL(serviceConfig.baseUrl).origin !== policy.issuer) throw new Error("Registered issuer required");
  const { authRequest } = await getAuthRequest({ serviceConfig, authRequestId: requestId.slice(5) });
  if (!authRequest || !policy.clientIds.includes(authRequest.clientId))
    throw new Error("Actual registered native request required");
  const url = new URL(basePath + "/workforce-enrollment", policy.issuer);
  url.searchParams.set("operationId", operationId);
  url.searchParams.set("requestId", requestId);
  const value = url.href + "#code={{.Code}}";
  if (value.length > 200) throw new Error("Native verification template exceeds bound");
  return value;
}
