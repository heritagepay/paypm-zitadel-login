import { Code, create, type Client } from "@zitadel/client";
import { RequestChallengesSchema } from "@zitadel/proto/zitadel/session/v2/challenge_pb";
import type { Session } from "@zitadel/proto/zitadel/session/v2/session_pb";
import { ChecksSchema, SessionService } from "@zitadel/proto/zitadel/session/v2/session_service_pb";
import "server-only";
import {
  activeSessionIdentifiesUser,
  providerTimestampMs,
  sessionIdentifiesUser,
  sessionLifetime,
  verifiedFactor,
} from "./authentication-policy";
import { getUserAgent } from "./fingerprint";
import { isClassifiedError } from "./grpc/interceptors/error-classification";
import { createServiceForHost } from "./service";
import { WorkforceStoreError, type WorkforceAttempt, type WorkforceChallenge } from "./workforce-store";
import type { ServiceConfig } from "./zitadel";

const bytes = (value: string) => new TextEncoder().encode(value);
const text = (value: Uint8Array | undefined) => (value ? new TextDecoder().decode(value) : undefined);
const creationKey = "paypm_workforce_challenge";
export class WorkforceProvider {
  constructor(
    private readonly api: Client<typeof SessionService>,
    private readonly organizationId: string,
  ) {}
  private binding(session: Session, row: WorkforceChallenge) {
    if (
      session.factors?.user?.id !== row.provider_subject ||
      session.factors.user.organizationId !== this.organizationId ||
      text(session.metadata[creationKey]) !== row.id ||
      !activeSessionIdentifiesUser(session)
    )
      throw new WorkforceStoreError("provider_session_mismatch");
    return session;
  }
  async create(row: WorkforceChallenge) {
    const result = await this.api.createSession({
      checks: create(ChecksSchema, { user: { search: { case: "userId", value: row.provider_subject } } }),
      metadata: { [creationKey]: bytes(row.id) },
      lifetime: sessionLifetime(),
      userAgent: await getUserAgent(),
    });
    if (!result.sessionId || !result.sessionToken) throw new WorkforceStoreError("provider_create_unconfirmed");
    const session = this.binding((await this.api.getSession({ sessionId: result.sessionId })).session!, row);
    return { session, token: result.sessionToken };
  }
  async find(row: WorkforceChallenge) {
    const results = await this.api.listSessions({
      query: { limit: 100, offset: BigInt(0), asc: false },
      queries: [{ query: { case: "userIdQuery", value: { id: row.provider_subject } } }],
    });
    const matches = results.sessions.filter((s) => text(s.metadata[creationKey]) === row.id);
    if (matches.length !== 1 || Number(results.details?.totalResult ?? 0) > 100)
      throw new WorkforceStoreError("provider_create_unconfirmed");
    return this.binding(matches[0], row);
  }
  async read(row: WorkforceChallenge) {
    if (!row.provider_session_id) throw new WorkforceStoreError("provider_session_pending");
    const session = (await this.api.getSession({ sessionId: row.provider_session_id })).session;
    if (!session) throw new WorkforceStoreError("provider_session_unavailable");
    return this.binding(session, row);
  }
  async token(row: WorkforceChallenge) {
    const current = await this.read(row),
      result = await this.api.setSession({
        sessionId: current.id,
        checks: {},
        lifetime: sessionLifetime(undefined, current),
      });
    if (!result.sessionToken) throw new WorkforceStoreError("provider_token_unconfirmed");
    return { session: await this.read(row), token: result.sessionToken };
  }
  async attachEnrollment(row: WorkforceChallenge, ceremonyHash: string) {
    if (row.purpose !== "reviewed_enrollment" || !/^[a-f0-9]{64}$/.test(ceremonyHash))
      throw new WorkforceStoreError("enrollment_purpose_mismatch");
    const current = await this.read(row),
      key = "paypm_workforce_enrollment_" + row.id;
    const old = text(current.metadata[key]);
    if (old && old !== ceremonyHash) throw new WorkforceStoreError("enrollment_metadata_changed");
    if (!old)
      await this.api.setSession({
        sessionId: current.id,
        checks: {},
        metadata: { [key]: bytes(ceremonyHash) },
        lifetime: sessionLifetime(undefined, current),
      });
    const final = await this.read(row);
    if (text(final.metadata[key]) !== ceremonyHash) throw new WorkforceStoreError("enrollment_metadata_unconfirmed");
    return final;
  }
  async deliver(row: WorkforceChallenge) {
    const current = await this.read(row),
      result = await this.api.setSession({
        sessionId: current.id,
        checks: {},
        metadata: { ["paypm_workforce_delivery_" + row.id]: bytes(row.operation_key) },
        challenges: create(RequestChallengesSchema, { otpEmail: { deliveryType: { case: "sendCode", value: {} } } }),
        lifetime: sessionLifetime(undefined, current),
      });
    if (!result.sessionToken) throw new WorkforceStoreError("provider_delivery_unconfirmed");
    return { session: await this.read(row), token: result.sessionToken };
  }
  deliveryAccepted(session: Session, row: WorkforceChallenge) {
    return text(session.metadata["paypm_workforce_delivery_" + row.id]) === row.operation_key;
  }
  async verify(row: WorkforceChallenge, attempt: WorkforceAttempt, code: string) {
    const current = await this.read(row),
      result = await this.api.setSession({
        sessionId: current.id,
        checks: create(ChecksSchema, { otpEmail: { code } }),
        metadata: { ["paypm_workforce_attempt_" + attempt.id]: bytes(attempt.code_hash) },
        lifetime: sessionLifetime(undefined, current),
      });
    if (!result.sessionToken) throw new WorkforceStoreError("provider_verify_unconfirmed");
    return { session: await this.read(row), token: result.sessionToken };
  }
  verificationAccepted(session: Session, row: WorkforceChallenge, attempt: WorkforceAttempt) {
    const verifiedAt = providerTimestampMs(session.factors?.otpEmail?.verifiedAt);
    return (
      this.deliveryAccepted(session, row) &&
      text(session.metadata["paypm_workforce_attempt_" + attempt.id]) === attempt.code_hash &&
      verifiedFactor(session, session.factors?.otpEmail?.verifiedAt) &&
      verifiedAt !== undefined &&
      verifiedAt >= attempt.created_at.getTime() &&
      verifiedAt >= (row.issued_at?.getTime() ?? Infinity)
    );
  }
  async revoke(sessionId: string) {
    await this.api.deleteSession({ sessionId });
  }
  /** Purpose-bound logout rereads uncertain deletion; never retires a caller-selected subject. */
  async retireOwnedSession(sessionId: string, subject: string) {
    const read = async () => {
      try {
        const session = (await this.api.getSession({ sessionId })).session;
        if (!session) throw new WorkforceStoreError("provider_retirement_unconfirmed");
        return session;
      } catch (error) {
        if (isClassifiedError(error) && error.code === Code.NotFound) return undefined;
        throw error;
      }
    };
    const current = await read();
    if (!current) return true;
    if (
      current.id !== sessionId ||
      current.factors?.user?.id !== subject ||
      current.factors.user.organizationId !== this.organizationId
    )
      throw new WorkforceStoreError("retirement_provider_binding_changed");
    try {
      await this.api.deleteSession({ sessionId });
    } catch (error) {
      if (!isClassifiedError(error) || error.code !== Code.NotFound) throw error;
    }
    return (await read()) === undefined;
  }
  /** Restart retirement is bound to the exact challenge metadata, even for expired native Sessions. */
  async retireEnrollmentChallenge(sessionId: string, row: WorkforceChallenge) {
    if (row.purpose !== "reviewed_enrollment") throw new WorkforceStoreError("enrollment_purpose_mismatch");
    const read = async () => {
      try {
        const session = (await this.api.getSession({ sessionId })).session;
        if (!session) throw new WorkforceStoreError("provider_retirement_unconfirmed");
        return session;
      } catch (error) {
        if (isClassifiedError(error) && error.code === Code.NotFound) return undefined;
        throw error;
      }
    };
    const session = await read();
    if (!session) return true;
    if (
      session.id !== sessionId ||
      session.factors?.user?.id !== row.provider_subject ||
      session.factors.user.organizationId !== this.organizationId ||
      text(session.metadata[creationKey]) !== row.id ||
      !sessionIdentifiesUser(session)
    )
      throw new WorkforceStoreError("retirement_provider_binding_changed");
    try {
      await this.api.deleteSession({ sessionId });
    } catch (error) {
      if (!isClassifiedError(error) || error.code !== Code.NotFound) throw error;
    }
    return (await read()) === undefined;
  }
  async findActionIntent(operationKey: string, subject: string, metadataKey = "paypm_workforce_action_intent") {
    const result = await this.api.listSessions({
      query: { limit: 100, offset: BigInt(0), asc: false },
      queries: [{ query: { case: "userIdQuery", value: { id: subject } } }],
    });
    const matches = result.sessions.filter((s) => text(s.metadata[metadataKey]) === operationKey);
    if (
      result.details?.totalResult === undefined ||
      Number(result.details.totalResult) > 100 ||
      Number(result.details.totalResult) < result.sessions.length ||
      matches.length !== 1 ||
      matches[0].factors?.user?.id !== subject ||
      matches[0].factors.user.organizationId !== this.organizationId ||
      !activeSessionIdentifiesUser(matches[0])
    )
      throw new WorkforceStoreError("action_provider_pending");
    return matches[0].id;
  }
  /** Complete, bounded read only. An absent result never proves an in-flight creation failed. */
  async inspectActionIntent(operationKey: string, subject: string, metadataKey: string) {
    const result = await this.api.listSessions({
      query: { limit: 100, offset: BigInt(0), asc: false },
      queries: [{ query: { case: "userIdQuery", value: { id: subject } } }],
    });
    const matches = result.sessions.filter((s) => text(s.metadata[metadataKey]) === operationKey);
    if (
      result.details?.totalResult === undefined ||
      Number(result.details.totalResult) !== result.sessions.length ||
      result.sessions.length > 100 ||
      matches.length > 1
    )
      throw new WorkforceStoreError("action_provider_pending");
    const session = matches[0];
    if (!session) return undefined;
    if (
      session.factors?.user?.id !== subject ||
      session.factors.user.organizationId !== this.organizationId ||
      !sessionIdentifiesUser(session)
    )
      throw new WorkforceStoreError("action_provider_pending");
    return session;
  }
}
export async function workforceProvider(serviceConfig: ServiceConfig, organizationId: string) {
  return new WorkforceProvider(await createServiceForHost(SessionService, serviceConfig), organizationId);
}
