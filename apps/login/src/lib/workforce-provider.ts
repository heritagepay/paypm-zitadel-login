import { create, type Client } from "@zitadel/client";
import { RequestChallengesSchema } from "@zitadel/proto/zitadel/session/v2/challenge_pb";
import type { Session } from "@zitadel/proto/zitadel/session/v2/session_pb";
import { ChecksSchema, SessionService } from "@zitadel/proto/zitadel/session/v2/session_service_pb";
import "server-only";
import { providerTimestampMs, sessionLifetime, verifiedFactor } from "./authentication-policy";
import { getUserAgent } from "./fingerprint";
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
      !verifiedFactor(session, session.factors.user.verifiedAt)
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
}
export async function workforceProvider(serviceConfig: ServiceConfig, organizationId: string) {
  return new WorkforceProvider(await createServiceForHost(SessionService, serviceConfig), organizationId);
}
