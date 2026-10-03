import type { Duration, Timestamp } from "@zitadel/client";
import { Prompt, type AuthRequest } from "@zitadel/proto/zitadel/oidc/v2/authorization_pb";
import type { Session } from "@zitadel/proto/zitadel/session/v2/session_pb";

export const WEB_SESSION_ABSOLUTE_MS = 8 * 60 * 60 * 1000;
export const FRESH_PASSKEY_MS = 60 * 1000;

export function providerTimestampMs(value: Timestamp | undefined): number | undefined {
  if (!value || typeof value.seconds !== "bigint") return undefined;
  const nanos = value.nanos ?? 0;
  if (!Number.isInteger(nanos) || nanos < 0 || nanos >= 1_000_000_000) return undefined;
  const milliseconds = Number(value.seconds) * 1000 + nanos / 1_000_000;
  return Number.isSafeInteger(Math.trunc(milliseconds)) && milliseconds > 0 ? milliseconds : undefined;
}

/** Only provider timestamps constrain lifetime; browser cookie timestamps are untrusted. */
export function sessionExpiresAt(session: Partial<Session>, now = Date.now()): number | undefined {
  const created = providerTimestampMs(session.creationDate);
  const expires = providerTimestampMs(session.expirationDate);
  if (created === undefined || expires === undefined || created > now || expires <= created) return undefined;
  const cutoff = Math.min(expires, created + WEB_SESSION_ABSOLUTE_MS);
  return cutoff > now ? cutoff : undefined;
}

export function verifiedFactor(session: Partial<Session>, timestamp: Timestamp | undefined, now = Date.now()): boolean {
  const verified = providerTimestampMs(timestamp);
  const created = providerTimestampMs(session.creationDate);
  return (
    sessionExpiresAt(session, now) !== undefined &&
    created !== undefined &&
    verified !== undefined &&
    verified >= created &&
    verified <= now
  );
}

export function sessionLifetime(requested?: Duration, session?: Partial<Session>, now = Date.now()): Duration {
  const cutoff = session ? sessionExpiresAt(session, now) : now + WEB_SESSION_ABSOLUTE_MS;
  if (cutoff === undefined) throw new Error("Session has expired or has no bounded provider lifetime");
  let requestedMs = WEB_SESSION_ABSOLUTE_MS;
  if (requested) {
    if (typeof requested.seconds !== "bigint") throw new Error("Invalid session lifetime");
    const nanos = requested.nanos ?? 0;
    if (!Number.isInteger(nanos) || nanos < 0 || nanos >= 1_000_000_000) throw new Error("Invalid session lifetime");
    requestedMs = Number(requested.seconds) * 1000 + nanos / 1_000_000;
    if (!Number.isFinite(requestedMs) || requestedMs <= 0) throw new Error("Invalid session lifetime");
  }
  // Round down so updates cannot extend the absolute cutoff by serialization rounding.
  const milliseconds = Math.floor(Math.min(requestedMs, cutoff - now));
  if (milliseconds <= 0) throw new Error("Session has expired");
  return { seconds: BigInt(Math.floor(milliseconds / 1000)), nanos: (milliseconds % 1000) * 1_000_000 } as Duration;
}

/** Authentication evidence only. Owning APIs must bind and consume action receipts separately. */
export function hasFreshPasskeyVerification(
  session: Partial<Session>,
  expectedUserId: string,
  ceremonyStartedAt: number,
  now = Date.now(),
): boolean {
  const factor = session.factors?.webAuthN;
  const verified = providerTimestampMs(factor?.verifiedAt);
  return (
    Number.isFinite(ceremonyStartedAt) &&
    ceremonyStartedAt <= now &&
    now - ceremonyStartedAt <= FRESH_PASSKEY_MS &&
    session.factors?.user?.id === expectedUserId &&
    verifiedFactor(session, session.factors.user.verifiedAt, now) &&
    factor?.userVerified === true &&
    verified !== undefined &&
    verified >= ceremonyStartedAt &&
    verifiedFactor(session, factor.verifiedAt, now)
  );
}

export function satisfiesAuthorizationFreshness(
  session: Session,
  request: AuthRequest,
  emailPrimary = false,
  now = Date.now(),
) {
  const candidates = [
    session.factors?.password?.verifiedAt,
    session.factors?.webAuthN?.verifiedAt,
    session.factors?.intent?.verifiedAt,
    ...(emailPrimary ? [session.factors?.otpEmail?.verifiedAt] : []),
  ];
  const verified = candidates
    .filter((value) => verifiedFactor(session, value, now))
    .map((value) => providerTimestampMs(value)!);
  const requested = providerTimestampMs(request.creationDate);
  const forced = request.prompt.includes(Prompt.LOGIN);
  const age = request.maxAge;
  if (!forced && !age) return true;
  if (verified.length === 0 || requested === undefined || requested > now) return false;
  if (forced && !verified.some((time) => time >= requested)) return false;
  if (age) {
    if (
      typeof age.seconds !== "bigint" ||
      age.seconds < BigInt(0) ||
      !Number.isInteger(age.nanos) ||
      age.nanos < 0 ||
      age.nanos >= 1e9
    )
      return false;
    const milliseconds = Number(age.seconds) * 1000 + age.nanos / 1e6;
    if (!Number.isFinite(milliseconds)) return false;
    if (!verified.some((time) => (milliseconds === 0 ? time >= requested : now - time <= milliseconds))) return false;
  }
  return true;
}
