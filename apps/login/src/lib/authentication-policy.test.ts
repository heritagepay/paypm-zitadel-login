import { Prompt } from "@zitadel/proto/zitadel/oidc/v2/authorization_pb";
import type { Session } from "@zitadel/proto/zitadel/session/v2/session_pb";
import { describe, expect, it } from "vitest";
import {
  activeSessionIdentifiesUser,
  hasFreshPasskeyVerification,
  providerTimestampMs,
  satisfiesAuthorizationFreshness,
  sessionExpiresAt,
  sessionIdentifiesUser,
  sessionLifetime,
  verifiedFactor,
  WEB_SESSION_ABSOLUTE_MS,
} from "./authentication-policy";

const now = 1_800_000_000_000;
const timestamp = (milliseconds: number) =>
  ({ seconds: BigInt(Math.floor(milliseconds / 1000)), nanos: (milliseconds % 1000) * 1_000_000 }) as any;
const session = (): Session =>
  ({
    creationDate: timestamp(now - 300000),
    expirationDate: timestamp(now + 3600000),
    factors: {
      user: { id: "expected-user", verifiedAt: timestamp(now - 300000) },
      webAuthN: { userVerified: true, verifiedAt: timestamp(now - 1000) },
    },
  }) as any;

describe("bounded provider authentication evidence", () => {
  it.each([
    undefined,
    { seconds: "1800000000", nanos: 0 },
    { seconds: BigInt(1800000000), nanos: -1 },
    { seconds: BigInt(1800000000), nanos: 1e9 },
    { seconds: BigInt(1800000000), nanos: 0.5 },
    { seconds: BigInt(Number.MAX_SAFE_INTEGER), nanos: 0 },
  ])("denies malformed timestamp fixture %#", (value) => {
    expect(providerTimestampMs(value as any)).toBeUndefined();
  });
  it("caps sessions at 8h even when provider expiry is later", () => {
    const value = session();
    value.expirationDate = timestamp(now + 24 * 3600000);
    expect(sessionExpiresAt(value, now)).toBe(now - 300000 + WEB_SESSION_ABSOLUTE_MS);
    expect(sessionExpiresAt(value, now + WEB_SESSION_ABSOLUTE_MS)).toBeUndefined();
  });
  it.each(["creationDate", "expirationDate"] as const)("denies missing %s", (field) => {
    const value = session();
    value[field] = undefined;
    expect(sessionExpiresAt(value, now)).toBeUndefined();
  });
  it("denies future creation and elapsed provider expiry", () => {
    expect(sessionExpiresAt({ ...session(), creationDate: timestamp(now + 1) }, now)).toBeUndefined();
    expect(sessionExpiresAt({ ...session(), expirationDate: timestamp(now) }, now)).toBeUndefined();
  });
  it("does not accept a missing, future or pre-session factor", () => {
    expect(verifiedFactor(session(), undefined, now)).toBe(false);
    expect(verifiedFactor(session(), timestamp(now + 1), now)).toBe(false);
    expect(verifiedFactor(session(), timestamp(now - 300001), now)).toBe(false);
    expect(verifiedFactor(session(), timestamp(now - 1000), now)).toBe(true);
  });
  it("clamps creation and extension against live provider absolute expiry", () => {
    expect(sessionLifetime(undefined, undefined, now).seconds).toBe(BigInt(28800));
    expect(sessionLifetime({ seconds: BigInt(86400), nanos: 0 } as any, undefined, now).seconds).toBe(BigInt(28800));
    expect(sessionLifetime({ seconds: BigInt(86400), nanos: 0 } as any, session(), now).seconds).toBe(BigInt(3600));
    expect(sessionLifetime({ seconds: BigInt(600), nanos: 0 } as any, session(), now).seconds).toBe(BigInt(600));
    expect(() =>
      sessionLifetime(undefined, { ...session(), creationDate: timestamp(now - WEB_SESSION_ABSOLUTE_MS) }, now),
    ).toThrow();
    expect(() => sessionLifetime({ seconds: BigInt(0), nanos: 0 } as any, undefined, now)).toThrow();
  });
  it("accepts only expected identity and fresh provider-verified UV after ceremony start", () => {
    expect(hasFreshPasskeyVerification(session(), "expected-user", now - 2000, now)).toBe(true);
    expect(hasFreshPasskeyVerification(session(), "different-user", now - 2000, now)).toBe(false);
    expect(hasFreshPasskeyVerification(session(), "expected-user", now - 500, now)).toBe(false);
    expect(hasFreshPasskeyVerification(session(), "expected-user", now - 60001, now)).toBe(false);
    expect(hasFreshPasskeyVerification(session(), "expected-user", now + 1, now)).toBe(false);
    const value = session();
    value.factors!.webAuthN!.userVerified = false;
    expect(hasFreshPasskeyVerification(value, "expected-user", now - 2000, now)).toBe(false);
  });
  it("honors OIDC max_age and prompt=login without treating an MFA-only check as a new primary", () => {
    const request = { creationDate: timestamp(now - 500), prompt: [Prompt.LOGIN] } as any;
    expect(satisfiesAuthorizationFreshness(session(), request, false, now)).toBe(false);
    request.creationDate = timestamp(now - 2000);
    expect(satisfiesAuthorizationFreshness(session(), request, false, now)).toBe(true);
    request.prompt = [];
    request.maxAge = { seconds: BigInt(0), nanos: 0 };
    expect(satisfiesAuthorizationFreshness(session(), request, false, now)).toBe(true);
    request.creationDate = timestamp(now - 500);
    expect(satisfiesAuthorizationFreshness(session(), request, false, now)).toBe(false);
    request.maxAge = { seconds: BigInt(1), nanos: 0 };
    expect(satisfiesAuthorizationFreshness(session(), request, false, now)).toBe(true);
    request.maxAge = { seconds: BigInt(0), nanos: 1000 };
    expect(satisfiesAuthorizationFreshness(session(), request, false, now)).toBe(false);
  });
});

describe("native user identification is not credential verification", () => {
  const nativeSession = () =>
    ({
      creationDate: { seconds: BigInt(1791481361), nanos: 712607000 },
      expirationDate: { seconds: BigInt(1791510161), nanos: 712607000 },
      factors: { user: { id: "expected-user", verifiedAt: { seconds: BigInt(1791481361), nanos: 709949000 } } },
    }) as any;
  const observed = 1791481362000;
  it("accepts the recorded CheckUser-before-SessionAdded ordering without a tolerance window", () => {
    const value = nativeSession();
    expect(activeSessionIdentifiesUser(value, observed)).toBe(true);
    expect(verifiedFactor(value, value.factors.user.verifiedAt, observed)).toBe(false);
    expect(hasFreshPasskeyVerification(value, "expected-user", observed - 1000, observed)).toBe(false);
    const request = { creationDate: timestamp(observed - 1000), prompt: [Prompt.LOGIN] } as any;
    expect(satisfiesAuthorizationFreshness(value, request, true, observed)).toBe(false);
    for (const factor of ["password", "webAuthN", "intent", "otpEmail"]) {
      const candidate = nativeSession();
      candidate.factors[factor] = { userVerified: true, verifiedAt: candidate.factors.user.verifiedAt };
      expect(satisfiesAuthorizationFreshness(candidate, request, true, observed)).toBe(false);
    }
    value.factors.webAuthN = { userVerified: true, verifiedAt: timestamp(observed - 100) };
    expect(hasFreshPasskeyVerification(value, "expected-user", observed - 500, observed)).toBe(true);
    expect(hasFreshPasskeyVerification(value, "other-user", observed - 500, observed)).toBe(false);
    value.factors.webAuthN.userVerified = false;
    expect(hasFreshPasskeyVerification(value, "expected-user", observed - 500, observed)).toBe(false);
  });
  it.each([
    "no-user",
    "empty-subject",
    "missing-lookup",
    "future-lookup",
    "bad-lookup",
    "no-creation",
    "future-creation",
    "no-expiry",
    "invalid-expiry",
  ])("denies %s", (kind) => {
    const value = nativeSession();
    if (kind === "no-user") value.factors.user = undefined;
    if (kind === "empty-subject") value.factors.user.id = " ";
    if (kind === "missing-lookup") value.factors.user.verifiedAt = undefined;
    if (kind === "future-lookup") value.factors.user.verifiedAt = timestamp(observed + 1);
    if (kind === "bad-lookup") value.factors.user.verifiedAt.nanos = 1e9;
    if (kind === "no-creation") value.creationDate = undefined;
    if (kind === "future-creation") value.creationDate = timestamp(observed + 1);
    if (kind === "no-expiry") value.expirationDate = undefined;
    if (kind === "invalid-expiry") value.expirationDate = value.creationDate;
    expect(activeSessionIdentifiesUser(value, observed)).toBe(false);
    expect(sessionIdentifiesUser(value, observed)).toBe(false);
  });
  it("allows structural retirement readback of expired records while denying active use or renewal", () => {
    const value = nativeSession();
    value.expirationDate = timestamp(observed - 100);
    expect(sessionIdentifiesUser(value, observed)).toBe(true);
    expect(activeSessionIdentifiesUser(value, observed)).toBe(false);
    expect(() => sessionLifetime(undefined, value, observed)).toThrow();
    value.expirationDate = timestamp(observed + 86400000);
    expect(activeSessionIdentifiesUser(value, observed + WEB_SESSION_ABSOLUTE_MS)).toBe(false);
    expect(sessionIdentifiesUser(value, observed + WEB_SESSION_ABSOLUTE_MS)).toBe(true);
  });
});
