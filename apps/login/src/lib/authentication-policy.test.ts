import { Prompt } from "@zitadel/proto/zitadel/oidc/v2/authorization_pb";
import type { Session } from "@zitadel/proto/zitadel/session/v2/session_pb";
import { describe, expect, it } from "vitest";
import {
  hasFreshPasskeyVerification,
  providerTimestampMs,
  satisfiesAuthorizationFreshness,
  sessionExpiresAt,
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
