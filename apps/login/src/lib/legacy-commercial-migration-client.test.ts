import { createHmac } from "crypto";
import { readFileSync } from "fs";
import { resolve } from "path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  obtainLegacyEligibility,
  validLegacyEligibility,
  type LegacyMigrationEligibility,
} from "./legacy-commercial-migration-client";
import { decryptLegacyMigrationState, encryptLegacyMigrationState } from "./legacy-commercial-migration-state";
vi.mock("next/headers", () => ({ cookies: vi.fn() }));
const fixture = JSON.parse(
  readFileSync(resolve(import.meta.dirname, "../../../../docs/auth/merchant-migration-eligibility-fixture.json"), "utf8"),
) as { frozenAt: string; eligibility: LegacyMigrationEligibility };
const e = fixture.eligibility,
  scope = { appId: e.appId, deploymentId: e.deploymentId, environment: e.environment };
beforeEach(() => {
  vi.useFakeTimers();
  vi.setSystemTime(new Date(fixture.frozenAt));
  vi.stubEnv("PAYPM_LEGACY_MIGRATION_ISSUER", e.legacyAuthentication.issuer);
  vi.stubEnv("PAYPM_LEGACY_MIGRATION_FLOW_KEY_BASE64", Buffer.alloc(32, 25).toString("base64"));
  vi.stubEnv(
    "PAYPM_LEGACY_MIGRATION_CONTEXTS_JSON",
    JSON.stringify([
      {
        ...scope,
        clientIds: [e.legacyAuthentication.clientId],
        backendUrl: "https://api.example.test",
        backendApiKey: "independent-reader-token".repeat(2),
        backendSigningKey: "independent-reader-key".repeat(2),
        backendApprovalApiKey: "independent-approval-token".repeat(2),
        backendApprovalSigningKey: "independent-approval-key".repeat(2),
        rpId: "login.example.test",
        origin: "https://login.example.test",
      },
    ]),
  );
});
afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
});
describe("independent legacy migration broker wire and protected state", () => {
  it("accepts actual backend frozen hash/schema and uses exact private HMACv2 body/path", async () => {
    expect(validLegacyEligibility(e, scope)).toEqual(e);
    const fetcher = vi.fn().mockResolvedValue(new Response(JSON.stringify(e)));
    vi.stubGlobal("fetch", fetcher);
    const input = {
      operationKey: e.operationKey,
      originalAccessToken: "synthetic-old-access",
      businessId: e.businessId,
      ...scope,
      authentication: e.authentication,
      contactProof: { flowId: e.contactProofId, proofId: e.contactProofId, sessionToken: "synthetic-new-session" },
    };
    expect(await obtainLegacyEligibility(input)).toEqual(e);
    const [url, options] = fetcher.mock.calls[0];
    expect(url.pathname).toBe("/api/v1/internal/merchant/migration-proof-eligibility");
    const signature = options.headers["X-Plug-Wallet-Signature"],
      parts = /^t=(\d+),n=([a-f0-9-]+),v2=([a-f0-9]{64})$/.exec(signature)!;
    expect(parts[3]).toBe(
      createHmac("sha256", "independent-reader-key".repeat(2))
        .update(`${parts[1]}.${parts[2]}.POST.${url.pathname}.${options.body}`)
        .digest("hex"),
    );
    expect(options.body).toBe(JSON.stringify(input));
    expect(options.redirect).toBe("error");
  });
  it("denies substituted client, exact payload hash or scope and absent policy", () => {
    expect(() =>
      validLegacyEligibility(
        { ...e, legacyAuthentication: { ...e.legacyAuthentication, clientId: "workforce@paypm" } },
        scope,
      ),
    ).toThrow();
    expect(() => validLegacyEligibility({ ...e, personId: e.businessId }, scope)).toThrow();
    expect(() => validLegacyEligibility({ ...e, environment: "production" }, scope)).toThrow();
    vi.stubEnv("PAYPM_LEGACY_MIGRATION_CONTEXTS_JSON", "[]");
    expect(() => validLegacyEligibility(e, scope)).toThrow();
  });
  it("encrypts distinct legacy purpose state, denies tampering, wrong key and expiry", () => {
    const state = {
      requestId: e.eligibilityId,
      proofSessionId: "900",
      proofSessionToken: "secret-provider-token",
      challenge: "exact-provider-challenge",
      eligibility: e,
      issuedAt: Date.now(),
      expiresAt: Date.now() + 300000,
    };
    const value = encryptLegacyMigrationState(state);
    expect(value).not.toContain("secret-provider-token");
    expect(decryptLegacyMigrationState(value)).toEqual(state);
    const altered = Buffer.from(value, "base64url");
    altered[altered.length - 1] ^= 1;
    expect(decryptLegacyMigrationState(altered.toString("base64url"))).toBeUndefined();
    vi.stubEnv("PAYPM_LEGACY_MIGRATION_FLOW_KEY_BASE64", Buffer.alloc(32, 26).toString("base64"));
    expect(decryptLegacyMigrationState(value)).toBeUndefined();
    vi.stubEnv("PAYPM_LEGACY_MIGRATION_FLOW_KEY_BASE64", Buffer.alloc(32, 25).toString("base64"));
    vi.advanceTimersByTime(300000);
    expect(decryptLegacyMigrationState(value)).toBeUndefined();
  });
});
