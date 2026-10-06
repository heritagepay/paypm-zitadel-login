// @vitest-environment node
import { Code } from "@connectrpc/connect";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import fixture from "../../test-fixtures/identity-wallet-linkage.json";
import { readIdentityActionAuthority } from "./identity-action-authority";
import type { IdentityActionBinding } from "./identity-action-contract";
import {
  cancelIdentityPublicAction,
  completeIdentityPublicAction,
  observeIdentityAction,
  readIdentityAction,
  readIdentityPublicChallenge,
  startIdentityAction,
} from "./identity-action-service";
import { identityActionStore, type IdentityActionRow } from "./identity-action-store";
import { readIdentityAdmission } from "./identity-admission-reader";
import { workforceAssertionHash } from "./workforce-assertion";
import { workforceIdentityRequest } from "./workforce-identity-client";
import { workforcePolicy } from "./workforce-policy";
import { workforceProvider } from "./workforce-provider";
import { createSessionFromChecksAndChallenges, getSession, setSession } from "./zitadel";
vi.mock("next/headers", () => ({ headers: vi.fn(() => new Headers()) }));
vi.mock("./service-url", () => ({ getServiceConfig: () => ({ serviceConfig: { baseUrl: "https://auth.paypm.test" } }) }));
vi.mock("./identity-action-store", () => ({ identityActionStore: vi.fn() }));
vi.mock("./identity-action-authority", () => ({ readIdentityActionAuthority: vi.fn() }));
vi.mock("./identity-admission-reader", () => ({ readIdentityAdmission: vi.fn() }));
vi.mock("./workforce-policy", () => ({ workforcePolicy: vi.fn() }));
vi.mock("./workforce-identity-client", () => ({ workforceIdentityRequest: vi.fn() }));
vi.mock("./workforce-provider", () => ({ workforceProvider: vi.fn() }));
vi.mock("./workforce-store", () => ({ workforceStore: vi.fn(() => ({})) }));
vi.mock("./workforce-revocations", () => ({ flushWorkforceRevocations: vi.fn() }));
vi.mock("./zitadel", () => ({ createSessionFromChecksAndChallenges: vi.fn(), getSession: vi.fn(), setSession: vi.fn() }));
vi.mock("./grpc/interceptors/error-classification", () => ({ isClassifiedError: (e: any) => e?.classified === true }));
for (const purpose of ["staff_invitation", "staff_access_approval"] as const) {
  describe(`Staff original ceremony: ${purpose}`, () => {
    const command =
      purpose === "staff_invitation"
        ? {
            purpose,
            operationKey: fixture.command.operationKey,
            input: { email: "staff@example.test", givenName: "Test", familyName: "Staff" },
          }
        : {
            purpose,
            operationKey: fixture.command.operationKey,
            requestId: fixture.command.operationKey,
            requestCommitment: "a".repeat(64),
          };
    const binding = {
      expected: {
        ...fixture.expected,
        action: purpose === "staff_invitation" ? "identity.staff.invitation.issue" : "identity.staff.access.approve",
      },
      command,
      caseId: command.operationKey,
    } as IdentityActionBinding;
    const expected = binding.expected,
      now = new Date("2026-10-05T19:00:00Z"),
      id = randomUUID(),
      proofId = randomUUID();
    const cap = randomBytes(32).toString("base64url"),
      state = randomBytes(48).toString("base64url"),
      challenge = Buffer.from("original-real-challenge-public-synthetic-vector").toString("base64url");
    const ts = (ms: number) => ({ seconds: BigInt(Math.floor(ms / 1000)), nanos: (ms % 1000) * 1000000 });
    const caller = {
      idToken: "synthetic-id-token",
      accessToken: "synthetic-access-token",
      nonce: "synthetic-nonce",
      clientId: expected.clientId,
      capability: cap,
      callbackState: state,
      callbackUrl: "https://identity.paypm.test/api/v1/auth/browser/staff-actions/callback",
    };
    const provider = {
      sessionId: "901",
      sessionToken: "synthetic-private-step-token",
      publicKey: { rpId: "login.paypm.test", challenge, userVerification: "required" },
    };
    const receipt = `paypm-wf1.${Buffer.from(JSON.stringify({ version: 1, proofId, ...expected, verifiedAt: now.toISOString(), expiresAt: new Date(now.getTime() + 60000).toISOString() })).toString("base64url")}.${randomBytes(32).toString("base64url")}`;
    let row: IdentityActionRow, store: any, session: any;
    const path = "https://login.paypm.test/ui/v2/login/api/internal/v1/identity/actions/requests";
    const auth = (consumer = false) => ({ authorization: `Bearer ${consumer ? "c".repeat(40) : "b".repeat(40)}` });
    const pair = () => ({
      idToken: caller.idToken,
      accessToken: caller.accessToken,
      nonce: caller.nonce,
      clientId: expected.clientId,
    });
    const startBody = () => ({
      requestId: id,
      operationKey: binding.caseId,
      expected,
      command: binding.command,
      callbackState: state,
      ...pair(),
    });
    const start = (body: unknown = startBody(), suffix = "", headers: Record<string, string> = auth()) =>
      startIdentityAction(new Request(path + suffix, { method: "POST", headers, body: JSON.stringify(body) }));
    function assertion(flags = 5) {
      const ad = Buffer.alloc(37);
      createHash("sha256").update("login.paypm.test").digest().copy(ad);
      ad[32] = flags;
      return {
        id: "credential",
        rawId: "credential",
        type: "public-key",
        response: {
          clientDataJSON: Buffer.from(
            JSON.stringify({ type: "webauthn.get", origin: "https://login.paypm.test", challenge }),
          ).toString("base64url"),
          authenticatorData: ad.toString("base64url"),
          signature: "synthetic-provider-verified",
          userHandle: null,
        },
      };
    }
    const pub = (name: string, body: unknown) =>
      new Request(`https://login.paypm.test/ui/v2/login/api/identity/actions/${id}/${name}`, {
        method: "POST",
        headers: { origin: "https://login.paypm.test" },
        body: JSON.stringify(body),
      });
    const complete = (a = assertion()) =>
      completeIdentityPublicAction(pub("complete", { capability: cap, assertion: a }), id);
    function registered() {
      row = {
        ...row,
        state: "registered",
        provider_started_at: new Date(now.getTime() - 2000),
        provider_session_id: provider.sessionId,
        provider_material_sealed: "sealed-provider",
        proof_id: proofId,
        proof_expires_at: new Date(now.getTime() + 300000),
      };
    }
    beforeEach(() => {
      vi.useFakeTimers();
      vi.setSystemTime(now);
      vi.resetAllMocks();
      vi.stubEnv("PAYPM_WORKFORCE_PASSKEY_ORIGIN", "https://login.paypm.test");
      vi.stubEnv("PAYPM_WORKFORCE_PASSKEY_RP_ID", "login.paypm.test");
      vi.stubEnv("PAYPM_IDENTITY_ACTION_BFF_TOKEN", "b".repeat(40));
      vi.stubEnv("PAYPM_IDENTITY_ACTION_CONSUMER_TOKEN", "c".repeat(40));
      vi.stubEnv("PAYPM_IDENTITY_ADMISSION_READER_TOKEN", "d".repeat(40));
      vi.stubEnv(
        "PAYPM_IDENTITY_ACTION_CLIENT_POLICIES_JSON",
        JSON.stringify([
          { clientId: expected.clientId, callbackUrl: "https://identity.paypm.test/api/v1/auth/browser/actions/callback" },
        ]),
      );
      vi.mocked(workforcePolicy).mockReturnValue({
        issuer: expected.issuer,
        organizationId: expected.contextId,
        emailOtpReady: true,
        clientIds: [expected.clientId],
      } as any);
      vi.mocked(readIdentityAdmission).mockImplementation(async () =>
        Response.json({
          active: true,
          ...expected,
          plane: "workforce",
          authenticationClass: "workforce_limited",
          requestId: "original-oidc-request",
          revocationVersion: "0",
        }),
      );
      vi.mocked(readIdentityActionAuthority).mockImplementation(async (e, c) => ({ ...binding, expected: e, command: c }));
      row = {
        id,
        operation_key: binding.caseId,
        request_hash: "a".repeat(64),
        issuer: expected.issuer,
        provider_subject: expected.providerSubject,
        base_session_id: expected.baseSessionId,
        client_id: expected.clientId,
        request_id: "original-oidc-request",
        epoch: "0",
        binding,
        capability_hash: "c".repeat(64),
        caller_material_sealed: "sealed-caller",
        predecessor_request_id: null,
        state: "reserved",
        provider_conflicted: false,
        provider_started_at: null,
        provider_session_id: null,
        provider_material_sealed: null,
        proof_id: null,
        proof_expires_at: null,
        assertion_hash: null,
        assertion_sealed: null,
        verification_started_at: null,
        verified_at: null,
        receipt_hash: null,
        receipt_sealed: null,
        receipt_expires_at: null,
        created_at: new Date(now.getTime() - 5000),
        expires_at: new Date(now.getTime() + 295000),
      };
      store = {
        reserve: vi.fn(async () => row),
        clearExpired: vi.fn(),
        claimCreation: vi.fn(async () => {
          row.provider_started_at = new Date(now.getTime() - 1000);
          return true;
        }),
        caller: vi.fn(() => caller),
        provider: vi.fn(() => provider),
        assertion: vi.fn(() => assertion()),
        receipt: vi.fn(() => receipt),
        row: vi.fn(async () => row),
        observe: vi.fn(async () => row),
        capability: vi.fn(async () => row),
        created: vi.fn(
          async () =>
            (row = {
              ...row,
              state: "created",
              provider_session_id: provider.sessionId,
              provider_material_sealed: "sealed-provider",
            }),
        ),
        registered: vi.fn(
          async (_id, pid, expiry) => (row = { ...row, state: "registered", proof_id: pid, proof_expires_at: expiry }),
        ),
        attempt: vi.fn(async (_id, a) => {
          const first = !row.assertion_hash;
          row = {
            ...row,
            assertion_hash: workforceAssertionHash(a),
            assertion_sealed: "sealed-assertion",
            verification_started_at: new Date(now.getTime() - 1000),
          };
          return { row, first };
        }),
        verified: vi.fn(
          async (_id, verified, r, expiry) =>
            (row = {
              ...row,
              state: "verified",
              verified_at: verified,
              receipt_hash: createHash("sha256").update(r).digest("hex"),
              receipt_expires_at: expiry,
            }),
        ),
        retire: vi.fn(async () => {
          row.state = "retired";
        }),
        cancel: vi.fn(async () => {
          row.state = "cancelled";
        }),
      };
      vi.mocked(identityActionStore).mockReturnValue(store);
      vi.mocked(createSessionFromChecksAndChallenges).mockResolvedValue({
        sessionId: provider.sessionId,
        sessionToken: provider.sessionToken,
        challenges: { webAuthN: { publicKeyCredentialRequestOptions: { publicKey: provider.publicKey } } },
      } as any);
      session = {
        id: provider.sessionId,
        creationDate: ts(now.getTime() - 5000),
        expirationDate: ts(now.getTime() + 295000),
        factors: {
          user: { id: expected.providerSubject, organizationId: expected.contextId },
          webAuthN: { userVerified: true, verifiedAt: ts(now.getTime()) },
        },
        metadata: {
          paypm_identity_action_intent: new TextEncoder().encode(id),
          paypm_identity_action_client: new TextEncoder().encode(expected.clientId),
          paypm_identity_action_base: new TextEncoder().encode(expected.baseSessionId),
        },
      };
      vi.mocked(getSession).mockImplementation(async () => ({ session }) as any);
      vi.mocked(setSession).mockImplementation(async () => {
        session.metadata["paypm_workforce_passkey_request_" + proofId] = new TextEncoder().encode(row.assertion_hash!);
        return { sessionToken: "new-step-token" } as any;
      });
      vi.mocked(workforceIdentityRequest).mockImplementation(async (p) =>
        p.endsWith("/complete")
          ? { receipt, expiresAt: new Date(now.getTime() + 60000).toISOString(), binding: expected }
          : { requestId: proofId, expiresAt: new Date(now.getTime() + 300000).toISOString(), binding: expected },
      );
      vi.mocked(workforceProvider).mockResolvedValue({ inspectActionIntent: vi.fn(async () => undefined) } as any);
    });
    afterEach(() => {
      vi.useRealTimers();
      vi.unstubAllEnvs();
    });
    describe("headless Identity-only ceremony (provider/owner fakes, no real actor)", () => {
      it("reserves original and registers named Identity proof before capability-only redirect", async () => {
        const r = await start();
        expect(r.status).toBe(200);
        const body = await r.json();
        expect(body.redirectUrl).toBe(
          `https://login.paypm.test/ui/v2/login/identity/step-up?requestId=${id}&capability=${cap}`,
        );
        expect(JSON.stringify(body)).not.toContain(provider.sessionToken);
        expect(store.reserve.mock.invocationCallOrder[0]).toBeLessThan(
          vi.mocked(createSessionFromChecksAndChallenges).mock.invocationCallOrder[0],
        );
        expect(store.registered).toHaveBeenCalledWith(id, proofId, new Date(now.getTime() + 300000));
        expect(row.expires_at.getTime()).toBe(now.getTime() + 295000);
        expect(createSessionFromChecksAndChallenges).toHaveBeenCalledOnce();
      });
      it.each(["consumer", "cookie", "origin", "query", "wrongPath", "otherPurpose", "changedCase"])(
        "rejects %s before any reservation/provider effect",
        async (mode) => {
          const h = {
            ...auth(),
            ...(mode === "consumer" ? auth(true) : {}),
            ...(mode === "cookie" ? { cookie: "x=y" } : {}),
            ...(mode === "origin" ? { origin: "https://identity.paypm.test" } : {}),
          };
          const b =
            mode === "otherPurpose"
              ? { ...startBody(), command: { ...binding.command, purpose: "credential_recovery" } }
              : mode === "changedCase"
                ? { ...startBody(), operationKey: expected.personId }
                : startBody();
          expect((await start(b, mode === "query" ? "?token=x" : mode === "wrongPath" ? "/unexpected" : "", h)).status).toBe(
            403,
          );
          expect(store.reserve).not.toHaveBeenCalled();
          expect(createSessionFromChecksAndChallenges).not.toHaveBeenCalled();
        },
      );
      it.each(["defaultOff", "wrongPlane", "changedPerson", "changedSID", "ownerDenied"])(
        "denies current admission/authority %s",
        async (mode) => {
          if (mode === "defaultOff") vi.mocked(workforcePolicy).mockReturnValue({ emailOtpReady: false } as any);
          else if (mode === "ownerDenied")
            vi.mocked(readIdentityActionAuthority).mockRejectedValue(new Error("owner denied"));
          else
            vi.mocked(readIdentityAdmission).mockImplementation(async () =>
              Response.json({
                active: true,
                ...expected,
                plane: mode === "wrongPlane" ? "commercial" : "workforce",
                personId: mode === "changedPerson" ? binding.caseId : expected.personId,
                baseSessionId: mode === "changedSID" ? "999" : expected.baseSessionId,
                authenticationClass: "workforce_limited",
                requestId: "original-oidc-request",
                revocationVersion: "0",
              }),
            );
          expect((await start()).status).toBe(403);
          expect(store.reserve).not.toHaveBeenCalled();
        },
      );
      it("unknown create never redispatches or interprets missing provider metadata as retirement", async () => {
        row.provider_started_at = new Date(now.getTime() - 15000);
        store.claimCreation.mockResolvedValue(false);
        expect((await start()).status).toBe(403);
        expect(createSessionFromChecksAndChallenges).not.toHaveBeenCalled();
        const r = await observeIdentityAction(
          new Request(path + `/${id}/status`, {
            method: "POST",
            headers: auth(),
            body: JSON.stringify({ ...pair(), expected, command: binding.command }),
          }),
          id,
        );
        expect(r.status).toBe(200);
        expect(await r.json()).toMatchObject({ state: "pending", providerRetirement: "pending" });
      });
      it.each(["subject", "client", "base", "intent", "issuer", "unknown"])(
        "create response %s lacks owned provider proof and cannot be adopted or queued",
        async (mode) => {
          if (mode === "subject") session.factors.user.id = "701";
          if (mode === "client") session.metadata.paypm_identity_action_client = new TextEncoder().encode("other-client");
          if (mode === "base") session.metadata.paypm_identity_action_base = new TextEncoder().encode("999");
          if (mode === "intent") session.metadata.paypm_identity_action_intent = new TextEncoder().encode(randomUUID());
          if (mode === "issuer") row.issuer = "https://other-provider.test";
          if (mode === "unknown") vi.mocked(getSession).mockRejectedValue(new Error("unknown outcome"));
          expect((await start()).status).toBe(403);
          expect(store.created).not.toHaveBeenCalled();
          expect(store.retire).not.toHaveBeenCalled();
          expect(workforceIdentityRequest).not.toHaveBeenCalled();
        },
      );
      it("malformed challenge may queue only the actually verified original provider-owned SID", async () => {
        vi.mocked(createSessionFromChecksAndChallenges).mockResolvedValue({
          sessionId: provider.sessionId,
          sessionToken: provider.sessionToken,
        } as any);
        expect((await start()).status).toBe(403);
        expect(store.created).not.toHaveBeenCalled();
        expect(store.retire).toHaveBeenCalledWith(id, provider.sessionId);
      });
      it("foreign-human orphan metadata cannot be queued during uncertain-create readback", async () => {
        row.provider_started_at = new Date(now.getTime() - 15000);
        store.claimCreation.mockResolvedValue(false);
        session.factors.user.id = "701";
        vi.mocked(workforceProvider).mockResolvedValue({ inspectActionIntent: vi.fn(async () => session) } as any);
        expect((await start()).status).toBe(403);
        expect(store.retire).not.toHaveBeenCalled();
        expect(createSessionFromChecksAndChallenges).not.toHaveBeenCalled();
      });
      it("conflicted provider custody cannot use partial first-SID NotFound to authorize continuation", async () => {
        registered();
        row = { ...row, state: "retired", provider_conflicted: true };
        vi.mocked(getSession).mockRejectedValue({ classified: true, code: Code.NotFound });
        const r = await observeIdentityAction(
          new Request(path + `/${id}/status`, {
            method: "POST",
            headers: auth(),
            body: JSON.stringify({ ...pair(), expected, command: binding.command }),
          }),
          id,
        );
        expect(r.status).toBe(200);
        expect(await r.json()).toMatchObject({ state: "pending", providerRetirement: "pending" });
        expect(getSession).not.toHaveBeenCalled();
        expect(
          (
            await startIdentityAction(
              new Request(path + `/${id}/continue`, {
                method: "POST",
                headers: auth(),
                body: JSON.stringify({ ...startBody(), requestId: randomUUID() }),
              }),
              id,
            )
          ).status,
        ).toBe(403);
        expect(store.reserve).not.toHaveBeenCalled();
      });
      it("lost proof registration reuses original provider session", async () => {
        row = {
          ...row,
          state: "created",
          provider_started_at: now,
          provider_session_id: provider.sessionId,
          provider_material_sealed: "sealed",
        };
        expect((await start()).status).toBe(200);
        expect(createSessionFromChecksAndChallenges).not.toHaveBeenCalled();
        expect(workforceIdentityRequest).toHaveBeenCalledWith(
          "internal/v1/workforce-action-proofs/requests",
          expect.objectContaining({ stepSessionId: provider.sessionId, challenge }),
        );
      });
      it.each([0, 1, 4])("missing signed UP+UV %i denies before provider verification", async (flags) => {
        registered();
        expect((await complete(assertion(flags))).status).toBe(403);
        expect(setSession).not.toHaveBeenCalled();
        expect(store.attempt).not.toHaveBeenCalled();
      });
      it("actual accepted provider evidence precedes named Identity receipt and original readback", async () => {
        registered();
        expect((await complete()).status).toBe(200);
        expect(setSession).toHaveBeenCalledOnce();
        expect(workforceIdentityRequest).toHaveBeenCalledWith(
          `internal/v1/workforce-action-proofs/requests/${proofId}/complete`,
          { assertion: assertion() },
        );
        const r = await readIdentityAction(
          new Request(path + `/${id}/readback`, {
            method: "POST",
            headers: auth(true),
            body: JSON.stringify({ expected, command: binding.command }),
          }),
          id,
        );
        expect(r.status).toBe(200);
        expect(await r.json()).toMatchObject({ receipt, proofId, caseId: binding.caseId, state: "verified" });
      });
      it("unknown verification observes original GET and never repeats provider verification", async () => {
        registered();
        vi.mocked(setSession).mockImplementation(async () => {
          session.metadata["paypm_workforce_passkey_request_" + proofId] = new TextEncoder().encode(row.assertion_hash!);
          throw new Error("lost response");
        });
        expect((await complete()).status).toBe(200);
        expect((await complete()).status).toBe(200);
        expect(setSession).toHaveBeenCalledOnce();
        expect(getSession).toHaveBeenCalledTimes(2);
      });
      it.each(["wrongSubject", "noUV", "wrongIntent", "stale", "wrongHash"])(
        "provider contradiction %s never issues receipt",
        async (mode) => {
          registered();
          if (mode === "wrongSubject") session.factors.user.id = "701";
          if (mode === "noUV") session.factors.webAuthN.userVerified = false;
          if (mode === "wrongIntent") session.metadata.paypm_identity_action_intent = new TextEncoder().encode(randomUUID());
          if (mode === "stale") session.factors.webAuthN.verifiedAt = ts(now.getTime() - 61000);
          if (mode === "wrongHash") vi.mocked(setSession).mockResolvedValue({ sessionToken: "token" } as any);
          expect((await complete()).status).toBe(403);
          expect(workforceIdentityRequest).not.toHaveBeenCalled();
          expect(store.verified).not.toHaveBeenCalled();
        },
      );
      it("revoked owner capability after provider acceptance blocks completion", async () => {
        registered();
        vi.mocked(readIdentityActionAuthority).mockResolvedValueOnce(binding).mockRejectedValue(new Error("revoked"));
        expect((await complete()).status).toBe(403);
        expect(setSession).toHaveBeenCalledOnce();
        expect(workforceIdentityRequest).not.toHaveBeenCalled();
      });
      it("Operations receipt cannot settle Identity ceremony", async () => {
        registered();
        vi.mocked(workforceIdentityRequest).mockResolvedValue({
          receipt: "paypm-ops1.fake",
          expiresAt: new Date(now.getTime() + 60000).toISOString(),
          binding: expected,
        });
        expect((await complete()).status).toBe(403);
        expect(store.verified).not.toHaveBeenCalled();
      });
      it("cancel retains original until actual named provider retirement", async () => {
        registered();
        expect((await cancelIdentityPublicAction(pub("cancel", { capability: cap }), id)).status).toBe(403);
        expect(row.state).toBe("cancelled");
        vi.mocked(getSession).mockRejectedValue({ classified: true, code: Code.NotFound });
        expect((await cancelIdentityPublicAction(pub("cancel", { capability: cap }), id)).status).toBe(200);
        expect(createSessionFromChecksAndChallenges).not.toHaveBeenCalled();
      });
      it.each(["proofId", "person", "baseSession", "expiry", "verifiedAt", "extra"])(
        "exact owner receipt contradicting %s never settles custody",
        async (mode) => {
          registered();
          const body = {
            version: 1,
            proofId,
            ...expected,
            verifiedAt: now.toISOString(),
            expiresAt: new Date(now.getTime() + 60000).toISOString(),
          } as Record<string, any>;
          if (mode === "proofId") body.proofId = randomUUID();
          if (mode === "person") body.personId = randomUUID();
          if (mode === "baseSession") body.baseSessionId = "999";
          if (mode === "expiry") body.expiresAt = new Date(now.getTime() + 61000).toISOString();
          if (mode === "verifiedAt") body.verifiedAt = new Date(now.getTime() - 1000).toISOString();
          if (mode === "extra") body.authority = true;
          const wrong = `paypm-wf1.${Buffer.from(JSON.stringify(body)).toString("base64url")}.${"x".repeat(43)}`;
          vi.mocked(workforceIdentityRequest).mockResolvedValue({
            receipt: wrong,
            expiresAt: new Date(now.getTime() + 60000).toISOString(),
            binding: expected,
          });
          expect((await complete()).status).toBe(403);
          expect(store.verified).not.toHaveBeenCalled();
        },
      );
      it("terminal known late SID permits only named provider retirement observation, never creation/verification", async () => {
        row = {
          ...row,
          state: "cancelled",
          provider_started_at: new Date(now.getTime() - 15000),
          provider_session_id: provider.sessionId,
        };
        vi.mocked(getSession).mockRejectedValue({ classified: true, code: Code.NotFound });
        const r = await observeIdentityAction(
          new Request(path + `/${id}/status`, {
            method: "POST",
            headers: auth(),
            body: JSON.stringify({ ...pair(), expected, command: binding.command }),
          }),
          id,
        );
        expect(r.status).toBe(200);
        expect(await r.json()).toMatchObject({ state: "cancelled", providerRetirement: "confirmed" });
        expect(getSession).toHaveBeenCalledWith(expect.objectContaining({ sessionId: provider.sessionId }));
        expect(createSessionFromChecksAndChallenges).not.toHaveBeenCalled();
        expect(setSession).not.toHaveBeenCalled();
        expect(workforceIdentityRequest).not.toHaveBeenCalled();
      });
      it("named retirement outage does not confirm absence or authorize successor", async () => {
        registered();
        row.state = "cancelled";
        vi.mocked(getSession).mockRejectedValue(new Error("provider unavailable"));
        const r = await observeIdentityAction(
          new Request(path + `/${id}/status`, {
            method: "POST",
            headers: auth(),
            body: JSON.stringify({ ...pair(), expected, command: binding.command }),
          }),
          id,
        );
        expect(r.status).toBe(403);
        expect(
          (
            await startIdentityAction(
              new Request(path + `/${id}/continue`, {
                method: "POST",
                headers: auth(),
                body: JSON.stringify({ ...startBody(), requestId: randomUUID() }),
              }),
              id,
            )
          ).status,
        ).toBe(403);
        expect(store.reserve).not.toHaveBeenCalled();
      });
      it("challenge exposes public options only", async () => {
        registered();
        const r = await readIdentityPublicChallenge(
          new Request(`https://login.paypm.test/ui/v2/login/api/identity/actions/${id}/challenge`),
          id,
          cap,
        );
        expect(r.status).toBe(200);
        const b = await r.json();
        expect(b.publicKey).toEqual(provider.publicKey);
        expect(JSON.stringify(b)).not.toContain(caller.accessToken);
        expect(JSON.stringify(b)).not.toContain(provider.sessionToken);
      });
      it("renewed same-owner status observes immutable old SID but cannot complete", async () => {
        registered();
        const e = { ...expected, baseSessionId: "999" };
        vi.mocked(readIdentityAdmission).mockImplementation(async () =>
          Response.json({
            active: true,
            ...e,
            plane: "workforce",
            authenticationClass: "workforce_limited",
            requestId: "renewed-oidc-request",
            revocationVersion: "0",
          }),
        );
        const r = await observeIdentityAction(
          new Request(path + `/${id}/status`, {
            method: "POST",
            headers: auth(),
            body: JSON.stringify({ ...pair(), expected: e, command: binding.command }),
          }),
          id,
        );
        expect(r.status).toBe(200);
        expect(row.base_session_id).toBe(expected.baseSessionId);
        expect((await complete()).status).toBe(403);
        expect(setSession).not.toHaveBeenCalled();
      });
      it("continuation requires exact old proof/command and retirement before successor reservation", async () => {
        registered();
        row.expires_at = new Date(now.getTime() - 1000);
        vi.mocked(getSession).mockRejectedValue({ classified: true, code: Code.NotFound });
        const successor = randomUUID();
        await startIdentityAction(
          new Request(path + `/${id}/continue`, {
            method: "POST",
            headers: auth(),
            body: JSON.stringify({ ...startBody(), requestId: successor }),
          }),
          id,
        );
        expect(readIdentityActionAuthority).toHaveBeenCalledWith(
          expected,
          binding.command,
          pair(),
          expect.objectContaining({ requestId: id, proofId, stepSessionId: provider.sessionId }),
        );
        expect(store.reserve).toHaveBeenCalledWith(
          expect.objectContaining({ id: successor, predecessor: expect.objectContaining({ id }) }),
        );
      });
    });
  });
}
