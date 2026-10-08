// @vitest-environment node
import { randomUUID } from "node:crypto";
import { afterEach, describe, expect, it, vi } from "vitest";
import { WorkforceProvider } from "./workforce-provider";

vi.mock("./fingerprint", () => ({ getUserAgent: vi.fn(async () => ({})) }));

const operationKey = randomUUID();
const timestamp = (ms: number) => ({ seconds: BigInt(Math.floor(ms / 1000)), nanos: (ms % 1000) * 1e6 });
function session() {
  return {
    id: "real-provider-session",
    creationDate: timestamp(Date.now() - 10000),
    expirationDate: timestamp(Date.now() + 60000),
    metadata: { paypm_workforce_action_intent: new TextEncoder().encode(operationKey) },
    factors: { user: { id: "700", organizationId: "300", verifiedAt: timestamp(Date.now() - 9000) } },
  };
}
describe("uncertain workforce action creation readback", () => {
  it("queries the exact subject and returns only its exact immutable operation", async () => {
    const listSessions = vi.fn(async () => ({ sessions: [session()], details: { totalResult: BigInt(1) } }));
    const provider = new WorkforceProvider({ listSessions } as any, "300");
    expect(await provider.findActionIntent(operationKey, "700")).toBe("real-provider-session");
    expect(listSessions).toHaveBeenCalledWith({
      query: { limit: 100, offset: BigInt(0), asc: false },
      queries: [{ query: { case: "userIdQuery", value: { id: "700" } } }],
    });
  });
  it.each([
    "different-operation",
    "different-subject",
    "different-organization",
    "unverified",
    "duplicate",
    "truncated",
    "missing-count",
  ])("denies %s rather than guessing an orphan to revoke", async (kind) => {
    const record = session();
    if (kind === "different-operation")
      record.metadata.paypm_workforce_action_intent = new TextEncoder().encode("another-operation");
    if (kind === "different-subject") record.factors.user.id = "999";
    if (kind === "different-organization") record.factors.user.organizationId = "999";
    if (kind === "unverified") (record.factors.user as any).verifiedAt = undefined;
    const sessions = kind === "duplicate" ? [record, { ...record, id: "second-provider-session" }] : [record];
    const api = {
      listSessions: vi.fn(async () => ({
        sessions,
        details:
          kind === "missing-count" ? undefined : { totalResult: BigInt(kind === "truncated" ? 101 : sessions.length) },
      })),
    };
    await expect(new WorkforceProvider(api as any, "300").findActionIntent(operationKey, "700")).rejects.toMatchObject({
      code: "action_provider_pending",
    });
  });
});

describe("exact owned provider retirement readback", () => {
  it("verifies actual subject/organization before deletion and rereads classified not-found", async () => {
    const { ClassifiedConnectError } = await import("./grpc/interceptors/error-classification");
    const { ConnectError, Code } = await import("@connectrpc/connect");
    const getSession = vi
      .fn()
      .mockResolvedValueOnce({ session: session() })
      .mockRejectedValueOnce(new ClassifiedConnectError(new ConnectError("not found", Code.NotFound)));
    const deleteSession = vi.fn();
    expect(
      await new WorkforceProvider({ getSession, deleteSession } as any, "300").retireOwnedSession(
        "real-provider-session",
        "700",
      ),
    ).toBe(true);
    expect(deleteSession).toHaveBeenCalledWith({ sessionId: "real-provider-session" });
    expect(getSession).toHaveBeenCalledTimes(2);
  });
  it("does not treat empty/mismatched/failed readback as confirmed or mutate another subject", async () => {
    const deleteSession = vi.fn(),
      getSession = vi.fn().mockResolvedValue({});
    const p = new WorkforceProvider({ getSession, deleteSession } as any, "300");
    await expect(p.retireOwnedSession("real-provider-session", "700")).rejects.toThrow();
    expect(deleteSession).not.toHaveBeenCalled();
    getSession.mockResolvedValue({ session: session() });
    await expect(p.retireOwnedSession("real-provider-session", "701")).rejects.toThrow();
    expect(deleteSession).not.toHaveBeenCalled();
  });
});

describe("pure operation intent inspection", () => {
  it("reads an exact expired provider session without renewing or deleting it", async () => {
    const record = session();
    record.expirationDate = timestamp(Date.now() - 1000);
    const listSessions = vi.fn(async () => ({ sessions: [record], details: { totalResult: BigInt(1) } })),
      deleteSession = vi.fn(),
      setSession = vi.fn(),
      createSession = vi.fn();
    expect(
      await new WorkforceProvider(
        { listSessions, deleteSession, setSession, createSession } as any,
        "300",
      ).inspectActionIntent(operationKey, "700", "paypm_workforce_action_intent"),
    ).toEqual(record);
    expect(deleteSession).not.toHaveBeenCalled();
    expect(setSession).not.toHaveBeenCalled();
    expect(createSession).not.toHaveBeenCalled();
  });
  it("a complete empty result is merely absent, leaving creation-outcome interpretation to its original journal", async () => {
    const api = { listSessions: vi.fn(async () => ({ sessions: [], details: { totalResult: BigInt(0) } })) };
    expect(
      await new WorkforceProvider(api as any, "300").inspectActionIntent(
        operationKey,
        "700",
        "paypm_workforce_action_intent",
      ),
    ).toBeUndefined();
  });
  it.each(["duplicate", "missing-count", "incomplete", "wrong-subject", "wrong-organization", "missing-expiry"])(
    "rejects %s without inventing retirement",
    async (kind) => {
      const record = session();
      if (kind === "wrong-subject") record.factors.user.id = "999";
      if (kind === "wrong-organization") record.factors.user.organizationId = "999";
      if (kind === "missing-expiry") (record as any).expirationDate = undefined;
      const sessions = kind === "duplicate" ? [record, { ...record, id: "second" }] : [record];
      const api = {
        listSessions: vi.fn(async () => ({
          sessions,
          details:
            kind === "missing-count" ? undefined : { totalResult: BigInt(kind === "incomplete" ? 2 : sessions.length) },
        })),
      };
      await expect(
        new WorkforceProvider(api as any, "300").inspectActionIntent(operationKey, "700", "paypm_workforce_action_intent"),
      ).rejects.toMatchObject({ code: "action_provider_pending" });
    },
  );
});

describe("native reviewed enrollment metadata", () => {
  it("attaches exact ceremony hash only to an owned enrollment session, then reads native acceptance", async () => {
    const record = session(),
      id = randomUUID();
    record.metadata["paypm_workforce_challenge" as keyof typeof record.metadata] = new TextEncoder().encode(id);
    const row: any = {
      id,
      purpose: "reviewed_enrollment",
      provider_session_id: record.id,
      provider_subject: "700",
      issuer: "https://auth.paypm.test",
      client_id: "staff",
      epoch: "0",
    };
    const getSession = vi.fn(async () => ({ session: record })),
      setSession = vi.fn(async (input: any) => {
        Object.assign(record.metadata, input.metadata);
        return {};
      });
    const provider = new WorkforceProvider({ getSession, setSession } as any, "300");
    await provider.attachEnrollment(row, "a".repeat(64));
    expect(setSession).toHaveBeenCalledOnce();
    expect(setSession.mock.calls[0][0].metadata).toEqual({
      ["paypm_workforce_enrollment_" + id]: new TextEncoder().encode("a".repeat(64)),
    });
    await provider.attachEnrollment(row, "a".repeat(64));
    expect(setSession).toHaveBeenCalledOnce();
    await expect(provider.attachEnrollment(row, "b".repeat(64))).rejects.toMatchObject({
      code: "enrollment_metadata_changed",
    });
    await expect(provider.attachEnrollment({ ...row, purpose: "login" }, "a".repeat(64))).rejects.toMatchObject({
      code: "enrollment_purpose_mismatch",
    });
  });
});

describe("native Session creation and exact lost-response recovery", () => {
  afterEach(() => vi.useRealTimers());
  function original() {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-10-08T17:42:42Z"));
    const id = randomUUID();
    const record: any = {
      id: "provider-session",
      creationDate: { seconds: BigInt(1791481361), nanos: 712607000 },
      expirationDate: { seconds: BigInt(1791510161), nanos: 712607000 },
      factors: { user: { id: "700", organizationId: "300", verifiedAt: { seconds: BigInt(1791481361), nanos: 709949000 } } },
      metadata: { paypm_workforce_challenge: new TextEncoder().encode(id) },
    };
    const row: any = { id, provider_subject: "700", provider_session_id: record.id };
    const api = {
      createSession: vi.fn(async () => ({ sessionId: record.id, sessionToken: "synthetic-private-token" })),
      getSession: vi.fn(async () => ({ session: record })),
      listSessions: vi.fn(async () => ({ sessions: [record], details: { totalResult: BigInt(1) } })),
      setSession: vi.fn(),
      deleteSession: vi.fn(),
    };
    return { record, row, api, provider: new WorkforceProvider(api as any, "300") };
  }
  it("binds provider-created user lookup to the original subject, OPS and immutable challenge marker", async () => {
    const { provider, row, api, record } = original();
    const created = await provider.create(row);
    expect(created.session).toEqual(record);
    expect(created.token).toBe("synthetic-private-token");
    expect(api.createSession).toHaveBeenCalledOnce();
    expect(api.getSession).toHaveBeenCalledWith({ sessionId: record.id });
    expect(api.setSession).not.toHaveBeenCalled();
    expect(await provider.find(row)).toEqual(record);
    expect(api.createSession).toHaveBeenCalledOnce();
  });
  it.each(["subject", "organization", "marker", "missing-user-time", "future-user-time", "expired"])(
    "rejects changed %s binding without delivery or renewal",
    async (kind) => {
      const { provider, row, api, record } = original();
      if (kind === "subject") record.factors.user.id = "999";
      if (kind === "organization") record.factors.user.organizationId = "999";
      if (kind === "marker") record.metadata.paypm_workforce_challenge = new TextEncoder().encode(randomUUID());
      if (kind === "missing-user-time") record.factors.user.verifiedAt = undefined;
      if (kind === "future-user-time") record.factors.user.verifiedAt = timestamp(Date.now() + 1);
      if (kind === "expired") record.expirationDate = timestamp(Date.now() - 1);
      await expect(provider.read(row)).rejects.toMatchObject({ code: "provider_session_mismatch" });
      await expect(provider.find(row)).rejects.toThrow();
      expect(api.createSession).not.toHaveBeenCalled();
      expect(api.setSession).not.toHaveBeenCalled();
      expect(api.deleteSession).not.toHaveBeenCalled();
    },
  );
  it("reads exact expired action intent without silently reauthenticating or renewing it", async () => {
    const { provider, api, record } = original();
    record.metadata.paypm_workforce_action_intent = new TextEncoder().encode(operationKey);
    record.expirationDate = timestamp(Date.now() - 1);
    expect(await provider.inspectActionIntent(operationKey, "700", "paypm_workforce_action_intent")).toEqual(record);
    await expect(provider.findActionIntent(operationKey, "700")).rejects.toThrow();
    expect(api.setSession).not.toHaveBeenCalled();
    expect(api.deleteSession).not.toHaveBeenCalled();
  });
});
