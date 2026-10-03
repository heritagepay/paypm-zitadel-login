// @vitest-environment node
import { randomUUID } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import { WorkforceProvider } from "./workforce-provider";

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
