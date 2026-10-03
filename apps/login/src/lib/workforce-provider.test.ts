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
