// @vitest-environment node
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createServiceForHost } from "./service";
import { deliverWorkforceProfileEmail } from "./workforce-profile-email-provider";
vi.mock("./service", () => ({ createServiceForHost: vi.fn() }));
const config = { baseUrl: "https://auth.paypm.test" };
const input = {
  subject: "700",
  organizationId: "300",
  template:
    "https://auth.paypm.test/ui/v2/login/workforce-enrollment?operationId=11111111-1111-4111-8111-111111111111&requestId=oidc_owned#code={{.Code}}",
};
let send: any, assertOwner: any;
const ack = () => ({
  details: {
    sequence: BigInt(42),
    resourceOwner: "300",
    changeDate: { seconds: BigInt(Math.floor(Date.now() / 1000)), nanos: 0 },
  },
});
beforeEach(() => {
  vi.resetAllMocks();
  send = vi.fn(async () => ack());
  assertOwner = vi.fn(async () => {});
  vi.mocked(createServiceForHost).mockResolvedValue({ sendEmailCode: send } as any);
});
afterEach(() => vi.useRealTimers());
describe("purpose-bound native profile email command", () => {
  it("sends only sendCode for exact native subject/template with actual abort and deadline", async () => {
    const result = await deliverWorkforceProfileEmail(config, input, assertOwner);
    expect(result).toMatchObject({ sequence: "42", resourceOwner: "300" });
    expect(send).toHaveBeenCalledOnce();
    expect(send.mock.calls[0][0]).toMatchObject({
      userId: "700",
      verification: { case: "sendCode", value: { urlTemplate: input.template } },
    });
    expect(send.mock.calls[0][1].signal).toBeInstanceOf(AbortSignal);
    expect(send.mock.calls[0][1].timeoutMs).toBeLessThanOrEqual(8000);
    expect(assertOwner.mock.invocationCallOrder[0]).toBeLessThan(send.mock.invocationCallOrder[0]);
    expect(JSON.stringify(result)).not.toContain("verificationCode");
  });
  it.each(["foreign", "root", "duplicate-query", "credential", "wrong-subject", "oversize"])(
    "denies %s before credentials/send",
    async (kind) => {
      const bad = { ...input };
      if (kind === "foreign") bad.template = bad.template.replace("auth.paypm.test", "other.test");
      if (kind === "root") bad.template = bad.template.replace("/ui/v2/login/", "/");
      if (kind === "duplicate-query") bad.template = bad.template.replace("#", "&requestId=oidc_other#");
      if (kind === "credential") bad.template = bad.template.replace("https://", "https://user@");
      if (kind === "wrong-subject") bad.subject = "user-selected";
      if (kind === "oversize") bad.template = bad.template.replace("oidc_owned", "oidc_" + "a".repeat(300));
      await expect(deliverWorkforceProfileEmail(config, bad, assertOwner)).rejects.toThrow();
      expect(createServiceForHost).not.toHaveBeenCalled();
      expect(send).not.toHaveBeenCalled();
    },
  );
  it.each(["code", "foreign-owner", "missing", "zero-sequence", "future"])(
    "rejects %s acknowledgement without code projection",
    async (kind) => {
      const value: any = ack();
      if (kind === "code") value.verificationCode = "ABC123";
      if (kind === "foreign-owner") value.details.resourceOwner = "301";
      if (kind === "missing") delete value.details;
      if (kind === "zero-sequence") value.details.sequence = BigInt(0);
      if (kind === "future") value.details.changeDate.seconds += BigInt(60);
      send.mockResolvedValue(value);
      await expect(deliverWorkforceProfileEmail(config, input, assertOwner)).rejects.toThrow("acknowledgement");
      expect(send).toHaveBeenCalledOnce();
    },
  );
  it("delayed credential resolution after deadline never sends", async () => {
    vi.useFakeTimers();
    let release!: (value: any) => void;
    vi.mocked(createServiceForHost).mockReturnValue(new Promise((resolve) => (release = resolve)));
    const result = deliverWorkforceProfileEmail(config, input, assertOwner);
    const rejected = expect(result).rejects.toThrow("unconfirmed");
    await vi.advanceTimersByTimeAsync(8001);
    await rejected;
    release({ sendEmailCode: send });
    await Promise.resolve();
    await Promise.resolve();
    expect(assertOwner).not.toHaveBeenCalled();
    expect(send).not.toHaveBeenCalled();
  });
  it("owner recheck delayed beyond deadline cannot start send", async () => {
    vi.useFakeTimers();
    let release!: () => void;
    assertOwner.mockReturnValue(new Promise<void>((resolve) => (release = resolve)));
    const result = deliverWorkforceProfileEmail(config, input, assertOwner);
    const rejected = expect(result).rejects.toThrow("unconfirmed");
    await vi.advanceTimersByTimeAsync(8001);
    await rejected;
    release();
    await Promise.resolve();
    expect(send).not.toHaveBeenCalled();
  });
  it("aborts an in-flight command on deadline without retry or accepted claim", async () => {
    vi.useFakeTimers();
    send.mockImplementation(
      (_body: any, options: any) =>
        new Promise((_resolve, reject) => options.signal.addEventListener("abort", () => reject(new Error("aborted")))),
    );
    const result = deliverWorkforceProfileEmail(config, input, assertOwner);
    const rejected = expect(result).rejects.toThrow();
    await vi.advanceTimersByTimeAsync(8001);
    await rejected;
    expect(send).toHaveBeenCalledOnce();
    expect(send.mock.calls[0][1].signal.aborted).toBe(true);
  });
  it("current-owner denial never calls native send", async () => {
    assertOwner.mockRejectedValue(new Error("retired"));
    await expect(deliverWorkforceProfileEmail(config, input, assertOwner)).rejects.toThrow();
    expect(send).not.toHaveBeenCalled();
  });
});
