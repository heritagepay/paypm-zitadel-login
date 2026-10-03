import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { NextIntlClientProvider } from "next-intl";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import en from "../../locales/en.json";
import fr from "../../locales/fr.json";
import { OperationsActionPasskey } from "./operations-action-passkey";
const { push } = vi.hoisted(() => ({ push: vi.fn() }));
vi.mock("next/navigation", () => ({ useRouter: () => ({ push }) }));
const id = "11111111-1111-4111-8111-111111111111",
  capability = "x".repeat(43),
  state = "s".repeat(64);
const callback = `https://ops.paypm.test/auth/workforce/actions/callback?requestId=${id}&state=${state}`;
const flow = () => ({
  requestId: id,
  action: "operations.merchant.settlement.approve",
  publicKey: { challenge: "aXNzdWVk", rpId: "login.paypm.test", userVerification: "required", allowCredentials: [] },
  expiresAt: new Date(Date.now() + 300000).toISOString(),
  returnUrl: "https://ops.paypm.test",
});
const credential = () => ({
  id: "credential",
  rawId: new Uint8Array([1, 2]).buffer,
  type: "public-key",
  response: {
    authenticatorData: new Uint8Array([1, 2]).buffer,
    clientDataJSON: new Uint8Array([3]).buffer,
    signature: new Uint8Array([4]).buffer,
    userHandle: null,
  },
});
function mount(locale = "en") {
  render(
    <NextIntlClientProvider locale={locale} messages={locale === "fr" ? fr : en}>
      <OperationsActionPasskey requestId={id} capability={capability} />
    </NextIntlClientProvider>,
  );
}
let fetcher: ReturnType<typeof vi.fn>, get: ReturnType<typeof vi.fn>;
beforeEach(() => {
  vi.resetAllMocks();
  vi.stubGlobal(
    "matchMedia",
    vi.fn(() => ({ matches: false, addEventListener: vi.fn(), removeEventListener: vi.fn() })),
  );
  fetcher = vi.fn(async (url: string) => Response.json(url.endsWith("/challenge") ? flow() : { callbackUrl: callback }));
  vi.stubGlobal("fetch", fetcher);
  get = vi.fn().mockResolvedValue(credential());
  Object.defineProperty(navigator, "credentials", { configurable: true, value: { get } });
  window.history.replaceState({}, "", `/?requestId=${id}&capability=${capability}`);
});
afterEach(() => {
  cleanup();
  vi.useRealTimers();
  vi.unstubAllGlobals();
});
describe("Operations action passkey experience", () => {
  it("loads only bounded options, strips the capability URL and requests native verification only on user action", async () => {
    mount("fr");
    await screen.findByRole("button", { name: fr.operationsAction.verify });
    expect(get).not.toHaveBeenCalled();
    expect(window.location.search).not.toContain(capability);
    expect(screen.getByText(fr.operationsAction.actions.approve)).toBeInTheDocument();
    expect(fetcher).toHaveBeenCalledWith(
      expect.stringContaining("/challenge"),
      expect.objectContaining({ cache: "no-store", headers: { "X-PayPM-Ceremony-Capability": capability } }),
    );
    fireEvent.click(screen.getByRole("button", { name: fr.operationsAction.verify }));
    await waitFor(() => expect(push).toHaveBeenCalledWith(callback));
    expect(get).toHaveBeenCalledWith(
      expect.objectContaining({
        publicKey: expect.objectContaining({ userVerification: "required", challenge: expect.any(ArrayBuffer) }),
        signal: expect.any(AbortSignal),
      }),
    );
    expect(screen.queryByText("paypm-ops1.")).toBeNull();
  });
  it("retries the identical assertion after a lost completion without a second native ceremony", async () => {
    fetcher.mockImplementation(async (url: string) =>
      url.endsWith("/challenge") ? Response.json(flow()) : Promise.reject(new Error("secret transport")),
    );
    mount();
    fireEvent.click(await screen.findByRole("button", { name: en.operationsAction.verify }));
    await screen.findByText(en.operationsAction.unavailable);
    fetcher.mockImplementation(async () => Response.json({ callbackUrl: callback }));
    fireEvent.click(screen.getByRole("button", { name: en.operationsAction.retryVerification }));
    await waitFor(() => expect(push).toHaveBeenCalledWith(callback));
    expect(get).toHaveBeenCalledTimes(1);
    const calls = fetcher.mock.calls.filter(([url]) => String(url).endsWith("/complete"));
    expect(calls[0][1].body).toEqual(calls[1][1].body);
    expect(screen.queryByText("secret transport")).toBeNull();
  });
  it("cancels durably before returning and ignores a late browser completion", async () => {
    let finish: (value: unknown) => void = () => {};
    get.mockImplementation(
      () =>
        new Promise((resolve) => {
          finish = resolve;
        }),
    );
    mount();
    fireEvent.click(await screen.findByRole("button", { name: en.operationsAction.verify }));
    fireEvent.click(screen.getByRole("button", { name: en.operationsAction.cancel }));
    await waitFor(() => expect(push).toHaveBeenCalledWith(callback));
    await act(() => finish(credential()));
    expect(fetcher.mock.calls.filter(([url]) => String(url).endsWith("/complete"))).toHaveLength(0);
    expect(get.mock.calls[0][0].signal.aborted).toBe(true);
  });
  it("blocks altered callback origins, extra fields and receipt-bearing URLs", async () => {
    fetcher.mockImplementation(async (url: string) =>
      Response.json(url.endsWith("/challenge") ? flow() : { callbackUrl: callback + "&receipt=secret" }),
    );
    mount();
    fireEvent.click(await screen.findByRole("button", { name: en.operationsAction.verify }));
    await screen.findByText(en.operationsAction.unavailable);
    expect(push).not.toHaveBeenCalled();
  });
  it("does not invoke native verification after expiry and leaves return/cancellation available", async () => {
    vi.useFakeTimers();
    mount();
    await act(async () => {});
    await act(() => vi.advanceTimersByTime(301000));
    expect(screen.getByText(en.operationsAction.expired)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: en.operationsAction.verify })).toBeDisabled();
    expect(screen.getByRole("button", { name: en.operationsAction.cancel })).toBeEnabled();
    expect(screen.getByRole("link", { name: en.operationsAction.return })).toHaveAttribute("href", "https://ops.paypm.test");
    expect(get).not.toHaveBeenCalled();
  });
  it("rejects unqualified UV options and exposes a quiet retry without account content", async () => {
    fetcher.mockResolvedValue(
      Response.json({ ...flow(), publicKey: { challenge: "aXNzdWVk", userVerification: "preferred" } }),
    );
    mount();
    await screen.findByText(en.operationsAction.unavailable);
    expect(screen.getByRole("button", { name: en.operationsAction.retry })).toBeEnabled();
    expect(get).not.toHaveBeenCalled();
    expect(screen.queryByRole("button", { name: en.operationsAction.cancel })).toBeNull();
  });
});
