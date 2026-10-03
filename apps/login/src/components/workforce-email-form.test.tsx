import {
  cancelWorkforceEmailOtp,
  resendWorkforceEmailOtp,
  startWorkforceEmailOtp,
  verifyWorkforceEmailOtp,
} from "@/lib/server/workforce-email";
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { NextIntlClientProvider } from "next-intl";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import en from "../../locales/en.json";
import fr from "../../locales/fr.json";
import { WorkforceEmailForm } from "./workforce-email-form";
const { push } = vi.hoisted(() => ({ push: vi.fn() }));
vi.mock("next/navigation", () => ({ useRouter: () => ({ push }) }));
vi.mock("@/lib/server/workforce-email", () => ({
  cancelWorkforceEmailOtp: vi.fn(),
  resendWorkforceEmailOtp: vi.fn(),
  startWorkforceEmailOtp: vi.fn(),
  verifyWorkforceEmailOtp: vi.fn(),
}));
const flow = () => ({
  sessionId: "provider-session",
  challengeId: "bounded-challenge",
  authenticationClass: "workforce_limited" as const,
  expiresAt: new Date(Date.now() + 300000).toISOString(),
  resendAt: new Date(Date.now() + 60000).toISOString(),
});
function mount(locale = "en") {
  render(
    <NextIntlClientProvider locale={locale} messages={locale === "fr" ? fr : en}>
      <WorkforceEmailForm requestId="oidc_exact" />
    </NextIntlClientProvider>,
  );
}
async function send() {
  fireEvent.change(screen.getByLabelText(new RegExp(en.workforceEmail.emailLabel)), {
    target: { value: "Staff@Example.test" },
  });
  fireEvent.click(screen.getByRole("button", { name: en.workforceEmail.send }));
  await screen.findByLabelText(new RegExp(en.workforceEmail.codeLabel));
}
beforeEach(() => {
  vi.resetAllMocks();
  vi.stubGlobal(
    "matchMedia",
    vi.fn(() => ({ matches: false, addEventListener: vi.fn(), removeEventListener: vi.fn() })),
  );
  vi.mocked(startWorkforceEmailOtp).mockResolvedValue(flow());
  vi.mocked(cancelWorkforceEmailOtp).mockResolvedValue({ cancelled: true });
  vi.mocked(verifyWorkforceEmailOtp).mockResolvedValue({ redirect: "/callback" });
});
afterEach(() => {
  cleanup();
  vi.useRealTimers();
  vi.unstubAllGlobals();
});
describe("workforce email-code experience", () => {
  it("uses bilingual incumbent controls, email autofill and explicit submission", () => {
    mount("fr");
    const input = screen.getByLabelText(new RegExp(fr.workforceEmail.emailLabel));
    expect(input).toHaveAttribute("type", "email");
    expect(input).toHaveAttribute("autocomplete", "email");
    expect(input).toHaveFocus();
    expect(screen.getByRole("button", { name: fr.workforceEmail.send })).toBeDisabled();
    expect(startWorkforceEmailOtp).not.toHaveBeenCalled();
  });
  it("retries the identical initial operation after a lost response and never leaks raw server errors", async () => {
    mount();
    vi.mocked(startWorkforceEmailOtp).mockRejectedValueOnce(new Error("secret-detail"));
    fireEvent.change(screen.getByLabelText(new RegExp(en.workforceEmail.emailLabel)), {
      target: { value: "Staff@Example.test" },
    });
    fireEvent.click(screen.getByRole("button", { name: en.workforceEmail.send }));
    await screen.findByText(en.workforceEmail.unavailable);
    fireEvent.click(screen.getByRole("button", { name: en.workforceEmail.send }));
    await screen.findByLabelText(new RegExp(en.workforceEmail.codeLabel));
    expect(vi.mocked(startWorkforceEmailOtp).mock.calls[0][0]).toEqual(vi.mocked(startWorkforceEmailOtp).mock.calls[1][0]);
    expect(vi.mocked(startWorkforceEmailOtp).mock.calls[0][0]).toMatchObject({
      email: "staff@example.test",
      requestId: "oidc_exact",
    });
    expect(screen.queryByText("secret-detail")).toBeNull();
  });
  it("supports code paste/autofill, binds verification to the actual flow and waits for server redirect", async () => {
    mount();
    await send();
    const input = screen.getByLabelText(new RegExp(en.workforceEmail.codeLabel));
    expect(input).toHaveFocus();
    expect(input).toHaveAttribute("autocomplete", "one-time-code");
    expect(input).toHaveAttribute("inputmode", "numeric");
    fireEvent.change(input, { target: { value: "123-456" } });
    expect(input).toHaveValue("123456");
    expect(verifyWorkforceEmailOtp).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole("button", { name: en.workforceEmail.verify }));
    await waitFor(() => expect(push).toHaveBeenCalledWith("/callback"));
    expect(verifyWorkforceEmailOtp).toHaveBeenCalledWith(
      expect.objectContaining({ sessionId: "provider-session", requestId: "oidc_exact", code: "123456" }),
    );
  });
  it("keeps truthful resend timing and preserves the resend operation after an uncertain result", async () => {
    vi.useFakeTimers();
    mount();
    await act(async () => {
      fireEvent.change(screen.getByLabelText(new RegExp(en.workforceEmail.emailLabel)), {
        target: { value: "staff@example.test" },
      });
      fireEvent.click(screen.getByRole("button", { name: en.workforceEmail.send }));
    });
    expect(screen.getByRole("button", { name: "Resend in 60s" })).toBeDisabled();
    await act(() => vi.advanceTimersByTime(61000));
    vi.mocked(resendWorkforceEmailOtp).mockRejectedValueOnce(new Error("lost response")).mockResolvedValueOnce(flow());
    await act(async () => fireEvent.click(screen.getByRole("button", { name: en.workforceEmail.resend })));
    await act(async () => fireEvent.click(screen.getByRole("button", { name: en.workforceEmail.resend })));
    expect(vi.mocked(resendWorkforceEmailOtp).mock.calls[0][0]).toEqual(vi.mocked(resendWorkforceEmailOtp).mock.calls[1][0]);
    expect(screen.getByRole("button", { name: "Resend in 60s" })).toBeDisabled();
  });
  it("cancels on the server before returning and ignores a late successful verification", async () => {
    mount();
    await send();
    let finish: (value: { redirect: string }) => void = () => {};
    vi.mocked(verifyWorkforceEmailOtp).mockImplementation(
      () =>
        new Promise((resolve) => {
          finish = resolve;
        }),
    );
    fireEvent.change(screen.getByLabelText(new RegExp(en.workforceEmail.codeLabel)), { target: { value: "123456" } });
    fireEvent.click(screen.getByRole("button", { name: en.workforceEmail.verify }));
    fireEvent.click(screen.getByRole("button", { name: en.workforceEmail.changeEmail }));
    await screen.findByLabelText(new RegExp(en.workforceEmail.emailLabel));
    expect(cancelWorkforceEmailOtp).toHaveBeenCalledWith({ requestId: "oidc_exact", sessionId: "provider-session" });
    await act(() => finish({ redirect: "/protected" }));
    expect(push).not.toHaveBeenCalled();
  });
  it("does not verify or resend an expired code and keeps the confirmed restart available", async () => {
    vi.useFakeTimers();
    mount();
    await act(async () => {
      fireEvent.change(screen.getByLabelText(new RegExp(en.workforceEmail.emailLabel)), {
        target: { value: "staff@example.test" },
      });
      fireEvent.click(screen.getByRole("button", { name: en.workforceEmail.send }));
    });
    fireEvent.change(screen.getByLabelText(new RegExp(en.workforceEmail.codeLabel)), { target: { value: "123456" } });
    await act(() => vi.advanceTimersByTime(301000));
    expect(screen.getByText(en.workforceEmail.expired)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: en.workforceEmail.verify })).toBeDisabled();
    expect(screen.getByRole("button", { name: en.workforceEmail.resend })).toBeDisabled();
    await act(async () => fireEvent.click(screen.getByRole("button", { name: en.workforceEmail.changeEmail })));
    expect(screen.getByLabelText(new RegExp(en.workforceEmail.emailLabel))).toHaveFocus();
    expect(verifyWorkforceEmailOtp).not.toHaveBeenCalled();
    expect(resendWorkforceEmailOtp).not.toHaveBeenCalled();
  });
  it("retains the challenge if cancellation is not confirmed and offers recovery without a privilege shortcut", async () => {
    mount();
    await send();
    vi.mocked(cancelWorkforceEmailOtp).mockResolvedValue({ error: "unavailable" });
    fireEvent.click(screen.getByRole("button", { name: en.workforceEmail.changeEmail }));
    await screen.findByText(en.workforceEmail.unavailable);
    expect(screen.getByLabelText(new RegExp(en.workforceEmail.codeLabel))).toBeInTheDocument();
    expect(screen.getByText(en.workforceEmail.recovery)).toBeInTheDocument();
    expect(push).not.toHaveBeenCalled();
  });
});
