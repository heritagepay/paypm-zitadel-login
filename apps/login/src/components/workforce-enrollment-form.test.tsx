import WorkforceEnrollmentPage from "@/app/(login)/workforce-enrollment/page";
import {
  cancelReviewedWorkforceEnrollment,
  completeReviewedWorkforceEnrollment,
  inspectReviewedWorkforceEnrollmentEntry,
  replaceReviewedWorkforceProfileEmail,
  resendReviewedWorkforceEnrollment,
  startReviewedWorkforceEnrollment,
  verifyReviewedWorkforceEnrollment,
  verifyReviewedWorkforceProfileEmail,
} from "@/lib/server/workforce-enrollment";
import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import { NextIntlClientProvider } from "next-intl";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import en from "../../locales/en.json";
import fr from "../../locales/fr.json";
import { WorkforceEnrollmentForm } from "./workforce-enrollment-form";

vi.mock("next/font/local", () => ({ default: () => ({ className: "scoped-workforce-font" }) }));
vi.mock("@/lib/server/workforce-enrollment", () => ({
  cancelReviewedWorkforceEnrollment: vi.fn(),
  completeReviewedWorkforceEnrollment: vi.fn(),
  inspectReviewedWorkforceEnrollmentEntry: vi.fn(),
  resendReviewedWorkforceEnrollment: vi.fn(),
  replaceReviewedWorkforceProfileEmail: vi.fn(),
  startReviewedWorkforceEnrollment: vi.fn(),
  verifyReviewedWorkforceEnrollment: vi.fn(),
  verifyReviewedWorkforceProfileEmail: vi.fn(),
}));
const operationId = "11111111-1111-4111-8111-111111111111";
const challengeId = "22222222-2222-4222-8222-222222222222";
const secondChallengeId = "33333333-3333-4333-8333-333333333333";
const requestId = "oidc_registered_request";
const email = "invited@example.test";
const ready = { state: "ready_to_start" as const, email, requestId };
const profile = { ...ready, state: "profile_email_verification_pending" as const };
const otp = () => ({
  ...ready,
  state: "otp_pending" as const,
  challengeId,
  expiresAt: new Date(Date.now() + 299000).toISOString(),
  resendAt: new Date(Date.now() + 60000).toISOString(),
});
type Entry = Awaited<ReturnType<typeof inspectReviewedWorkforceEnrollmentEntry>>;
function tree(entry: Entry = ready, locale = "en", id = operationId) {
  return (
    <NextIntlClientProvider locale={locale} messages={locale === "fr" ? fr : en}>
      <WorkforceEnrollmentForm operationId={id} entry={entry} />
    </NextIntlClientProvider>
  );
}
function mount(entry: Entry = ready, locale = "en") {
  return render(tree(entry, locale));
}
function change(value: string, label = en.workforceEnrollment.sessionCodeLabel) {
  const field = screen.getByLabelText(label);
  fireEvent.change(field, { target: { value } });
  return field;
}
async function click(name: string) {
  await act(async () => fireEvent.click(screen.getByRole("button", { name })));
}
function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => {
    resolve = done;
  });
  return { promise, resolve };
}
beforeEach(() => {
  vi.resetAllMocks();
  window.history.replaceState(null, "", "/ui/v2/login/workforce-enrollment");
  vi.mocked(startReviewedWorkforceEnrollment).mockResolvedValue({ state: "profile_email_verification_pending", email });
  vi.mocked(verifyReviewedWorkforceProfileEmail).mockResolvedValue({ state: "profile_email_verified" });
  vi.mocked(verifyReviewedWorkforceEnrollment).mockResolvedValue({ state: "identity_link_pending" });
  vi.mocked(cancelReviewedWorkforceEnrollment).mockResolvedValue({ state: "cancelled" });
  vi.mocked(completeReviewedWorkforceEnrollment).mockResolvedValue({ state: "enrollment_completed_access_pending" });
  vi.mocked(inspectReviewedWorkforceEnrollmentEntry).mockResolvedValue(ready);
});
afterEach(() => {
  cleanup();
  vi.useRealTimers();
  window.history.replaceState(null, "", "/");
});

describe("reviewed workforce enrollment presentation", () => {
  it.each(["en", "fr"])(
    "renders invited server email and an explicit initial action in %s without starting delivery",
    (locale) => {
      mount(ready, locale);
      const copy = locale === "fr" ? fr.workforceEnrollment : en.workforceEnrollment;
      expect(screen.getByRole("heading", { name: copy.readyTitle })).toHaveFocus();
      expect(screen.getByText(email)).toBeInTheDocument();
      expect(screen.queryByRole("textbox")).toBeNull();
      expect(screen.getByRole("button", { name: copy.start })).toBeEnabled();
      expect(startReviewedWorkforceEnrollment).not.toHaveBeenCalled();
      expect(verifyReviewedWorkforceProfileEmail).not.toHaveBeenCalled();
    },
  );
  it("shows missing original OIDC request as a bounded instruction, without inventing an application URL", () => {
    mount({ state: "oidc_request_required", email });
    expect(screen.getByText(en.workforceEnrollment.requestBody)).toBeInTheDocument();
    expect(screen.queryByRole("button")).toBeNull();
    expect(screen.queryByRole("link")).toBeNull();
    expect(startReviewedWorkforceEnrollment).not.toHaveBeenCalled();
  });
  it("starts only the exact server-owned request on a deliberate click and requires explicit six-character verification", async () => {
    mount();
    await click(en.workforceEnrollment.start);
    const field = screen.getByLabelText(en.workforceEnrollment.profileCodeLabel);
    expect(field).toHaveFocus();
    expect(field).toHaveAttribute("inputmode", "text");
    expect(field).toHaveAttribute("autocomplete", "one-time-code");
    expect(screen.getByRole("button", { name: en.workforceEnrollment.profileSubmit })).toBeDisabled();
    expect(startReviewedWorkforceEnrollment).toHaveBeenCalledWith({
      operationId,
      requestId,
      operationKey: expect.any(String),
    });
    for (const value of ["ABC12", "ABC1234", "abc123", "AB/123", "１２３４５６"]) {
      change(value, en.workforceEnrollment.profileCodeLabel);
      expect(screen.getByRole("button", { name: en.workforceEnrollment.profileSubmit })).toBeDisabled();
      fireEvent.submit(field.closest("form")!);
    }
    expect(verifyReviewedWorkforceProfileEmail).not.toHaveBeenCalled();
    change("AB C-123", en.workforceEnrollment.profileCodeLabel);
    await click(en.workforceEnrollment.profileSubmit);
    expect(verifyReviewedWorkforceProfileEmail).toHaveBeenCalledWith({
      operationId,
      operationKey: expect.any(String),
      code: "ABC123",
    });
    expect(screen.getByRole("heading", { name: en.workforceEnrollment.profileVerifiedTitle })).toBeInTheDocument();
    expect(startReviewedWorkforceEnrollment).toHaveBeenCalledTimes(1);
    vi.mocked(startReviewedWorkforceEnrollment).mockResolvedValue(otp());
    await click(en.workforceEnrollment.sendSessionCode);
    expect(startReviewedWorkforceEnrollment).toHaveBeenCalledTimes(2);
    expect(screen.getByLabelText(en.workforceEnrollment.sessionCodeLabel)).toHaveValue("");
  });
  it("consumes only a bounded profile fragment after original-request readback, removes it, and never auto-verifies", async () => {
    window.history.replaceState({ incumbent: true }, "", `?operationId=${operationId}#code=AB12CD`);
    mount();
    expect(window.location.hash).toBe("");
    expect(window.history.state).toEqual({ incumbent: true });
    expect(startReviewedWorkforceEnrollment).not.toHaveBeenCalled();
    await click(en.workforceEnrollment.start);
    expect(screen.getByLabelText(en.workforceEnrollment.profileCodeLabel)).toHaveValue("AB12CD");
    expect(verifyReviewedWorkforceProfileEmail).not.toHaveBeenCalled();
    await click(en.workforceEnrollment.profileSubmit);
    expect(verifyReviewedWorkforceProfileEmail).toHaveBeenCalledWith(expect.objectContaining({ code: "AB12CD" }));
  });
  it.each(["#code=abcdef", "#code=ABC123&code=DEF456", "#code=ABC123&extra=1", `#code=${"A".repeat(201)}`])(
    "removes but rejects malformed profile fragments %s",
    (fragment) => {
      window.history.replaceState(null, "", fragment);
      mount(profile);
      expect(window.location.hash).toBe("");
      expect(screen.getByLabelText(en.workforceEnrollment.profileCodeLabel)).toHaveValue("");
      expect(verifyReviewedWorkforceProfileEmail).not.toHaveBeenCalled();
    },
  );
  it("does not promote a profile verification fragment to Session OTP", () => {
    window.history.replaceState(null, "", "#code=123456");
    mount(otp());
    expect(screen.getByLabelText(en.workforceEnrollment.sessionCodeLabel)).toHaveValue("");
    expect(window.location.hash).toBe("");
    expect(verifyReviewedWorkforceEnrollment).not.toHaveBeenCalled();
  });
  it("accepts eight-digit paste/autofill but denies six, nonnumeric and non-ASCII codes without issuing verification", async () => {
    mount(otp());
    const field = screen.getByLabelText(en.workforceEnrollment.sessionCodeLabel);
    expect(field).toHaveFocus();
    expect(field).toHaveAttribute("inputmode", "numeric");
    expect(field).toHaveAttribute("autocomplete", "one-time-code");
    expect(screen.getByRole("button", { name: en.workforceEnrollment.sessionSubmit })).toBeDisabled();
    for (const value of ["123456", "1234567", "123456789", "1234567A", "１２３４５６７８", "1234/5678"]) {
      change(value);
      expect(screen.getByRole("button", { name: en.workforceEnrollment.sessionSubmit })).toBeDisabled();
      fireEvent.submit(field.closest("form")!);
    }
    expect(verifyReviewedWorkforceEnrollment).not.toHaveBeenCalled();
    change("1234- 5678");
    await click(en.workforceEnrollment.sessionSubmit);
    expect(verifyReviewedWorkforceEnrollment).toHaveBeenCalledWith({
      operationId,
      challengeId,
      operationKey: expect.any(String),
      code: "12345678",
    });
    expect(screen.getByRole("heading", { name: en.workforceEnrollment.linkTitle })).toBeInTheDocument();
    expect(completeReviewedWorkforceEnrollment).not.toHaveBeenCalled();
    await click(en.workforceEnrollment.complete);
    expect(completeReviewedWorkforceEnrollment).toHaveBeenCalledWith({
      operationId,
      challengeId,
      operationKey: expect.any(String),
    });
    expect(screen.getByRole("heading", { name: en.workforceEnrollment.completeTitle })).toBeInTheDocument();
    expect(screen.getAllByText(en.workforceEnrollment.accessPending)).toHaveLength(2);
    expect(screen.getByText(en.workforceEnrollment.accessBody)).toBeInTheDocument();
    expect(screen.queryByRole("button")).toBeNull();
    expect(screen.queryByRole("link")).toBeNull();
  });
  it("shows a fresh server countdown immediately after long profile dwell and honors its expiry without an extra tick", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-10-07T06:00:00Z"));
    mount(profile);
    await act(() => vi.advanceTimersByTime(125000));
    change("ABC123", en.workforceEnrollment.profileCodeLabel);
    await click(en.workforceEnrollment.profileSubmit);
    await act(() => vi.advanceTimersByTime(85000));
    const fresh = otp();
    vi.mocked(startReviewedWorkforceEnrollment).mockResolvedValue(fresh);
    await click(en.workforceEnrollment.sendSessionCode);
    expect(screen.getByRole("button", { name: "Resend in 01:00" })).toBeDisabled();
    expect(screen.getByLabelText(en.workforceEnrollment.sessionCodeLabel)).toBeEnabled();
    expect(screen.queryByText(en.workforceEnrollment.expired)).toBeNull();
    await act(() => vi.advanceTimersByTime(30000));
    expect(screen.getByRole("button", { name: "Resend in 00:30" })).toBeDisabled();
    await act(() => vi.advanceTimersByTime(269000));
    expect(screen.getByText(en.workforceEnrollment.expired)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: en.workforceEnrollment.sessionSubmit })).toBeDisabled();
    expect(screen.getByRole("button", { name: en.workforceEnrollment.resend })).toBeDisabled();
    expect(startReviewedWorkforceEnrollment).toHaveBeenCalledTimes(1);
    expect(resendReviewedWorkforceEnrollment).not.toHaveBeenCalled();
  });
  it("uses the observed resend deadline and retires the previous displayed code only after a confirmed new challenge", async () => {
    vi.useFakeTimers();
    mount(otp());
    change("12345678");
    expect(screen.getByRole("button", { name: "Resend in 01:00" })).toBeDisabled();
    await act(() => vi.advanceTimersByTime(61000));
    vi.mocked(resendReviewedWorkforceEnrollment).mockResolvedValue({ ...otp(), challengeId: secondChallengeId });
    await click(en.workforceEnrollment.resend);
    expect(resendReviewedWorkforceEnrollment).toHaveBeenCalledWith({
      operationId,
      challengeId,
      operationKey: expect.any(String),
    });
    expect(screen.getByLabelText(en.workforceEnrollment.sessionCodeLabel)).toHaveValue("");
    expect(screen.getByRole("button", { name: "Resend in 01:00" })).toBeDisabled();
    change("87654321");
    await click(en.workforceEnrollment.sessionSubmit);
    expect(verifyReviewedWorkforceEnrollment).toHaveBeenCalledWith(
      expect.objectContaining({ challengeId: secondChallengeId, code: "87654321" }),
    );
  });
  it("disables expired OTP verification and resend without automatically issuing a replacement", async () => {
    vi.useFakeTimers();
    mount(otp());
    change("12345678");
    await act(() => vi.advanceTimersByTime(300000));
    expect(screen.getByText(en.workforceEnrollment.expired)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: en.workforceEnrollment.sessionSubmit })).toBeDisabled();
    expect(screen.getByRole("button", { name: en.workforceEnrollment.resend })).toBeDisabled();
    expect(screen.getByRole("button", { name: en.workforceEnrollment.check })).toBeEnabled();
    expect(startReviewedWorkforceEnrollment).not.toHaveBeenCalled();
    expect(resendReviewedWorkforceEnrollment).not.toHaveBeenCalled();
  });
  it("keeps uncertain verification neutral, reads the original request, and recovers its observed link state without retrying delivery", async () => {
    const original = otp();
    mount(original);
    vi.mocked(verifyReviewedWorkforceEnrollment).mockRejectedValue(new Error("private-provider-detail"));
    change("12345678");
    await click(en.workforceEnrollment.sessionSubmit);
    expect(screen.getByRole("alert")).toHaveTextContent(en.workforceEnrollment.unconfirmed);
    expect(screen.queryByText("private-provider-detail")).toBeNull();
    expect(screen.getByLabelText(en.workforceEnrollment.sessionCodeLabel)).toBeDisabled();
    expect(screen.queryByRole("button", { name: en.workforceEnrollment.cancel })).toBeNull();
    vi.mocked(inspectReviewedWorkforceEnrollmentEntry).mockResolvedValue({ ...original, state: "identity_link_pending" });
    await click(en.workforceEnrollment.check);
    expect(inspectReviewedWorkforceEnrollmentEntry).toHaveBeenCalledWith({ operationId, requestId });
    expect(screen.getByRole("button", { name: en.workforceEnrollment.complete })).toBeEnabled();
    expect(verifyReviewedWorkforceEnrollment).toHaveBeenCalledTimes(1);
    expect(completeReviewedWorkforceEnrollment).not.toHaveBeenCalled();
  });
  it("retains the same operation key when an unknown start is read back as ready and the user explicitly retries", async () => {
    mount();
    vi.mocked(startReviewedWorkforceEnrollment)
      .mockResolvedValueOnce({ error: "unavailable" })
      .mockResolvedValueOnce({ state: "profile_email_verification_pending", email });
    await click(en.workforceEnrollment.start);
    expect(screen.getByRole("button", { name: en.workforceEnrollment.start })).toBeDisabled();
    await click(en.workforceEnrollment.check);
    await click(en.workforceEnrollment.start);
    expect(vi.mocked(startReviewedWorkforceEnrollment).mock.calls[0][0]).toEqual(
      vi.mocked(startReviewedWorkforceEnrollment).mock.calls[1][0],
    );
  });
  it("waits for actual cancellation and ignores a late successful verification", async () => {
    mount(otp());
    const pending = deferred<Awaited<ReturnType<typeof verifyReviewedWorkforceEnrollment>>>();
    vi.mocked(verifyReviewedWorkforceEnrollment).mockReturnValue(pending.promise);
    change("12345678");
    fireEvent.click(screen.getByRole("button", { name: en.workforceEnrollment.sessionSubmit }));
    await click(en.workforceEnrollment.cancel);
    expect(screen.getByRole("heading", { name: en.workforceEnrollment.cancelledTitle })).toBeInTheDocument();
    expect(cancelReviewedWorkforceEnrollment).toHaveBeenCalledWith({ operationId, operationKey: expect.any(String) });
    await act(() => pending.resolve({ state: "identity_link_pending" }));
    expect(screen.queryByRole("button", { name: en.workforceEnrollment.complete })).toBeNull();
    expect(completeReviewedWorkforceEnrollment).not.toHaveBeenCalled();
  });
  it("does not claim cancellation when its result is unknown, or expose generic server payload fields", async () => {
    mount(profile);
    vi.mocked(cancelReviewedWorkforceEnrollment).mockResolvedValue({ error: "session-secret" });
    await click(en.workforceEnrollment.cancel);
    expect(screen.getByRole("alert")).toHaveTextContent(en.workforceEnrollment.unconfirmed);
    expect(screen.queryByText("session-secret")).toBeNull();
    expect(screen.getByRole("heading", { name: en.workforceEnrollment.profileTitle })).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: en.workforceEnrollment.cancelledTitle })).toBeNull();
  });
  it("serializes repeated submission and discards unmounted completion", async () => {
    const pending = deferred<Awaited<ReturnType<typeof verifyReviewedWorkforceEnrollment>>>();
    vi.mocked(verifyReviewedWorkforceEnrollment).mockReturnValue(pending.promise);
    const rendered = mount(otp());
    const field = change("12345678");
    fireEvent.submit(field.closest("form")!);
    fireEvent.submit(field.closest("form")!);
    expect(verifyReviewedWorkforceEnrollment).toHaveBeenCalledTimes(1);
    rendered.unmount();
    await act(() => pending.resolve({ state: "identity_link_pending" }));
    expect(screen.queryByRole("heading")).toBeNull();
    expect(completeReviewedWorkforceEnrollment).not.toHaveBeenCalled();
  });
  it("preserves the entered code and original challenge when language changes without initiating a request", () => {
    const original = otp();
    const rendered = mount(original);
    change("12345678");
    rendered.rerender(tree(original, "fr"));
    expect(screen.getByLabelText(fr.workforceEnrollment.sessionCodeLabel)).toHaveValue("12345678");
    expect(screen.getByText(email)).toBeInTheDocument();
    expect(verifyReviewedWorkforceEnrollment).not.toHaveBeenCalled();
    expect(startReviewedWorkforceEnrollment).not.toHaveBeenCalled();
  });
  it("renders only the public projection and never exposes extra subject, role or session fields", () => {
    mount(
      Object.assign({}, profile, {
        sessionToken: "private-session-value",
        personId: "private-person-value",
        roles: ["administrator"],
      }),
    );
    expect(screen.queryByText("private-session-value")).toBeNull();
    expect(screen.queryByText("private-person-value")).toBeNull();
    expect(screen.queryByText("administrator")).toBeNull();
    expect(screen.getByText(email)).toBeInTheDocument();
  });
  it("keeps an unresolved cancel exclusive and does not declare completion before its owner reply", async () => {
    mount(profile);
    const pending = deferred<Awaited<ReturnType<typeof cancelReviewedWorkforceEnrollment>>>();
    vi.mocked(cancelReviewedWorkforceEnrollment).mockReturnValue(pending.promise);
    fireEvent.click(screen.getByRole("button", { name: en.workforceEnrollment.cancel }));
    expect(screen.getByText(en.workforceEnrollment.cancelling)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: en.workforceEnrollment.cancel })).toBeNull();
    expect(screen.queryByRole("heading", { name: en.workforceEnrollment.cancelledTitle })).toBeNull();
    expect(cancelReviewedWorkforceEnrollment).toHaveBeenCalledTimes(1);
    await act(() => pending.resolve({ state: "cancelled" }));
    expect(screen.getByRole("heading", { name: en.workforceEnrollment.cancelledTitle })).toBeInTheDocument();
  });
  it("rejects malformed timer or challenge projections without presenting a usable verification command", () => {
    mount({ ...otp(), expiresAt: "not-a-date" });
    expect(screen.getByRole("alert")).toBeInTheDocument();
    expect(screen.queryByRole("textbox")).toBeNull();
    expect(verifyReviewedWorkforceEnrollment).not.toHaveBeenCalled();
  });
});

describe("workforce enrollment server page", () => {
  it("only reads the original public projection and scopes its font without starting enrollment", async () => {
    const page = await WorkforceEnrollmentPage({ searchParams: Promise.resolve({ operationId, requestId }) });
    render(
      <NextIntlClientProvider locale="en" messages={en}>
        {page}
      </NextIntlClientProvider>,
    );
    expect(inspectReviewedWorkforceEnrollmentEntry).toHaveBeenCalledWith({ operationId, requestId });
    expect(screen.getByRole("heading", { name: en.workforceEnrollment.readyTitle })).toBeInTheDocument();
    expect(startReviewedWorkforceEnrollment).not.toHaveBeenCalled();
  });
  it.each([
    { operationId: [operationId] },
    { operationId: "unknown" },
    { operationId, requestId: [requestId] },
    { operationId, requestId: "wrong_request" },
  ])("does not call the reader for malformed query custody %o", async (params) => {
    const page = await WorkforceEnrollmentPage({ searchParams: Promise.resolve(params) });
    render(
      <NextIntlClientProvider locale="en" messages={en}>
        {page}
      </NextIntlClientProvider>,
    );
    expect(inspectReviewedWorkforceEnrollmentEntry).not.toHaveBeenCalled();
    expect(startReviewedWorkforceEnrollment).not.toHaveBeenCalled();
    expect(screen.getByRole("heading", { name: en.workforceEnrollment.unavailableTitle })).toBeInTheDocument();
  });
});

describe("profile request accepted/unknown/explicit replacement", () => {
  const delivery = (state: "accepted" | "unknown" = "accepted") => ({
    ...profile,
    expiresAt: new Date(Date.now() + 240000).toISOString(),
    profileDelivery: {
      state,
      attemptId: challengeId,
      resendAt: new Date(Date.now() + 60000).toISOString(),
      codeExpiresAt: new Date(Date.now() + 3600000).toISOString(),
    },
  });
  it.each(["fr", "en"])("unknown %s keeps received-code Verify, no send/readback loop or inbox claim", async (locale) => {
    mount(delivery("unknown"), locale);
    const copy = locale === "fr" ? fr.workforceEnrollment : en.workforceEnrollment;
    expect(screen.getByRole("status")).toHaveTextContent(copy.profileRequestUnknown);
    expect(screen.queryByText(copy.profileRequestAccepted)).toBeNull();
    const input = change("ABC123", copy.profileCodeLabel);
    expect(input).toBeEnabled();
    expect(screen.getByRole("button", { name: copy.profileSubmit })).toBeEnabled();
    expect(startReviewedWorkforceEnrollment).not.toHaveBeenCalled();
    expect(replaceReviewedWorkforceProfileEmail).not.toHaveBeenCalled();
    expect(inspectReviewedWorkforceEnrollmentEntry).not.toHaveBeenCalled();
    await click(copy.profileSubmit);
    expect(verifyReviewedWorkforceProfileEmail).toHaveBeenCalledOnce();
  });
  it("accepted feedback is command-only; explicit replacement waits deadline and passes original attempt once", async () => {
    vi.useFakeTimers();
    mount(delivery());
    change("ABC123", en.workforceEnrollment.profileCodeLabel);
    expect(screen.getByRole("status")).toHaveTextContent(en.workforceEnrollment.profileRequestAccepted);
    expect(screen.getByRole("button", { name: "New code in 01:00" })).toBeDisabled();
    await act(() => vi.advanceTimersByTime(61000));
    expect(screen.getByText(en.workforceEnrollment.profileReplacementConsequence)).toBeInTheDocument();
    const pending = deferred<any>();
    vi.mocked(replaceReviewedWorkforceProfileEmail).mockReturnValue(pending.promise);
    fireEvent.click(screen.getByRole("button", { name: en.workforceEnrollment.profileReplace }));
    expect(screen.getByRole("button", { name: en.workforceEnrollment.profileRequesting })).toBeDisabled();
    expect(screen.getByLabelText(en.workforceEnrollment.profileCodeLabel)).toBeDisabled();
    expect(replaceReviewedWorkforceProfileEmail).toHaveBeenCalledWith({
      operationId,
      attemptId: challengeId,
      operationKey: expect.any(String),
    });
    const next = delivery();
    next.profileDelivery.attemptId = secondChallengeId;
    await act(() => pending.resolve(next));
    expect(screen.getByLabelText(en.workforceEnrollment.profileCodeLabel)).toHaveValue("");
    expect(replaceReviewedWorkforceProfileEmail).toHaveBeenCalledOnce();
  });
  it("unknown replacement preserves typed code, new server attempt and received-code verification", async () => {
    vi.useFakeTimers();
    mount(delivery());
    change("ABC123", en.workforceEnrollment.profileCodeLabel);
    await act(() => vi.advanceTimersByTime(61000));
    const next = delivery("unknown");
    next.profileDelivery.attemptId = secondChallengeId;
    vi.mocked(replaceReviewedWorkforceProfileEmail).mockResolvedValue(next);
    await click(en.workforceEnrollment.profileReplace);
    expect(screen.getByRole("status")).toHaveTextContent(en.workforceEnrollment.profileRequestUnknown);
    expect(screen.getByLabelText(en.workforceEnrollment.profileCodeLabel)).toHaveValue("ABC123");
    expect(screen.getByRole("button", { name: en.workforceEnrollment.profileSubmit })).toBeEnabled();
    expect(screen.getByRole("button", { name: "New code in 01:00" })).toBeDisabled();
  });
  it("lost replacement reply retains deliberate Verify but prevents another send until original custody reread", async () => {
    vi.useFakeTimers();
    mount(delivery());
    change("ABC123", en.workforceEnrollment.profileCodeLabel);
    await act(() => vi.advanceTimersByTime(61000));
    vi.mocked(replaceReviewedWorkforceProfileEmail).mockRejectedValue(new Error("lost"));
    await click(en.workforceEnrollment.profileReplace);
    expect(screen.getByRole("button", { name: en.workforceEnrollment.profileSubmit })).toBeEnabled();
    expect(screen.getByRole("button", { name: en.workforceEnrollment.profileReplace })).toBeDisabled();
    expect(screen.getByRole("status")).toHaveTextContent(en.workforceEnrollment.profileRequestUnknown);
    expect(screen.queryByText(en.workforceEnrollment.profileRequestAccepted)).toBeNull();
    vi.mocked(inspectReviewedWorkforceEnrollmentEntry).mockResolvedValue(delivery("unknown"));
    await click(en.workforceEnrollment.check);
    expect(screen.getByLabelText(en.workforceEnrollment.profileCodeLabel)).toHaveValue("ABC123");
    expect(replaceReviewedWorkforceProfileEmail).toHaveBeenCalledOnce();
  });
  it.each(["fr", "en"])(
    "%s original expiry blocks native-valid1h code/replacement without claiming code expiry",
    async (locale) => {
      vi.useFakeTimers();
      const original = delivery("unknown"),
        mounted = mount(original);
      change("ABC123", en.workforceEnrollment.profileCodeLabel);
      const messages = locale === "fr" ? fr.workforceEnrollment : en.workforceEnrollment;
      mounted.rerender(tree(original, locale));
      expect(screen.getByLabelText(messages.profileCodeLabel)).toHaveValue("ABC123");
      await act(() => vi.advanceTimersByTime(241000));
      expect(Date.parse(original.profileDelivery.codeExpiresAt)).toBeGreaterThan(Date.now());
      expect(screen.getByText(messages.profileRequestExpired)).toBeInTheDocument();
      expect(screen.queryByText(messages.expired)).toBeNull();
      expect(screen.getByRole("button", { name: messages.profileSubmit })).toBeDisabled();
      expect(screen.getByRole("button", { name: messages.profileReplace })).toBeDisabled();
      expect(replaceReviewedWorkforceProfileEmail).not.toHaveBeenCalled();
      expect(verifyReviewedWorkforceProfileEmail).not.toHaveBeenCalled();
    },
  );
  it("cancellation fences late replacement projection and never claims delivered or verified", async () => {
    vi.useFakeTimers();
    mount(delivery());
    await act(() => vi.advanceTimersByTime(61000));
    const pending = deferred<any>();
    vi.mocked(replaceReviewedWorkforceProfileEmail).mockReturnValue(pending.promise);
    fireEvent.click(screen.getByRole("button", { name: en.workforceEnrollment.profileReplace }));
    await click(en.workforceEnrollment.cancel);
    await act(() => pending.resolve(delivery()));
    expect(screen.getByRole("heading", { name: en.workforceEnrollment.cancelledTitle })).toBeInTheDocument();
    expect(screen.queryByRole("textbox")).toBeNull();
    expect(verifyReviewedWorkforceProfileEmail).not.toHaveBeenCalled();
  });
});
