import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";
import { PasswordForm } from "./password-form";

const mocks = vi.hoisted(() => ({ push: vi.fn(), resetPassword: vi.fn() }));

vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: mocks.push }),
}));

vi.mock("next-intl", () => ({
  useTranslations: () => (key: string) => key,
}));

vi.mock("@/lib/server/password", () => ({
  sendPassword: vi.fn(),
  resetPassword: mocks.resetPassword,
}));

describe("PasswordForm", () => {
  beforeEach(() => vi.resetAllMocks());
  afterEach(cleanup);

  test("should autofocus the password input on mount", () => {
    const { getByTestId } = render(<PasswordForm loginSettings={undefined} loginName="test@example.com" />);
    expect(getByTestId("password-text-input")).toHaveFocus();
  });

  test("failed recovery stays on this step without a false sent confirmation or redirect", async () => {
    mocks.resetPassword.mockRejectedValueOnce(new Error("unavailable"));
    render(<PasswordForm loginSettings={undefined} loginName="test@example.com" />);
    fireEvent.click(screen.getByTestId("reset-button"));
    expect(await screen.findByRole("alert")).toHaveTextContent("errors.couldNotSendResetLink");
    expect(screen.queryByRole("status")).not.toBeInTheDocument();
    expect(mocks.push).not.toHaveBeenCalled();
    expect(screen.getByTestId("reset-button")).not.toBeDisabled();
  });
});
