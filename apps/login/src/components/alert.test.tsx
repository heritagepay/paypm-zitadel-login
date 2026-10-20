import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { Alert, AlertType } from "./alert";

afterEach(cleanup);

describe("Alert", () => {
  it("should announce persistent errors as alerts by default", () => {
    const { rerender } = render(<Alert>Unable to sign in. Try again.</Alert>);
    const alert = screen.getByRole("alert");
    expect(alert).toHaveTextContent("Unable to sign in. Try again.");
    expect(alert).toHaveClass("paypm-alert");
    expect(alert.querySelector("svg")).toHaveAttribute("aria-hidden", "true");

    rerender(<Alert>Unable to sign in. Try again.</Alert>);
    expect(screen.getByRole("alert")).toHaveTextContent("Unable to sign in. Try again.");
  });

  it("should retain the explicit ALERT type API", () => {
    render(<Alert type={AlertType.ALERT}>Verification failed.</Alert>);
    expect(screen.getByRole("alert")).toHaveTextContent("Verification failed.");
    expect(screen.queryByRole("status")).toBeNull();
  });

  it("should announce information with a status role and decorative icon", () => {
    render(<Alert type={AlertType.INFO}>Check your email for the reset link.</Alert>);
    const status = screen.getByRole("status");
    expect(status).toHaveTextContent("Check your email for the reset link.");
    expect(status).toHaveClass("paypm-alert");
    expect(status.querySelector("svg")).toHaveAttribute("aria-hidden", "true");
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("should preserve structured feedback and its recovery link", () => {
    render(
      <Alert>
        <strong>This request has expired.</strong> <a href="/loginname">Start again</a>
      </Alert>,
    );
    expect(screen.getByRole("alert")).toHaveTextContent("This request has expired. Start again");
    expect(screen.getByRole("link", { name: "Start again" })).toHaveAttribute("href", "/loginname");
  });
});
