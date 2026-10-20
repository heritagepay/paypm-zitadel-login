import { cleanup, render, screen } from "@testing-library/react";
import { ReactNode } from "react";
import { afterEach, describe, expect, test, vi } from "vitest";
import { DynamicTheme } from "./dynamic-theme";

const responsive = vi.hoisted(() => ({ isSideBySide: false }));
vi.mock("@/lib/theme-hooks", () => ({ useResponsiveLayout: () => responsive }));
vi.mock("./theme-wrapper", () => ({ ThemeWrapper: ({ children }: { children: ReactNode }) => <div>{children}</div> }));
vi.mock("@/components/logo", () => ({ Logo: () => <span>Organization logo</span> }));

afterEach(cleanup);

describe("PayPM shared authentication composition", () => {
  test.each([false, true])("retains every ceremony section with configured side-by-side=%s", (isSideBySide) => {
    responsive.isSideBySide = isSideBySide;
    const { container } = render(
      <DynamicTheme>
        <h1>Verify your account</h1>
        <form aria-label="verification">Code</form>
        <p>Recovery options</p>
        <p>Persistent failure</p>
      </DynamicTheme>,
    );
    expect(screen.getByRole("heading", { name: "Verify your account" })).toBeInTheDocument();
    expect(screen.getByRole("form", { name: "verification" })).toBeInTheDocument();
    expect(screen.getByText("Recovery options")).toBeInTheDocument();
    expect(screen.getByText("Persistent failure")).toBeInTheDocument();
    expect(container.querySelector(".paypm-auth-arrival h1")).not.toBeNull();
    expect(container.querySelector(".paypm-auth-work")?.textContent).toBe("CodeRecovery optionsPersistent failure");
  });

  test("retains a complete single section instead of guessing its structure", () => {
    const { container } = render(
      <DynamicTheme>
        <div>
          <h1>Unavailable</h1>
          <p>Try again</p>
        </div>
      </DynamicTheme>,
    );
    expect(container.querySelector(".paypm-auth-work h1")?.textContent).toBe("Unavailable");
    expect(screen.getByText("Try again")).toBeInTheDocument();
  });

  test("preserves the configured layout argument for render-function consumers", () => {
    responsive.isSideBySide = true;
    const child = vi.fn(() => <p>Complete ceremony</p>);
    render(<DynamicTheme>{child}</DynamicTheme>);
    expect(child).toHaveBeenCalledWith(true);
    expect(screen.getByText("Complete ceremony")).toBeInTheDocument();
  });
});
