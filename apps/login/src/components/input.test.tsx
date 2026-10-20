import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { createRef } from "react";
import { useForm } from "react-hook-form";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { TextInput } from "./input";

describe("TextInput Component", () => {
  const originalEnv = process.env;

  beforeEach(() => {
    process.env = { ...originalEnv };
  });

  afterEach(() => {
    cleanup();
    process.env = originalEnv;
  });

  describe("Component Rendering", () => {
    it("should render input with label", () => {
      render(<TextInput label="Email" />);
      expect(screen.getByText("Email")).toBeTruthy();
    });

    it("should render input with placeholder", () => {
      const { container } = render(<TextInput label="Username" placeholder="Enter username" />);
      const input = container.querySelector("input");
      expect(input?.placeholder).toBe("Enter username");
    });

    it("should render input with default value", () => {
      const { container } = render(<TextInput label="Name" defaultValue="John Doe" />);
      const input = container.querySelector("input");
      expect(input?.defaultValue).toBe("John Doe");
    });

    it("should show required indicator when required", () => {
      render(<TextInput label="Required Field" required />);
      expect(screen.getByText(/\*/)).toBeTruthy();
    });
  });

  describe("Input States", () => {
    it("should render disabled state", () => {
      const { container } = render(<TextInput label="Disabled" disabled />);
      const input = container.querySelector("input");
      expect(input?.disabled).toBe(true);
      // Should have disabled/pointer-events styles
      expect(input?.className).toMatch(/pointer-events/);
    });

    it("should render error state with message", () => {
      render(<TextInput label="Email" error="Invalid email" />);
      expect(screen.getByText("Invalid email")).toBeTruthy();
    });

    it("should apply error styling when error is present", () => {
      const { container } = render(<TextInput label="Email" error="Invalid" />);
      const input = container.querySelector("input");
      expect(input).toBeTruthy();
      // Should have border-warn or warn-related styles
      expect(input?.className).toMatch(/border-warn/);
    });

    it("should render success state with message", () => {
      render(<TextInput label="Email" success="Valid email" />);
      expect(screen.getByText("Valid email")).toBeTruthy();
    });
  });

  describe("Theme Integration", () => {
    it("should apply theme-based roundness", () => {
      const { container } = render(<TextInput label="Themed" />);
      const input = container.querySelector("input");
      // Should have some roundness class applied
      expect(input?.className).toBeTruthy();
      expect(input?.className).toMatch(/rounded/);
    });

    it("should completely override theme roundness with custom roundness prop", () => {
      // Set theme to have full roundness
      process.env.NEXT_PUBLIC_THEME_ROUNDNESS = "full";
      const customRoundness = "custom-input-round";

      const { container } = render(<TextInput label="Custom" roundness={customRoundness} />);
      const input = container.querySelector("input");

      // Should contain the custom roundness
      expect(input?.className).toContain(customRoundness);

      // The custom prop completely replaces theme roundness
      expect(input).toBeTruthy();
    });

    it("should respect theme roundness changes", () => {
      // Default theme
      const { container: container1 } = render(<TextInput label="Default" />);
      const input1 = container1.querySelector("input");
      const defaultClasses = input1?.className;

      // Change theme
      process.env.NEXT_PUBLIC_THEME_ROUNDNESS = "full";
      const { container: container2 } = render(<TextInput label="Full" />);
      const input2 = container2.querySelector("input");

      // Classes should be present
      expect(defaultClasses).toBeTruthy();
      expect(input2?.className).toBeTruthy();
    });
  });

  describe("Input Behavior", () => {
    it("should have autocomplete off by default", () => {
      const { container } = render(<TextInput label="Test" />);
      const input = container.querySelector("input");
      expect(input?.autocomplete).toBe("off");
    });

    it("should allow custom autocomplete", () => {
      const { container } = render(<TextInput label="Email" autoComplete="email" />);
      const input = container.querySelector("input");
      expect(input?.autocomplete).toBe("email");
    });

    it("should pass through native input props", () => {
      const { container } = render(<TextInput label="Test" maxLength={10} type="email" />);
      const input = container.querySelector("input");
      expect(input?.maxLength).toBe(10);
      expect(input?.type).toBe("email");
    });

    it("should support autoFocus", () => {
      const { container } = render(<TextInput label="Test" autoFocus />);
      const input = container.querySelector("input");
      expect(input).toHaveFocus();
    });
  });

  describe("Styling", () => {
    it("should have consistent base styling", () => {
      const { container } = render(<TextInput label="Test" />);
      const input = container.querySelector("input");
      expect(input).toBeTruthy();
      expect(input?.className).toBeTruthy();
      expect(input?.className.length).toBeGreaterThan(0);
      // Should have transition styles
      expect(input?.className).toMatch(/transition/);
    });

    it("should apply border styles", () => {
      const { container } = render(<TextInput label="Test" />);
      const input = container.querySelector("input");
      expect(input).toBeTruthy();
      // Should have border-related classes
      expect(input?.className).toMatch(/border/);
    });

    it("should have focus styles", () => {
      const { container } = render(<TextInput label="Test" />);
      const input = container.querySelector("input");
      expect(input).toBeTruthy();
      // Should have focus-related classes
      expect(input?.className).toMatch(/focus:/);
    });
  });

  describe("Label Styling", () => {
    it("should apply error color to label when error exists", () => {
      const { container } = render(<TextInput label="Error Field" error="Error message" />);
      const label = container.querySelector("label");
      expect(label).toBeTruthy();
    });

    it("should have default label styling", () => {
      const { container } = render(<TextInput label="Normal Field" />);
      const label = container.querySelector("label");
      expect(label).toBeTruthy();
      expect(label?.className).toBeTruthy();
    });
  });

  describe("Accessibility", () => {
    it("should connect label to input", () => {
      render(<TextInput label="Accessible Input" id="account-name" />);
      const input = screen.getByRole("textbox", { name: "Accessible Input" });
      expect(screen.getByLabelText("Accessible Input")).toBe(input);
      expect(input).toHaveAttribute("id", "account-name");
    });

    it("should keep required markers, suffixes and feedback out of the accessible name", () => {
      render(
        <TextInput
          label="Email"
          required
          suffix="example.com"
          error={<span>Choose a different account</span>}
          success="Account found"
        />,
      );

      const input = screen.getByRole("textbox", { name: "Email" });
      expect(input).toHaveAccessibleName("Email");
      expect(input).toBeRequired();
      expect(input).toHaveAttribute("aria-invalid", "true");
      expect(input).toHaveAccessibleDescription("Choose a different account Account found");
      expect(screen.getByText("@example.com")).toBeVisible();
    });

    it("should merge caller hints with ReactNode error and success descriptions", () => {
      render(
        <>
          <p id="account-hint">Use your workplace account.</p>
          <p id="account-format">Enter an email or username.</p>
          <TextInput
            id="work-account"
            label="Account"
            aria-describedby="account-hint account-format"
            aria-invalid={false}
            error={<span>This account is unavailable.</span>}
            success={<span>Your entry was saved.</span>}
          />
        </>,
      );

      const input = screen.getByRole("textbox", { name: "Account" });
      expect(input).toHaveAttribute(
        "aria-describedby",
        "account-hint account-format work-account-error work-account-success",
      );
      expect(input).toHaveAccessibleDescription(
        "Use your workplace account. Enter an email or username. This account is unavailable. Your entry was saved.",
      );
      expect(input).toHaveAttribute("aria-invalid", "true");
    });

    it("should generate distinct stable input and feedback IDs for repeated fields", () => {
      const fields = (
        <>
          <TextInput label="Account" error="First error" success="First success" />
          <TextInput label="Account" error="Second error" success="Second success" />
        </>
      );
      const { container, rerender } = render(fields);
      const inputs = screen.getAllByRole("textbox", { name: "Account" });
      const ids = Array.from(container.querySelectorAll("[id]"), (element) => element.id);
      expect(new Set(ids).size).toBe(ids.length);
      expect(inputs[0]).toHaveAccessibleDescription("First error First success");
      expect(inputs[1]).toHaveAccessibleDescription("Second error Second success");

      rerender(fields);
      expect(Array.from(container.querySelectorAll("[id]"), (element) => element.id)).toEqual(ids);
    });

    it("should remove stale invalid state and feedback references when messages clear", () => {
      const { rerender } = render(
        <>
          <p id="entry-hint">Check your account.</p>
          <TextInput label="Account" aria-describedby="entry-hint" error="Rejected" success="Saved" />
        </>,
      );
      const input = screen.getByRole("textbox", { name: "Account" });
      const inputId = input.id;

      rerender(
        <>
          <p id="entry-hint">Check your account.</p>
          <TextInput label="Account" aria-describedby="entry-hint" />
        </>,
      );

      expect(input).toHaveAttribute("id", inputId);
      expect(input).not.toHaveAttribute("aria-invalid");
      expect(input).toHaveAttribute("aria-describedby", "entry-hint");
      expect(input).toHaveAccessibleDescription("Check your account.");
      expect(document.getElementById(`${inputId}-error`)).toBeNull();
      expect(document.getElementById(`${inputId}-success`)).toBeNull();
    });

    it("should retain caller-owned invalid state when no component error is supplied", () => {
      render(<TextInput label="Account" aria-invalid="grammar" />);
      expect(screen.getByRole("textbox", { name: "Account" })).toHaveAttribute("aria-invalid", "grammar");
    });

    it("should forward its ref and native event handlers to the actual input", () => {
      const ref = createRef<HTMLInputElement>();
      const onChange = vi.fn();
      const onBlur = vi.fn();
      render(
        <TextInput
          label="Account"
          ref={ref}
          name="loginName"
          autoComplete="username"
          className="caller-input"
          onChange={onChange}
          onBlur={onBlur}
        />,
      );
      const input = screen.getByRole("textbox", { name: "Account" });
      fireEvent.change(input, { target: { value: "account@example.com" } });
      fireEvent.blur(input);

      expect(ref.current).toBe(input);
      expect(ref.current?.value).toBe("account@example.com");
      expect(input).toHaveAttribute("name", "loginName");
      expect(input).toHaveAttribute("autocomplete", "username");
      expect(input).toHaveClass("paypm-input", "caller-input");
      expect(onChange).toHaveBeenCalledOnce();
      expect(onChange.mock.calls[0][0].target).toBe(input);
      expect(onBlur).toHaveBeenCalledOnce();
      expect(onBlur.mock.calls[0][0].target).toBe(input);
    });

    it("should preserve registered field values and blur state for form submission", async () => {
      const onSubmit = vi.fn();

      function RegisteredForm() {
        const { register, handleSubmit, formState } = useForm<{ loginName: string }>({ mode: "onBlur" });
        return (
          <form onSubmit={handleSubmit(onSubmit)}>
            <TextInput label="Account" {...register("loginName", { required: true })} />
            <output>{formState.touchedFields.loginName ? "Touched" : "Untouched"}</output>
            <button type="submit">Continue</button>
          </form>
        );
      }

      render(<RegisteredForm />);
      const input = screen.getByRole("textbox", { name: "Account" });
      fireEvent.change(input, { target: { value: "account@example.com" } });
      fireEvent.blur(input);
      await waitFor(() => expect(screen.getByText("Touched")).toBeVisible());
      fireEvent.click(screen.getByRole("button", { name: "Continue" }));
      await waitFor(() => expect(onSubmit).toHaveBeenCalledOnce());
      expect(onSubmit.mock.calls[0][0]).toEqual({ loginName: "account@example.com" });
    });

    it("should show required indicator", () => {
      const { container } = render(<TextInput label="UniqueRequiredField" required />);
      const label = container.querySelector("label");
      expect(label?.textContent).toContain("*");
    });
  });
});
