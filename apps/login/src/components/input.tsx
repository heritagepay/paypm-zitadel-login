"use client";

import { getComponentRoundness } from "@/lib/theme";
import { CheckCircleIcon } from "@heroicons/react/24/solid";
import { clsx } from "clsx";
import { ChangeEvent, DetailedHTMLProps, forwardRef, InputHTMLAttributes, ReactNode, useId } from "react";

export type TextInputProps = DetailedHTMLProps<InputHTMLAttributes<HTMLInputElement>, HTMLInputElement> & {
  label: string;
  suffix?: string;
  placeholder?: string;
  defaultValue?: string;
  error?: string | ReactNode;
  success?: string | ReactNode;
  disabled?: boolean;
  onChange?: (value: ChangeEvent<HTMLInputElement>) => void;
  onBlur?: (value: ChangeEvent<HTMLInputElement>) => void;
  roundness?: string; // Allow override via props
};

const styles = (error: boolean, disabled: boolean, roundnessClasses: string = "rounded-md") =>
  clsx(
    "paypm-input",
    {
      "h-[48px] mb-[2px] p-[7px] bg-input-light-background dark:bg-input-dark-background transition-colors duration-300 grow": true,
      "border border-input-light-border dark:border-input-dark-border hover:border-black hover:dark:border-white focus:border-primary-light-500 focus:dark:border-primary-dark-500": true,
      "focus:outline-none focus:ring-0 text-base text-black dark:text-white placeholder:italic placeholder-gray-700 dark:placeholder-gray-700": true,
      "border border-warn-light-500 dark:border-warn-dark-500 hover:border-warn-light-500 hover:dark:border-warn-dark-500 focus:border-warn-light-500 focus:dark:border-warn-dark-500":
        error,
      "pointer-events-none text-gray-500 dark:text-gray-800 border border-input-light-border dark:border-input-dark-border hover:border-light-hoverborder hover:dark:border-hoverborder cursor-default":
        disabled,
    },
    roundnessClasses, // Apply the full roundness classes directly
  );

// Helper function to get default input roundness from theme
function getDefaultInputRoundness(): string {
  return getComponentRoundness("input");
}

export const TextInput = forwardRef<HTMLInputElement, TextInputProps>(
  (
    {
      label,
      placeholder,
      defaultValue,
      suffix,
      required = false,
      error,
      disabled,
      success,
      onChange,
      onBlur,
      roundness,
      id,
      className,
      "aria-describedby": describedBy,
      "aria-invalid": invalid,
      ...props
    },
    ref,
  ) => {
    // Use theme-based roundness if not explicitly provided
    const actualRoundness = roundness || getDefaultInputRoundness();
    const generatedId = useId();
    const inputId = id ?? `paypm-input-${generatedId}`;
    const errorId = `${inputId}-error`;
    const successId = `${inputId}-success`;
    const hasError = !!error;
    const hasSuccess = !!success;
    const feedbackIds = [describedBy, hasError && errorId, hasSuccess && successId].filter(Boolean).join(" ") || undefined;

    return (
      <div className="paypm-field text-12px text-input-light-label dark:text-input-dark-label relative flex flex-col">
        <label
          htmlFor={inputId}
          className={clsx("paypm-field-label mb-1 leading-3", {
            "text-warn-light-500 dark:text-warn-dark-500": hasError,
          })}
        >
          {label} {required && <span aria-hidden="true">*</span>}
        </label>
        <div className="paypm-input-row">
          <input
            suppressHydrationWarning
            ref={ref}
            id={inputId}
            className={clsx(styles(hasError, !!disabled, actualRoundness), className)}
            defaultValue={defaultValue}
            required={required}
            disabled={disabled}
            placeholder={placeholder}
            autoComplete={props.autoComplete ?? "off"}
            onChange={(e) => onChange && onChange(e)}
            onBlur={(e) => onBlur && onBlur(e)}
            {...props}
            aria-invalid={hasError ? true : invalid}
            aria-describedby={feedbackIds}
          />

          {suffix && <span className="paypm-input-suffix">@{suffix}</span>}
        </div>

        <div
          id={hasError ? errorId : undefined}
          className="paypm-field-feedback leading-14.5px h-14.5px text-12px text-warn-light-500 dark:text-warn-dark-500 flex flex-row items-center"
        >
          <span>{error ? error : " "}</span>
        </div>

        {hasSuccess && (
          <div id={successId} className="paypm-field-feedback text-md mt-1 flex flex-row items-center text-green-500">
            <CheckCircleIcon aria-hidden="true" className="h-4 w-4" />
            <span className="ml-1">{success}</span>
          </div>
        )}
      </div>
    );
  },
);
