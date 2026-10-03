"use client";

import { isSafeRedirectUri } from "@/lib/client-utils";
import {
  cancelWorkforceEmailOtp,
  resendWorkforceEmailOtp,
  startWorkforceEmailOtp,
  verifyWorkforceEmailOtp,
} from "@/lib/server/workforce-email";
import type { BrandingSettings } from "@zitadel/proto/zitadel/settings/v2/branding_settings_pb";
import { useTranslations } from "next-intl";
import { useRouter } from "next/navigation";
import { FormEvent, useCallback, useEffect, useRef, useState } from "react";
import { Alert } from "./alert";
import { Button, ButtonVariants } from "./button";
import { DynamicTheme } from "./dynamic-theme";
import { TextInput } from "./input";
import { Spinner } from "./spinner";

type Flow = {
  sessionId: string;
  challengeId: string;
  expiresAt: string;
  resendAt: string;
  authenticationClass: "workforce_limited";
};
function admittedFlow(value: unknown): value is Flow {
  if (!value || typeof value !== "object") return false;
  const flow = value as Flow;
  return (
    typeof flow.sessionId === "string" &&
    !!flow.sessionId &&
    typeof flow.challengeId === "string" &&
    !!flow.challengeId &&
    flow.authenticationClass === "workforce_limited" &&
    Number.isFinite(Date.parse(flow.expiresAt)) &&
    Number.isFinite(Date.parse(flow.resendAt))
  );
}

/** The browser holds bounded flow IDs only; credentials and admission stay server-side. */
export function WorkforceEmailForm({ requestId, branding }: { requestId: string; branding?: BrandingSettings }) {
  const t = useTranslations("workforceEmail"),
    router = useRouter();
  const [email, setEmail] = useState(""),
    [code, setCode] = useState(""),
    [flow, setFlow] = useState<Flow>(),
    [busy, setBusy] = useState(false),
    [cancelling, setCancelling] = useState(false),
    [error, setError] = useState(false),
    [now, setNow] = useState(0);
  const epoch = useRef(0),
    emailInput = useRef<HTMLInputElement>(null),
    codeInput = useRef<HTMLInputElement>(null);
  const invalidate = useCallback(() => {
    epoch.current++;
  }, []);
  const issuance = useRef<{ email: string; operationKey: string } | undefined>(undefined),
    verification = useRef<{ code: string; operationKey: string } | undefined>(undefined),
    resend = useRef<string | undefined>(undefined);
  useEffect(() => {
    setNow(Date.now());
    const timer = setInterval(() => setNow(Date.now()), 1000);
    return () => {
      clearInterval(timer);
      invalidate();
    };
  }, [invalidate]);
  useEffect(() => {
    if (flow) codeInput.current?.focus();
    else emailInput.current?.focus();
  }, [flow]);
  const seconds = flow ? Math.max(0, Math.ceil((Date.parse(flow.resendAt) - now) / 1000)) : 0;
  const expired = !!flow && now >= Date.parse(flow.expiresAt);
  const emailValid = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim());
  async function submit(event: FormEvent) {
    event.preventDefault();
    if (busy || cancelling || (flow ? expired || !/^\d{6}$/.test(code) : !emailValid)) return;
    const current = epoch.current;
    setBusy(true);
    setError(false);
    try {
      if (!flow) {
        const normalized = email.trim().toLowerCase();
        if (issuance.current?.email !== normalized)
          issuance.current = { email: normalized, operationKey: crypto.randomUUID() };
        const result = await startWorkforceEmailOtp({
          email: normalized,
          requestId,
          operationKey: issuance.current.operationKey,
        });
        if (current !== epoch.current) return;
        if (!admittedFlow(result)) throw new Error("unavailable");
        setFlow(result);
        setCode("");
        verification.current = undefined;
        resend.current = undefined;
        setNow(Date.now());
      } else {
        if (verification.current?.code !== code) verification.current = { code, operationKey: crypto.randomUUID() };
        const result = await verifyWorkforceEmailOtp({
          sessionId: flow.sessionId,
          requestId,
          code,
          operationKey: verification.current.operationKey,
        });
        if (current !== epoch.current) return;
        if (!result || !("redirect" in result) || !isSafeRedirectUri(result.redirect)) throw new Error("unavailable");
        router.push(result.redirect);
      }
    } catch {
      if (current === epoch.current) setError(true);
    } finally {
      if (current === epoch.current) setBusy(false);
    }
  }
  async function sendAgain() {
    if (!flow || busy || cancelling || seconds > 0) return;
    const current = epoch.current;
    resend.current ??= crypto.randomUUID();
    setBusy(true);
    setError(false);
    try {
      const result = await resendWorkforceEmailOtp({ sessionId: flow.sessionId, requestId, operationKey: resend.current });
      if (current !== epoch.current) return;
      if (!admittedFlow(result)) throw new Error("unavailable");
      setFlow(result);
      setCode("");
      verification.current = undefined;
      resend.current = undefined;
      setNow(Date.now());
      codeInput.current?.focus();
    } catch {
      if (current === epoch.current) setError(true);
    } finally {
      if (current === epoch.current) setBusy(false);
    }
  }
  async function cancel() {
    if (!flow || cancelling) return;
    invalidate();
    setCancelling(true);
    setError(false);
    try {
      const result = await cancelWorkforceEmailOtp({ requestId, sessionId: flow.sessionId });
      if (!("cancelled" in result) || !result.cancelled) throw new Error("unavailable");
      setFlow(undefined);
      setCode("");
      issuance.current = undefined;
      verification.current = undefined;
      resend.current = undefined;
    } catch {
      setError(true);
    } finally {
      setBusy(false);
      setCancelling(false);
    }
  }
  return (
    <DynamicTheme branding={branding}>
      <div className="flex flex-col space-y-4">
        <h1>{t(flow ? "codeTitle" : "title")}</h1>
        <p className="ztdl-p">{t(flow ? "codeDescription" : "description")}</p>
      </div>
      <form className="paypm-identifier-form w-full" onSubmit={submit} aria-busy={busy || cancelling}>
        {flow ? (
          <>
            <p className="ztdl-p mb-4">{email.trim()}</p>
            <TextInput
              ref={codeInput}
              label={t("codeLabel")}
              value={code}
              type="text"
              inputMode="numeric"
              autoComplete="one-time-code"
              autoCapitalize="none"
              spellCheck={false}
              maxLength={12}
              pattern="[0-9]{6}"
              required
              disabled={cancelling}
              onChange={(e) => {
                setCode(e.target.value.replace(/[\s-]/g, ""));
                setError(false);
              }}
              aria-describedby="workforce-code-timing"
            />
            <p id="workforce-code-timing" className="paypm-auth-return-guidance">
              {expired
                ? t("expired")
                : t("expires", { minutes: Math.max(1, Math.ceil((Date.parse(flow.expiresAt) - now) / 60000)) })}
            </p>
          </>
        ) : (
          <TextInput
            ref={emailInput}
            type="email"
            autoComplete="email"
            autoCapitalize="none"
            autoCorrect="off"
            spellCheck={false}
            label={t("emailLabel")}
            value={email}
            required
            disabled={busy}
            onChange={(e) => {
              setEmail(e.target.value);
              setError(false);
            }}
          />
        )}
        {error && (
          <div className="py-4">
            <Alert>{t("unavailable")}</Alert>
          </div>
        )}
        <div className="paypm-identifier-submit">
          <Button
            type="submit"
            className="w-full"
            variant={ButtonVariants.Primary}
            disabled={busy || cancelling || (flow ? expired || !/^\d{6}$/.test(code) : !emailValid)}
          >
            {busy && <Spinner className="mr-2 h-5 w-5" />}
            {t(flow ? "verify" : "send")}
          </Button>
        </div>
        {flow && (
          <>
            <div className="paypm-identifier-register">
              <Button
                className="w-full"
                variant={ButtonVariants.Secondary}
                disabled={busy || cancelling || expired || seconds > 0}
                onClick={sendAgain}
              >
                {seconds > 0 ? t("resendAfter", { seconds }) : t("resend")}
              </Button>
            </div>
            <div className="paypm-identifier-return">
              <Button className="w-full" variant={ButtonVariants.Secondary} disabled={cancelling} onClick={cancel}>
                {t("changeEmail")}
              </Button>
            </div>
            <details className="paypm-auth-return-guidance">
              <summary>{t("lostAccess")}</summary>
              <p className="mt-2">{t("recovery")}</p>
            </details>
          </>
        )}
        <p className="paypm-auth-return-guidance">{t("invitedOnly")}</p>
      </form>
    </DynamicTheme>
  );
}
