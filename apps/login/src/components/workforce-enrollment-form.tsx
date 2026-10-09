"use client";

import {
  cancelReviewedWorkforceEnrollment,
  completeReviewedWorkforceEnrollment,
  inspectReviewedWorkforceEnrollmentEntry,
  replaceReviewedWorkforceProfileEmail,
  resendReviewedWorkforceEnrollment,
  returnToReviewedWorkforceApplication,
  startReviewedWorkforceEnrollment,
  verifyReviewedWorkforceEnrollment,
  verifyReviewedWorkforceProfileEmail,
} from "@/lib/server/workforce-enrollment";
import {
  ArrowRightIcon,
  CheckCircleIcon,
  ClockIcon,
  EnvelopeIcon,
  InformationCircleIcon,
} from "@heroicons/react/24/outline";
import { useTranslations } from "next-intl";
import { useRouter } from "next/navigation";
import { FormEvent, useEffect, useRef, useState } from "react";
import styles from "./workforce-enrollment-form.module.css";

type Entry = Awaited<ReturnType<typeof inspectReviewedWorkforceEnrollmentEntry>>;
type Phase =
  | "ready_to_start"
  | "oidc_request_required"
  | "profile_email_verification_pending"
  | "profile_email_verified"
  | "otp_pending"
  | "identity_link_pending"
  | "enrollment_completed_access_pending"
  | "cancelled";
type View = {
  state: Phase;
  email?: string;
  requestId?: string;
  challengeId?: string;
  expiresAt?: string;
  resendAt?: string;
  returnApplication?: "identity" | "operations" | "super-admin";
  profileDelivery?: {
    state: "pending" | "accepted" | "unknown";
    attemptId: string;
    resendAt: string;
    codeExpiresAt: string;
  };
};
type Action = "start" | "profile" | "verify" | "resend" | "complete" | "cancel" | "inspect" | "replaceProfile" | "return";
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const request = /^oidc_[A-Za-z0-9_-]{1,480}$/;
const phases: Phase[] = [
  "ready_to_start",
  "oidc_request_required",
  "profile_email_verification_pending",
  "profile_email_verified",
  "otp_pending",
  "identity_link_pending",
  "enrollment_completed_access_pending",
  "cancelled",
];
const formattedCode = (value: string) => value.replace(/[ -]/g, "");

/** Only the public, server-derived projection enters local presentation state. */
function projection(value: unknown, previous?: View): View | undefined {
  if (!value || typeof value !== "object" || "error" in value) return undefined;
  const fields = value as Record<string, unknown>;
  if (!phases.includes(fields.state as Phase)) return undefined;
  const state = fields.state as Phase;
  const returnApplication = fields.returnApplication ?? previous?.returnApplication;
  if (returnApplication !== undefined && !["identity", "operations", "super-admin"].includes(returnApplication as string))
    return undefined;
  const email = fields.email ?? previous?.email;
  const requestId = fields.requestId ?? previous?.requestId;
  // A historical completion exposes only state and original request binding.
  if (state !== "cancelled" && state !== "enrollment_completed_access_pending" &&
      (typeof email !== "string" || !email.length || email.length > 320)) return undefined;
  if (
    state !== "oidc_request_required" &&
    state !== "cancelled" &&
    (typeof requestId !== "string" || !request.test(requestId))
  )
    return undefined;
  const result: View = {
    state,
    email: typeof email === "string" ? email : undefined,
    requestId: typeof requestId === "string" ? requestId : undefined,
    returnApplication: returnApplication as View["returnApplication"],
  };
  if (state === "profile_email_verification_pending") {
    if (fields.expiresAt !== undefined) {
      if (typeof fields.expiresAt !== "string" || !Number.isFinite(Date.parse(fields.expiresAt))) return undefined;
      result.expiresAt = fields.expiresAt;
    }
    if (fields.profileDelivery !== undefined) {
      const d = fields.profileDelivery as Record<string, unknown>;
      if (
        !d ||
        typeof d !== "object" ||
        !["pending", "accepted", "unknown"].includes(d.state as string) ||
        typeof d.attemptId !== "string" ||
        !uuid.test(d.attemptId) ||
        typeof d.resendAt !== "string" ||
        !Number.isFinite(Date.parse(d.resendAt)) ||
        typeof d.codeExpiresAt !== "string" ||
        !Number.isFinite(Date.parse(d.codeExpiresAt))
      )
        return undefined;
      result.profileDelivery = {
        state: d.state as "pending" | "accepted" | "unknown",
        attemptId: d.attemptId,
        resendAt: d.resendAt,
        codeExpiresAt: d.codeExpiresAt,
      };
      result.resendAt = d.resendAt;
    }
  }
  if (state === "otp_pending" || state === "identity_link_pending") {
    if (
      typeof fields.challengeId !== "string" ||
      !uuid.test(fields.challengeId) ||
      typeof fields.expiresAt !== "string" ||
      !Number.isFinite(Date.parse(fields.expiresAt)) ||
      typeof fields.resendAt !== "string" ||
      !Number.isFinite(Date.parse(fields.resendAt))
    )
      return undefined;
    result.challengeId = fields.challengeId;
    result.expiresAt = fields.expiresAt;
    result.resendAt = fields.resendAt;
  }
  return result;
}

export function WorkforceEnrollmentForm({ operationId, entry }: { operationId: string; entry: Entry }) {
  const t = useTranslations("workforceEnrollment");
  const router = useRouter();
  const [view, setView] = useState<View | undefined>(() => projection(entry));
  const [code, setCode] = useState("");
  const [unconfirmed, setUnconfirmed] = useState(!projection(entry));
  const [profileSendUnknown, setProfileSendUnknown] = useState(false);
  const [busy, setBusy] = useState<Action | undefined>();
  const [now, setNow] = useState(Date.now);
  const epoch = useRef(0);
  const mounted = useRef(true);
  const inFlight = useRef<Action | undefined>(undefined);
  const keys = useRef(new Map<string, string>());
  const stagedProfileCode = useRef<string | undefined>(undefined);
  const input = useRef<HTMLInputElement>(null);
  const heading = useRef<HTMLHeadingElement>(null);
  const validOperation = uuid.test(operationId);
  const state = view?.state;
  const profile = state === "profile_email_verification_pending";
  const otp = state === "otp_pending";
  const linking = state === "identity_link_pending";
  const completed = state === "enrollment_completed_access_pending";
  const terminal = completed || state === "cancelled";
  const expired = (otp || profile || linking) && !!view?.expiresAt && now >= Date.parse(view.expiresAt);
  const recovery = (expired || state === "oidc_request_required") && !!view?.returnApplication;
  const remaining = view?.resendAt ? Math.max(0, Math.ceil((Date.parse(view.resendAt) - now) / 1000)) : 0;
  const currentCode = formattedCode(code);
  const codeValid = profile ? /^[A-Z0-9]{6}$/.test(currentCode) : /^\d{8}$/.test(currentCode);
  const canCancel =
    validOperation &&
    !!view?.requestId &&
    !terminal &&
    !expired &&
    state !== "ready_to_start" &&
    state !== "oidc_request_required" &&
    busy !== "cancel" &&
    !unconfirmed;

  useEffect(() => {
    mounted.current = true;
    const operationKeys = keys.current;
    const hash = window.location.hash;
    if (hash) {
      // Remove the secret-bearing fragment before parsing; never navigate with it.
      window.history.replaceState(window.history.state, "", `${window.location.pathname}${window.location.search}`);
      if (hash.length <= 200 && validOperation && (state === "ready_to_start" || profile)) {
        const values = new URLSearchParams(hash.slice(1));
        const value = values.get("code");
        if (values.size === 1 && values.getAll("code").length === 1 && value && /^[A-Z0-9]{6}$/.test(value)) {
          if (profile) setCode(value);
          else stagedProfileCode.current = value;
        }
      }
    }
    return () => {
      mounted.current = false;
      epoch.current += 1;
      operationKeys.clear();
      stagedProfileCode.current = undefined;
    };
    // Initial server entry owns fragment eligibility; locale refresh cannot initiate a flow.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    if (!otp && !profile && !linking) return;
    const timer = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, [otp, profile, linking]);

  useEffect(() => {
    if ((profile || otp) && !recovery) input.current?.focus();
    else heading.current?.focus();
  }, [state, view?.challengeId, profile, otp, recovery]);

  function intent(key: string) {
    let value = keys.current.get(key);
    if (!value) {
      value = crypto.randomUUID();
      keys.current.set(key, value);
    }
    return value;
  }

  async function run(action: Action, command: () => Promise<unknown>) {
    if (!validOperation || inFlight.current === "cancel" || (inFlight.current && action !== "cancel")) return;
    const current = ++epoch.current;
    inFlight.current = action;
    setBusy(action);
    try {
      const result = await command();
      if (!mounted.current || epoch.current !== current) return;
      if (
        action === "return" &&
        result &&
        typeof result === "object" &&
        "redirect" in result &&
        typeof result.redirect === "string"
      ) {
        const url = new URL(result.redirect);
        if (url.protocol !== "https:" || url.username || url.password || url.search || url.hash)
          throw new Error("Invalid return");
        router.push(url.href);
        return;
      }
      // A status readback owns current return availability; it must withdraw a removed registration.
      const next = projection(result, action === "inspect" && view ? { ...view, returnApplication: undefined } : view);
      if (!next) {
        if (action === "replaceProfile" && profile) setProfileSendUnknown(true);
        else setUnconfirmed(true);
        return;
      }
      const unchanged = action === "inspect" && next.state === view?.state && next.challengeId === view?.challengeId;
      // Accept the server projection against the current local clock, including after a long profile step.
      setNow(Date.now());
      setView(next);
      setUnconfirmed(false);
      setProfileSendUnknown(false);
      const retainedProfile =
        profile &&
        next.state === "profile_email_verification_pending" &&
        (action === "inspect" || (action === "replaceProfile" && next.profileDelivery?.state !== "accepted"));
      if (!unchanged && !retainedProfile) {
        setCode(next.state === "profile_email_verification_pending" ? (stagedProfileCode.current ?? "") : "");
        stagedProfileCode.current = undefined;
      }
      if (next.state === "cancelled" || next.state === "enrollment_completed_access_pending") {
        keys.current.clear();
        stagedProfileCode.current = undefined;
      }
    } catch {
      if (mounted.current && epoch.current === current) {
        if (action === "replaceProfile" && profile) setProfileSendUnknown(true);
        else setUnconfirmed(true);
      }
    } finally {
      if (mounted.current && epoch.current === current) {
        inFlight.current = undefined;
        setBusy(undefined);
      }
    }
  }

  function start() {
    if (!view?.requestId || unconfirmed) return;
    void run("start", () =>
      startReviewedWorkforceEnrollment({ operationId, requestId: view.requestId!, operationKey: intent("start") }),
    );
  }
  function submit(event: FormEvent) {
    event.preventDefault();
    if (!codeValid || busy || unconfirmed || expired) return;
    if (profile)
      void run("profile", () =>
        verifyReviewedWorkforceProfileEmail({
          operationId,
          operationKey: intent(`profile:${currentCode}`),
          code: currentCode,
        }),
      );
    else if (otp && view?.challengeId)
      void run("verify", async () => {
        const result = await verifyReviewedWorkforceEnrollment({
          operationId,
          challengeId: view.challengeId!,
          operationKey: intent(`verify:${view.challengeId}:${currentCode}`),
          code: currentCode,
        });
        // This reply has no timer fields; retain only this original challenge's known bounds.
        return result && "state" in result && result.state === "identity_link_pending"
          ? { ...result, challengeId: view.challengeId, expiresAt: view.expiresAt, resendAt: view.resendAt }
          : result;
      });
  }
  function check() {
    void run("inspect", () => inspectReviewedWorkforceEnrollmentEntry({ operationId, requestId: view?.requestId }));
  }
  function cancel() {
    if (!canCancel) return;
    stagedProfileCode.current = undefined;
    setCode("");
    void run("cancel", () => cancelReviewedWorkforceEnrollment({ operationId, operationKey: intent("cancel") }));
  }

  const proofEmail =
    !recovery && (state === "profile_email_verified" || otp || state === "identity_link_pending" || completed);
  const proofSession = (linking && !expired) || completed;
  const title = completed
    ? "completeTitle"
    : state === "cancelled"
      ? "cancelledTitle"
      : linking
        ? expired
          ? "requestTitle"
          : "linkTitle"
        : otp
          ? "sessionTitle"
          : state === "profile_email_verified"
            ? "profileVerifiedTitle"
            : state === "ready_to_start"
              ? "readyTitle"
              : state === "oidc_request_required"
                ? "requestTitle"
                : profile
                  ? "profileTitle"
                  : "unavailableTitle";
  const body = completed
    ? "completeBody"
    : state === "cancelled"
      ? "cancelledBody"
      : linking
        ? expired
          ? "requestBody"
          : "linkBody"
        : otp
          ? "sessionBody"
          : state === "profile_email_verified"
            ? "profileVerifiedBody"
            : state === "ready_to_start"
              ? "readyBody"
              : state === "oidc_request_required"
                ? "requestBody"
                : profile
                  ? "profileBody"
                  : "unavailableBody";

  return (
    <div className={styles.surface}>
      <header className={styles.header}>
        <span className={styles.brand} aria-label="PayPM">
          Pay<span>PM</span>
        </span>
        <span className={styles.team}>{t("team")}</span>
      </header>
      <ol className={styles.steps} aria-label={t("progressLabel")}>
        <li className={proofEmail ? styles.verified : styles.active}>
          <div className={styles.stepLine} aria-hidden="true" />
          {t("stepEmail")}
        </li>
        <li className={proofSession ? styles.verified : otp ? styles.active : undefined}>
          <div className={styles.stepLine} aria-hidden="true" />
          {t("stepSession")}
        </li>
        <li className={completed ? styles.pending : undefined}>
          <div className={styles.stepLine} aria-hidden="true" />
          {completed ? t("accessPending") : t("stepAccess")}
        </li>
      </ol>
      <main className={`${styles.panel} ${recovery ? styles.recovery : ""}`} aria-busy={!!busy}>
        <div key={`${state}:${recovery}`} className={styles.transition}>
          <h1 ref={heading} tabIndex={-1} className={styles.heading}>
            {t(recovery ? "returnTitle" : title)}
          </h1>
          <p className={styles.body}>
            {recovery ? t("returnBody", { application: t(`applications.${view!.returnApplication}`) }) : t(body)}
          </p>
        </div>
        {view?.email && state !== "cancelled" && (
          <div className={styles.destination}>
            <EnvelopeIcon className={styles.icon} aria-hidden="true" />
            <div>
              <span className={styles.destinationLabel}>{t("destination")}</span>
              <span className={styles.email}>{view.email}</span>
              {proofEmail && <span className={styles.verifiedLabel}>{t("verifiedEmail")}</span>}
            </div>
          </div>
        )}
        {unconfirmed && (
          <p className={styles.status} role="alert">
            {t("unconfirmed")}
          </p>
        )}
        {profile && !unconfirmed && (profileSendUnknown || view?.profileDelivery?.state === "unknown") && (
          <p className={styles.status} role="status">
            {t("profileRequestUnknown")}
          </p>
        )}
        {profile && !unconfirmed && !profileSendUnknown && view?.profileDelivery?.state === "accepted" && (
          <p className={`${styles.destination} ${styles.verifiedLabel}`} role="status">
            {t("profileRequestAccepted")}
          </p>
        )}
        {expired && (
          <p className={styles.status} role="status">
            {t(recovery ? "returnExpired" : profile ? "profileRequestExpired" : "expired")}
          </p>
        )}
        {(profile || otp) && !recovery && (
          <form onSubmit={submit}>
            <label htmlFor="workforce-enrollment-code" className={styles.label}>
              {t(profile ? "profileCodeLabel" : "sessionCodeLabel")}
            </label>
            <input
              id="workforce-enrollment-code"
              ref={input}
              className={styles.input}
              type="text"
              inputMode={profile ? "text" : "numeric"}
              autoComplete="one-time-code"
              autoCapitalize={profile ? "characters" : "off"}
              spellCheck={false}
              maxLength={32}
              value={code}
              onChange={(event) => setCode(event.target.value)}
              disabled={!!busy || unconfirmed || expired}
              aria-describedby="workforce-enrollment-code-help"
            />
            <p id="workforce-enrollment-code-help" className={styles.helper}>
              {t(profile ? "profileHelper" : "sessionHelper")}
            </p>
            {profile && view?.profileDelivery && (
              <>
                <button
                  type="button"
                  className={`${styles.button} ${styles.resend}`}
                  disabled={remaining > 0 || !!busy || unconfirmed || expired || profileSendUnknown}
                  onClick={() => {
                    if (view?.profileDelivery)
                      void run("replaceProfile", () =>
                        replaceReviewedWorkforceProfileEmail({
                          operationId,
                          attemptId: view.profileDelivery!.attemptId,
                          operationKey: intent(`replaceProfile:${view.profileDelivery!.attemptId}`),
                        }),
                      );
                  }}
                >
                  {busy === "replaceProfile"
                    ? t("profileRequesting")
                    : remaining > 0
                      ? t("profileReplacementCountdown", {
                          remaining: `${Math.floor(remaining / 60)
                            .toString()
                            .padStart(2, "0")}:${(remaining % 60).toString().padStart(2, "0")}`,
                        })
                      : t("profileReplace")}
                </button>
                {remaining === 0 && <p className={styles.helper}>{t("profileReplacementConsequence")}</p>}
              </>
            )}
            <button
              type="submit"
              className={`${styles.button} ${styles.primary}`}
              disabled={!codeValid || !!busy || unconfirmed || expired}
            >
              {t(busy === "profile" || busy === "verify" ? "verifying" : profile ? "profileSubmit" : "sessionSubmit")}
              <ArrowRightIcon className={styles.icon} aria-hidden="true" />
            </button>
          </form>
        )}
        {otp && !recovery && (
          <button
            type="button"
            className={`${styles.button} ${styles.resend}`}
            disabled={remaining > 0 || !!busy || unconfirmed || expired}
            onClick={() => {
              if (view?.challengeId)
                void run("resend", () =>
                  resendReviewedWorkforceEnrollment({
                    operationId,
                    challengeId: view.challengeId!,
                    operationKey: intent(`resend:${view.challengeId}`),
                  }),
                );
            }}
          >
            {remaining > 0
              ? t("resendCountdown", {
                  remaining: `${Math.floor(remaining / 60)
                    .toString()
                    .padStart(2, "0")}:${(remaining % 60).toString().padStart(2, "0")}`,
                })
              : t("resend")}
          </button>
        )}
        {(state === "ready_to_start" || state === "profile_email_verified") && (
          <button
            type="button"
            className={`${styles.button} ${styles.primary}`}
            onClick={start}
            disabled={!!busy || unconfirmed}
          >
            {t(busy === "start" ? "starting" : state === "profile_email_verified" ? "sendSessionCode" : "start")}
            <ArrowRightIcon className={styles.icon} aria-hidden="true" />
          </button>
        )}
        {linking && !recovery && (
          <button
            type="button"
            className={`${styles.button} ${styles.primary}`}
            disabled={!!busy || unconfirmed || expired}
            onClick={() => {
              // Background tabs may throttle the interval: check the wall clock at dispatch too.
              const clickedAt = Date.now();
              if (!view?.expiresAt || clickedAt >= Date.parse(view.expiresAt)) {
                setNow(clickedAt);
                return;
              }
              if (view?.challengeId)
                void run("complete", () =>
                  completeReviewedWorkforceEnrollment({
                    operationId,
                    challengeId: view.challengeId!,
                    operationKey: intent(`complete:${view.challengeId}`),
                  }),
                );
            }}
          >
            {t(busy === "complete" ? "completing" : "complete")}
          </button>
        )}
        {recovery && validOperation && (
          <>
            <button
              type="button"
              className={`${styles.button} ${styles.primary}`}
              disabled={!!busy}
              onClick={() => void run("return", () => returnToReviewedWorkforceApplication({ operationId }))}
            >
              {busy === "return"
                ? t("returning")
                : t("return", { application: t(`shortApplications.${view!.returnApplication}`) })}
              <ArrowRightIcon className={styles.icon} aria-hidden="true" />
            </button>
            <p className={styles.helper} role={busy === "return" ? "status" : undefined}>
              {t(busy === "return" ? "returning" : "returnHint")}
            </p>
          </>
        )}
        {(unconfirmed || profileSendUnknown || expired || recovery || state === "identity_link_pending") &&
          validOperation && (
            <button type="button" className={`${styles.button} ${styles.secondary}`} disabled={!!busy} onClick={check}>
              {t(busy === "inspect" ? "checking" : "check")}
            </button>
          )}
        {canCancel && (
          <button type="button" className={`${styles.button} ${styles.secondary}`} onClick={cancel}>
            {t("cancel")}
          </button>
        )}
        {busy === "cancel" && (
          <p role="status" className={styles.helper}>
            {t("cancelling")}
          </p>
        )}
        {completed && (
          <>
            <ul className={styles.proofs}>
              <li>
                <CheckCircleIcon className={`${styles.icon} ${styles.confirmed}`} aria-hidden="true" />
                {t("emailProof")}
              </li>
              <li>
                <CheckCircleIcon className={`${styles.icon} ${styles.confirmed}`} aria-hidden="true" />
                {t("sessionProof")}
              </li>
              <li>
                <ClockIcon className={`${styles.icon} ${styles.waiting}`} aria-hidden="true" />
                {t("accessPending")}
              </li>
            </ul>
            <div className={styles.notice}>
              <InformationCircleIcon className={styles.icon} aria-hidden="true" />
              <span>{t("accessBody")}</span>
            </div>
            <p className={styles.body}>{t("closeHint")}</p>
          </>
        )}
      </main>
      <footer className={styles.footer}>{t("footer")}</footer>
    </div>
  );
}
