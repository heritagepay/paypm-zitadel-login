import { WorkforceEnrollmentForm } from "@/components/workforce-enrollment-form";
import { inspectReviewedWorkforceEnrollmentEntry } from "@/lib/server/workforce-enrollment";
import localFont from "next/font/local";

const workforceFont = localFont({
  src: [
    { path: "../../../assets/fonts/DMSans/DMSans-Regular.ttf", weight: "400", style: "normal" },
    { path: "../../../assets/fonts/DMSans/DMSans-Medium.ttf", weight: "500", style: "normal" },
    { path: "../../../assets/fonts/DMSans/DMSans-SemiBold.ttf", weight: "600", style: "normal" },
  ],
  display: "swap",
  fallback: ["Arial", "sans-serif"],
});

export default async function WorkforceEnrollmentPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const params = await searchParams;
  const operationId =
    typeof params.operationId === "string" &&
    /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(params.operationId)
      ? params.operationId
      : "";
  const requestId =
    typeof params.requestId === "string" && /^oidc_[A-Za-z0-9_-]{1,480}$/.test(params.requestId)
      ? params.requestId
      : undefined;
  const invalidRequest = params.requestId !== undefined && requestId === undefined;
  const entry =
    operationId && !invalidRequest
      ? await inspectReviewedWorkforceEnrollmentEntry({ operationId, requestId })
      : { error: "Reviewed workforce enrollment unavailable" };

  return (
    <section className={workforceFont.className}>
      <WorkforceEnrollmentForm key={`${operationId}:${requestId ?? ""}`} operationId={operationId} entry={entry} />
    </section>
  );
}
