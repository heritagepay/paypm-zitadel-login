import { readCurrentWorkforceEnrollment } from "@/lib/workforce-enrollment-reader";
export const runtime = "nodejs";
export const dynamic = "force-dynamic";
export async function POST(request: Request) {
  return readCurrentWorkforceEnrollment(request);
}
