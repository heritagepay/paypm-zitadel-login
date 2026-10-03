import { readCurrentWorkforceAdmission } from "@/lib/workforce-admission-reader";
export const runtime = "nodejs";
export const dynamic = "force-dynamic";
export async function POST(request: Request) {
  return readCurrentWorkforceAdmission(request);
}
