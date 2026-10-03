import { readOperationsAdmission } from "@/lib/operations-admission-reader";
export const runtime = "nodejs";
export const dynamic = "force-dynamic";
export async function POST(request: Request) {
  return readOperationsAdmission(request);
}
