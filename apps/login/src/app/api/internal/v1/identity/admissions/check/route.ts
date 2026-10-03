import { readIdentityAdmission } from "@/lib/identity-admission-reader";
export const runtime = "nodejs";
export const dynamic = "force-dynamic";
export async function POST(request: Request) {
  return readIdentityAdmission(request);
}
