import { retireLegacyRecoveryProfile } from "@/lib/legacy-recovery-retirement";
export const runtime = "nodejs";
export const dynamic = "force-dynamic";
export async function POST(request: Request) {
  return retireLegacyRecoveryProfile(request);
}
