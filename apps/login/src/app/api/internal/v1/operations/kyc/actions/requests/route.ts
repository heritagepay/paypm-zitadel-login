import { startOperationsAction } from "@/lib/operations-action-service";
export const runtime = "nodejs";
export const dynamic = "force-dynamic";
export async function POST(request: Request) {
  return startOperationsAction(request, "kyc");
}
