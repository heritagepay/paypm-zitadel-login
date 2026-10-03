import { consumeOperationsAction } from "@/lib/operations-action-service";
export const runtime = "nodejs";
export const dynamic = "force-dynamic";
export async function POST(request: Request) {
  return consumeOperationsAction(request, true, "kyc-grant");
}
