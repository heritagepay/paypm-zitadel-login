import { readOperationsAction } from "@/lib/operations-action-service";
export const runtime = "nodejs";
export const dynamic = "force-dynamic";
export async function POST(request: Request, context: { params: Promise<{ id: string }> }) {
  return readOperationsAction(request, (await context.params).id, "kyc");
}
