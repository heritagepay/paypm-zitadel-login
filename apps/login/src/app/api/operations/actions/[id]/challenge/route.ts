import { readOperationsPublicChallenge } from "@/lib/operations-action-service";
export const runtime = "nodejs";
export const dynamic = "force-dynamic";
export async function GET(request: Request, context: { params: Promise<{ id: string }> }) {
  return readOperationsPublicChallenge(
    request,
    (await context.params).id,
    request.headers.get("X-PayPM-Ceremony-Capability") ?? "",
  );
}
