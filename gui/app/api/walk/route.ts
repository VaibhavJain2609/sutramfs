import { NextRequest } from "next/server";
import { convertEntry } from "@/lib/convert";
import { getClient } from "@/lib/grpc";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

// Streams NDJSON: one converted FsEntry per line, as the daemon emits them.
export async function GET(req: NextRequest) {
  const p = req.nextUrl.searchParams;
  const handle = p.get("handle");
  if (!handle) return Response.json({ error: "handle required" }, { status: 400 });

  const grpcReq = {
    handle_id: handle,
    status_filter: p.get("status") ?? "all",
    kind_filter: p.get("kind") ?? "all",
    path_prefix: p.get("prefix") ?? "",
    max_entries: Number(p.get("max") ?? 0),
  };

  try {
    const client = await getClient();
    const call = client.walk(grpcReq);
    const encoder = new TextEncoder();

    const stream = new ReadableStream({
      start(controller) {
        call.on("data", (entry: any) => {
          try {
            controller.enqueue(
              encoder.encode(JSON.stringify(convertEntry(entry)) + "\n"),
            );
          } catch {
            /* enqueue after close — ignore */
          }
        });
        call.on("end", () => {
          try {
            controller.close();
          } catch {
            /* already closed */
          }
        });
        call.on("error", (err: any) => {
          try {
            controller.enqueue(
              encoder.encode(
                JSON.stringify({ __error: err.details || err.message }) + "\n",
              ),
            );
            controller.close();
          } catch {
            /* closed */
          }
        });
      },
      cancel() {
        call.cancel();
      },
    });

    return new Response(stream, {
      headers: {
        "content-type": "application/x-ndjson",
        "cache-control": "no-store",
      },
    });
  } catch (e: any) {
    return Response.json({ error: e.message }, { status: 500 });
  }
}
