import { NextRequest } from "next/server";
import { getClient } from "@/lib/grpc";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

// GET /api/read?handle=..&path=..&offset=..&len=..[&preview=1][&download=1]
// Streams recoverable file bytes. preview=1 caps at 64 KiB for hex/text panes.
export async function GET(req: NextRequest) {
  const p = req.nextUrl.searchParams;
  const handle = p.get("handle");
  const fpath = p.get("path");
  if (!handle || fpath === null)
    return Response.json({ error: "handle and path required" }, { status: 400 });

  const preview = p.get("preview") === "1";
  const len = Number(p.get("len") ?? 0);
  const grpcReq = {
    handle_id: handle,
    path: fpath,
    offset: Number(p.get("offset") ?? 0),
    len: preview ? Math.min(len || 64 * 1024, 64 * 1024) : len,
    chunk_size: 256 * 1024,
  };

  try {
    const client = await getClient();
    const call = client.read(grpcReq);

    const stream = new ReadableStream({
      start(controller) {
        call.on("data", (chunk: any) => {
          try {
            const data: Buffer = Buffer.isBuffer(chunk.data)
              ? chunk.data
              : Buffer.from(chunk.data);
            controller.enqueue(new Uint8Array(data));
          } catch {
            /* closed */
          }
        });
        call.on("end", () => {
          try {
            controller.close();
          } catch {
            /* closed */
          }
        });
        call.on("error", (err: any) => {
          controller.error(new Error(err.details || err.message));
        });
      },
      cancel() {
        call.cancel();
      },
    });

    const name = fpath.split("/").pop() || "file";
    const headers: Record<string, string> = {
      "content-type": "application/octet-stream",
      "cache-control": "no-store",
    };
    if (p.get("download") === "1") {
      headers["content-disposition"] =
        `attachment; filename="${name.replace(/"/g, "_")}"`;
    }
    return new Response(stream, { headers });
  } catch (e: any) {
    return Response.json({ error: e.message }, { status: 500 });
  }
}
