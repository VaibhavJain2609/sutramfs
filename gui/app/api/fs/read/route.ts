import { NextRequest } from "next/server";
import { open } from "node:fs/promises";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

// Raw byte window from a server-local file — backs the hex inspector and
// carve-hit preview/download. Capped at 8 MiB per request.
export async function GET(req: NextRequest) {
  const p = req.nextUrl.searchParams;
  const fpath = p.get("path");
  if (!fpath) return Response.json({ error: "path required" }, { status: 400 });
  const offset = Math.max(0, Number(p.get("offset") ?? 0));
  const len = Math.min(Math.max(1, Number(p.get("len") ?? 4096)), 8 * 1024 * 1024);
  const download = p.get("download") === "1";

  try {
    const fh = await open(fpath, "r");
    try {
      const buf = Buffer.alloc(len);
      const { bytesRead } = await fh.read(buf, 0, len, offset);
      const headers: Record<string, string> = {
        "content-type": "application/octet-stream",
        "x-bytes-read": String(bytesRead),
        "cache-control": "no-store",
      };
      if (download) {
        headers["content-disposition"] =
          `attachment; filename="carved-${offset.toString(16)}.bin"`;
      }
      return new Response(new Uint8Array(buf.subarray(0, bytesRead)), { headers });
    } finally {
      await fh.close();
    }
  } catch (e: any) {
    return Response.json({ error: e.message }, { status: 500 });
  }
}
