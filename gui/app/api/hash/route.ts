import { NextRequest } from "next/server";
import { createHash, getHashes } from "node:crypto";
import { getClient } from "@/lib/grpc";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const ALGS = ["md5", "sha1", "sha256", "sha512", "blake2b512"] as const;

// GET /api/hash?handle=..&path=..
// Streams recoverable file bytes through every supported digest in one pass.
// `bytes` reports how much was actually hashed (partial for damaged files).
export async function GET(req: NextRequest) {
  const p = req.nextUrl.searchParams;
  const handle = p.get("handle");
  const fpath = p.get("path");
  if (!handle || fpath === null)
    return Response.json({ error: "handle and path required" }, { status: 400 });

  const grpcReq = {
    handle_id: handle,
    path: fpath,
    offset: 0,
    len: 0,
    chunk_size: 256 * 1024,
  };

  try {
    const client = await getClient();
    const call = client.read(grpcReq);
    const supported = new Set(getHashes());
    const hashers = ALGS.filter((a) => supported.has(a)).map(
      (a) => [a, createHash(a)] as const,
    );
    let bytes = 0;

    await new Promise<void>((resolve, reject) => {
      call.on("data", (chunk: any) => {
        const d: Buffer = Buffer.isBuffer(chunk.data)
          ? chunk.data
          : Buffer.from(chunk.data);
        bytes += d.length;
        for (const [, h] of hashers) h.update(d);
      });
      call.on("end", () => resolve());
      call.on("error", (err: any) =>
        reject(new Error(err.details || err.message)),
      );
    });

    const digests: Record<string, string> = {};
    for (const [name, h] of hashers) digests[name] = h.digest("hex");

    return Response.json(
      { bytes, ...digests },
      { headers: { "cache-control": "no-store" } },
    );
  } catch (e: any) {
    return Response.json({ error: e.message }, { status: 500 });
  }
}
