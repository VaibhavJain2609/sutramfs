import { NextRequest } from "next/server";
import { spawn } from "node:child_process";
import { sutramfsBin } from "@/lib/paths";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

// Streams `sutramfs remnants` JSONL output straight through (plus stderr as
// __log lines) so the UI can show progress on multi-GB scans.
export async function GET(req: NextRequest) {
  const p = req.nextUrl.searchParams;
  const image = p.get("image");
  if (!image) return Response.json({ error: "image required" }, { status: 400 });

  const args = ["remnants", image];
  if (p.get("partition")) args.push("-p", p.get("partition")!);
  if (p.get("offset")) args.push("--offset", p.get("offset")!);
  if (p.get("len")) args.push("--len", p.get("len")!);
  if (p.get("sector_size")) args.push("--sector-size", p.get("sector_size")!);
  if (p.get("rec_size")) args.push("--rec-size", p.get("rec_size")!);
  if (p.get("indx_size")) args.push("--indx-size", p.get("indx_size")!);
  if (p.get("aligned_only") === "1") args.push("--aligned-only");
  if (p.get("exclude_live_mft") === "1") args.push("--exclude-live-mft");

  const child = spawn(sutramfsBin(), args, { stdio: ["ignore", "pipe", "pipe"] });
  const encoder = new TextEncoder();
  const decoder = new TextDecoder();

  const stream = new ReadableStream({
    start(controller) {
      let outBuf = "";
      let errBuf = "";
      const flush = (buf: string, isErr: boolean) => {
        const lines = buf.split("\n");
        const rest = lines.pop() ?? "";
        for (const line of lines) {
          if (!line.trim()) continue;
          controller.enqueue(
            encoder.encode(
              isErr ? JSON.stringify({ __log: line }) + "\n" : line + "\n",
            ),
          );
        }
        return rest;
      };
      child.stdout.on("data", (d) => {
        outBuf = flush(outBuf + decoder.decode(d, { stream: true }), false);
      });
      child.stderr.on("data", (d) => {
        errBuf = flush(errBuf + decoder.decode(d, { stream: true }), true);
      });
      child.on("error", (e) => {
        controller.enqueue(
          encoder.encode(JSON.stringify({ __error: e.message }) + "\n"),
        );
        controller.close();
      });
      child.on("close", (code) => {
        if (outBuf.trim())
          controller.enqueue(encoder.encode(outBuf.trim() + "\n"));
        if (errBuf.trim())
          controller.enqueue(
            encoder.encode(JSON.stringify({ __log: errBuf.trim() }) + "\n"),
          );
        controller.enqueue(
          encoder.encode(JSON.stringify({ __done: true, code }) + "\n"),
        );
        controller.close();
      });
    },
    cancel() {
      child.kill("SIGKILL");
    },
  });

  return new Response(stream, {
    headers: {
      "content-type": "application/x-ndjson",
      "cache-control": "no-store",
    },
  });
}
