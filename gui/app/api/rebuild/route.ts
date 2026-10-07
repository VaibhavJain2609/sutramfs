import { NextRequest, NextResponse } from "next/server";
import { requireOk, runCli } from "@/lib/cli";
import { writeFile, mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

// POST /api/rebuild { image, partition?, offset?, len?, under?, remnantsJsonl? }
// Runs `sutramfs rebuild -o jsonl`. If remnantsJsonl is provided (output of a
// prior remnants scan), it's written to a temp file and passed via --remnants.
export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const { image, partition, offset, len, under, remnantsJsonl } = body;
    if (!image) return NextResponse.json({ error: "image required" }, { status: 400 });

    const args = ["rebuild", image, "-o", "jsonl"];
    if (partition !== undefined && partition !== null && partition !== "")
      args.push("-p", String(partition));
    if (offset) args.push("--offset", String(offset));
    if (len) args.push("--len", String(len));
    if (under) args.push("--under", String(under));

    if (remnantsJsonl) {
      const dir = await mkdtemp(path.join(tmpdir(), "sutram-remnants-"));
      const f = path.join(dir, "remnants.jsonl");
      await writeFile(f, remnantsJsonl, "utf8");
      args.push("--remnants", f);
    }

    const r = requireOk(await runCli(args, 10 * 60_000));
    const plan = r.stdout
      .split("\n")
      .filter((l) => l.trim())
      .map((l) => {
        try {
          return JSON.parse(l);
        } catch {
          return { raw: l };
        }
      });
    return NextResponse.json({ plan, log: r.stderr.trim() });
  } catch (e: any) {
    return NextResponse.json({ error: e.message }, { status: 500 });
  }
}
