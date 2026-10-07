import { NextRequest, NextResponse } from "next/server";
import { runCli } from "@/lib/cli";
import { parseCarve } from "@/lib/parse";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET(req: NextRequest) {
  const p = req.nextUrl.searchParams;
  const image = p.get("image");
  if (!image) return NextResponse.json({ error: "image required" }, { status: 400 });

  const args = ["carve", image];
  if (p.get("partition")) args.push("-p", p.get("partition")!);
  if (p.get("type")) args.push("-t", p.get("type")!);
  if (p.get("unallocated") === "1") {
    args.push("--unallocated");
  } else {
    if (p.get("offset")) args.push("--offset", p.get("offset")!);
    if (p.get("len")) args.push("--len", p.get("len")!);
  }
  if (p.get("align")) args.push("--align", p.get("align")!);

  try {
    const r = await runCli(args, 10 * 60_000); // carving scans bytes — allow 10 min
    return NextResponse.json({
      hits: parseCarve(r.stdout),
      log: r.stderr.trim(),
      code: r.code,
    });
  } catch (e: any) {
    return NextResponse.json({ error: e.message }, { status: 500 });
  }
}
