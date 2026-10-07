import { NextRequest, NextResponse } from "next/server";
import { requireOk, runCli } from "@/lib/cli";
import { parseParts } from "@/lib/parse";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET(req: NextRequest) {
  const image = req.nextUrl.searchParams.get("image");
  if (!image) return NextResponse.json({ error: "image required" }, { status: 400 });
  try {
    const r = requireOk(await runCli(["parts", image]));
    return NextResponse.json({ partitions: parseParts(r.stdout), raw: r.stdout });
  } catch (e: any) {
    return NextResponse.json({ error: e.message }, { status: 500 });
  }
}
