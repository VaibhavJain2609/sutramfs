import { NextRequest, NextResponse } from "next/server";
import { convertInfo, convertMount } from "@/lib/convert";
import { getClient, unary } from "@/lib/grpc";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const { path, offset = 0, length = 0, parser = "" } = body;
    if (!path) return NextResponse.json({ error: "path required" }, { status: 400 });
    const client = await getClient();
    const handle = await unary<any>(client, "mount", {
      image: { path, offset, length },
      options: {
        strict: !!body.strict,
        check_magic: body.check_magic !== false,
        include_orphans: body.include_orphans !== false,
      },
      parser,
    });
    const info = await unary<any>(client, "info", { id: handle.id });
    return NextResponse.json({
      mount: { ...convertMount(handle), image: path, offset, length },
      info: convertInfo(info),
    });
  } catch (e: any) {
    return NextResponse.json({ error: e.message }, { status: 500 });
  }
}
