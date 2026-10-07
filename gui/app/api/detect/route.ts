import { NextRequest, NextResponse } from "next/server";
import { getClient, unary } from "@/lib/grpc";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function POST(req: NextRequest) {
  try {
    const { path } = await req.json();
    if (!path) return NextResponse.json({ error: "path required" }, { status: 400 });
    const client = await getClient();
    const res = await unary<any>(client, "detect", {
      path,
      offset: 0,
      length: 0,
    });
    return NextResponse.json({ results: res.results ?? [] });
  } catch (e: any) {
    return NextResponse.json({ error: e.message }, { status: 500 });
  }
}
