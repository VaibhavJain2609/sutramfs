import { NextRequest, NextResponse } from "next/server";
import { getClient, unary } from "@/lib/grpc";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function POST(req: NextRequest) {
  try {
    const { id } = await req.json();
    if (!id) return NextResponse.json({ error: "id required" }, { status: 400 });
    const client = await getClient();
    const res = await unary<any>(client, "unmount", { id });
    return NextResponse.json({ unmounted: !!res.unmounted });
  } catch (e: any) {
    return NextResponse.json({ error: e.message }, { status: 500 });
  }
}
