import { NextResponse } from "next/server";
import { daemonLog, getClient } from "@/lib/grpc";
import { DAEMON_ADDR, sutramfsBin, sutramfsdBin } from "@/lib/paths";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET() {
  let daemon = "unknown";
  try {
    await getClient();
    daemon = "connected";
  } catch (e: any) {
    daemon = `error: ${e.message}`;
  }
  return NextResponse.json({
    daemon,
    addr: DAEMON_ADDR,
    sutramfs: sutramfsBin(),
    sutramfsd: sutramfsdBin(),
    log: daemonLog().slice(-20),
  });
}
