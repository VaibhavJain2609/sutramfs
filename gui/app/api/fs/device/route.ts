import { NextRequest, NextResponse } from "next/server";
import { execFile, spawn } from "node:child_process";
import { accessSync, constants, openSync, readSync, closeSync } from "node:fs";
import { promisify } from "node:util";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const execFileP = promisify(execFile);

function pipe(cmd: string, args: string[], stdin: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const child = spawn(cmd, args);
    const out: Buffer[] = [];
    const err: Buffer[] = [];
    child.stdout.on("data", (d) => out.push(d));
    child.stderr.on("data", (d) => err.push(d));
    child.on("error", reject);
    child.on("close", (code) =>
      code === 0
        ? resolve(Buffer.concat(out).toString("utf8"))
        : reject(new Error(Buffer.concat(err).toString("utf8") || `${cmd} exited ${code}`)),
    );
    child.stdin.end(stdin);
  });
}

// Device diagnostics for /dev/* paths — wraps `diskutil info -plist` (macOS)
// plus a readability probe, to support a write-blocker-style posture check
// before a single byte is read by the parser layer.
export async function GET(req: NextRequest) {
  const p = req.nextUrl.searchParams.get("path");
  if (!p || !p.startsWith("/dev/")) {
    return NextResponse.json({ error: "expected a /dev/ path" }, { status: 400 });
  }

  // diskutil wants the block node (disk*), not the raw node (rdisk*).
  const base = p.split("/").pop()!;
  const blockBase = base.startsWith("r") ? base.slice(1) : base;
  const blockNode = `/dev/${blockBase}`;
  const rawNode = `/dev/r${blockBase}`;

  // Readability probe: actually open + read 1 byte as *this* process.
  // (If sutramfsd runs under sudo separately, its access may differ — the
  // daemon reports its own errors on mount/detect regardless.)
  let readable = false;
  try {
    accessSync(p, constants.R_OK);
    const fd = openSync(p, "r");
    try {
      readable = readSync(fd, Buffer.alloc(1), 0, 1, 0) === 1;
    } finally {
      closeSync(fd);
    }
  } catch {
    readable = false;
  }

  let info: Record<string, any> = {};
  let diskutilErr: string | null = null;
  try {
    const { stdout } = await execFileP("diskutil", ["info", "-plist", blockNode], {
      timeout: 10_000,
    });
    const json = await pipe("plutil", ["-convert", "json", "-o", "-", "-"], stdout);
    info = JSON.parse(json);
  } catch (e: any) {
    diskutilErr = e.message;
  }

  return NextResponse.json({
    path: p,
    block_node: blockNode,
    raw_node: rawNode,
    is_raw: base.startsWith("r"),
    readable,
    diskutil_error: diskutilErr,
    device: {
      node: info.DeviceNode ?? blockNode,
      identifier: info.DeviceIdentifier ?? blockBase,
      bus: info.BusProtocol ?? info.Protocol ?? "",
      size: info.IOKitSize ?? info.Size ?? info.TotalSize ?? 0,
      block_size: info.DeviceBlockSize ?? 0,
      media_type: info.MediaType ?? "",
      registry_name: info.IORegistryEntryName ?? "",
      internal: !!info.Internal,
      ejectable: !!info.Ejectable,
      mounted: !!info.MountPoint,
      mount_point: info.MountPoint ?? "",
      fs_name: info.FilesystemName ?? "",
      fs_visible: info.FilesystemUserVisibleName ?? "",
      volume_name: info.VolumeName ?? "",
      writable: !!info.Writable,
      writable_media: !!info.WritableMedia,
      writable_volume: !!info.WritableVolume,
      smart: info.SMARTStatus ?? "",
      device_tree: info.DeviceTreePath ?? "",
    },
  });
}
