import fs from "node:fs";
import path from "node:path";

// gui/ sits at the repo root alongside the sutram-* crates.
export const REPO_ROOT = path.resolve(process.cwd(), "..");

export const PROTO_PATH = path.join(
  REPO_ROOT,
  "sutram-fsd",
  "proto",
  "sutramfs.proto",
);

function firstExisting(candidates: string[]): string | null {
  for (const c of candidates) {
    try {
      if (c && fs.existsSync(c)) return c;
    } catch {
      /* ignore */
    }
  }
  return null;
}

export function sutramfsBin(): string {
  if (process.env.SUTRAMFS_BIN) return process.env.SUTRAMFS_BIN;
  return (
    firstExisting([
      path.join(REPO_ROOT, "sutram-cli", "target", "release", "sutramfs"),
      path.join(REPO_ROOT, "sutram-cli", "target", "debug", "sutramfs"),
      path.join(REPO_ROOT, "target", "release", "sutramfs"),
      path.join(REPO_ROOT, "target", "debug", "sutramfs"),
    ]) ?? "sutramfs" // fall back to PATH
  );
}

export function sutramfsdBin(): string | null {
  if (process.env.SUTRAMFSD_BIN) return process.env.SUTRAMFSD_BIN;
  return firstExisting([
    path.join(REPO_ROOT, "sutram-fsd", "target", "release", "sutramfsd"),
    path.join(REPO_ROOT, "sutram-fsd", "target", "debug", "sutramfsd"),
  ]);
}

export const DAEMON_ADDR = process.env.SUTRAMFSD_ADDR ?? "127.0.0.1:50051";
