import { NextRequest, NextResponse } from "next/server";
import { readdir, stat } from "node:fs/promises";
import { homedir } from "node:os";
import path from "node:path";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

// Directory listing so the GUI can browse the *local* filesystem for disk
// images. Local-only tool — this intentionally exposes local paths.
export async function GET(req: NextRequest) {
  const dir = req.nextUrl.searchParams.get("path") || homedir();
  try {
    const names = await readdir(dir);
    const entries = await Promise.all(
      names
        .filter((n) => !n.startsWith("."))
        .slice(0, 2000)
        .map(async (name) => {
          const full = path.join(dir, name);
          try {
            const s = await stat(full);
            return {
              name,
              path: full,
              dir: s.isDirectory(),
              size: s.isDirectory() ? 0 : s.size,
              mtime: s.mtimeMs,
            };
          } catch {
            return null;
          }
        }),
    );
    const clean = entries
      .filter((e): e is NonNullable<typeof e> => e !== null)
      .sort((a, b) => Number(b.dir) - Number(a.dir) || a.name.localeCompare(b.name));
    return NextResponse.json({ path: path.resolve(dir), parent: path.dirname(path.resolve(dir)), entries: clean });
  } catch (e: any) {
    return NextResponse.json({ error: e.message }, { status: 500 });
  }
}
