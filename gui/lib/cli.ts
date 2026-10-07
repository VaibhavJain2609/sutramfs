import { spawn } from "node:child_process";
import { sutramfsBin } from "./paths";

export interface CliResult {
  stdout: string;
  stderr: string;
  code: number;
}

/** Run `sutramfs <args>` and capture output. Times out after `timeoutMs`. */
export function runCli(args: string[], timeoutMs = 120_000): Promise<CliResult> {
  return new Promise((resolve, reject) => {
    const child = spawn(sutramfsBin(), args, {
      stdio: ["ignore", "pipe", "pipe"],
    });
    const out: Buffer[] = [];
    const err: Buffer[] = [];
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      reject(new Error(`sutramfs ${args[0]} timed out after ${timeoutMs}ms`));
    }, timeoutMs);
    child.stdout.on("data", (d) => out.push(d));
    child.stderr.on("data", (d) => err.push(d));
    child.on("error", (e) => {
      clearTimeout(timer);
      reject(
        new Error(
          `failed to run sutramfs (${sutramfsBin()}): ${e.message}. ` +
            `Build it with 'cd sutram-cli && cargo build --release' or set SUTRAMFS_BIN.`,
        ),
      );
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      resolve({
        stdout: Buffer.concat(out).toString("utf8"),
        stderr: Buffer.concat(err).toString("utf8"),
        code: code ?? -1,
      });
    });
  });
}

export function requireOk(r: CliResult): CliResult {
  if (r.code !== 0) {
    throw new Error(r.stderr.trim() || `sutramfs exited with code ${r.code}`);
  }
  return r;
}
