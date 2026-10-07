import * as grpc from "@grpc/grpc-js";
import * as protoLoader from "@grpc/proto-loader";
import { spawn, type ChildProcess } from "node:child_process";
import { DAEMON_ADDR, PROTO_PATH, REPO_ROOT, sutramfsdBin } from "./paths";

// Survive Next.js dev-server module reloads: the daemon child process and the
// client promise live on globalThis so we never spawn two daemons.
const g = globalThis as unknown as {
  __sutramClient?: Promise<any>;
  __sutramDaemon?: ChildProcess;
  __sutramDaemonLog?: string[];
};

function log(line: string) {
  const buf = (g.__sutramDaemonLog ??= []);
  buf.push(`[${new Date().toISOString()}] ${line}`);
  if (buf.length > 200) buf.splice(0, buf.length - 200);
}

export function daemonLog(): string[] {
  return g.__sutramDaemonLog ?? [];
}

function makeClient(): any {
  const def = protoLoader.loadSync(PROTO_PATH, {
    keepCase: true,
    longs: String,
    enums: String,
    defaults: true,
    oneofs: true,
  });
  const pkg = grpc.loadPackageDefinition(def) as any;
  return new pkg.sutramfs.v1.SutramFs(
    DAEMON_ADDR,
    grpc.credentials.createInsecure(),
    { "grpc.max_receive_message_length": 64 * 1024 * 1024 },
  );
}

function waitReady(client: any, ms: number): Promise<void> {
  return new Promise((resolve, reject) => {
    const deadline = new Date(Date.now() + ms);
    client.waitForReady(deadline, (err: Error | null) =>
      err ? reject(err) : resolve(),
    );
  });
}

async function spawnDaemon(): Promise<void> {
  if (g.__sutramDaemon && g.__sutramDaemon.exitCode === null) return;

  const bin = sutramfsdBin();
  let child: ChildProcess;
  if (bin) {
    log(`spawning ${bin} --listen ${DAEMON_ADDR}`);
    child = spawn(bin, ["--listen", DAEMON_ADDR], { stdio: ["ignore", "pipe", "pipe"] });
  } else {
    // No built binary — build+run via cargo (slow first time).
    log(`no sutramfsd binary found; cargo run in ${REPO_ROOT}/sutram-fsd`);
    child = spawn(
      "cargo",
      ["run", "--manifest-path", `${REPO_ROOT}/sutram-fsd/Cargo.toml`, "--bin", "sutramfsd", "--", "--listen", DAEMON_ADDR],
      { stdio: ["ignore", "pipe", "pipe"] },
    );
  }
  g.__sutramDaemon = child;
  child.stdout?.on("data", (d) => log(String(d).trimEnd()));
  child.stderr?.on("data", (d) => log(String(d).trimEnd()));
  child.on("exit", (code, sig) =>
    log(`sutramfsd exited code=${code} sig=${sig}`),
  );
}

/** Returns a connected gRPC client, starting sutramfsd if needed. */
export async function getClient(): Promise<any> {
  if (!g.__sutramClient) {
    g.__sutramClient = (async () => {
      const client = makeClient();
      try {
        await waitReady(client, 1500);
      } catch {
        await spawnDaemon();
        // cargo-build fallback can take a while; a plain binary is fast.
        const budget = sutramfsdBin() ? 15_000 : 300_000;
        const deadline = Date.now() + budget;
        for (;;) {
          try {
            await waitReady(client, 2000);
            break;
          } catch (e) {
            if (Date.now() > deadline) {
              throw new Error(
                `sutramfsd did not become ready at ${DAEMON_ADDR}: ${e}. ` +
                  `Recent daemon output: ${daemonLog().slice(-8).join(" | ") || "(none)"}`,
              );
            }
          }
        }
      }
      return client;
    })();
    // If connection failed permanently, reset so the next request retries.
    g.__sutramClient.catch(() => {
      g.__sutramClient = undefined;
    });
  }
  return g.__sutramClient;
}

/** uint64 fields come back as strings (longs:String); convert for JSON+math. */
export function u64(v: unknown): number {
  if (v === null || v === undefined || v === "") return 0;
  return typeof v === "number" ? v : Number(v);
}

export function unary<T>(client: any, method: string, req: object): Promise<T> {
  return new Promise((resolve, reject) => {
    client[method](req, (err: any, res: T) =>
      err ? reject(new Error(err.details || err.message)) : resolve(res),
    );
  });
}
