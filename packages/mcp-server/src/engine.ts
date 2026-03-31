import { existsSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

const __dirname = dirname(fileURLToPath(import.meta.url));

function repoRootFromPackage(): string {
  return join(__dirname, "..", "..", "..");
}

export function runAnalyzeCodebase(root: string): unknown {
  const absRoot = resolve(root);
  const repoRoot = repoRootFromPackage();
  const engineDir = join(repoRoot, "engine");
  const bin = process.env.THREATLENS_ENGINE_BIN;
  let cmd: string;
  const args: string[] = [];
  if (bin && existsSync(bin)) {
    cmd = bin;
    args.push(absRoot);
  } else {
    cmd = process.env.THREATLENS_GO ?? "go";
    args.push("run", "./cmd/threatlens-engine", absRoot);
  }
  const result = spawnSync(cmd, args, {
    cwd: engineDir,
    encoding: "utf-8",
    env: { ...process.env },
    maxBuffer: 50 * 1024 * 1024,
  });
  if (result.error) {
    throw result.error;
  }
  if (result.status !== 0) {
    const err = (result.stderr || result.stdout || "").trim();
    throw new Error(err || `engine exited with code ${result.status}`);
  }
  return JSON.parse(result.stdout) as unknown;
}
