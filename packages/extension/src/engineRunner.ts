import { spawnSync } from "child_process";
import { existsSync } from "fs";
import { dirname, join } from "path";

/** Repo root of ThreatLensAI (…/packages/extension/out → three levels up). */
export function threatlensRepoRoot(extensionOutDir: string): string {
  return dirname(dirname(dirname(extensionOutDir)));
}

export function runThreatlensEngine(repoRoot: string, workspaceRoot: string): string {
  const engineDir = join(repoRoot, "engine");
  const bin = process.env.THREATLENS_ENGINE_BIN;
  let cmd: string;
  const args: string[] = [];
  if (bin && existsSync(bin)) {
    cmd = bin;
    args.push(workspaceRoot);
  } else {
    cmd = process.env.THREATLENS_GO ?? "go";
    args.push("run", "./cmd/threatlens-engine", workspaceRoot);
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
    throw new Error((result.stderr || result.stdout || "").trim() || `exit ${result.status}`);
  }
  return result.stdout;
}
