import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, relative, resolve } from "node:path";

export {
  buildThreatAssessmentHTML,
  buildThreatAssessmentMarkdown,
  type ThreatReportMeta,
  type ThreatReportOptions,
} from "@threatlensai/ai";

/**
 * Ensures the resolved file path stays under root (no path traversal).
 */
export function resolveSafeOutputPath(projectRoot: string, outputRelative: string): string {
  const rootAbs = resolve(projectRoot);
  const rel = outputRelative.trim().replace(/^[/\\]+/, "");
  if (!rel || rel.includes("..")) {
    throw new Error("output_path must be a relative path without ..");
  }
  const abs = resolve(rootAbs, rel);
  const check = relative(rootAbs, abs);
  if (check.startsWith("..") || check === "..") {
    throw new Error("resolved path escapes project root");
  }
  return abs;
}

export function writeThreatReportFile(absPath: string, contents: string): void {
  mkdirSync(dirname(absPath), { recursive: true });
  writeFileSync(absPath, contents, { encoding: "utf-8" });
}
