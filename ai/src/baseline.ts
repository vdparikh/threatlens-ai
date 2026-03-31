import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";

import {
  isSyntheticChainThreatId,
  parseSecuritySignalsFromModel,
  signalsMatchingThreat,
  type SecuritySignalRow,
} from "./signalGrounding.js";
import type { ThreatOutput } from "./schemas.js";

export const BASELINE_VERSION = 1;
export const BASELINE_RELATIVE_PATH = join(".threatlensai", "baseline.json");

export type BaselineFindingEntry = {
  key: string;
  id: string;
  title: string;
  stride: string;
  severity: string;
};

export type BaselineFile = {
  version: number;
  updatedAt: string;
  findings: BaselineFindingEntry[];
};

export type FindingDeltaStatus = "NEW" | "UNCHANGED";

export type ReportDelta = {
  /** True if a baseline file existed before this run. */
  hadBaseline: boolean;
  /** Previous snapshot timestamp (from baseline file), if any. */
  previousUpdatedAt: string | null;
  /** Per stable key: NEW or UNCHANGED. */
  statusByKey: Record<string, FindingDeltaStatus>;
  /** Findings present last run but absent now (by stable key). */
  resolved: BaselineFindingEntry[];
};

export function baselinePathForProject(projectRoot: string): string {
  return join(projectRoot, BASELINE_RELATIVE_PATH);
}

function shortHash(s: string): string {
  return createHash("sha256").update(s, "utf8").digest("hex").slice(0, 16);
}

/**
 * Stable identity for delta tracking across runs (ignores renumbered ids like S1 vs S2).
 * Chain rows use their synthetic id; grounded rows prefer signal id(s); else a content hash.
 */
export function findingKeyForThreat(
  t: ThreatOutput["threats"][number],
  signals: SecuritySignalRow[],
): string {
  if (isSyntheticChainThreatId(t.id)) {
    return `chain:${t.id}`;
  }
  const matched = signalsMatchingThreat(t, signals);
  if (matched.length === 1) {
    return `signal:${matched[0].id}`;
  }
  if (matched.length > 1) {
    return `signals:${matched.map((m) => m.id).sort().join("+")}`;
  }
  const paths = [...t.related_paths].map((p) => p.trim()).filter(Boolean).sort().join("|");
  const blob = `${t.stride}\n${t.title.trim()}\n${paths}`;
  return `ungrounded:${shortHash(blob)}`;
}

export function loadBaseline(projectRoot: string): BaselineFile | null {
  const p = baselinePathForProject(projectRoot);
  if (!existsSync(p)) {
    return null;
  }
  try {
    const raw = readFileSync(p, "utf-8");
    const parsed = JSON.parse(raw) as unknown;
    if (parsed === null || typeof parsed !== "object") {
      return null;
    }
    const o = parsed as Record<string, unknown>;
    if (o.version !== BASELINE_VERSION || !Array.isArray(o.findings)) {
      return null;
    }
    return {
      version: BASELINE_VERSION,
      updatedAt: typeof o.updatedAt === "string" ? o.updatedAt : "",
      findings: (o.findings as unknown[])
        .filter((x) => x !== null && typeof x === "object")
        .map((x) => {
          const f = x as Record<string, unknown>;
          return {
            key: String(f.key ?? ""),
            id: String(f.id ?? ""),
            title: String(f.title ?? ""),
            stride: String(f.stride ?? ""),
            severity: String(f.severity ?? ""),
          };
        })
        .filter((f) => f.key.length > 0),
    };
  } catch {
    return null;
  }
}

export function buildBaselineSnapshot(
  threats: ThreatOutput,
  signals: SecuritySignalRow[],
): BaselineFile {
  const findings: BaselineFindingEntry[] = threats.threats.map((t) => ({
    key: findingKeyForThreat(t, signals),
    id: t.id,
    title: t.title,
    stride: t.stride,
    severity: t.severity,
  }));
  return {
    version: BASELINE_VERSION,
    updatedAt: new Date().toISOString(),
    findings,
  };
}

export function saveBaseline(projectRoot: string, snapshot: BaselineFile): void {
  const p = baselinePathForProject(projectRoot);
  mkdirSync(dirname(p), { recursive: true });
  writeFileSync(p, `${JSON.stringify(snapshot, null, 2)}\n`, "utf-8");
}

export function computeReportDelta(
  previous: BaselineFile | null,
  threats: ThreatOutput,
  signals: SecuritySignalRow[],
): ReportDelta {
  if (!previous || previous.findings.length === 0) {
    const statusByKey: Record<string, FindingDeltaStatus> = {};
    for (const t of threats.threats) {
      statusByKey[findingKeyForThreat(t, signals)] = "NEW";
    }
    return {
      hadBaseline: false,
      previousUpdatedAt: null,
      statusByKey,
      resolved: [],
    };
  }
  const prevByKey = new Map(previous.findings.map((f) => [f.key, f]));
  const currentKeys = new Set<string>();
  const statusByKey: Record<string, FindingDeltaStatus> = {};

  for (const t of threats.threats) {
    const key = findingKeyForThreat(t, signals);
    currentKeys.add(key);
    statusByKey[key] = prevByKey.has(key) ? "UNCHANGED" : "NEW";
  }

  const resolved: BaselineFindingEntry[] = [];
  for (const f of previous.findings) {
    if (!currentKeys.has(f.key)) {
      resolved.push({ ...f });
    }
  }

  return {
    hadBaseline: true,
    previousUpdatedAt: previous.updatedAt || null,
    statusByKey,
    resolved,
  };
}

export function reportDeltaFromModel(
  projectRoot: string,
  model: Record<string, unknown>,
  threats: ThreatOutput,
): { delta: ReportDelta; snapshot: BaselineFile } {
  const signals = parseSecuritySignalsFromModel(model);
  const previous = loadBaseline(projectRoot);
  const delta = computeReportDelta(previous, threats, signals);
  const snapshot = buildBaselineSnapshot(threats, signals);
  return { delta, snapshot };
}
