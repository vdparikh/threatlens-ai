/**
 * Parse static security_signals from the Go engine and match them to LLM threats
 * for merging, cross-links in reports, and chained-finding synthesis.
 */
import type { ThreatOutput } from "./schemas.js";

export type SecuritySignalRow = {
  id: string;
  path: string;
  severity: string;
  summary: string;
};

export const CHAINED_THREAT_ID = "CHAIN-TLS-META";
export const CHAIN_HARDCODED_CREDS_ID = "CHAIN-HARDCODED-CREDS";

export function isSyntheticChainThreatId(id: string): boolean {
  return (
    id === CHAINED_THREAT_ID ||
    id === CHAIN_HARDCODED_CREDS_ID ||
    id.startsWith("CHAIN-")
  );
}

export function parseSecuritySignalsFromModel(model: Record<string, unknown>): SecuritySignalRow[] {
  if (!Array.isArray(model.security_signals)) {
    return [];
  }
  const out: SecuritySignalRow[] = [];
  for (const raw of model.security_signals) {
    if (raw === null || typeof raw !== "object") {
      continue;
    }
    const r = raw as Record<string, unknown>;
    const id = String(r.id ?? "").trim();
    const path = String(r.path ?? "").trim();
    const severity = String(r.severity ?? "").trim() || "LOW";
    const summary = String(r.summary ?? "").trim();
    if (!id && !path) {
      continue;
    }
    out.push({ id: id || "signal", path, severity, summary: summary || "—" });
  }
  return out;
}

/**
 * True when a threat's related path refers to the same file as the signal (suffix-safe).
 * Basename-only match is intentionally omitted so unrelated `main.go` files do not collide.
 */
export function pathsMatch(repoPath: string, signalPath: string): boolean {
  const norm = (p: string) => p.trim().replace(/\\/g, "/").replace(/^\.\//, "");
  const a = norm(repoPath);
  const b = norm(signalPath);
  if (a.length === 0 || b.length === 0) {
    return false;
  }
  if (a === b) {
    return true;
  }
  if (a.endsWith("/" + b) || b.endsWith("/" + a)) {
    return true;
  }
  return false;
}

/** Signals whose `path` overlaps a path in `related_paths` — only these are merged into the card. */
export function signalsMatchingThreat(
  threat: { title: string; description: string; related_paths: string[] },
  signals: SecuritySignalRow[],
): SecuritySignalRow[] {
  const seen = new Set<string>();
  const out: SecuritySignalRow[] = [];
  const paths = threat.related_paths.map((p) => p.trim()).filter(Boolean);
  for (const sig of signals) {
    if (!paths.some((p) => pathsMatch(p, sig.path))) {
      continue;
    }
    if (!seen.has(sig.id)) {
      seen.add(sig.id);
      out.push(sig);
    }
  }
  return out;
}

export function severityRank(s: string): number {
  const u = s.toUpperCase();
  if (u === "CRITICAL") {
    return 0;
  }
  if (u === "HIGH") {
    return 1;
  }
  if (u === "MEDIUM") {
    return 2;
  }
  if (u === "LOW") {
    return 3;
  }
  return 4;
}

type Sev = ThreatOutput["threats"][number]["severity"];

function coerceSeverity(s: string): Sev {
  const u = s.toUpperCase();
  if (u === "CRITICAL" || u === "HIGH" || u === "MEDIUM" || u === "LOW") {
    return u;
  }
  return "LOW";
}

/** More severe wins (uses severityRank: lower rank = worse). */
export function maxSeverity(a: string, b: string): Sev {
  return severityRank(a) <= severityRank(b) ? coerceSeverity(a) : coerceSeverity(b);
}

export function maxSeverityOf(list: string[]): Sev {
  return list.reduce<Sev>((acc, s) => maxSeverity(acc, s), "LOW");
}

export function sortSignalsBySeverity(signals: SecuritySignalRow[]): SecuritySignalRow[] {
  return [...signals].sort((a, b) => severityRank(a.severity) - severityRank(b.severity));
}

type ThreatRow = ThreatOutput["threats"][number];

/** When TLS can be off and metadata identity fallback exists — single HIGH chained finding. */
export function synthesizeChainedTlsMetadataThreat(signals: SecuritySignalRow[]): ThreatRow | null {
  const tls = signals.find((s) => s.id === "tls-optional-config");
  const meta = signals.find((s) => s.id === "grpc-metadata-identity-fallback");
  if (!tls || !meta) {
    return null;
  }

  const paths = Array.from(
    new Set(
      [tls.path, meta.path].filter((p) => typeof p === "string" && p.trim().length > 0),
    ),
  );

  const tlsBit = tls.summary.trim();
  const metaBit = meta.summary.trim();

  return {
    id: CHAINED_THREAT_ID,
    stride: "S",
    title: "Chained: optional TLS with header-trusted gRPC identity",
    description: [
      "**Attack chain (from static signals):** If TLS/mTLS is not enforced, clients may connect without presenting a client certificate identity. The service then accepts identity from gRPC metadata (`user` / `x-user`) when certificate identity is absent.",
      "",
      `- **tls-optional-config** (\`${tls.path}\`): ${tlsBit}`,
      `- **grpc-metadata-identity-fallback** (\`${meta.path}\`): ${metaBit}`,
      "",
      "An attacker who can reach the service over the network may send crafted metadata and impersonate arbitrary principals unless transport and identity policy close this gap.",
    ].join("\n"),
    severity: "HIGH",
    related_paths: paths,
    immediate_actions: [
      "Enforce TLS/mTLS in all non-dev deployment profiles; reject plaintext gRPC where identity matters.",
      "Remove or strictly gate metadata-based identity fallback; require authenticated client identity via mTLS or equivalent.",
      "Add integration tests that assert failed/missing client cert does not yield a trusted identity from headers alone.",
    ],
    mitigations: [
      "Treat metadata identity as untrusted unless bound to a verified transport identity.",
      "Use peer certificate fields (SPIFFE/URI SAN) or signed tokens minted only after mTLS.",
    ],
    verification: "Review `grpc_server.go` (or equivalent) interceptor order: verify no header identity is honored without verified peer identity when production TLS flags are on.",
    references: [],
    attack_scenario:
      "Attacker on the network connects without client cert (or via plaintext if TLS is off), sends `user`/`x-user` metadata, and is accepted as that principal.",
    prerequisites: "Network access to the gRPC endpoint; TLS not strictly required or client cert identity not wired through.",
    cwe_candidates: ["CWE-290", "CWE-306"],
    detection_and_monitoring:
      "Alert on connections without client cert in mTLS mode; log metadata-derived identity with peer cert fingerprint correlation.",
    likelihood_rationale: "Common misconfiguration when TLS is optional for local dev and accidentally shipped.",
    impact_rationale: "Full logical identity impersonation against authorization decisions keyed on gRPC identity.",
  };
}

/** default-hsm-pin + default-db-dsn in bootstrap: insider / supply-chain exposure of HSM and DB credentials. */
export function synthesizeChainedHardcodedCredsThreat(signals: SecuritySignalRow[]): ThreatRow | null {
  const hsm = signals.find((s) => s.id === "default-hsm-pin");
  const db = signals.find((s) => s.id === "default-db-dsn-with-password");
  if (!hsm || !db) {
    return null;
  }
  const paths = Array.from(
    new Set([hsm.path, db.path].filter((p) => typeof p === "string" && p.trim().length > 0)),
  );
  const sameFile = pathsMatch(hsm.path, db.path);
  const where = sameFile
    ? `Both static findings reference the same file (\`${hsm.path}\`).`
    : `Signals span \`${hsm.path}\` and \`${db.path}\` — both are material to bootstrap trust.`;

  return {
    id: CHAIN_HARDCODED_CREDS_ID,
    stride: "E",
    title: "Chained: hardcoded HSM and database bootstrap credentials",
    description: [
      "**Attack chain (from static signals):** Default or inlined HSM PIN and database DSN credentials live in source-backed bootstrap configuration.",
      "",
      `- **default-hsm-pin** (\`${hsm.path}\`, ${hsm.severity}): ${hsm.summary.trim()}`,
      `- **default-db-dsn-with-password** (\`${db.path}\`, ${db.severity}): ${db.summary.trim()}`,
      "",
      where,
      "",
      "Anyone with repository or build-artifact access can obtain **both** cryptographic operations material (HSM) and **online data store** access — insider threat, compromised CI, or leaked image equals broad compromise without touching production ingress.",
    ].join("\n"),
    severity: maxSeverity("HIGH", maxSeverity(hsm.severity, db.severity)),
    related_paths: paths,
    immediate_actions: [
      "Remove default PINs and inline DSN secrets from committed config; source from a secret manager or sealed env injection only in non-dev.",
      "Rotate any credentials that ever appeared in git history; treat repo as partially exposed.",
      "Split bootstrap: HSM trust material must not ship beside DB passwords in the same artifact without deliberate break-glass controls.",
    ],
    mitigations: [
      "Require separate principal paths for HSM vs DB with distinct secret lifecycle and access reviews.",
      "Block merges that reintroduce default crypto or DSN password patterns in CI.",
    ],
    verification: "Grep/build pipeline fails on `default-hsm-pin` / `default-db-dsn-with-password` patterns; confirm production profiles inject secrets only at runtime.",
    references: [],
    attack_scenario:
      "Malicious insider or attacker with clone/build access uses committed defaults to operate the HSM and connect to production-like data stores.",
    prerequisites: "Read access to the repo, artifact, or developer workstation with the bootstrap bundle.",
    cwe_candidates: ["CWE-798", "CWE-321"],
    detection_and_monitoring:
      "Secret scanning in CI; alerts on use of bootstrap env vars in non-local environments.",
    likelihood_rationale: "Committed defaults are common in internal services; impact is high when both crypto and DB are affected.",
    impact_rationale: "Combined exposure undermines confidentiality and integrity of keys and stored tenant/policy data.",
  };
}

/** Ordered list of synthetic chain rows to prepend (stable order). */
export function synthesizeAllChainThreats(signals: SecuritySignalRow[]): ThreatRow[] {
  const out: ThreatRow[] = [];
  const t = synthesizeChainedTlsMetadataThreat(signals);
  if (t) {
    out.push(t);
  }
  const c = synthesizeChainedHardcodedCredsThreat(signals);
  if (c) {
    out.push(c);
  }
  return out;
}
