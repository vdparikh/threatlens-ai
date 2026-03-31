import test from "node:test";
import assert from "node:assert/strict";

import {
  buildBaselineSnapshot,
  computeReportDelta,
  findingKeyForThreat,
} from "./baseline.js";
import type { ThreatOutput } from "./schemas.js";
import type { SecuritySignalRow } from "./signalGrounding.js";

const signals: SecuritySignalRow[] = [
  { id: "grpc-reflection-enabled", path: "hsmaas/server.go", severity: "LOW", summary: "r" },
  { id: "tls-optional-config", path: "a.go", severity: "MEDIUM", summary: "t" },
  { id: "grpc-metadata-identity-fallback", path: "b.go", severity: "MEDIUM", summary: "m" },
];

test("findingKeyForThreat uses chain id for synthetic chains", () => {
  const t = {
    id: "CHAIN-TLS-META",
    stride: "S" as const,
    title: "x",
    description: "d",
    severity: "HIGH" as const,
    related_paths: ["a.go"],
    immediate_actions: [],
    mitigations: [],
    verification: "",
    references: [],
    attack_scenario: "",
    prerequisites: "",
    cwe_candidates: [],
    detection_and_monitoring: "",
    likelihood_rationale: "",
    impact_rationale: "",
  };
  assert.equal(findingKeyForThreat(t, signals), "chain:CHAIN-TLS-META");
});

test("findingKeyForThreat uses signal id when exactly one path overlap", () => {
  const t = {
    id: "I1",
    stride: "I" as const,
    title: "Reflection",
    description: "d",
    severity: "LOW" as const,
    related_paths: ["hsmaas/server.go"],
    immediate_actions: [],
    mitigations: [],
    verification: "",
    references: [],
    attack_scenario: "",
    prerequisites: "",
    cwe_candidates: [],
    detection_and_monitoring: "",
    likelihood_rationale: "",
    impact_rationale: "",
  };
  assert.equal(findingKeyForThreat(t, signals), "signal:grpc-reflection-enabled");
});

test("computeReportDelta marks new and resolved", () => {
  const prev = {
    version: 1 as const,
    updatedAt: "t0",
    findings: [
      {
        key: "signal:grpc-reflection-enabled",
        id: "I1",
        title: "Old",
        stride: "I",
        severity: "LOW",
      },
      {
        key: "chain:CHAIN-TLS-META",
        id: "CHAIN-TLS-META",
        title: "Chain",
        stride: "S",
        severity: "HIGH",
      },
    ],
  };
  const threats: ThreatOutput = {
    architecture_flows: [],
    threat_actor_categories: [],
    threats: [
      {
        id: "CHAIN-TLS-META",
        stride: "S",
        title: "Chain",
        description: "d",
        severity: "HIGH",
        related_paths: ["a.go", "b.go"],
        immediate_actions: [],
        mitigations: [],
        verification: "",
        references: [],
        attack_scenario: "",
        prerequisites: "",
        cwe_candidates: [],
        detection_and_monitoring: "",
        likelihood_rationale: "",
        impact_rationale: "",
      },
    ],
    notes: "",
  };
  const delta = computeReportDelta(prev, threats, signals);
  assert.equal(delta.hadBaseline, true);
  assert.equal(delta.resolved.length, 1);
  assert.equal(delta.resolved[0].key, "signal:grpc-reflection-enabled");
  assert.equal(delta.statusByKey["chain:CHAIN-TLS-META"], "UNCHANGED");
});

test("buildBaselineSnapshot stores keys", () => {
  const out = buildBaselineSnapshot(
    {
      architecture_flows: [],
      threat_actor_categories: [],
      threats: [
        {
          id: "I1",
          stride: "I",
          title: "R",
          description: "d",
          severity: "LOW",
          related_paths: ["hsmaas/server.go"],
          immediate_actions: [],
          mitigations: [],
          verification: "",
          references: [],
          attack_scenario: "",
          prerequisites: "",
          cwe_candidates: [],
          detection_and_monitoring: "",
          likelihood_rationale: "",
          impact_rationale: "",
        },
      ],
      notes: "",
    },
    signals,
  );
  assert.equal(out.findings[0].key, "signal:grpc-reflection-enabled");
});
