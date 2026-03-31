import test from "node:test";
import assert from "node:assert/strict";

import { postprocessThreatOutput } from "./postprocess.js";
import type { ThreatOutput } from "./schemas.js";

test("postprocessThreatOutput fixes stride mismatch and fills related paths", () => {
  const model = {
    files: [
      { path: "cmd/hsmaas/main.go" },
      { path: "hsmaas/grpc_server.go" },
      { path: "hsmaas/store.go" },
      { path: "hsmaas/policy.go" },
    ],
    flow_graph: {
      nodes: [
        { id: "actor_user", label: "User / Client" },
        { id: "proc_http", label: "gRPC API surface" },
        { id: "data_store", label: "Policy store" },
      ],
      edges: [{ from: "actor_user", to: "proc_http", label: "gRPC calls" }],
    },
  };
  const input: ThreatOutput = {
    architecture_flows: [
      { boundary_name: "/tmp/repo", from_component: "actor_user", to_component: "proc_http" },
    ],
    threat_actor_categories: [],
    threats: [
      {
        id: "S1",
        stride: "T",
        title: "Spoofing gRPC Connection",
        description: "Spoofing through metadata",
        severity: "HIGH",
        related_paths: [],
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
  const out = postprocessThreatOutput(model, input);
  assert.equal(out.threats[0].stride, "S");
  assert.equal(out.threats[0].related_paths.length > 0, true);
  assert.equal(out.architecture_flows[0].from_component, "User / Client");
});

test("postprocessThreatOutput downgrades unsupported CRITICAL without evidence", () => {
  const input: ThreatOutput = {
    architecture_flows: [],
    threat_actor_categories: [],
    threats: [
      {
        id: "x",
        stride: "T",
        title: "Tampering",
        description: "generic",
        severity: "CRITICAL",
        related_paths: [],
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
  const out = postprocessThreatOutput({}, input);
  assert.equal(out.threats[0].severity, "HIGH");
});

test("postprocessThreatOutput prefers STRIDE implied by title over id prefix letter", () => {
  const model = { files: [{ path: "hsmaas/grpc_server.go" }] };
  const input: ThreatOutput = {
    architecture_flows: [],
    threat_actor_categories: [],
    threats: [
      {
        id: "T1",
        stride: "T",
        title: "Repudiation of gRPC reflection exposure",
        description: "Attacker denies actions",
        severity: "LOW",
        related_paths: ["hsmaas/grpc_server.go"],
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
  const out = postprocessThreatOutput(model, input);
  assert.equal(out.threats[0].stride, "R");
});

test("postprocessThreatOutput calibrates naked HIGH to MEDIUM when signals exist but paths do not overlap", () => {
  const model = {
    files: [
      { path: "hsmaas/grpc_server.go" },
      { path: "cmd/hsmaas/main.go" },
    ],
    security_signals: [
      {
        id: "default-hsm-pin",
        path: "cmd/hsmaas/main.go",
        severity: "HIGH",
        summary: "pin",
      },
    ],
  };
  const input: ThreatOutput = {
    architecture_flows: [],
    threat_actor_categories: [],
    threats: [
      {
        id: "D1",
        stride: "D",
        title: "Denial of Service on API",
        description: "Overload",
        severity: "HIGH",
        related_paths: ["hsmaas/grpc_server.go"],
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
  const out = postprocessThreatOutput(model, input);
  assert.equal(out.threats.find((t) => t.id === "D1")?.severity, "MEDIUM");
});

test("postprocessThreatOutput forces stride letter to match id prefix (e.g. R1)", () => {
  const model = { files: [{ path: "hsmaas/grpc_server.go" }] };
  const input: ThreatOutput = {
    architecture_flows: [],
    threat_actor_categories: [],
    threats: [
      {
        id: "R1",
        stride: "T",
        title: "gRPC reflection exposure",
        description: "Server reflection",
        severity: "MEDIUM",
        related_paths: ["hsmaas/grpc_server.go"],
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
  const out = postprocessThreatOutput(model, input);
  assert.equal(out.threats[0].stride, "R");
});

test("postprocessThreatOutput attaches static signals only when related_paths overlap signal path", () => {
  const model = {
    files: [
      { path: "hsmaas/grpc_server.go" },
      { path: "cmd/hsmaas/main.go" },
    ],
    security_signals: [
      {
        id: "default-hsm-pin",
        path: "cmd/hsmaas/main.go",
        severity: "HIGH",
        summary: "Default HSM PIN in bootstrap",
      },
      {
        id: "grpc-metadata-identity-fallback",
        path: "hsmaas/grpc_server.go",
        severity: "MEDIUM",
        summary: "metadata identity",
      },
    ],
  };
  const input: ThreatOutput = {
    architecture_flows: [],
    threat_actor_categories: [],
    threats: [
      {
        id: "D1",
        stride: "D",
        title: "Denial of Service due to gRPC API overload",
        description: "Attacker floods handlers.",
        severity: "MEDIUM",
        related_paths: ["hsmaas/grpc_server.go"],
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
  const out = postprocessThreatOutput(model, input);
  const dos = out.threats.find((t) => t.title.includes("Denial of Service"));
  assert.ok(dos);
  assert.ok(
    !dos!.description.includes("default-hsm-pin"),
    "DoS card must not mention off-path HSM signal",
  );
  assert.ok(
    dos!.description.includes("grpc-metadata-identity-fallback"),
    "gRPC-server path should merge matching signal",
  );
});

test("postprocessThreatOutput elevates severity when overlapping signal is higher", () => {
  const model = {
    files: [{ path: "cmd/hsmaas/main.go" }],
    security_signals: [
      {
        id: "default-hsm-pin",
        path: "cmd/hsmaas/main.go",
        severity: "HIGH",
        summary: "Default HSM PIN",
      },
    ],
  };
  const input: ThreatOutput = {
    architecture_flows: [],
    threat_actor_categories: [],
    threats: [
      {
        id: "I1",
        stride: "I",
        title: "Key management disclosure",
        description: "KMS exposure narrative",
        severity: "LOW",
        related_paths: ["cmd/hsmaas/main.go"],
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
  const out = postprocessThreatOutput(model, input);
  const i1 = out.threats.find((t) => t.id === "I1");
  assert.equal(i1?.severity, "HIGH");
});

test("postprocessThreatOutput prepends CHAIN-HARDCODED-CREDS when HSM + DB DSN signals exist", () => {
  const model = {
    files: [{ path: "cmd/hsmaas/main.go" }],
    security_signals: [
      {
        id: "default-hsm-pin",
        path: "cmd/hsmaas/main.go",
        severity: "HIGH",
        summary: "pin",
      },
      {
        id: "default-db-dsn-with-password",
        path: "cmd/hsmaas/main.go",
        severity: "MEDIUM",
        summary: "dsn",
      },
    ],
  };
  const input: ThreatOutput = {
    architecture_flows: [],
    threat_actor_categories: [],
    threats: [
      {
        id: "S1",
        stride: "S",
        title: "Spoofing",
        description: "x",
        severity: "LOW",
        related_paths: [],
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
  const out = postprocessThreatOutput(model, input);
  assert.ok(out.threats.some((t) => t.id === "CHAIN-HARDCODED-CREDS"));
});

test("postprocessThreatOutput prepends CHAIN threat when TLS optional + metadata fallback signals exist", () => {
  const model = {
    files: [
      { path: "hsmaas/main.go" },
      { path: "hsmaas/grpc_server.go" },
    ],
    security_signals: [
      {
        id: "tls-optional-config",
        path: "hsmaas/main.go",
        severity: "MEDIUM",
        summary: "TLS can be disabled when cert/key env vars are absent.",
      },
      {
        id: "grpc-metadata-identity-fallback",
        path: "hsmaas/grpc_server.go",
        severity: "MEDIUM",
        summary: "Identity from user/x-user metadata when cert absent.",
      },
    ],
  };
  const input: ThreatOutput = {
    architecture_flows: [],
    threat_actor_categories: [],
    threats: [
      {
        id: "S1",
        stride: "S",
        title: "Spoofing",
        description: "generic",
        severity: "LOW",
        related_paths: [],
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
  const out = postprocessThreatOutput(model, input);
  assert.equal(out.threats[0].id, "CHAIN-TLS-META");
  assert.equal(out.threats[0].severity, "HIGH");
});

test("postprocessThreatOutput drops redundant I-disclosure rows when CHAIN-HARDCODED-CREDS covers same bootstrap signals", () => {
  const model = {
    files: [{ path: "cmd/hsmaas/main.go" }],
    security_signals: [
      {
        id: "default-hsm-pin",
        path: "cmd/hsmaas/main.go",
        severity: "HIGH",
        summary: "Default HSM PIN",
      },
      {
        id: "default-db-dsn-with-password",
        path: "cmd/hsmaas/main.go",
        severity: "MEDIUM",
        summary: "Inline DSN password",
      },
      {
        id: "tls-optional-config",
        path: "cmd/hsmaas/main.go",
        severity: "MEDIUM",
        summary: "TLS optional in dev",
      },
    ],
  };
  const input: ThreatOutput = {
    architecture_flows: [],
    threat_actor_categories: [],
    threats: [
      {
        id: "E1",
        stride: "I",
        title: "Information Disclosure through DB DSN",
        description: "Default DSN exposes credentials in bootstrap.",
        severity: "HIGH",
        related_paths: ["cmd/hsmaas/main.go"],
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
  const out = postprocessThreatOutput(model, input);
  assert.ok(out.threats.some((t) => t.id === "CHAIN-HARDCODED-CREDS"));
  assert.ok(!out.threats.some((t) => t.id === "E1"));
});

test("postprocessThreatOutput drops unmoored SQL injection claim when scanner has no SQLi signal", () => {
  const model = {
    files: [
      { path: "cmd/hsmaas/main.go" },
      { path: "hsmaas/store.go" },
    ],
    security_signals: [
      {
        id: "default-hsm-pin",
        path: "cmd/hsmaas/main.go",
        severity: "HIGH",
        summary: "PIN",
      },
    ],
  };
  const input: ThreatOutput = {
    architecture_flows: [],
    threat_actor_categories: [],
    threats: [
      {
        id: "R1",
        stride: "E",
        title: "Elevation of Privilege through SQL Injection",
        description: "Attacker injects SQL via request parameters.",
        severity: "HIGH",
        related_paths: [],
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
  const out = postprocessThreatOutput(model, input);
  assert.ok(!out.threats.some((t) => t.id === "R1"));
});

test("postprocessThreatOutput removes non-file related paths", () => {
  const model = { files: [{ path: "hsmaas/grpc_server.go" }] };
  const input: ThreatOutput = {
    architecture_flows: [],
    threat_actor_categories: [],
    threats: [
      {
        id: "x",
        stride: "D",
        title: "DoS",
        description: "db pressure",
        severity: "LOW",
        related_paths: ["Data Stores (Postgres, SQL)", "hsmaas/grpc_server.go"],
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
  const out = postprocessThreatOutput(model, input);
  assert.deepEqual(out.threats[0].related_paths, ["hsmaas/grpc_server.go"]);
});

test("postprocessThreatOutput reindexes id prefix from final stride", () => {
  const model = { files: [{ path: "hsmaas/grpc_server.go" }] };
  const input: ThreatOutput = {
    architecture_flows: [],
    threat_actor_categories: [],
    threats: [
      {
        id: "S2",
        stride: "D",
        title: "Denial of Service through gRPC Reflection",
        description: "Reflection can be abused.",
        severity: "LOW",
        related_paths: ["hsmaas/grpc_server.go"],
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
  const out = postprocessThreatOutput(model, input);
  assert.equal(out.threats[0].id, "D1");
});

test("postprocessThreatOutput dedupes duplicate single-signal reflection rows and prefers information disclosure stride", () => {
  const model = {
    files: [{ path: "hsmaas/server.go" }],
    security_signals: [
      {
        id: "grpc-reflection-enabled",
        path: "hsmaas/server.go",
        severity: "LOW",
        summary: "gRPC reflection is enabled in runtime server setup.",
      },
    ],
  };
  const input: ThreatOutput = {
    architecture_flows: [],
    threat_actor_categories: [],
    threats: [
      {
        id: "S2",
        stride: "D",
        title: "Denial of Service through gRPC Reflection",
        description: "A denial of service occurs via reflection queries.",
        severity: "LOW",
        related_paths: ["hsmaas/server.go"],
        immediate_actions: [],
        mitigations: [],
        verification: "",
        references: [{ label: "Security Signal", url: "https://example.com/security-signal" }],
        attack_scenario: "",
        prerequisites: "",
        cwe_candidates: [],
        detection_and_monitoring: "",
        likelihood_rationale: "",
        impact_rationale: "",
      },
      {
        id: "T2",
        stride: "R",
        title: "Repudiation through gRPC Reflection Enabled",
        description: "Reflection methods are discoverable.",
        severity: "LOW",
        related_paths: ["hsmaas/server.go"],
        immediate_actions: [],
        mitigations: [],
        verification: "",
        references: [{ label: "Security Signal", url: "https://example.com/security-signal" }],
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
  const out = postprocessThreatOutput(model, input);
  assert.equal(out.threats.length, 1);
  assert.equal(out.threats[0].stride, "I");
  assert.equal(out.threats[0].id, "I1");
  assert.deepEqual(out.threats[0].references, []);
});

test("postprocessThreatOutput enriches sparse metadata-fallback rows", () => {
  const model = {
    files: [{ path: "hsmaas/grpc_server.go" }],
    security_signals: [
      {
        id: "grpc-metadata-identity-fallback",
        path: "hsmaas/grpc_server.go",
        severity: "MEDIUM",
        summary: "Identity can be sourced from user metadata.",
      },
    ],
  };
  const input: ThreatOutput = {
    architecture_flows: [],
    threat_actor_categories: [],
    threats: [
      {
        id: "T1",
        stride: "R",
        title: "Repudiation through gRPC Identity Fallback",
        description: "Metadata identity fallback exists.",
        severity: "MEDIUM",
        related_paths: ["hsmaas/grpc_server.go"],
        immediate_actions: [],
        mitigations: [],
        verification: "",
        references: [{ label: "Security Signal", url: "https://example.com/security-signal" }],
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
  const out = postprocessThreatOutput(model, input);
  const t = out.threats[0];
  assert.equal(t.stride, "R");
  assert.equal(t.id, "R1");
  assert.ok(t.description.includes("audit logs"));
  assert.ok(t.attack_scenario.length > 0);
  assert.ok(t.prerequisites.length > 0);
  assert.ok(t.cwe_candidates.length > 0);
  assert.ok(t.detection_and_monitoring.length > 0);
  assert.ok(t.likelihood_rationale.length > 0);
  assert.ok(t.impact_rationale.length > 0);
  assert.deepEqual(t.references, []);
});

test("postprocessThreatOutput drops non-chain threats when their primary signal is already covered by chain findings", () => {
  const model = {
    files: [
      { path: "cmd/hsmaas/main.go" },
      { path: "hsmaas/grpc_server.go" },
      { path: "hsmaas/server.go" },
    ],
    security_signals: [
      {
        id: "tls-optional-config",
        path: "cmd/hsmaas/main.go",
        severity: "MEDIUM",
        summary: "TLS optional.",
      },
      {
        id: "grpc-metadata-identity-fallback",
        path: "hsmaas/grpc_server.go",
        severity: "MEDIUM",
        summary: "Metadata identity fallback.",
      },
      {
        id: "default-hsm-pin",
        path: "cmd/hsmaas/main.go",
        severity: "HIGH",
        summary: "Default HSM PIN.",
      },
      {
        id: "default-db-dsn-with-password",
        path: "cmd/hsmaas/main.go",
        severity: "MEDIUM",
        summary: "Default DB DSN with password.",
      },
      {
        id: "grpc-reflection-enabled",
        path: "hsmaas/server.go",
        severity: "LOW",
        summary: "Reflection enabled.",
      },
    ],
  };
  const input: ThreatOutput = {
    architecture_flows: [],
    threat_actor_categories: [],
    threats: [
      {
        id: "S1",
        stride: "S",
        title: "Spoofing gRPC identity via metadata",
        description: "user/x-user headers may be accepted.",
        severity: "HIGH",
        related_paths: ["hsmaas/grpc_server.go"],
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
      {
        id: "S2",
        stride: "S",
        title: "Exposure of Postgres DB DSN",
        description: "DSN is visible in bootstrap code.",
        severity: "HIGH",
        related_paths: ["cmd/hsmaas/main.go"],
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
      {
        id: "T1",
        stride: "R",
        title: "gRPC reflection enabled",
        description: "Service method enumeration possible.",
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
  };
  const out = postprocessThreatOutput(model, input);
  const ids = out.threats.map((t) => t.id);
  assert.deepEqual(ids, ["CHAIN-TLS-META", "CHAIN-HARDCODED-CREDS", "I1"]);
  const i1 = out.threats.find((t) => t.id === "I1");
  assert.equal(i1?.severity, "LOW");
});

test("postprocessThreatOutput synthesizes reflection disclosure when scanner has reflection signal but LLM omitted it", () => {
  const model = {
    files: [
      { path: "cmd/hsmaas/main.go" },
      { path: "hsmaas/grpc_server.go" },
      { path: "hsmaas/server.go" },
    ],
    security_signals: [
      {
        id: "tls-optional-config",
        path: "cmd/hsmaas/main.go",
        severity: "MEDIUM",
        summary: "TLS optional.",
      },
      {
        id: "grpc-metadata-identity-fallback",
        path: "hsmaas/grpc_server.go",
        severity: "MEDIUM",
        summary: "Metadata identity fallback.",
      },
      {
        id: "default-hsm-pin",
        path: "cmd/hsmaas/main.go",
        severity: "HIGH",
        summary: "Default HSM PIN.",
      },
      {
        id: "default-db-dsn-with-password",
        path: "cmd/hsmaas/main.go",
        severity: "MEDIUM",
        summary: "Default DB DSN with password.",
      },
      {
        id: "grpc-reflection-enabled",
        path: "hsmaas/server.go",
        severity: "LOW",
        summary: "Reflection enabled.",
      },
    ],
  };
  const input: ThreatOutput = {
    architecture_flows: [],
    threat_actor_categories: [],
    threats: [],
    notes: "",
  };
  const out = postprocessThreatOutput(model, input);
  assert.deepEqual(
    out.threats.map((t) => t.id),
    ["CHAIN-TLS-META", "CHAIN-HARDCODED-CREDS", "I1"],
  );
  const refl = out.threats.find((t) => t.id === "I1");
  assert.equal(refl?.stride, "I");
  assert.equal(refl?.severity, "LOW");
  assert.deepEqual(refl?.related_paths, ["hsmaas/server.go"]);
});

test("postprocessThreatOutput drops too-short immediate actions and injects reflection fallback action", () => {
  const model = {
    files: [{ path: "hsmaas/server.go" }],
    security_signals: [
      {
        id: "grpc-reflection-enabled",
        path: "hsmaas/server.go",
        severity: "LOW",
        summary: "Reflection enabled.",
      },
    ],
  };
  const input: ThreatOutput = {
    architecture_flows: [],
    threat_actor_categories: [],
    threats: [
      {
        id: "I7",
        stride: "I",
        title: "Information disclosure via reflection",
        description: "Reflection allows service enumeration.",
        severity: "LOW",
        related_paths: ["hsmaas/server.go"],
        immediate_actions: ["Disable", "Restrict"],
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
  const out = postprocessThreatOutput(model, input);
  const i1 = out.threats.find((t) => t.id === "I1");
  assert.ok(i1);
  assert.deepEqual(i1.immediate_actions, [
    "Disable grpc-reflection-enabled in hsmaas/server.go for production builds.",
  ]);
});

