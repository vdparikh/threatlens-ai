import test from "node:test";
import assert from "node:assert/strict";
import {
  inferStrideFromId,
  inferStrideFromTitle,
  normalizeStride,
  normalizeThreatPayload,
} from "./normalize.js";
import { ThreatOutputSchema } from "./schemas.js";

test("normalizeThreatPayload fills missing references and mitigations", () => {
  const raw = {
    threats: [
      {
        id: "1",
        stride: "S",
        title: "t",
        description: "d",
        severity: "LOW",
      },
    ],
    notes: "n",
  };
  const out = ThreatOutputSchema.parse(normalizeThreatPayload(raw));
  assert.equal(out.threats[0].references.length, 0);
  assert.equal(out.threats[0].mitigations.length, 0);
});

test("inferStrideFromId overrides wrong stride field", () => {
  const raw = {
    threats: [
      {
        id: "S",
        stride: "T",
        title: "Spoofing issue",
        description: "d",
        severity: "LOW",
      },
    ],
    notes: "",
  };
  const out = ThreatOutputSchema.parse(normalizeThreatPayload(raw));
  assert.equal(out.threats[0].stride, "S");
});

test("inferStrideFromTitle when id is generic", () => {
  assert.equal(inferStrideFromId("threat-1"), null);
  assert.equal(inferStrideFromTitle("Tampering: bad input"), "T");
  assert.equal(inferStrideFromTitle("Information Disclosure: leak"), "I");
  assert.equal(inferStrideFromTitle("Spoofing gRPC connection"), "S");
});

test("inferStrideFromId parses letter+digit threat ids", () => {
  assert.equal(inferStrideFromId("R1"), "R");
  assert.equal(inferStrideFromId("s2"), "S");
  assert.equal(inferStrideFromId("E12"), "E");
});

test("normalizeStride maps full STRIDE names to letters", () => {
  assert.equal(normalizeStride("Spoofing"), "S");
  assert.equal(normalizeStride("Tampering"), "T");
  assert.equal(normalizeStride("Repudiation"), "R");
  assert.equal(normalizeStride("Information Disclosure"), "I");
  assert.equal(normalizeStride("Denial of Service"), "D");
  assert.equal(normalizeStride("Elevation of Privilege"), "E");
  assert.equal(normalizeStride("STRIDE: Tampering"), "T");
});

test("full threat with Spoofing label and no references validates", () => {
  const raw = {
    threats: [
      {
        id: "1",
        stride: "Spoofing",
        title: "t",
        description: "d",
        severity: "LOW",
      },
    ],
    notes: "n",
  };
  const out = ThreatOutputSchema.parse(normalizeThreatPayload(raw));
  assert.equal(out.threats[0].stride, "S");
  assert.equal(out.threats[0].references.length, 0);
});

test("normalizeThreatPayload defaults architecture_flows and threat_actor_categories", () => {
  const raw = {
    threats: [
      {
        id: "1",
        stride: "T",
        title: "t",
        description: "d",
        severity: "LOW",
      },
    ],
    notes: "",
  };
  const out = ThreatOutputSchema.parse(normalizeThreatPayload(raw));
  assert.equal(out.architecture_flows.length, 0);
  assert.equal(out.threat_actor_categories.length, 0);
});

test("normalizeThreatPayload fills new optional threat fields", () => {
  const raw = {
    threats: [
      {
        id: "1",
        stride: "T",
        title: "t",
        description: "d",
        severity: "LOW",
        cwe_candidates: ["CWE-400"],
      },
    ],
    notes: "",
  };
  const out = ThreatOutputSchema.parse(normalizeThreatPayload(raw));
  assert.equal(out.threats[0].attack_scenario, "");
  assert.equal(out.threats[0].cwe_candidates[0], "CWE-400");
  assert.equal(out.threats[0].detection_and_monitoring, "");
});

test("normalizeThreatPayload fixes null references", () => {
  const raw = {
    threats: [
      {
        id: "1",
        stride: "T",
        title: "t",
        description: "d",
        severity: "MEDIUM",
        mitigations: ["x"],
        references: null,
      },
    ],
    notes: "",
  };
  const out = ThreatOutputSchema.parse(normalizeThreatPayload(raw));
  assert.equal(Array.isArray(out.threats[0].references), true);
});

test("normalizeThreatPayload coerces related_paths objects to strings", () => {
  const raw = {
    threats: [
      {
        id: "1",
        stride: "T",
        title: "t",
        description: "d",
        severity: "LOW",
        related_paths: [{ path: "internal/a.go" }, { file: " cmd/b.go " }, "pkg/c.go", {}, null],
      },
    ],
    notes: "",
  };
  const out = ThreatOutputSchema.parse(normalizeThreatPayload(raw));
  assert.deepEqual(out.threats[0].related_paths, ["internal/a.go", "cmd/b.go", "pkg/c.go"]);
});

test("normalizeThreatPayload coerces mitigations/immediate_actions object entries to strings", () => {
  const raw = {
    threats: [
      {
        id: "1",
        stride: "S",
        title: "t",
        description: "d",
        severity: "LOW",
        mitigations: [{ text: "Use mTLS" }, { mitigation: "Rotate secrets" }, {}],
        immediate_actions: [{ action: "Disable reflection" }, "Audit defaults", { value: "Patch config" }],
      },
    ],
    notes: "",
  };
  const out = ThreatOutputSchema.parse(normalizeThreatPayload(raw));
  assert.deepEqual(out.threats[0].mitigations, ["Use mTLS", "Rotate secrets"]);
  assert.deepEqual(out.threats[0].immediate_actions, [
    "Disable reflection",
    "Audit defaults",
    "Patch config",
  ]);
});
