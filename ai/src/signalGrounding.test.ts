import test from "node:test";
import assert from "node:assert/strict";
import {
  maxSeverity,
  maxSeverityOf,
  pathsMatch,
  signalsMatchingThreat,
  synthesizeChainedHardcodedCredsThreat,
} from "./signalGrounding.js";

test("pathsMatch does not equate unrelated main.go paths", () => {
  assert.equal(pathsMatch("cmd/hsmaas/main.go", "internal/admin/main.go"), false);
});

test("pathsMatch accepts suffix and exact", () => {
  assert.equal(pathsMatch("hsmaas/grpc_server.go", "repo/hsmaas/grpc_server.go"), true);
  assert.equal(pathsMatch("grpc_server.go", "hsmaas/grpc_server.go"), true);
});

test("signalsMatchingThreat only uses path overlap", () => {
  const signals = [
    { id: "a", path: "cmd/x/main.go", severity: "HIGH", summary: "x" },
    { id: "b", path: "hsmaas/server.go", severity: "MEDIUM", summary: "y" },
  ];
  const m = signalsMatchingThreat(
    {
      title: "DoS overload",
      description: "mentions hsm and db and grpc everywhere",
      related_paths: ["hsmaas/server.go"],
    },
    signals,
  );
  assert.equal(m.length, 1);
  assert.equal(m[0].id, "b");
});

test("maxSeverity picks higher impact", () => {
  assert.equal(maxSeverity("LOW", "HIGH"), "HIGH");
  assert.equal(maxSeverity("HIGH", "MEDIUM"), "HIGH");
  assert.equal(maxSeverityOf(["LOW", "MEDIUM", "HIGH"]), "HIGH");
});

test("synthesizeChainedHardcodedCredsThreat returns row when both signals exist", () => {
  const row = synthesizeChainedHardcodedCredsThreat([
    {
      id: "default-hsm-pin",
      path: "cmd/boot.go",
      severity: "HIGH",
      summary: "pin",
    },
    {
      id: "default-db-dsn-with-password",
      path: "cmd/boot.go",
      severity: "MEDIUM",
      summary: "dsn",
    },
  ]);
  assert.ok(row);
  assert.equal(row?.id, "CHAIN-HARDCODED-CREDS");
  assert.equal(row?.stride, "E");
});
