import test from "node:test";
import assert from "node:assert/strict";

import { renderExplainOutputToMarkdown } from "./explain.js";

test("renderExplainOutputToMarkdown supports structured sections output", () => {
  const out = renderExplainOutputToMarkdown({
    sections: {
      summary: "Short summary.",
      attack_scenario: "Attacker abuses weak identity binding.",
      affected_components: "hsmaas/grpc_server.go, cmd/hsmaas/main.go",
      detection: "Log metadata principal|Alert on cert/principal mismatch",
      verification_checklist: "Review interceptors|Add integration tests",
      residual_risk: "Residual risk is medium without strict mTLS.",
    },
  });
  assert.ok(out.includes("## Summary"));
  assert.ok(out.includes("## Detection"));
  assert.ok(out.includes("- Log metadata principal"));
  assert.ok(out.includes("## Verification Checklist"));
});

test("renderExplainOutputToMarkdown preserves legacy markdown output", () => {
  const out = renderExplainOutputToMarkdown({ markdown: "## Summary\n\nLegacy." });
  assert.equal(out, "## Summary\n\nLegacy.");
});
