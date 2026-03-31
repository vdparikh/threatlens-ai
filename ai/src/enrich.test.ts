import test from "node:test";
import assert from "node:assert/strict";

import { renderDeepDiveRowToMarkdown } from "./enrich.js";

test("renderDeepDiveRowToMarkdown supports structured deep-dive rows", () => {
  const out = renderDeepDiveRowToMarkdown({
    id: "R1",
    attack_path: "Attacker forges metadata identity and performs privileged action.",
    code_review: ["Check auth interceptor order.", "Verify metadata is not trusted without mTLS."],
    detection: ["Alert on metadata-only identity.", "Track principal/source mismatch."],
  });
  assert.ok(out.includes("### Attack path"));
  assert.ok(out.includes("### Code review focus"));
  assert.ok(out.includes("### Detection and monitoring"));
  assert.ok(out.includes("- Check auth interceptor order."));
});

test("renderDeepDiveRowToMarkdown preserves legacy markdown rows", () => {
  const out = renderDeepDiveRowToMarkdown({
    id: "R1",
    markdown: "### Existing\n\nalready formatted",
  });
  assert.equal(out, "### Existing\n\nalready formatted");
});

test("renderDeepDiveRowToMarkdown strips shallow-model prefix when attack path is substantive", () => {
  const out = renderDeepDiveRowToMarkdown({
    id: "S1",
    attack_path:
      "System model is limited for this threat — First sentence explains risk. Second sentence provides concrete path.",
    code_review: [],
    detection: [],
  });
  assert.ok(!out.includes("System model is limited for this threat —"));
  assert.ok(out.includes("First sentence explains risk."));
});
