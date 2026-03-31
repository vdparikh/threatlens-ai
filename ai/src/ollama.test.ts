import test from "node:test";
import assert from "node:assert/strict";
import { parseThreatJsonFromAssistant } from "./ollama.js";

test("parseThreatJsonFromAssistant accepts preamble before JSON", () => {
  const text = `Here is the output:

{"architecture_flows":[],"threat_actor_categories":[],"threats":[{"id":"1","stride":"S","title":"t","description":"d","severity":"LOW"}],"notes":"n"}`;
  const out = parseThreatJsonFromAssistant(text);
  assert.equal(out.notes, "n");
  assert.equal(out.threats.length, 1);
});

test("parseThreatJsonFromAssistant accepts fenced JSON", () => {
  const text = `\`\`\`json
{"threats":[{"id":"1","stride":"S","title":"t","description":"d","severity":"LOW","mitigations":["m"],"references":[{"label":"OWASP","url":"https://owasp.org"}]}],"notes":"n"}
\`\`\``;
  const out = parseThreatJsonFromAssistant(text);
  assert.equal(out.threats.length, 1);
  assert.equal(out.notes, "n");
});
