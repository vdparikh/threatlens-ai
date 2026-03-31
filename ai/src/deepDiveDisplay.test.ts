import test from "node:test";
import assert from "node:assert/strict";
import { decodeDeepDiveDisplayText, formatDeepDiveForDisplay } from "./deepDiveDisplay.js";

test("decodeDeepDiveDisplayText unwraps JSON-quoted string", () => {
  const s = '"### Title\\n\\nBody paragraph"';
  const out = decodeDeepDiveDisplayText(s);
  assert.ok(out.startsWith("### Title"));
  assert.ok(out.includes("Body paragraph"));
  assert.ok(out.includes("\n"), "should contain real newlines");
});

test("decodeDeepDiveDisplayText fixes literal backslash-n without JSON wrapper", () => {
  const out = decodeDeepDiveDisplayText("Line1\\nLine2");
  assert.ok(out.includes("\n"));
});

test("formatDeepDiveForDisplay strips trailing leaked JSON closers", () => {
  const out = formatDeepDiveForDisplay('### Section\n\nProse here.\n", ""}]}');
  assert.ok(out.includes("Prose"));
  assert.ok(!out.includes("]}"));
});

test("formatDeepDiveForDisplay unwraps a full threat-shaped JSON object", () => {
  const raw =
    '{"description":"The default DB DSN contains inline credentials.","stride":"I","title":"E1","id":"E1"}';
  const out = formatDeepDiveForDisplay(raw);
  assert.ok(out.includes("DSN"));
  assert.ok(!out.includes('"stride"'));
});

test("formatDeepDiveForDisplay removes json junk-only trailing lines", () => {
  const out = formatDeepDiveForDisplay("### A\n\nB\n} ] }");
  assert.ok(out.includes("B"));
  assert.ok(!out.trimEnd().endsWith("}"));
});
