import test from "node:test";
import assert from "node:assert/strict";
import {
  extractFirstJsonObject,
  parseJsonObjectFromModelText,
  repairTruncatedJsonSlice,
} from "./jsonUtils.js";

test("extractFirstJsonObject finds object after prose", () => {
  const inner = `{"a":1,"b":{"c":2}}`;
  const text = `Here is the result:\n\n${inner}\n\nHope this helps!`;
  assert.equal(extractFirstJsonObject(text), inner);
});

test("parseJsonObjectFromModelText handles Here is preamble", () => {
  const text = `Here is the threat model you requested:

{"x":true,"y":"ok"}`;
  const o = parseJsonObjectFromModelText(text) as { x: boolean; y: string };
  assert.equal(o.x, true);
  assert.equal(o.y, "ok");
});

test("parseJsonObjectFromModelText still parses clean JSON", () => {
  const o = parseJsonObjectFromModelText(`  {"k": "v"}  `) as { k: string };
  assert.equal(o.k, "v");
});

test("parseJsonObjectFromModelText repairs trailing commas", () => {
  const text = `Here:\n{"a":1,"b":[1,2,],}`;
  const o = parseJsonObjectFromModelText(text) as { a: number; b: number[] };
  assert.equal(o.a, 1);
  assert.equal(o.b.length, 2);
});

test("parseJsonObjectFromModelText escapes raw newlines in string values", () => {
  const text = `{"note":"line1
line2","ok":true}`;
  const o = parseJsonObjectFromModelText(text) as { note: string; ok: boolean };
  assert.equal(o.ok, true);
  assert.equal(o.note.includes("line2"), true);
});

test("repairTruncatedJsonSlice closes open arrays and objects", () => {
  const raw = `{"architecture_flows":[{"a":1},`;
  const fixed = repairTruncatedJsonSlice(raw);
  const o = JSON.parse(fixed) as { architecture_flows: unknown[] };
  assert.equal(o.architecture_flows.length, 1);
});

test("parseJsonObjectFromModelText recovers truncated top-level JSON (token limit)", () => {
  const truncated = `{"architecture_flows":[{"boundary_name":"x","from_component":"a","to_component":"b"}],"threats":[{"id":"S1","stride":"S","title":"t","description":"d","severity":"LOW","related_paths":[],"immediate_actions":[],"mitigations":[],"verification":"","references":[]`;
  const o = parseJsonObjectFromModelText(truncated) as {
    threats: Array<{ id: string }>;
  };
  assert.equal(o.threats.length, 1);
  assert.equal(o.threats[0].id, "S1");
});
