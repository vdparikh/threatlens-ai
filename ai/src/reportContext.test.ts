import test from "node:test";
import assert from "node:assert/strict";

import { isLowQualityArchitectureRows } from "./reportContext.js";

test("isLowQualityArchitectureRows treats import/file-like rows as low quality", () => {
  const rows = [
    {
      boundary_name: "imports",
      from_component: "github.com/acme/service/pkg/auth",
      to_component: "github.com/acme/service/pkg/store",
    },
    {
      boundary_name: "file edge",
      from_component: "cmd/hsmaas/main.go",
      to_component: "hsmaas/grpc_server.go",
    },
  ];
  assert.equal(isLowQualityArchitectureRows(rows), true);
});
