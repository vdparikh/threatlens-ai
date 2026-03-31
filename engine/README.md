# ThreatLensAI analysis engine (Go)

Walks a project tree, loads `.threatlensai.json`, and emits a JSON **system model**. For `.go` files, the engine uses `go/parser` to attach **package name and import paths** (high-signal for STRIDE).

```bash
cd engine
go run ./cmd/threatlens-engine /path/to/repo
```

Build a static binary:

```bash
go build -o threatlens-engine ./cmd/threatlens-engine
```

Environment for integrations:

- `THREATLENS_ENGINE_BIN` — path to a prebuilt binary (optional; otherwise callers use `go run`).
- `THREATLENS_GO` — Go toolchain binary name (default `go`).
