---
name: threatlens-sdlc-handoff
description: >-
  Set up ThreatLensAI for production readiness: MCP config, .threatlensai.json,
  and generating Markdown + HTML threat reports for security review. Use when
  the user wants SDLC / security handoff, threat assessment artifacts, or
  onboarding developers to ThreatLensAI in a repo.
---

# ThreatLensAI — SDLC security handoff

## Goal

Help the developer produce **reviewable threat artifacts** (commit under `security/`) for internal security or production readiness—without requiring them to learn every MCP tool.

## Golden path (minimum)

1. **Clone / use ThreatLensAI** and run `npm install && npm run build` in that repo.
2. **Cursor MCP** — add a server entry that runs `node` with argument the absolute path to `ThreatLensAI/packages/mcp-server/dist/index.js`, with env:
   - `ANTHROPIC_API_KEY` *or* `OLLAMA_MODEL` (and local Ollama).
   - `go` on `PATH`, or `THREATLENS_ENGINE_BIN` pointing at a built `threatlens-engine`.
3. In **Agent mode**, ask the assistant to call **`write_threat_report`** with **`root`** = the **absolute path** to the **application** repo (not ThreatLensAI itself).
4. Commit **`security/threat-assessment.md`** and **`security/threat-assessment.html`** (HTML is written by default; security can open the HTML in a browser for a card-style catalog).

Other MCP tools (`generate_threats`, `export_threat_dragon`, `explain_threat`, …) are **optional** for advanced workflows.

## Repository config (continued testing)

If the project has no `.threatlensai.json`, run from ThreatLensAI (after build):

```bash
npm exec -w @threatlensai/cli threatlens init /path/to/application
```

This writes a **valid** engine config (`exclude_paths`, `include_extensions`, `max_files`, `max_file_bytes`). Tweak excludes/extensions for the team’s stack.

## What to tell security

- Outputs are **LLM-assisted STRIDE** grounded in a **static code index** (Go engine JSON). They are **starting points**, not pen-test results.
- Ask reviewers to confirm **trust boundaries** and **threat actors** against the real deployment (the report includes tables for both).
- For visual DFD work, optionally export **Threat Dragon JSON** via MCP `export_threat_dragon`.

## Comparison note (STRIDE-GPT)

[STRIDE-GPT](https://github.com/mrwadams/stride-gpt) is a Streamlit app with a form-first UX. ThreatLensAI is **IDE-native**: same class of output (STRIDE + mitigations), but input is **repo-derived context** + MCP/CLI automation for **SDLC attach artifacts**.
