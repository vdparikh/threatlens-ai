#!/usr/bin/env node
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import {
  buildThreatAssessmentHTML,
  buildThreatAssessmentMarkdown,
  generateThreats,
  reportDeltaFromModel,
  runDeepDiveEnrichment,
  saveBaseline,
} from "@threatlensai/ai";

const DEFAULT_THREATLENSAI_JSON = `{
  "exclude_paths": [
    "node_modules",
    "dist",
    "build",
    ".git",
    "vendor",
    ".venv",
    "venv",
    "__pycache__",
    ".next",
    "coverage",
    "target"
  ],
  "include_extensions": [
    ".ts",
    ".tsx",
    ".js",
    ".jsx",
    ".go",
    ".py",
    ".java",
    ".yaml",
    ".yml",
    ".json",
    ".md",
    ".tf",
    ".proto"
  ],
  "max_files": 10000,
  "max_file_bytes": 524288
}
`;

const __dirname = dirname(fileURLToPath(import.meta.url));

function isEngineDir(enginePath: string): boolean {
  return (
    existsSync(join(enginePath, "go.mod")) &&
    existsSync(join(enginePath, "cmd", "threatlens-engine", "main.go"))
  );
}

/**
 * Locate the Go engine source tree for `go run ./cmd/threatlens-engine`.
 * Walks upward from this package, then checks THREATLENSAI_ROOT / THREATLENS_ENGINE_ROOT.
 */
function resolveEngineDir(): string {
  const envRoot = process.env.THREATLENSAI_ROOT ?? process.env.THREATLENS_ENGINE_ROOT;
  if (envRoot) {
    const asEngine = resolve(envRoot);
    if (isEngineDir(asEngine)) {
      return asEngine;
    }
    const nested = join(asEngine, "engine");
    if (isEngineDir(nested)) {
      return nested;
    }
  }
  let dir = resolve(__dirname);
  for (let i = 0; i < 16; i++) {
    const engine = join(dir, "engine");
    if (isEngineDir(engine)) {
      return engine;
    }
    const parent = dirname(dir);
    if (parent === dir) {
      break;
    }
    dir = parent;
  }
  throw new Error(
    "ThreatLensAI Go engine not found.\n" +
      "Fix one of:\n" +
      "  • Clone ThreatLensAI and run: npm install && npm run build && npx threatlens … from the repo (or link the CLI).\n" +
      "  • Set THREATLENSAI_ROOT to the ThreatLensAI repository root (directory that contains engine/go.mod).\n" +
      "  • Set THREATLENS_ENGINE_BIN to a built binary (go build -o threatlens-engine ./engine/cmd/threatlens-engine).",
  );
}

function runEngine(root: string): string {
  const resolvedRoot = resolve(root);
  const bin = process.env.THREATLENS_ENGINE_BIN;
  if (bin && existsSync(bin)) {
    const result = spawnSync(bin, [resolvedRoot], {
      encoding: "utf-8",
      env: { ...process.env },
      maxBuffer: 50 * 1024 * 1024,
    });
    if (result.error) {
      throw result.error;
    }
    if (result.status !== 0) {
      throw new Error((result.stderr || result.stdout || "").trim() || `exit ${result.status}`);
    }
    return result.stdout;
  }

  const engineDir = resolveEngineDir();
  const cmd = process.env.THREATLENS_GO ?? "go";
  const result = spawnSync(cmd, ["run", "./cmd/threatlens-engine", resolvedRoot], {
    cwd: engineDir,
    encoding: "utf-8",
    env: { ...process.env },
    maxBuffer: 50 * 1024 * 1024,
  });
  if (result.error) {
    throw result.error;
  }
  if (result.status !== 0) {
    throw new Error((result.stderr || result.stdout || "").trim() || `exit ${result.status}`);
  }
  return result.stdout;
}

function resolveSafeOutputPath(projectRoot: string, outputRelative: string): string {
  const rootAbs = resolve(projectRoot);
  const rel = outputRelative.trim().replace(/^[/\\]+/, "");
  if (!rel || rel.includes("..")) {
    throw new Error("--output must be a relative path without .. when under the project root");
  }
  const abs = resolve(rootAbs, rel);
  const check = relative(rootAbs, abs);
  if (check.startsWith("..") || check === "..") {
    throw new Error("resolved path escapes project root");
  }
  return abs;
}

/** Allow absolute --output for report; otherwise keep file under analyzed root. */
function resolveReportDestination(projectRoot: string, outputArg: string | undefined): string {
  if (!outputArg?.trim()) {
    return resolveSafeOutputPath(projectRoot, "security/threat-assessment.md");
  }
  const trimmed = outputArg.trim();
  if (trimmed.startsWith("/") || /^[a-zA-Z]:[\\/]/.test(trimmed)) {
    return resolve(trimmed);
  }
  return resolveSafeOutputPath(projectRoot, trimmed);
}

type ParsedFlags = {
  output?: string;
  title?: string;
  noDeepDive?: boolean;
  noAppendix?: boolean;
  noHtml?: boolean;
};

function parseFlags(argv: string[], startIndex: number): ParsedFlags {
  const flags: ParsedFlags = {};
  for (let i = startIndex; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--output" && argv[i + 1]) {
      flags.output = argv[i + 1];
      i++;
      continue;
    }
    if (a === "--title" && argv[i + 1]) {
      flags.title = argv[i + 1];
      i++;
      continue;
    }
    if (a === "--no-deep-dive") {
      flags.noDeepDive = true;
      continue;
    }
    if (a === "--no-appendix") {
      flags.noAppendix = true;
      continue;
    }
    if (a === "--no-html") {
      flags.noHtml = true;
      continue;
    }
  }
  return flags;
}

function siblingHtmlFromMdPath(mdPath: string): string {
  if (mdPath.toLowerCase().endsWith(".md")) {
    return mdPath.slice(0, -3) + ".html";
  }
  return `${mdPath}.html`;
}

function usage(): never {
  console.error(`ThreatLensAI CLI — commands that work today:

  threatlens init [project-root]
      Create .threatlensai.json (engine indexing: excludes, extensions, limits).
      Default project-root: current directory. Fails if the file already exists.

  threatlens analyze <path> [--output model.json]
      Walk the tree and write the system model as JSON (stdout or --output).
      Note: output is always JSON, not Markdown.

  threatlens threats <path> [--output threats.json]
      analyze + STRIDE threats (needs ANTHROPIC_API_KEY or OLLAMA_MODEL + Ollama).

  threatlens report <path> [--output path] [--title "…"] [--no-deep-dive] [--no-appendix] [--no-html]
      analyze + threats + Markdown report (same pipeline as MCP write_threat_report).
      Also writes a sibling .html dashboard by default; use --no-html for Markdown only.
      Default Markdown: <path>/security/threat-assessment.md

Engine: set THREATLENSAI_ROOT if the CLI is installed outside the ThreatLensAI repo,
or THREATLENS_ENGINE_BIN to a built threatlens-engine binary.`);
  process.exit(1);
}

async function main(): Promise<void> {
  const argv = process.argv.slice(2);
  if (argv.length < 1) {
    usage();
  }
  const cmd = argv[0];

  if (cmd === "init") {
    const root = argv[1] ? resolve(argv[1]) : process.cwd();
    const dest = join(root, ".threatlensai.json");
    if (existsSync(dest)) {
      console.error(`refusing to overwrite existing ${dest}`);
      process.exit(1);
    }
    mkdirSync(root, { recursive: true });
    writeFileSync(dest, DEFAULT_THREATLENSAI_JSON.trimEnd() + "\n", "utf-8");
    console.error(`Wrote ${dest}`);
    return;
  }

  if (argv.length < 2) {
    usage();
  }
  const target = argv[1];
  const flags = parseFlags(argv, 2);
  let out = flags.output;

  if (cmd === "analyze") {
    if (out && /\.md$/i.test(out)) {
      console.error(
        `error: 'analyze' writes JSON (the system model), not Markdown.\n` +
          `  Use:  threatlens report ${target} --output ${out}\n` +
          `  Or:   threatlens analyze ${target} --output system-model.json`,
      );
      process.exit(1);
    }
    const json = runEngine(target);
    if (out) {
      writeFileSync(out, json, "utf-8");
    } else {
      process.stdout.write(json);
      if (!json.endsWith("\n")) {
        process.stdout.write("\n");
      }
    }
    return;
  }

  if (cmd === "threats") {
    const ollamaEnabled =
      Boolean(process.env.OLLAMA_MODEL?.trim()) ||
      process.env.THREATLENS_LLM === "ollama";
    if (!ollamaEnabled && !process.env.ANTHROPIC_API_KEY) {
      console.error("Set ANTHROPIC_API_KEY or OLLAMA_MODEL (with Ollama running)");
      process.exit(1);
    }
    const raw = runEngine(target);
    const model = JSON.parse(raw) as unknown;
    const threats = await generateThreats(model);
    const text = JSON.stringify(threats, null, 2);
    if (out) {
      writeFileSync(out, text, "utf-8");
    } else {
      console.log(text);
    }
    return;
  }

  if (cmd === "report") {
    const ollamaEnabled =
      Boolean(process.env.OLLAMA_MODEL?.trim()) ||
      process.env.THREATLENS_LLM === "ollama";
    if (!ollamaEnabled && !process.env.ANTHROPIC_API_KEY) {
      console.error("Set ANTHROPIC_API_KEY or OLLAMA_MODEL (with Ollama running)");
      process.exit(1);
    }
    const projectRoot = resolve(target);
    const raw = runEngine(target);
    const model = JSON.parse(raw) as Record<string, unknown>;
    const title = flags.title?.trim() || "Threat assessment";
    const threats = await generateThreats(model);
    const includeDeep = !flags.noDeepDive;
    let deepDiveById: Record<string, string> | undefined;
    if (includeDeep) {
      try {
        deepDiveById = await runDeepDiveEnrichment(model, threats, {});
      } catch (e) {
        console.error(
          "warning: deep-dive enrichment failed; report will omit LLM deep-dives.\n",
          e instanceof Error ? e.message : e,
        );
      }
    }
    const { delta, snapshot } = reportDeltaFromModel(projectRoot, model, threats);
    const reportOpts = {
      deepDiveById,
      includeReferenceAppendix: !flags.noAppendix,
      delta,
    };
    const md = buildThreatAssessmentMarkdown(
      model,
      threats,
      { title, projectRoot },
      reportOpts,
    );
    const dest = resolveReportDestination(projectRoot, out);
    mkdirSync(dirname(dest), { recursive: true });
    writeFileSync(dest, md, "utf-8");
    console.error(`Wrote ${dest}`);
    if (!flags.noHtml) {
      const htmlPath = siblingHtmlFromMdPath(dest);
      const html = buildThreatAssessmentHTML(
        model,
        threats,
        { title, projectRoot },
        reportOpts,
      );
      mkdirSync(dirname(htmlPath), { recursive: true });
      writeFileSync(htmlPath, html, "utf-8");
      console.error(`Wrote ${htmlPath}`);
    }
    try {
      saveBaseline(projectRoot, snapshot);
      console.error(`Wrote ${join(projectRoot, ".threatlensai", "baseline.json")}`);
    } catch (e) {
      console.error(
        "warning: could not write baseline.json\n",
        e instanceof Error ? e.message : e,
      );
    }
    return;
  }

  usage();
}

main().catch((e) => {
  console.error(e instanceof Error ? e.message : e);
  process.exit(1);
});
