/**
 * Multi-turn Q&A over a threat assessment document (Markdown or plain text).
 * Used by the VS Code "Chat with report" webview and other integrations.
 */
import Anthropic from "@anthropic-ai/sdk";

import { type GenerateThreatsOptions, useOllama } from "./llmOptions.js";

export type ReportChatMessage = { role: "user" | "assistant"; content: string };

const REPORT_CHAT_INSTRUCTIONS = `You are a senior application security reviewer helping a developer understand their ThreatLens threat assessment report.

Rules:
- Ground answers in the threat report below. Quote or reference findings (IDs, STRIDE categories, file paths) when relevant.
- If the user asks something not covered in the report, say so clearly; you may still give general secure-engineering guidance if helpful.
- Prefer concise, actionable answers. Use markdown (headings, bullets, \`code\`) when it improves clarity.
- Do not invent findings that are not in the report or in well-known facts about the technologies mentioned.`;

const DEFAULT_REPORT_CAP = 120_000;

function capReport(text: string): string {
  const max = (() => {
    const env = process.env.THREATLENS_REPORT_CHAT_MAX_CHARS;
    const n = env ? parseInt(env, 10) : NaN;
    return Number.isFinite(n) && n > 0 ? n : DEFAULT_REPORT_CAP;
  })();
  if (text.length <= max) {
    return text;
  }
  return `${text.slice(0, max)}\n\n[…report truncated for model context…]`;
}

function buildSystemPrompt(reportText: string): string {
  return `${REPORT_CHAT_INSTRUCTIONS}\n\n---\n\n# Threat report\n\n${capReport(reportText)}`;
}

async function anthropicReportChat(
  system: string,
  messages: ReportChatMessage[],
  apiKey: string,
  opts: GenerateThreatsOptions,
): Promise<string> {
  const model = opts.model ?? "claude-sonnet-4-20250514";
  const maxTokens = opts.maxTokens ?? 8192;
  const client = new Anthropic({ apiKey });
  const msg = await client.messages.create({
    model,
    max_tokens: maxTokens,
    system,
    messages: messages.map((m) => ({
      role: m.role === "assistant" ? "assistant" : "user",
      content: m.content,
    })),
  });
  const block = msg.content.find((b) => b.type === "text");
  if (!block || block.type !== "text") {
    throw new Error("unexpected Anthropic response: no text block");
  }
  return block.text;
}

async function ollamaReportChat(
  system: string,
  messages: ReportChatMessage[],
  opts: GenerateThreatsOptions,
): Promise<string> {
  const host = (opts.ollamaHost ?? process.env.OLLAMA_HOST ?? "http://127.0.0.1:11434").replace(
    /\/$/,
    "",
  );
  const model = opts.ollamaModel ?? process.env.OLLAMA_MODEL ?? "llama3.2";
  const url = `${host}/api/chat`;
  const ollamaMessages = [
    { role: "system" as const, content: system },
    ...messages.map((m) => ({ role: m.role, content: m.content })),
  ];
  const body = {
    model,
    messages: ollamaMessages,
    stream: false,
    options: {
      num_predict: opts.maxTokens ?? 8192,
    },
  };
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const t = await res.text();
    throw new Error(`Ollama HTTP ${res.status}: ${t.slice(0, 500)}`);
  }
  const data = (await res.json()) as {
    message?: { content?: string };
  };
  const content = data.message?.content;
  if (!content || typeof content !== "string") {
    throw new Error("Ollama response missing message.content");
  }
  return content;
}

/**
 * Send a multi-turn conversation about the given report. `messages` must be non-empty
 * and the last message must be from the user.
 */
export async function chatWithThreatReport(
  options: {
    reportText: string;
    messages: ReportChatMessage[];
  } & GenerateThreatsOptions,
): Promise<string> {
  const { reportText, messages, ...llm } = options;
  if (!messages.length) {
    throw new Error("messages must not be empty");
  }
  const last = messages[messages.length - 1];
  if (last.role !== "user") {
    throw new Error("last message must be from the user");
  }
  const trimmedReport = reportText.trim();
  if (!trimmedReport) {
    throw new Error("report text is empty; load a Markdown or HTML report first");
  }
  const system = buildSystemPrompt(trimmedReport);

  if (useOllama(llm)) {
    return ollamaReportChat(system, messages, llm);
  }
  const apiKey = llm.apiKey ?? process.env.ANTHROPIC_API_KEY;
  if (!apiKey) {
    throw new Error(
      "No LLM configured for Chat with report. " +
        "Use VS Code / Cursor settings **threatlens.ollamaModel** (e.g. llama3.2) with `ollama serve`, " +
        "or **threatlens.anthropicApiKey** / env **ANTHROPIC_API_KEY** for Claude. " +
        "Typing `export …` in this chat does not change the extension host; set settings or restart the editor from a shell that already has OLLAMA_MODEL.",
    );
  }
  return anthropicReportChat(system, messages, apiKey, llm);
}
