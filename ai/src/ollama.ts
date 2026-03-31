import { parseJsonObjectFromModelText } from "./jsonUtils.js";
import { normalizeThreatPayload } from "./normalize.js";
import { ThreatOutputSchema, type ThreatOutput } from "./schemas.js";

export type OllamaThreatOptions = {
  host?: string;
  model: string;
  systemPrompt: string;
  userContent: string;
  maxTokens?: number;
};

export async function callOllamaChat(opts: OllamaThreatOptions): Promise<string> {
  const host = (opts.host ?? process.env.OLLAMA_HOST ?? "http://127.0.0.1:11434").replace(
    /\/$/,
    "",
  );
  const url = `${host}/api/chat`;
  const body = {
    model: opts.model,
    messages: [
      { role: "system", content: opts.systemPrompt },
      { role: "user", content: opts.userContent },
    ],
    stream: false,
    options: {
      num_predict: opts.maxTokens ?? 16_384,
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

export function parseThreatJsonFromAssistant(text: string): ThreatOutput {
  let parsed: unknown;
  try {
    parsed = parseJsonObjectFromModelText(text);
  } catch (e) {
    throw new Error(`failed to parse threat JSON from model: ${e}`);
  }
  return ThreatOutputSchema.parse(normalizeThreatPayload(parsed));
}
