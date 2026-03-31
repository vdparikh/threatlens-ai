import Anthropic from "@anthropic-ai/sdk";

export async function anthropicCompleteText(
  system: string,
  user: string,
  options: { model?: string; maxTokens?: number; apiKey: string },
): Promise<string> {
  const model = options.model ?? "claude-sonnet-4-20250514";
  const maxTokens = options.maxTokens ?? 16_384;
  const client = new Anthropic({ apiKey: options.apiKey });
  const msg = await client.messages.create({
    model,
    max_tokens: maxTokens,
    system,
    messages: [{ role: "user", content: user }],
  });
  const block = msg.content.find((b) => b.type === "text");
  if (!block || block.type !== "text") {
    throw new Error("unexpected Anthropic response: no text block");
  }
  return block.text;
}
