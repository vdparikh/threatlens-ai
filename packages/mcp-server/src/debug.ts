/**
 * MCP uses stdout for JSON-RPC. Debug lines must go to stderr only.
 */
export function mcpDebugEnabled(): boolean {
  const v = process.env.THREATLENS_MCP_DEBUG;
  return v === "1" || v === "true" || v === "yes";
}

export function mcpDebugLog(message: string): void {
  if (!mcpDebugEnabled()) {
    return;
  }
  const line = `[threatlensai-mcp] ${new Date().toISOString()} ${message}\n`;
  process.stderr.write(line);
}
