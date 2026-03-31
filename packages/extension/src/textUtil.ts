/**
 * Best-effort HTML → plain text for threat reports pasted or opened as .html.
 */
export function stripHtmlToText(html: string): string {
  const s = html
    .replace(/<script[\s\S]*?<\/script>/gi, " ")
    .replace(/<style[\s\S]*?<\/style>/gi, " ")
    .replace(/<br\s*\/?>/gi, "\n")
    .replace(/<\/(p|div|h[1-6]|li|tr)>/gi, "\n")
    .replace(/<[^>]+>/g, " ");
  return s.replace(/[ \t]+\n/g, "\n").replace(/\n{3,}/g, "\n\n").replace(/[ \t]{2,}/g, " ").trim();
}

export function looksLikeHtml(text: string): boolean {
  const t = text.slice(0, 500).trimStart().toLowerCase();
  return t.startsWith("<!doctype html") || t.startsWith("<html") || (t.includes("<body") && t.includes("</"));
}
