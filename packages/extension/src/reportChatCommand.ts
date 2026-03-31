import * as vscode from "vscode";

import { buildReportChatWebviewHtml } from "./reportChatWebview.js";
import { looksLikeHtml, stripHtmlToText } from "./textUtil.js";

type ReportChatMessage = { role: "user" | "assistant"; content: string };

function normalizeReportText(raw: string, fileName: string): string {
  const t = raw.replace(/^\uFEFF/, "");
  const lower = fileName.toLowerCase();
  if (lower.endsWith(".html") || lower.endsWith(".htm") || looksLikeHtml(t)) {
    return stripHtmlToText(t);
  }
  return t;
}

export function registerReportChat(context: vscode.ExtensionContext): void {
  const cmd = vscode.commands.registerCommand("threatlens.chatWithReport", () => {
    const panel = vscode.window.createWebviewPanel(
      "threatlensReportChat",
      "ThreatLens: Chat with report",
      vscode.ViewColumn.Beside,
      {
        enableScripts: true,
        retainContextWhenHidden: true,
      },
    );
    panel.webview.html = buildReportChatWebviewHtml(panel.webview);

    const sendLoaded = (text: string, label: string) => {
      void panel.webview.postMessage({ type: "loaded", text, label });
    };

    const trySendActiveEditor = () => {
      const ed = vscode.window.activeTextEditor;
      if (!ed) {
        return;
      }
      const doc = ed.document;
      const lang = doc.languageId.toLowerCase();
      const name = doc.fileName.split(/[/\\]/).pop() ?? "file";
      if (
        lang !== "markdown" &&
        lang !== "html" &&
        !name.toLowerCase().endsWith(".md") &&
        !name.toLowerCase().match(/\.(html?|htm)$/)
      ) {
        return;
      }
      const raw = doc.getText();
      sendLoaded(normalizeReportText(raw, name), name);
    };

    const sub = panel.webview.onDidReceiveMessage(
      async (msg: { type?: string; report?: string; messages?: ReportChatMessage[] }) => {
        if (!msg || typeof msg !== "object") {
          return;
        }
        if (msg.type === "ready") {
          trySendActiveEditor();
          return;
        }
        if (msg.type === "loadActiveEditor") {
          const ed = vscode.window.activeTextEditor;
          if (!ed) {
            void vscode.window.showWarningMessage("No active editor.");
            return;
          }
          const name = ed.document.fileName.split(/[/\\]/).pop() ?? "file";
          const raw = ed.document.getText();
          sendLoaded(normalizeReportText(raw, name), name);
          return;
        }
        if (msg.type === "pickFile") {
          const uris = await vscode.window.showOpenDialog({
            canSelectMany: false,
            openLabel: "Load report",
            filters: {
              Reports: ["md", "markdown", "html", "htm"],
              "All files": ["*"],
            },
          });
          if (!uris?.[0]) {
            return;
          }
          const buf = await vscode.workspace.fs.readFile(uris[0]);
          const raw = new TextDecoder("utf-8").decode(buf);
          const name = uris[0].fsPath.split(/[/\\]/).pop() ?? "file";
          sendLoaded(normalizeReportText(raw, name), name);
          return;
        }
        if (msg.type === "openLlmSettings") {
          await vscode.commands.executeCommand("workbench.action.openSettings", "threatlens");
          return;
        }
        if (msg.type === "chat") {
          const report = typeof msg.report === "string" ? msg.report : "";
          const messages = Array.isArray(msg.messages) ? msg.messages : [];
          try {
            const { chatWithThreatReport } = await import("@threatlensai/ai");
            const cfg = vscode.workspace.getConfiguration("threatlens");
            const keyFromConfig = cfg.get<string>("anthropicApiKey")?.trim();
            const ollamaModel = cfg.get<string>("ollamaModel")?.trim();
            const ollamaHost = cfg.get<string>("ollamaHost")?.trim();
            const text = await chatWithThreatReport({
              reportText: report,
              messages: messages as ReportChatMessage[],
              apiKey: keyFromConfig || undefined,
              ollamaModel: ollamaModel || undefined,
              ollamaHost: ollamaHost || undefined,
            });
            void panel.webview.postMessage({ type: "reply", text });
          } catch (e) {
            const err = e instanceof Error ? e.message : String(e);
            void panel.webview.postMessage({ type: "error", message: err });
          }
          return;
        }
      },
    );
    panel.onDidDispose(() => sub.dispose());
  });

  context.subscriptions.push(cmd);
}
