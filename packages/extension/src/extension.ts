import * as vscode from "vscode";
import { showArchitectureFlowWebview } from "./flowWebview.js";
import { runThreatlensEngine, threatlensRepoRoot } from "./engineRunner.js";
import { registerReportChat } from "./reportChatCommand.js";

export function activate(context: vscode.ExtensionContext): void {
  const analyze = vscode.commands.registerCommand("threatlens.analyzeWorkspace", () => {
    const folder = vscode.workspace.workspaceFolders?.[0];
    if (!folder) {
      void vscode.window.showWarningMessage("Open a folder workspace first.");
      return;
    }
    const root = folder.uri.fsPath;
    const repoRoot = threatlensRepoRoot(__dirname);
    let out: string;
    try {
      out = runThreatlensEngine(repoRoot, root);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      void vscode.window.showErrorMessage(`ThreatLens: ${msg}`);
      return;
    }
    void vscode.workspace
      .openTextDocument({
        content: out,
        language: "json",
      })
      .then((doc) => vscode.window.showTextDocument(doc));
  });

  const flow = vscode.commands.registerCommand("threatlens.showArchitectureFlow", () => {
    const folder = vscode.workspace.workspaceFolders?.[0];
    if (!folder) {
      void vscode.window.showWarningMessage("Open a folder workspace first.");
      return;
    }
    const root = folder.uri.fsPath;
    const repoRoot = threatlensRepoRoot(__dirname);
    let out: string;
    try {
      out = runThreatlensEngine(repoRoot, root);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      void vscode.window.showErrorMessage(`ThreatLens: ${msg}`);
      return;
    }
    let model: { mermaid_flow?: string };
    try {
      model = JSON.parse(out) as { mermaid_flow?: string };
    } catch {
      void vscode.window.showErrorMessage("ThreatLens: engine output was not valid JSON.");
      return;
    }
    const m = model.mermaid_flow?.trim();
    if (!m) {
      void vscode.window.showInformationMessage(
        "No Mermaid flow yet (no Go routes detected, or analysis empty). Try a Go HTTP service or check engine output JSON.",
      );
      return;
    }
    const panel = vscode.window.createWebviewPanel(
      "threatlensArchitectureFlow",
      "ThreatLens: Architecture flow",
      vscode.ViewColumn.Beside,
      { enableScripts: true, retainContextWhenHidden: true },
    );
    panel.webview.html = showArchitectureFlowWebview(panel.webview, m);
  });

  registerReportChat(context);

  context.subscriptions.push(analyze, flow);
}

export function deactivate(): void {}
