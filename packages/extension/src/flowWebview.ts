import * as vscode from "vscode";

export function showArchitectureFlowWebview(
  webview: vscode.Webview,
  mermaidSource: string,
): string {
  const m = JSON.stringify(mermaidSource);
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src ${webview.cspSource} https://cdn.jsdelivr.net 'unsafe-inline'; script-src https://cdn.jsdelivr.net 'unsafe-inline'; img-src data: https:;">
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
  <title>ThreatLens — Architecture flow</title>
</head>
<body class="container-fluid py-3">
  <h5 class="mb-2">Architecture &amp; trust flow</h5>
  <p class="text-muted small mb-3">
    Generated from the Go engine (HTTP routes, data-store hints). Use with STRIDE / threat findings.
    Re-run <strong>ThreatLens: Analyze Workspace</strong> or open the JSON to refresh.
  </p>
  <div id="wrap" class="border rounded p-3 bg-body-secondary overflow-auto"></div>
  <script src="https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.min.js"></script>
  <script>
    (function () {
      const src = ${m};
      const el = document.getElementById('wrap');
      const pre = document.createElement('pre');
      pre.className = 'mermaid';
      pre.textContent = src;
      el.appendChild(pre);
      mermaid.initialize({ startOnLoad: false, securityLevel: 'strict', theme: 'default' });
      mermaid.run({ nodes: [pre] }).catch(function (e) {
        el.innerHTML = '<p class="text-danger">Could not render diagram.</p><pre class="small"></pre>';
        el.querySelector('pre').textContent = String(e) + '\\n' + src;
      });
    })();
  </script>
</body>
</html>`;
}
