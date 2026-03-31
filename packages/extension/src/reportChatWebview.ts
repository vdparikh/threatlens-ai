import * as vscode from "vscode";

/**
 * Self-contained chat UI: Bootstrap 5 + marked (CDN). LLM calls run in the extension host only.
 */
export function buildReportChatWebviewHtml(webview: vscode.Webview): string {
  const csp = [
    "default-src 'none'",
    `style-src ${webview.cspSource} https://cdn.jsdelivr.net 'unsafe-inline'`,
    `font-src https://cdn.jsdelivr.net`,
    `img-src ${webview.cspSource} data: https:`,
    "script-src https://cdn.jsdelivr.net 'unsafe-inline'",
  ].join("; ");

  return `<!DOCTYPE html>
<html lang="en" data-bs-theme="dark">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <meta http-equiv="Content-Security-Policy" content="${csp}">
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
  <title>ThreatLens — Chat with report</title>
  <style>
    :root {
      --tl-accent: #58a6ff;
      --tl-bg: #0d1117;
      --tl-surface: #161b22;
      --tl-border: #30363d;
    }
    body {
      min-height: 100vh;
      background: linear-gradient(165deg, #0d1117 0%, #0f1419 40%, #0a0e14 100%);
      font-family: ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
    }
    .tl-hero {
      border-bottom: 1px solid var(--tl-border);
      background: rgba(22, 27, 34, 0.85);
      backdrop-filter: blur(8px);
    }
    .tl-brand {
      letter-spacing: -0.02em;
      font-weight: 600;
      background: linear-gradient(90deg, #58a6ff, #a371f7);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      background-clip: text;
    }
    .tl-report-card {
      max-height: 140px;
      overflow: auto;
      font-size: 0.75rem;
      line-height: 1.4;
      border: 1px solid var(--tl-border);
      background: var(--tl-surface);
      border-radius: 0.5rem;
      white-space: pre-wrap;
      word-break: break-word;
    }
    #chatScroll {
      min-height: 220px;
      max-height: calc(100vh - 380px);
      overflow-y: auto;
      scroll-behavior: smooth;
    }
    .bubble-user {
      background: linear-gradient(135deg, #1f6feb 0%, #388bfd 100%);
      color: #fff;
      border-radius: 1rem 1rem 0.25rem 1rem;
      max-width: 92%;
      margin-left: auto;
    }
    .bubble-assistant {
      background: var(--tl-surface);
      border: 1px solid var(--tl-border);
      border-radius: 1rem 1rem 1rem 0.25rem;
      max-width: 96%;
    }
    .bubble-assistant .markdown-body { font-size: 0.9rem; }
    .bubble-assistant .markdown-body pre {
      background: #010409;
      border: 1px solid var(--tl-border);
      border-radius: 0.375rem;
      padding: 0.5rem 0.75rem;
      overflow-x: auto;
    }
    .bubble-assistant .markdown-body code {
      background: rgba(110, 118, 129, 0.2);
      padding: 0.1rem 0.35rem;
      border-radius: 0.25rem;
      font-size: 0.85em;
    }
    .chip {
      cursor: pointer;
      font-size: 0.75rem;
      border-radius: 999px;
      padding: 0.25rem 0.65rem;
      border: 1px solid var(--tl-border);
      background: transparent;
      color: #8b949e;
      transition: color 0.15s, border-color 0.15s, background 0.15s;
    }
    .chip:hover {
      color: var(--tl-accent);
      border-color: rgba(88, 166, 255, 0.5);
      background: rgba(88, 166, 255, 0.08);
    }
    .tl-input-wrap {
      border: 1px solid var(--tl-border);
      border-radius: 0.75rem;
      background: var(--tl-surface);
      transition: border-color 0.2s, box-shadow 0.2s;
    }
    .tl-input-wrap:focus-within {
      border-color: rgba(88, 166, 255, 0.6);
      box-shadow: 0 0 0 3px rgba(88, 166, 255, 0.12);
    }
    textarea.tl-input {
      resize: none;
      min-height: 44px;
      max-height: 160px;
      border: none !important;
      background: transparent !important;
      color: #e6edf3;
    }
    textarea.tl-input:focus { box-shadow: none !important; }
    .typing-dot {
      display: inline-block;
      width: 6px; height: 6px;
      border-radius: 50%;
      background: #8b949e;
      animation: tl-bounce 1.2s infinite ease-in-out both;
    }
    .typing-dot:nth-child(1) { animation-delay: -0.24s; }
    .typing-dot:nth-child(2) { animation-delay: -0.12s; }
    @keyframes tl-bounce {
      0%, 80%, 100% { transform: scale(0.6); opacity: 0.4; }
      40% { transform: scale(1); opacity: 1; }
    }
  </style>
</head>
<body class="pb-4">
  <div class="tl-hero px-3 py-3 mb-3">
    <div class="d-flex flex-wrap align-items-center justify-content-between gap-2">
      <div>
        <div class="tl-brand fs-5">ThreatLens</div>
        <div class="text-secondary small">Chat with your threat assessment — grounded in the report you load.</div>
      </div>
      <div class="d-flex flex-wrap gap-2">
        <button type="button" class="btn btn-sm btn-outline-primary" id="btnLoadEditor">Active editor</button>
        <button type="button" class="btn btn-sm btn-outline-secondary" id="btnPickFile">Open file…</button>
        <button type="button" class="btn btn-sm btn-outline-info" id="btnLlmSettings" title="threatlens.ollamaModel, anthropicApiKey">LLM settings</button>
        <button type="button" class="btn btn-sm btn-outline-danger" id="btnClear" title="Clear chat only">Clear chat</button>
      </div>
    </div>
    <div class="mt-3">
      <div class="d-flex justify-content-between align-items-baseline mb-1">
        <span class="small text-secondary">Report</span>
        <span class="small font-monospace text-muted" id="reportMeta">No report loaded</span>
      </div>
      <div id="reportPreview" class="tl-report-card p-2 text-muted">Load a Markdown or HTML threat report to begin.</div>
    </div>
    <div class="mt-2 d-flex flex-wrap gap-1" id="quickChips" aria-label="Quick prompts">
      <button type="button" class="chip" data-q="Summarize the top risks in this report in 5 bullets.">Top risks</button>
      <button type="button" class="chip" data-q="What should I fix first, and why?">Fix first</button>
      <button type="button" class="chip" data-q="Explain the STRIDE table: what does each row imply for this codebase?">STRIDE table</button>
      <button type="button" class="chip" data-q="List any delta / NEW / RESOLVED findings and what they mean for our next sprint.">Delta</button>
    </div>
  </div>

  <div class="container-fluid px-3">
    <div id="chatScroll" class="mb-3 d-flex flex-column gap-3"></div>
    <div id="typingRow" class="d-none mb-2">
      <div class="bubble-assistant px-3 py-2 d-inline-flex gap-1 align-items-center">
        <span class="typing-dot"></span><span class="typing-dot"></span><span class="typing-dot"></span>
        <span class="small text-secondary ms-2">Thinking…</span>
      </div>
    </div>
    <div class="tl-input-wrap p-2">
      <textarea class="form-control tl-input shadow-none" id="msg" rows="2" placeholder="Ask about findings, mitigations, or what to verify…"></textarea>
      <div class="d-flex justify-content-between align-items-center px-1 pt-1 pb-1">
        <span class="small text-secondary">Enter sends · Shift+Enter newline</span>
        <button type="button" class="btn btn-primary btn-sm px-4" id="btnSend">Send</button>
      </div>
    </div>
    <p class="small text-secondary mt-2 mb-0">
      The model runs in the extension host. Configure <strong>threatlens.ollamaModel</strong> (local) or <strong>threatlens.anthropicApiKey</strong> / <strong>ANTHROPIC_API_KEY</strong> — not via chat messages.
    </p>
  </div>

  <script src="https://cdn.jsdelivr.net/npm/marked@12/marked.min.js"></script>
  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
  <script>
    (function () {
      const vscode = acquireVsCodeApi();
      let reportText = '';
      let messages = [];

      const elReportPreview = document.getElementById('reportPreview');
      const elReportMeta = document.getElementById('reportMeta');
      const elChat = document.getElementById('chatScroll');
      const elMsg = document.getElementById('msg');
      const elTyping = document.getElementById('typingRow');

      function renderMarkdown(html) {
        if (typeof marked !== 'undefined' && marked.parse) {
          return marked.parse(html, { mangle: false, headerIds: false });
        }
        return '<pre class="mb-0">' + escapeHtml(html) + '</pre>';
      }
      function escapeHtml(s) {
        return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
      }

      function scrollChat() {
        elChat.scrollTop = elChat.scrollHeight;
      }

      function setReport(text, label) {
        reportText = text || '';
        const lines = reportText.split(/\\n/).length;
        const chars = reportText.length;
        elReportMeta.textContent = reportText
          ? (label || 'Loaded') + ' · ' + lines + ' lines · ' + chars + ' chars'
          : 'No report loaded';
        const preview = reportText.slice(0, 1200) + (reportText.length > 1200 ? '\\n…' : '');
        elReportPreview.textContent = preview || 'Load a Markdown or HTML threat report to begin.';
      }

      function appendBubble(role, body, isHtml) {
        const wrap = document.createElement('div');
        wrap.className = role === 'user' ? 'd-flex justify-content-end' : 'd-flex justify-content-start';
        const inner = document.createElement('div');
        inner.className = role === 'user' ? 'bubble-user px-3 py-2' : 'bubble-assistant px-3 py-2 markdown-body';
        if (role === 'user') {
          inner.textContent = body;
        } else {
          inner.innerHTML = isHtml ? body : renderMarkdown(body);
        }
        wrap.appendChild(inner);
        elChat.appendChild(wrap);
        scrollChat();
      }

      function setTyping(on) {
        elTyping.classList.toggle('d-none', !on);
        if (on) scrollChat();
      }

      function sendUser(text) {
        const t = (text || '').trim();
        if (!t) return;
        if (!reportText.trim()) {
          appendBubble('assistant', 'Load a report first (Active editor or Open file).', true);
          return;
        }
        appendBubble('user', t, false);
        messages.push({ role: 'user', content: t });
        elMsg.value = '';
        setTyping(true);
        vscode.postMessage({ type: 'chat', report: reportText, messages: messages });
      }

      document.getElementById('btnSend').addEventListener('click', function () { sendUser(elMsg.value); });
      elMsg.addEventListener('keydown', function (e) {
        if (e.key === 'Enter' && !e.shiftKey) {
          e.preventDefault();
          sendUser(elMsg.value);
        }
      });

      document.getElementById('btnLoadEditor').addEventListener('click', function () {
        vscode.postMessage({ type: 'loadActiveEditor' });
      });
      document.getElementById('btnPickFile').addEventListener('click', function () {
        vscode.postMessage({ type: 'pickFile' });
      });
      document.getElementById('btnLlmSettings').addEventListener('click', function () {
        vscode.postMessage({ type: 'openLlmSettings' });
      });
      document.getElementById('btnClear').addEventListener('click', function () {
        messages = [];
        elChat.innerHTML = '';
        vscode.postMessage({ type: 'telemetry', event: 'clearChat' });
      });

      document.querySelectorAll('.chip').forEach(function (btn) {
        btn.addEventListener('click', function () {
          const q = btn.getAttribute('data-q');
          if (q) {
            elMsg.value = q;
            sendUser(q);
          }
        });
      });

      window.addEventListener('message', function (event) {
        const m = event.data;
        if (!m || typeof m !== 'object') return;
        if (m.type === 'loaded') {
          setReport(m.text || '', m.label || '');
        }
        if (m.type === 'reply') {
          setTyping(false);
          const text = m.text || '';
          messages.push({ role: 'assistant', content: text });
          appendBubble('assistant', text, false);
        }
        if (m.type === 'error') {
          setTyping(false);
          var errWrap = document.createElement('div');
          errWrap.className = 'd-flex justify-content-start';
          var errInner = document.createElement('div');
          errInner.className = 'bubble-assistant px-3 py-2 border-danger';
          errInner.innerHTML = '<p class="text-danger small mb-0">' + escapeHtml(m.message || 'Unknown error') + '</p>';
          errWrap.appendChild(errInner);
          elChat.appendChild(errWrap);
          scrollChat();
        }
      });

      vscode.postMessage({ type: 'ready' });
    })();
  </script>
</body>
</html>`;
}
