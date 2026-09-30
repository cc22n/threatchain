DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>AgentGate - Governance & Permission Dashboard</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <script src="https://unpkg.com/htmx.org@1.9.10"></script>
  <style>
    body { background-color: #0b0f19; color: #e2e8f0; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; }
  </style>
</head>
<body class="p-6">
  <div class="max-w-7xl mx-auto space-y-6">
    <!-- Header -->
    <div class="flex items-center justify-between border-b border-slate-800 pb-4">
      <div>
        <h1 class="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
          <span class="text-cyan-400">&#9881;</span> AgentGate
          <span class="text-xs bg-cyan-950 text-cyan-400 border border-cyan-800 px-2 py-0.5 rounded">v0.3.0</span>
        </h1>
        <p class="text-sm text-slate-400">Deterministic PEP/PDP Permission Harness & Human-in-the-Loop Orchestration</p>
      </div>
      <div class="flex items-center gap-3">
        <input id="api-key" type="password" placeholder="X-API-Key" autocomplete="off"
               class="bg-slate-900 border border-slate-700 rounded px-2 py-1 text-xs w-40 text-slate-200">
        <span class="inline-block w-2.5 h-2.5 bg-emerald-500 rounded-full animate-pulse"></span>
        <span class="text-xs text-emerald-400 font-semibold">PILOT ACTIVE: ThreatChain</span>
      </div>
    </div>

    <!-- Metrics Cards -->
    <div id="metrics-cards" class="grid grid-cols-1 md:grid-cols-4 gap-4" hx-get="/agentgate/api/metrics-cards" hx-trigger="load, every 5s">
      <div class="bg-slate-900 border border-slate-800 p-4 rounded-lg">
        <div class="text-xs text-slate-400">Total Invocations</div>
        <div class="text-2xl font-bold text-white mt-1">--</div>
      </div>
      <div class="bg-slate-900 border border-slate-800 p-4 rounded-lg">
        <div class="text-xs text-slate-400">Denial Rate</div>
        <div class="text-2xl font-bold text-rose-400 mt-1">--%</div>
      </div>
      <div class="bg-slate-900 border border-slate-800 p-4 rounded-lg">
        <div class="text-xs text-slate-400">Masked Sensitive Calls</div>
        <div class="text-2xl font-bold text-amber-400 mt-1">--</div>
      </div>
      <div class="bg-slate-900 border border-slate-800 p-4 rounded-lg">
        <div class="text-xs text-slate-400">Pending HITL Approvals</div>
        <div class="text-2xl font-bold text-cyan-400 mt-1">--</div>
      </div>
    </div>

    <!-- Main Grid -->
    <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
      <!-- Left Column: Pending HITL Queue -->
      <div class="lg:col-span-1 bg-slate-900 border border-slate-800 rounded-lg p-4">
        <div class="flex items-center justify-between border-b border-slate-800 pb-3 mb-4">
          <h2 class="text-sm font-bold uppercase tracking-wider text-slate-300">Human Approvals Queue</h2>
          <span class="text-xs text-slate-500">Auto-refresh 3s</span>
        </div>
        <div id="pending-queue" hx-get="/agentgate/api/pending-html" hx-trigger="load, every 3s">
          <p class="text-xs text-slate-500">Loading pending requests...</p>
        </div>
      </div>

      <!-- Right Column: Live Audit Feed -->
      <div class="lg:col-span-2 bg-slate-900 border border-slate-800 rounded-lg p-4">
        <div class="flex items-center justify-between border-b border-slate-800 pb-3 mb-4">
          <h2 class="text-sm font-bold uppercase tracking-wider text-slate-300">Audit Stream (Append-Only)</h2>
          <span class="text-xs text-slate-500">Auto-refresh 5s</span>
        </div>
        <div id="audit-feed" class="overflow-x-auto" hx-get="/agentgate/api/decisions-html" hx-trigger="load, every 5s">
          <p class="text-xs text-slate-500">Loading audit feed...</p>
        </div>
      </div>
    </div>

    <!-- Bottom: Manifests Explorer -->
    <div class="bg-slate-900 border border-slate-800 rounded-lg p-4">
      <h2 class="text-sm font-bold uppercase tracking-wider text-slate-300 mb-3">Registered Agent Manifests</h2>
      <div id="manifests-view" hx-get="/agentgate/api/manifests-html" hx-trigger="load">
        <p class="text-xs text-slate-500">Loading agent manifests...</p>
      </div>
    </div>
  </div>
  <script>
    // The key lives only in sessionStorage and is sent as X-API-Key on every htmx request.
    const keyInput = document.getElementById("api-key");
    try { keyInput.value = sessionStorage.getItem("agentgate_key") || ""; } catch (e) {}
    keyInput.addEventListener("change", () => {
      try { sessionStorage.setItem("agentgate_key", keyInput.value); } catch (e) {}
      location.reload();
    });
    document.body.addEventListener("htmx:configRequest", (evt) => {
      evt.detail.headers["X-API-Key"] = keyInput.value;
    });

    async function saveManifest(agent) {
      const ta = document.getElementById("editor-" + agent);
      const statusEl = document.getElementById("status-" + agent);
      const key = keyInput.value;
      statusEl.className = "text-cyan-400 text-xs mt-2";
      statusEl.textContent = "Saving...";
      try {
        const parsed = JSON.parse(ta.value);
        const resp = await fetch("/agentgate/api/manifests/" + encodeURIComponent(agent), {
          method: "PUT",
          headers: { "Content-Type": "application/json", "X-API-Key": key },
          body: JSON.stringify(parsed)
        });
        const data = await resp.json();
        if (!resp.ok) {
          statusEl.className = "text-rose-400 text-xs mt-2";
          statusEl.textContent = "Error (" + resp.status + "): " + (data.detail || JSON.stringify(data));
        } else {
          statusEl.className = "text-emerald-400 text-xs mt-2";
          statusEl.textContent = "Saved! Version: " + data.version;
          ta.value = JSON.stringify(data.manifest, null, 2);
        }
      } catch (err) {
        statusEl.className = "text-rose-400 text-xs mt-2";
        statusEl.textContent = "JSON Syntax Error: " + err.message;
      }
    }
  </script>
</body>
</html>
"""
