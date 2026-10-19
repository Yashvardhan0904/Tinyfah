/**
 * Tinyfah Autonomous Security Harness - Frontend Controller
 * Powered by Server-Sent Events (SSE) for Real-Time CDP & Agent Visibility
 */

const API_BASE = window.location.port === "8000" ? "" : "http://localhost:8000";

let currentEventSource = null;
let allAsvsResults = [];
let activeFilter = "all";

document.addEventListener("DOMContentLoaded", () => {
  initFormHandler();
  initRecentScans();
  initFilterTabs();
  initCopyButtons();
});

// -------------------------------------------------------------
// Scan Launch & SSE Stream Handler
// -------------------------------------------------------------
function initFormHandler() {
  const form = document.getElementById("scan-form");
  const urlInput = document.getElementById("target-url-input");
  const suiteSelect = document.getElementById("suite-select");
  const submitBtn = document.getElementById("start-scan-btn");

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const url = urlInput.value.trim();
    const suite = suiteSelect.value;

    if (!url) return;

    // Reset UI state
    submitBtn.disabled = true;
    submitBtn.querySelector(".button-text").textContent = "Initializing...";
    resetScanViews();

    try {
      const resp = await fetch(`${API_BASE}/api/scans`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url, suite }),
      });

      if (!resp.ok) {
        const err = await resp.json();
        throw new Error(err.detail || "Failed to start scan");
      }

      const scan = await resp.json();
      console.log("Scan initiated:", scan);

      // Start live Server-Sent Events stream
      startSseStream(scan.id);
    } catch (err) {
      alert(`Error starting scan: ${err.message}`);
      submitBtn.disabled = false;
      submitBtn.querySelector(".button-text").textContent = "Launch Security Scan";
    }
  });
}

function startSseStream(scanId) {
  if (currentEventSource) {
    currentEventSource.close();
  }

  const hudSection = document.getElementById("browser-hud-section");
  const feedSection = document.getElementById("execution-feed-section");
  hudSection.style.display = "block";
  feedSection.style.display = "block";

  const streamUrl = `${API_BASE}/api/scans/${scanId}/stream`;
  console.log(`Connecting to SSE stream: ${streamUrl}`);

  currentEventSource = new EventSource(streamUrl);

  currentEventSource.onmessage = (event) => {
    try {
      const data = JSON.parse(event.data);
      handleLiveProgressUpdate(data);

      if (data.status === "completed" || data.status === "failed" || data.status === "not_assessed") {
        console.log("Scan reached terminal status:", data.status);
        if (data.results) {
          renderFinalReport(data.results, data.grade, data.score);
        } else {
          fetchFinalScan(scanId);
        }
        finishScanState();
      }
    } catch (e) {
      console.error("Error parsing SSE event:", e);
    }
  };

  currentEventSource.addEventListener("done", () => {
    console.log("SSE Stream closed by server");
    currentEventSource.close();
    finishScanState();
    fetchFinalScan(scanId);
  });

  currentEventSource.onerror = (err) => {
    console.warn("SSE connection closed or lost. Falling back to poll:", err);
    currentEventSource.close();
    // Fallback single fetch to verify if completed
    setTimeout(() => fetchFinalScan(scanId), 1500);
  };
}

function handleLiveProgressUpdate(data) {
  // 1. Update Browser HUD (Session ID & CDP WebSocket)
  if (data.browser_session) {
    updateBrowserHud(data.browser_session, data.url);
  }

  // 2. Update Live Agent Terminal
  if (data.agent_trace && data.agent_trace.length > 0) {
    renderTerminalTrace(data.agent_trace);
  }

  // 3. Update Step Counter
  const counterEl = document.getElementById("step-counter");
  if (counterEl) {
    counterEl.textContent = `Step ${data.trace_count || (data.agent_trace ? data.agent_trace.length : 0)}`;
  }
}

function updateBrowserHud(session, targetUrl) {
  const hudTargetEl = document.getElementById("hud-target-url");
  const hudSessionIdEl = document.getElementById("hud-session-id");
  const hudCdpUrlEl = document.getElementById("hud-cdp-url");
  const hudStatusDesc = document.getElementById("hud-status-desc");
  const providerBadge = document.getElementById("session-provider-badge");
  const statusBadge = document.getElementById("session-status-badge");
  const copyBtn = document.getElementById("copy-session-btn");

  if (hudTargetEl) hudTargetEl.textContent = targetUrl || session.target_url || "—";
  
  if (session.session_id) {
    hudSessionIdEl.textContent = session.session_id;
    copyBtn.style.display = "inline-flex";
  }

  if (session.cdp_url) {
    hudCdpUrlEl.textContent = session.cdp_url;
  }

  if (session.provider === "tinyfish") {
    providerBadge.textContent = "TinyFish Cloud CDP";
    providerBadge.className = "badge badge-purple";
    hudStatusDesc.textContent = "Cloud container active. Chrome DevTools Protocol attached.";
  } else {
    providerBadge.textContent = "Local Chromium CDP";
    providerBadge.className = "badge badge-cyan";
    hudStatusDesc.textContent = "Local headless Chromium active.";
  }

  if (session.status === "connected") {
    statusBadge.textContent = "CONNECTED";
    statusBadge.className = "badge badge-emerald";
  } else if (session.status === "fallback") {
    statusBadge.textContent = "FALLBACK";
    statusBadge.className = "badge badge-amber";
  }
}

function renderTerminalTrace(trace) {
  const container = document.getElementById("terminal-logs");
  if (!container) return;

  container.innerHTML = "";

  trace.forEach((step) => {
    const item = document.createElement("div");
    const phaseClass = step.phase || "agent";
    item.className = `terminal-step-item ${phaseClass}`;

    const agentName = step.agent || step.tool || "Agent";
    const statusText = (step.status || "executing").toUpperCase();

    let screenshotHtml = "";
    if (step.screenshot) {
      screenshotHtml = `
        <a href="${API_BASE}/screenshots/${step.screenshot}" target="_blank" class="step-screenshot-chip">
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <rect x="3" y="3" width="18" height="18" rx="2" ry="2"/>
            <circle cx="8.5" cy="8.5" r="1.5"/>
            <polyline points="21 15 16 10 5 21"/>
          </svg>
          HUD Screenshot: ${step.screenshot.substring(0, 16)}...
        </a>
      `;
    }

    item.innerHTML = `
      <div class="step-meta-row">
        <span class="step-agent-badge">
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <polyline points="9 11 12 14 22 4"/>
            <path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"/>
          </svg>
          ${agentName}
        </span>
        <span class="step-time">[Step ${step.step}] &bull; ${statusText}</span>
      </div>
      <div class="step-message">${step.observation_preview || step.reason || ""}</div>
      ${screenshotHtml}
    `;

    container.appendChild(item);
  });

  // Auto-scroll terminal
  const terminalBox = document.getElementById("terminal-container");
  if (terminalBox) {
    terminalBox.scrollTop = terminalBox.scrollHeight;
  }
}

async function fetchFinalScan(scanId) {
  try {
    const res = await fetch(`${API_BASE}/api/scans/${scanId}`);
    if (res.ok) {
      const scan = await res.json();
      if (scan.results) {
        renderFinalReport(scan.results, scan.grade, scan.score);
      }
    }
  } catch (e) {
    console.error("Error fetching final scan:", e);
  } finally {
    finishScanState();
  }
}

function finishScanState() {
  const submitBtn = document.getElementById("start-scan-btn");
  if (submitBtn) {
    submitBtn.disabled = false;
    submitBtn.querySelector(".button-text").textContent = "Launch Security Scan";
  }
  const sseTag = document.getElementById("sse-state-tag");
  if (sseTag) {
    sseTag.textContent = "COMPLETED";
    sseTag.style.background = "rgba(16, 185, 129, 0.15)";
    sseTag.style.color = "var(--accent-emerald)";
    sseTag.style.borderColor = "rgba(16, 185, 129, 0.3)";
  }
  initRecentScans();
}

function resetScanViews() {
  document.getElementById("results-section").style.display = "none";
  document.getElementById("terminal-logs").innerHTML = "";
  document.getElementById("hud-session-id").textContent = "Requesting session from TinyFish API...";
  document.getElementById("hud-cdp-url").textContent = "Awaiting WebSocket connection...";
  document.getElementById("session-status-badge").textContent = "CONNECTING";
  document.getElementById("session-status-badge").className = "badge badge-amber pulsing";
}

// -------------------------------------------------------------
// Report & Dashboard Rendering
// -------------------------------------------------------------
function renderFinalReport(results, gradeVal, scoreVal) {
  const resultsSec = document.getElementById("results-section");
  resultsSec.style.display = "flex";

  const grade = gradeVal || results.grade || "F";
  const score = scoreVal !== undefined && scoreVal !== null ? scoreVal : (results.score !== undefined ? results.score : 0);

  // Grade & Score
  const gradeEl = document.getElementById("report-grade");
  const scoreEl = document.getElementById("report-score");
  const ringEl = document.getElementById("grade-ring");

  gradeEl.textContent = grade;
  scoreEl.textContent = score;

  ringEl.className = "grade-ring";
  if (grade === "A") ringEl.classList.add("grade-a");
  else if (grade === "B") ringEl.classList.add("grade-b");
  else if (grade === "C") ringEl.classList.add("grade-c");

  // Metrics
  const metrics = results.metrics || {};
  document.getElementById("metric-total").textContent = metrics.total_requirements || 345;
  document.getElementById("metric-evaluated").textContent = metrics.total_evaluated || 0;
  document.getElementById("metric-passed").textContent = metrics.passed || 0;
  document.getElementById("metric-failed").textContent = metrics.failed || 0;
  document.getElementById("metric-manual").textContent = metrics.manual_verify || 0;

  // Executive Summary (Markdown formatted simple parser)
  const summaryEl = document.getElementById("summary-content");
  if (summaryEl) {
    summaryEl.innerHTML = parseSimpleMarkdown(results.summary || "No executive summary available.");
  }

  // Findings
  renderFindings(results.findings || []);

  // ASVS Matrix
  allAsvsResults = results.asvs_results || [];
  updateMatrixTabCounts();
  renderAsvsMatrixTable();

  // Scroll smoothly to results
  resultsSec.scrollIntoView({ behavior: "smooth" });
}

function renderFindings(findings) {
  const list = document.getElementById("findings-list");
  document.getElementById("findings-count").textContent = findings.length;
  list.innerHTML = "";

  if (findings.length === 0) {
    list.innerHTML = `<div class="scans-empty">No vulnerabilities or critical header omissions detected!</div>`;
    return;
  }

  findings.forEach((f) => {
    const card = document.createElement("div");
    card.className = `finding-item severity-${f.severity || "medium"}`;

    let screenshotHtml = "";
    if (f.screenshot) {
      screenshotHtml = `
        <a href="${API_BASE}/screenshots/${f.screenshot}" target="_blank" class="step-screenshot-chip">
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <rect x="3" y="3" width="18" height="18" rx="2" ry="2"/>
            <circle cx="8.5" cy="8.5" r="1.5"/>
            <polyline points="21 15 16 10 5 21"/>
          </svg>
          DevTools HUD Evidence Screenshot
        </a>
      `;
    }

    card.innerHTML = `
      <div class="finding-header">
        <span class="finding-title">${f.detail || "Security Finding"}</span>
        <span class="badge ${f.severity === 'high' ? 'badge-rose' : 'badge-amber'}">${(f.severity || 'medium').toUpperCase()}</span>
      </div>
      <div class="finding-evidence">ASVS: ${f.asvs || f.requirement_id || "V3"} &bull; Evidence: ${f.evidence || "Observed during scan"}</div>
      ${f.remediation ? `<div class="finding-remediation"><strong>Remediation:</strong> ${f.remediation}</div>` : ""}
      ${screenshotHtml}
    `;

    list.appendChild(card);
  });
}

function renderAsvsMatrixTable() {
  const tbody = document.getElementById("asvs-table-body");
  tbody.innerHTML = "";

  const filtered = allAsvsResults.filter((r) => {
    if (activeFilter === "all") return true;
    return r.status === activeFilter;
  });

  if (filtered.length === 0) {
    tbody.innerHTML = `<tr><td colspan="5" style="text-align:center; color: var(--text-muted); padding: 24px;">No requirements match this filter.</td></tr>`;
    return;
  }

  filtered.forEach((r) => {
    const tr = document.createElement("tr");

    let statusBadgeClass = "badge-amber";
    if (r.status === "PASS") statusBadgeClass = "badge-emerald";
    if (r.status === "FAIL") statusBadgeClass = "badge-rose";

    tr.innerHTML = `
      <td><strong class="font-mono">${r.requirement_id || r.shortcode}</strong></td>
      <td>${r.chapter_name || r.chapter_code || "V1"}</td>
      <td><span class="badge ${statusBadgeClass}">${r.status}</span></td>
      <td><span style="font-size: 0.75rem; text-transform: uppercase; color: var(--text-muted);">${r.severity || "info"}</span></td>
      <td>
        <div style="font-size: 0.82rem; color: #cbd5e1; margin-bottom: 4px;">${r.description || ""}</div>
        <div class="font-mono" style="font-size: 0.75rem; color: #94a3b8;">${r.evidence || ""}</div>
        ${r.remediation ? `<div style="font-size: 0.75rem; color: var(--accent-emerald); margin-top: 4px;">&rarr; ${r.remediation}</div>` : ""}
      </td>
    `;
    tbody.appendChild(tr);
  });
}

function updateMatrixTabCounts() {
  const allCount = allAsvsResults.length;
  const failCount = allAsvsResults.filter(r => r.status === "FAIL").length;
  const passCount = allAsvsResults.filter(r => r.status === "PASS").length;
  const manualCount = allAsvsResults.filter(r => r.status === "MANUAL_VERIFY").length;

  document.getElementById("tab-all-count").textContent = allCount;
  document.getElementById("tab-fail-count").textContent = failCount;
  document.getElementById("tab-pass-count").textContent = passCount;
  document.getElementById("tab-manual-count").textContent = manualCount;
}

function initFilterTabs() {
  const tabs = document.querySelectorAll(".filter-tab");
  tabs.forEach(tab => {
    tab.addEventListener("click", () => {
      tabs.forEach(t => t.classList.remove("active"));
      tab.classList.add("active");
      activeFilter = tab.getAttribute("data-filter");
      renderAsvsMatrixTable();
    });
  });
}

// -------------------------------------------------------------
// Recent Scans History
// -------------------------------------------------------------
async function initRecentScans() {
  const list = document.getElementById("recent-scans-list");
  const refreshBtn = document.getElementById("refresh-scans-btn");

  if (refreshBtn) {
    refreshBtn.onclick = () => initRecentScans();
  }

  try {
    const res = await fetch(`${API_BASE}/api/scans`);
    if (!res.ok) throw new Error("Failed to load scans");

    const scans = await res.json();
    list.innerHTML = "";

    if (!scans || scans.length === 0) {
      list.innerHTML = `<div class="scans-empty">No recent scans recorded yet.</div>`;
      return;
    }

    scans.forEach((scan) => {
      const item = document.createElement("div");
      item.className = "scan-history-item";

      const grade = scan.grade || "—";
      let badgeClass = "badge-rose";
      if (grade === "A") badgeClass = "badge-emerald";
      else if (grade === "B" || grade === "C") badgeClass = "badge-amber";

      item.innerHTML = `
        <div>
          <div class="history-url" title="${scan.url}">${scan.url}</div>
          <div class="history-meta">Scan #${scan.id} &bull; ${scan.status}</div>
        </div>
        <span class="badge ${badgeClass}">${grade}</span>
      `;

      item.onclick = () => {
        if (scan.results) {
          if (scan.results.browser_session) {
            document.getElementById("browser-hud-section").style.display = "block";
            updateBrowserHud(scan.results.browser_session, scan.url);
          }
          if (scan.results.agent_trace) {
            document.getElementById("execution-feed-section").style.display = "block";
            renderTerminalTrace(scan.results.agent_trace);
          }
          renderFinalReport(scan.results, scan.grade, scan.score);
        } else {
          fetchFinalScan(scan.id);
        }
      };

      list.appendChild(item);
    });
  } catch (err) {
    console.error("Failed to load scan history:", err);
  }
}

// -------------------------------------------------------------
// Utilities
// -------------------------------------------------------------
function initCopyButtons() {
  const copyBtn = document.getElementById("copy-session-btn");
  if (copyBtn) {
    copyBtn.addEventListener("click", () => {
      const text = document.getElementById("hud-session-id").textContent;
      navigator.clipboard.writeText(text).then(() => {
        copyBtn.style.color = "var(--accent-emerald)";
        setTimeout(() => copyBtn.style.color = "", 1500);
      });
    });
  }
}

function parseSimpleMarkdown(md) {
  if (!md) return "";
  let html = md
    .replace(/^### (.*$)/gim, '<h4 style="color:var(--accent-cyan); margin: 12px 0 6px;">$1</h4>')
    .replace(/^## (.*$)/gim, '<h3 style="color:#f8fafc; margin: 16px 0 8px;">$1</h3>')
    .replace(/^\*\* (.*$)/gim, '<strong>$1</strong>')
    .replace(/\*\*(.*?)\*\*/gim, '<strong>$1</strong>')
    .replace(/\*(.*?)\*/gim, '<em>$1</em>')
    .replace(/`([^`]+)`/gim, '<code class="font-mono" style="background:rgba(0,0,0,0.4); padding:2px 6px; border-radius:4px; font-size:0.85em; color:var(--accent-cyan);">$1</code>')
    .replace(/\n\n/gim, '</p><p>')
    .replace(/\n/gim, '<br/>');

  return `<p>${html}</p>`;
}
