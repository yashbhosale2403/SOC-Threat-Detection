/**
 * CyberSentinel AI-Powered SOC Platform - Dashboard Controller
 * Handles real-time polling, Chart.js visual analytics, simulation triggers,
 * and analyst incident containment workflows.
 */

let categoryChartInstance = null;
let ipChartInstance = null;
let detectionChartInstance = null;
let currentLogs = [];
const openInlineDetails = {};
let lastIncidentsJson = "";

// Initialize Dashboard upon DOM Load
document.addEventListener("DOMContentLoaded", () => {
    initCharts();
    refreshAllData();
    // Live update interval every 4 seconds
    setInterval(refreshAllData, 4000);
});


// Tab Navigation
function switchTab(tabId) {
    document.querySelectorAll(".tab-pane").forEach(el => el.classList.remove("active"));
    document.querySelectorAll(".tab-btn").forEach(el => el.classList.remove("active"));

    const targetPane = document.getElementById(`tab-pane-${tabId}`) || document.getElementById(`tab-${tabId}`);
    if (targetPane) targetPane.classList.add("active");

    const activeBtn = Array.from(document.querySelectorAll(".tab-btn")).find(btn => 
        btn.getAttribute("onclick") && btn.getAttribute("onclick").includes(`'${tabId}'`)
    );
    if (activeBtn) activeBtn.classList.add("active");


    if (tabId === 'logs') fetchLogs();
    if (tabId === 'threat-intel') fetchThreatIntel();
    if (tabId === 'incidents') fetchIncidents(true);
    if (tabId === 'rules') fetchRules();
}


// Refresh all live dashboard panels
function refreshAllData() {
    fetchStats();
    fetchAnalytics();
    fetchAlerts();
    fetchIncidents();
    fetchLogs(false);
}

// 1. Fetch KPI Metrics
async function fetchStats() {
    try {
        const res = await fetch("/api/stats/");
        if (!res.ok) return;
        const data = await res.json();

        document.getElementById("kpi-total-logs").innerText = data.total_logs;
        document.getElementById("kpi-active-alerts").innerText = data.active_alerts;
        document.getElementById("kpi-critical-threats").innerText = data.critical_threats;
        document.getElementById("kpi-containment-rate").innerText = `${data.containment_rate}%`;

        const threatLvl = document.getElementById("top-threat-level");
        threatLvl.innerText = data.threat_level;
        if (data.threat_level === "CRITICAL" || data.threat_level === "ELEVATED") {
            threatLvl.style.color = "var(--accent-red)";
        } else if (data.threat_level === "GUARDED") {
            threatLvl.style.color = "var(--accent-amber)";
        } else {
            threatLvl.style.color = "var(--accent-cyan)";
        }
    } catch (e) {
        console.warn("Stats fetch failed:", e);
    }
}

// 2. Initialize Chart.js Graphs
function initCharts() {
    const commonOptions = {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
            legend: {
                labels: { color: "#94a3b8", font: { size: 11 } }
            }
        }
    };

    // Category Doughnut Chart
    const ctxCat = document.getElementById("categoryChart")?.getContext("2d");
    if (ctxCat) {
        categoryChartInstance = new Chart(ctxCat, {
            type: "doughnut",
            data: {
                labels: ["No Active Threats"],
                datasets: [{
                    data: [0],
                    backgroundColor: ["#f87171", "#fbbf24", "#60a5fa", "#c084fc"],
                    borderColor: "#111827",
                    borderWidth: 2
                }]
            },
            options: commonOptions
        });
    }

    // Top Source IPs Bar Chart
    const ctxIp = document.getElementById("ipChart")?.getContext("2d");
    if (ctxIp) {
        ipChartInstance = new Chart(ctxIp, {
            type: "bar",
            data: {
                labels: [],
                datasets: [{
                    label: "Alert Count",
                    data: [],
                    backgroundColor: "#06b6d4",
                    borderRadius: 4
                }]
            },
            options: {
                ...commonOptions,
                scales: {
                    x: { ticks: { color: "#94a3b8" }, grid: { display: false } },
                    y: { ticks: { color: "#94a3b8", precision: 0 }, grid: { color: "rgba(255,255,255,0.05)" } }
                }
            }
        });
    }

    // Detection Method Split Pie Chart
    const ctxDet = document.getElementById("detectionChart")?.getContext("2d");
    if (ctxDet) {
        detectionChartInstance = new Chart(ctxDet, {
            type: "pie",
            data: {
                labels: ["No Detections"],
                datasets: [{
                    data: [0],
                    backgroundColor: ["#3b82f6", "#10b981", "#8b5cf6"],
                    borderColor: "#111827",
                    borderWidth: 2
                }]
            },
            options: commonOptions
        });
    }
}

// 3. Fetch Analytics & Update Charts
async function fetchAnalytics() {
    try {
        const res = await fetch("/api/analytics/");
        if (!res.ok) return;
        const data = await res.json();

        if (categoryChartInstance) {
            const hasData = data.categories && data.categories.labels && data.categories.labels.length > 0;
            categoryChartInstance.data.labels = hasData ? data.categories.labels : ["No Active Threats"];
            categoryChartInstance.data.datasets[0].data = hasData ? data.categories.data : [0];
            categoryChartInstance.update();
        }

        if (ipChartInstance) {
            const hasData = data.top_ips && data.top_ips.labels && data.top_ips.labels.length > 0;
            ipChartInstance.data.labels = hasData ? data.top_ips.labels : [];
            ipChartInstance.data.datasets[0].data = hasData ? data.top_ips.data : [];
            ipChartInstance.update();
        }

        if (detectionChartInstance) {
            const hasData = data.detection_methods && data.detection_methods.labels && data.detection_methods.labels.length > 0;
            detectionChartInstance.data.labels = hasData ? data.detection_methods.labels : ["No Detections"];
            detectionChartInstance.data.datasets[0].data = hasData ? data.detection_methods.data : [0];
            detectionChartInstance.update();
        }
    } catch (e) {
        console.warn("Analytics fetch failed:", e);
    }
}

// 4. Fetch Security Alerts
async function fetchAlerts() {
    try {
        const res = await fetch("/api/alerts/?limit=10");
        if (!res.ok) return;
        const alerts = await res.json();

        const badge = document.getElementById("alert-counter-badge");
        if (badge) badge.innerText = `${alerts.length} Alerts`;

        const tbody = document.getElementById("overview-alerts-body");
        if (!tbody) return;

        if (alerts.length === 0) {
            tbody.innerHTML = `<tr><td colspan="4" style="text-align:center; color: var(--text-dim);">No alerts detected yet.</td></tr>`;
            return;
        }

        let html = "";
        alerts.forEach(a => {
            const sevClass = getSeverityBadgeClass(a.severity);
            html += `
                <tr>
                    <td>
                        <div style="font-weight: 600; font-size: 0.85rem;">${escapeHtml(a.title)}</div>
                        <div style="font-size: 0.72rem; color: var(--text-dim);">${escapeHtml(a.source_ip)} &rarr; ${escapeHtml(a.target_asset)}</div>
                    </td>
                    <td><span class="badge badge-info">${escapeHtml(a.detection_method.replace('_', ' '))}</span></td>
                    <td><span class="badge ${sevClass}">${a.risk_score}/100</span></td>
                    <td class="mono-cell" style="color: var(--text-muted); font-size: 0.75rem;">${a.created_at_formatted.split(' ')[1] || a.created_at_formatted}</td>
                </tr>
            `;
        });
        tbody.innerHTML = html;
    } catch (e) {
        console.warn("Alerts fetch failed:", e);
    }
}

// 5. Fetch Incidents
async function fetchIncidents(forceRender = false) {
    try {
        const res = await fetch("/api/incidents/");
        if (!res.ok) return;
        const incidents = await res.json();

        const incidentsJson = JSON.stringify(incidents);
        if (!forceRender && incidentsJson === lastIncidentsJson) {
            return;
        }
        lastIncidentsJson = incidentsJson;

        // 1. Populate Overview Table
        const overviewTbody = document.getElementById("overview-incidents-body");
        if (overviewTbody) {
            if (incidents.length === 0) {
                overviewTbody.innerHTML = `<tr><td colspan="6" style="text-align:center; color: var(--text-dim);">No active incidents. SOC environment secure.</td></tr>`;
            } else {
                let html = "";
                incidents.slice(0, 5).forEach(inc => {
                    const isBlocked = inc.status === 'CONTAINED';
                    const isAllowed = inc.status === 'RESOLVED';
                    const sevClass = getSeverityBadgeClass(inc.severity);
                    const statusClass = isBlocked ? 'badge-low' : (isAllowed ? 'badge-info' : 'badge-critical');
                    
                    let blockBtn;
                    if (isBlocked) {
                        blockBtn = `<button class="btn-primary" style="background: rgba(225, 29, 72, 0.2); color: #fda4af; border: 1px solid rgba(225, 29, 72, 0.5); padding: 0.3rem 0.55rem; font-size: 0.72rem; border-radius: 4px; cursor: pointer;" onclick="toggleInlineAudit('${inc.incident_id}', 'ov')" title="Threat blocked on firewall. Click to inspect audit log.">Blocked</button>`;
                    } else {
                        blockBtn = `<button class="btn-primary" style="background: linear-gradient(135deg, #e11d48, #be123c); color: #fff; padding: 0.3rem 0.55rem; font-size: 0.72rem; border-radius: 4px; cursor: pointer;" onclick="blockIncidentDirect('${inc.incident_id}')" title="Block attacker IP on firewall">Block</button>`;
                    }

                    let allowBtn;
                    if (isAllowed) {
                        allowBtn = `<button class="btn-success" style="background: rgba(16, 185, 129, 0.2); color: #6ee7b7; border: 1px solid rgba(16, 185, 129, 0.5); padding: 0.3rem 0.55rem; font-size: 0.72rem; border-radius: 4px; cursor: pointer;" onclick="toggleInlineAudit('${inc.incident_id}', 'ov')" title="Traffic whitelisted. Click to inspect audit log.">Allowed</button>`;
                    } else {
                        allowBtn = `<button class="btn-success" style="background: linear-gradient(135deg, #059669, #10b981); color: #fff; padding: 0.3rem 0.55rem; font-size: 0.72rem; border-radius: 4px; cursor: pointer;" onclick="allowIncidentDirect('${inc.incident_id}')" title="Allow / Whitelist IP (False positive)">Allow</button>`;
                    }

                    const askAiBtn = `<button class="btn-primary" style="background: linear-gradient(135deg, #4f46e5, #7c3aed); color: #fff; padding: 0.3rem 0.55rem; font-size: 0.72rem; border-radius: 4px; cursor: pointer;" onclick="toggleInlineAI('${inc.incident_id}', 'ov')" title="Consult Google Gemini AI for 4-line incident assessment">AI Triage</button>`;
                    const detailsBtn = `<button class="btn-primary" style="background: #1e293b; color: #cbd5e1; border: 1px solid #475569; padding: 0.3rem 0.55rem; font-size: 0.72rem; border-radius: 4px; cursor: pointer;" onclick="openIncidentModal('${inc.incident_id}')" title="Open complete incident details & assign analyst modal">Details</button>`;

                    const detailKey = `ov-${inc.incident_id}`;
                    const isDetailOpen = Boolean(openInlineDetails[detailKey]);
                    const detailDisplay = isDetailOpen ? 'table-row' : 'none';
                    const detailContent = isDetailOpen ? openInlineDetails[detailKey].html : '';
                    const detailMode = isDetailOpen ? openInlineDetails[detailKey].mode : '';

                    html += `
                        <tr>
                            <td class="mono-cell" style="font-weight: 700; color: #fff;">
                                <a href="javascript:void(0)" onclick="openIncidentModal('${inc.incident_id}')" style="color: #38bdf8; text-decoration: underline; font-weight: 700; cursor: pointer;" title="Click to view full incident details & assign analyst">${escapeHtml(inc.incident_id)}</a>
                            </td>
                            <td>
                                <div onclick="openIncidentModal('${inc.incident_id}')" style="font-weight: 600; cursor: pointer; color: #f8fafc;" onmouseover="this.style.color='#38bdf8'" onmouseout="this.style.color='#f8fafc'" title="Click to open full incident popup">${escapeHtml(inc.title)}</div>
                                <div style="font-size: 0.72rem; color: var(--accent-cyan); margin-top: 0.2rem;">Assigned: <strong>${escapeHtml(inc.assigned_to || 'Unassigned')}</strong></div>
                            </td>
                            <td class="ip-text">${escapeHtml(inc.source_ip)}</td>
                            <td style="font-size: 0.75rem; color: var(--text-muted);">${escapeHtml(inc.mitre_tactic)}</td>
                            <td><span class="badge ${statusClass}">${inc.status}</span></td>
                            <td><div style="display: flex; gap: 0.35rem; align-items: center; flex-wrap: wrap;">${detailsBtn} ${blockBtn} ${allowBtn} ${askAiBtn}</div></td>
                        </tr>
                        <tr id="inline-details-ov-${inc.incident_id}" style="display: ${detailDisplay};">
                            <td colspan="6" style="padding: 0; border-top: none;"><div id="inline-content-ov-${inc.incident_id}" data-mode="${detailMode}">${detailContent}</div></td>
                        </tr>
                    `;
                });
                overviewTbody.innerHTML = html;
            }
        }

        // 2. Populate Full Incident Management Tab Table
        const fullTbody = document.getElementById("full-incidents-body");
        if (fullTbody) {
            if (incidents.length === 0) {
                fullTbody.innerHTML = `<tr><td colspan="9" style="text-align:center; color: var(--text-dim);">No incidents found.</td></tr>`;
            } else {
                let fullHtml = "";
                incidents.forEach(inc => {
                    const isBlocked = inc.status === 'CONTAINED';
                    const isAllowed = inc.status === 'RESOLVED';
                    const sevClass = getSeverityBadgeClass(inc.severity);
                    const statusClass = isBlocked ? 'badge-low' : (isAllowed ? 'badge-info' : 'badge-critical');
                    
                    let blockBtn;
                    if (isBlocked) {
                        blockBtn = `<button class="btn-primary" style="background: rgba(225, 29, 72, 0.2); color: #fda4af; border: 1px solid rgba(225, 29, 72, 0.5); padding: 0.35rem 0.65rem; font-size: 0.74rem; border-radius: 4px; cursor: pointer;" onclick="toggleInlineAudit('${inc.incident_id}', 'full')" title="Threat blocked on firewall. Click to inspect audit log.">Blocked</button>`;
                    } else {
                        blockBtn = `<button class="btn-primary" style="background: linear-gradient(135deg, #e11d48, #be123c); color: #fff; padding: 0.35rem 0.65rem; font-size: 0.74rem; border-radius: 4px; cursor: pointer;" onclick="blockIncidentDirect('${inc.incident_id}')" title="Block attacker IP on firewall">Block</button>`;
                    }

                    let allowBtn;
                    if (isAllowed) {
                        allowBtn = `<button class="btn-success" style="background: rgba(16, 185, 129, 0.2); color: #6ee7b7; border: 1px solid rgba(16, 185, 129, 0.5); padding: 0.35rem 0.65rem; font-size: 0.74rem; border-radius: 4px; cursor: pointer;" onclick="toggleInlineAudit('${inc.incident_id}', 'full')" title="Traffic whitelisted. Click to inspect audit log.">Allowed</button>`;
                    } else {
                        allowBtn = `<button class="btn-success" style="background: linear-gradient(135deg, #059669, #10b981); color: #fff; padding: 0.35rem 0.65rem; font-size: 0.74rem; border-radius: 4px; cursor: pointer;" onclick="allowIncidentDirect('${inc.incident_id}')" title="Allow / Whitelist IP (False positive)">Allow</button>`;
                    }

                    const askAiBtn = `<button class="btn-primary" style="background: linear-gradient(135deg, #4f46e5, #7c3aed); color: #fff; padding: 0.35rem 0.65rem; font-size: 0.74rem; border-radius: 4px; cursor: pointer;" onclick="toggleInlineAI('${inc.incident_id}', 'full')" title="Consult Google Gemini AI for 4-line incident assessment">AI Triage</button>`;
                    const detailsBtn = `<button class="btn-primary" style="background: #1e293b; color: #cbd5e1; border: 1px solid #475569; padding: 0.35rem 0.65rem; font-size: 0.74rem; border-radius: 4px; cursor: pointer;" onclick="openIncidentModal('${inc.incident_id}')" title="Open complete incident details & assign analyst modal">Details</button>`;

                    const detailKey = `full-${inc.incident_id}`;
                    const isDetailOpen = Boolean(openInlineDetails[detailKey]);
                    const detailDisplay = isDetailOpen ? 'table-row' : 'none';
                    const detailContent = isDetailOpen ? openInlineDetails[detailKey].html : '';
                    const detailMode = isDetailOpen ? openInlineDetails[detailKey].mode : '';

                    fullHtml += `
                        <tr>
                            <td class="mono-cell" style="font-weight: 700; color: #fff;">
                                <a href="javascript:void(0)" onclick="openIncidentModal('${inc.incident_id}')" style="color: #38bdf8; text-decoration: underline; font-weight: 700; cursor: pointer;" title="Click to view full incident details & assign analyst">${escapeHtml(inc.incident_id)}</a>
                            </td>
                            <td>
                                <div onclick="openIncidentModal('${inc.incident_id}')" style="font-weight: 600; cursor: pointer; color: #f8fafc;" onmouseover="this.style.color='#38bdf8'" onmouseout="this.style.color='#f8fafc'" title="Click to open full incident popup">${escapeHtml(inc.title)}</div>
                                <div style="font-size: 0.72rem; color: var(--text-dim);">${escapeHtml(inc.summary)}</div>
                                <div style="font-size: 0.72rem; color: var(--accent-cyan); margin-top: 0.2rem;">Assigned: <strong>${escapeHtml(inc.assigned_to || 'Unassigned')}</strong></div>
                            </td>
                            <td><span class="badge ${sevClass}">${inc.severity}</span></td>
                            <td class="mono-cell" style="font-weight: 700; color: #fff;">${inc.risk_score}/100</td>
                            <td class="ip-text">${escapeHtml(inc.source_ip)}</td>
                            <td style="font-size: 0.8rem;">${escapeHtml(inc.affected_asset)}</td>
                            <td><span class="badge ${statusClass}">${inc.status}</span></td>
                            <td style="font-size: 0.75rem; color: var(--text-muted); max-width: 250px;">${escapeHtml(inc.recommended_action)}</td>
                            <td><div style="display: flex; gap: 0.35rem; align-items: center; flex-wrap: wrap;">${detailsBtn} ${blockBtn} ${allowBtn} ${askAiBtn}</div></td>
                        </tr>
                        <tr id="inline-details-full-${inc.incident_id}" style="display: ${detailDisplay};">
                            <td colspan="9" style="padding: 0; border-top: none;"><div id="inline-content-full-${inc.incident_id}" data-mode="${detailMode}">${detailContent}</div></td>
                        </tr>
                    `;
                });
                fullTbody.innerHTML = fullHtml;
            }
        }
    } catch (e) {
        console.warn("Incidents fetch failed:", e);
    }
}

// 6. Fetch Logs & Filter
async function fetchLogs(renderTable = true) {
    try {
        const res = await fetch("/api/logs/?limit=50");
        if (!res.ok) return;
        currentLogs = await res.json();
        if (renderTable) renderLogsTable(currentLogs);
    } catch (e) {
        console.warn("Logs fetch failed:", e);
    }
}

function renderLogsTable(logs) {
    const tbody = document.getElementById("logs-table-body");
    if (!tbody) return;

    if (logs.length === 0) {
        tbody.innerHTML = `<tr><td colspan="8" style="text-align:center; color: var(--text-dim);">No logs in repository.</td></tr>`;
        return;
    }

    let html = "";
    logs.forEach(l => {
        const sevClass = getSeverityBadgeClass(l.severity);
        html += `
            <tr>
                <td class="mono-cell" style="color: var(--text-dim);">${escapeHtml(l.timestamp_formatted || l.timestamp)}</td>
                <td><span class="badge badge-info">${escapeHtml(l.source)}</span></td>
                <td class="ip-text">${escapeHtml(l.source_ip)}</td>
                <td>${escapeHtml(l.user)}</td>
                <td style="font-weight: 600; font-size: 0.8rem;">${escapeHtml(l.event_type)}</td>
                <td>${escapeHtml(l.target)}</td>
                <td><span class="badge ${sevClass}">${l.severity}</span></td>
                <td><div class="log-snippet">${escapeHtml(l.raw_log.substring(0, 75))}${l.raw_log.length > 75 ? '...' : ''}</div></td>
            </tr>
        `;
    });
    tbody.innerHTML = html;
}

function filterLogs() {
    const q = document.getElementById("log-search-input")?.value.toLowerCase() || "";
    if (!q) {
        renderLogsTable(currentLogs);
        return;
    }
    const filtered = currentLogs.filter(l => 
        l.source_ip.toLowerCase().includes(q) ||
        l.user.toLowerCase().includes(q) ||
        l.event_type.toLowerCase().includes(q) ||
        l.target.toLowerCase().includes(q) ||
        l.raw_log.toLowerCase().includes(q)
    );
    renderLogsTable(filtered);
}

// 7. Fetch Threat Intelligence IOCs
async function fetchThreatIntel() {
    try {
        const res = await fetch("/api/threat-intel/");
        if (!res.ok) return;
        const iocs = await res.json();
        const tbody = document.getElementById("threat-intel-body");
        if (!tbody) return;

        let html = "";
        iocs.forEach(i => {
            html += `
                <tr>
                    <td><span class="badge badge-info">${escapeHtml(i.ioc_type)}</span></td>
                    <td class="ip-text" style="font-weight: 700;">${escapeHtml(i.value)}</td>
                    <td style="font-weight: 600;">${escapeHtml(i.threat_name)}</td>
                    <td style="color: var(--accent-amber);">${escapeHtml(i.threat_actor)}</td>
                    <td><span class="badge badge-high">${i.confidence}% Confidence</span></td>
                    <td><span class="badge badge-critical">Active Malicious</span></td>
                </tr>
            `;
        });
        tbody.innerHTML = html;
    } catch (e) {
        console.warn("Threat Intel fetch failed:", e);
    }
}

// 8. Trigger Live Simulation
async function triggerSimulation(scenario) {
    showToast(`Initiating simulation: ${scenario}...`, "info");
    try {
        const res = await fetch("/api/simulate/", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ scenario: scenario })
        });
        const data = await res.json();
        if (res.ok) {
            showToast(`Simulation executed: ${data.message}`, "success");
            // Immediate UI update
            refreshAllData();
        } else {
            showToast(`Simulation error: ${data.error}`, "error");
        }
    } catch (e) {
        showToast(`Simulation network request failed`, "error");
    }
}

// 9. Inline Incident Actions (Direct in table, no separate popup windows)
async function toggleInlineAI(incidentId, contextPrefix = 'full') {
    const key = `${contextPrefix}-${incidentId}`;
    const row = document.getElementById(`inline-details-${contextPrefix}-${incidentId}`);
    const content = document.getElementById(`inline-content-${contextPrefix}-${incidentId}`);
    if (!row || !content) return;

    if (row.style.display !== "none" && content.dataset.mode === "ai") {
        row.style.display = "none";
        content.dataset.mode = "";
        delete openInlineDetails[key];
        return;
    }

    const loadingHtml = `
        <div style="background: rgba(15, 23, 42, 0.98); border: 1px solid rgba(139, 92, 246, 0.45); border-radius: 8px; padding: 0.9rem 1.15rem; margin: 0.4rem 0;">
            <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 0.5rem;">
                <div style="display: flex; align-items: center; gap: 0.5rem;">
                    <strong style="color: #c084fc; font-size: 0.88rem;">Gemini AI Threat Assessment: ${escapeHtml(incidentId)}</strong>
                    <span class="pulse-dot"></span>
                </div>
                <button class="btn-primary" style="background: #374151; padding: 0.2rem 0.55rem; font-size: 0.72rem;" onclick="closeInlineDetails('${contextPrefix}', '${incidentId}')">Close</button>
            </div>
            <div id="inline-ai-text-${contextPrefix}-${incidentId}" style="color: var(--text-dim); font-size: 0.84rem; padding: 0.35rem 0;">
                Consulting Google Gemini AI for real-time telemetry assessment...
            </div>
        </div>
    `;

    row.style.display = "table-row";
    content.dataset.mode = "ai";
    content.innerHTML = loadingHtml;
    openInlineDetails[key] = {
        mode: "ai",
        html: loadingHtml
    };

    try {
        const res = await fetch("/api/ai-assist/", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ incident_id: incidentId })
        });
        const data = await res.json();

        let rawText = data.analysis_markdown || data.fallback_analysis?.analysis_markdown || "No analysis available.";
        // Clean and ensure maximum 4 lines
        const lines = rawText.split("\n").map(l => l.trim()).filter(l => l.length > 0).slice(0, 4);
        
        const formatted = lines.map(line => {
            return `<div style="margin-bottom: 0.35rem; color: #f1f5f9; font-size: 0.84rem; line-height: 1.6;">${escapeHtml(line)}</div>`;
        }).join("");

        const resultHtml = `
            <div style="background: rgba(15, 23, 42, 0.98); border: 1px solid rgba(139, 92, 246, 0.45); border-radius: 8px; padding: 0.9rem 1.15rem; margin: 0.4rem 0;">
                <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 0.5rem;">
                    <div style="display: flex; align-items: center; gap: 0.5rem;">
                        <strong style="color: #c084fc; font-size: 0.88rem;">Gemini AI Threat Assessment: ${escapeHtml(incidentId)}</strong>
                    </div>
                    <button class="btn-primary" style="background: #374151; padding: 0.2rem 0.55rem; font-size: 0.72rem;" onclick="closeInlineDetails('${contextPrefix}', '${incidentId}')">Close</button>
                </div>
                <div id="inline-ai-text-${contextPrefix}-${incidentId}" style="padding: 0.35rem 0;">
                    <div style="background: rgba(30, 41, 59, 0.75); border-left: 3px solid #a855f7; border-radius: 4px; padding: 0.7rem 0.95rem;">
                        ${formatted}
                    </div>
                    <div style="margin-top: 0.6rem; display: flex; gap: 0.5rem; justify-content: flex-end;">
                        <button class="btn-primary" style="background: linear-gradient(135deg, #e11d48, #be123c); font-size: 0.75rem; padding: 0.35rem 0.75rem; border-radius: 4px; cursor: pointer;" onclick="blockIncidentDirect('${incidentId}')">Block Source IP</button>
                        <button class="btn-success" style="background: linear-gradient(135deg, #059669, #10b981); font-size: 0.75rem; padding: 0.35rem 0.75rem; border-radius: 4px; cursor: pointer;" onclick="allowIncidentDirect('${incidentId}')">Allow Traffic</button>
                    </div>
                </div>
            </div>
        `;

        openInlineDetails[key] = {
            mode: "ai",
            html: resultHtml
        };

        const currentContent = document.getElementById(`inline-content-${contextPrefix}-${incidentId}`);
        if (currentContent) {
            currentContent.innerHTML = resultHtml;
        }
    } catch (e) {
        const errorHtml = `
            <div style="background: rgba(15, 23, 42, 0.98); border: 1px solid rgba(239, 68, 68, 0.45); border-radius: 8px; padding: 0.9rem 1.15rem; margin: 0.4rem 0;">
                <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 0.5rem;">
                    <div style="display: flex; align-items: center; gap: 0.5rem;">
                        <strong style="color: #f87171; font-size: 0.88rem;">Gemini AI Threat Assessment: ${escapeHtml(incidentId)}</strong>
                    </div>
                    <button class="btn-primary" style="background: #374151; padding: 0.2rem 0.55rem; font-size: 0.72rem;" onclick="closeInlineDetails('${contextPrefix}', '${incidentId}')">Close</button>
                </div>
                <div style="color: var(--accent-red); font-size: 0.84rem; padding: 0.35rem 0;">
                    Error retrieving Gemini AI assessment. Please retry.
                </div>
            </div>
        `;
        openInlineDetails[key] = {
            mode: "ai",
            html: errorHtml
        };
        const currentContent = document.getElementById(`inline-content-${contextPrefix}-${incidentId}`);
        if (currentContent) currentContent.innerHTML = errorHtml;
    }
}

// Inline Containment Audit Log (No separate modal window)
async function toggleInlineAudit(incidentId, contextPrefix = 'full') {
    const key = `${contextPrefix}-${incidentId}`;
    const row = document.getElementById(`inline-details-${contextPrefix}-${incidentId}`);
    const content = document.getElementById(`inline-content-${contextPrefix}-${incidentId}`);
    if (!row || !content) return;

    if (row.style.display !== "none" && content.dataset.mode === "audit") {
        row.style.display = "none";
        content.dataset.mode = "";
        delete openInlineDetails[key];
        return;
    }

    const loadingHtml = `
        <div style="background: rgba(15, 23, 42, 0.98); border: 1px solid rgba(16, 185, 129, 0.4); border-radius: 8px; padding: 0.9rem 1.15rem; margin: 0.4rem 0;">
            <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 0.5rem;">
                <strong style="color: #34d399; font-size: 0.88rem;">Containment Execution Audit: ${escapeHtml(incidentId)}</strong>
                <button class="btn-primary" style="background: #374151; padding: 0.2rem 0.55rem; font-size: 0.72rem;" onclick="closeInlineDetails('${contextPrefix}', '${incidentId}')">Close</button>
            </div>
            <div id="inline-audit-text-${contextPrefix}-${incidentId}" style="color: var(--text-dim); font-size: 0.84rem;">
                Loading audit execution log...
            </div>
        </div>
    `;

    row.style.display = "table-row";
    content.dataset.mode = "audit";
    content.innerHTML = loadingHtml;
    openInlineDetails[key] = {
        mode: "audit",
        html: loadingHtml
    };

    try {
        const res = await fetch(`/api/incidents/${incidentId}/`);
        if (!res.ok) return;
        const inc = await res.json();

        let logsHtml = "";
        if (inc.responses && inc.responses.length > 0) {
            inc.responses.forEach(r => {
                logsHtml += `
                    <div style="margin-bottom: 0.5rem;">
                        <div style="font-weight: 600; font-size: 0.8rem; color: var(--accent-cyan);">${escapeHtml(r.action_type_display)} - Status: ${r.status}</div>
                        <div class="log-snippet" style="margin-top: 0.25rem; font-family: var(--font-mono); font-size: 0.78rem;">${escapeHtml(r.execution_log || 'Action executed successfully.')}</div>
                    </div>
                `;
            });
        } else {
            logsHtml = `<div style="color: var(--text-dim);">No response execution logs recorded.</div>`;
        }

        const resultHtml = `
            <div style="background: rgba(15, 23, 42, 0.98); border: 1px solid rgba(16, 185, 129, 0.4); border-radius: 8px; padding: 0.9rem 1.15rem; margin: 0.4rem 0;">
                <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 0.5rem;">
                    <strong style="color: #34d399; font-size: 0.88rem;">Containment Execution Audit: ${escapeHtml(incidentId)}</strong>
                    <button class="btn-primary" style="background: #374151; padding: 0.2rem 0.55rem; font-size: 0.72rem;" onclick="closeInlineDetails('${contextPrefix}', '${incidentId}')">Close</button>
                </div>
                <div id="inline-audit-text-${contextPrefix}-${incidentId}" style="color: var(--text-dim); font-size: 0.84rem;">
                    ${logsHtml}
                </div>
            </div>
        `;

        openInlineDetails[key] = {
            mode: "audit",
            html: resultHtml
        };

        const currentContent = document.getElementById(`inline-content-${contextPrefix}-${incidentId}`);
        if (currentContent) currentContent.innerHTML = resultHtml;
    } catch (e) {
        const errorHtml = `
            <div style="background: rgba(15, 23, 42, 0.98); border: 1px solid rgba(239, 68, 68, 0.4); border-radius: 8px; padding: 0.9rem 1.15rem; margin: 0.4rem 0;">
                <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 0.5rem;">
                    <strong style="color: #f87171; font-size: 0.88rem;">Containment Execution Audit: ${escapeHtml(incidentId)}</strong>
                    <button class="btn-primary" style="background: #374151; padding: 0.2rem 0.55rem; font-size: 0.72rem;" onclick="closeInlineDetails('${contextPrefix}', '${incidentId}')">Close</button>
                </div>
                <div style="color: var(--accent-red); font-size: 0.84rem;">Error loading audit records.</div>
            </div>
        `;
        openInlineDetails[key] = {
            mode: "audit",
            html: errorHtml
        };
        const currentContent = document.getElementById(`inline-content-${contextPrefix}-${incidentId}`);
        if (currentContent) currentContent.innerHTML = errorHtml;
    }
}

function closeInlineDetails(contextPrefix, incidentId) {
    const key = `${contextPrefix}-${incidentId}`;
    delete openInlineDetails[key];
    const row = document.getElementById(`inline-details-${contextPrefix}-${incidentId}`);
    if (row) row.style.display = "none";
    const content = document.getElementById(`inline-content-${contextPrefix}-${incidentId}`);
    if (content) {
        content.dataset.mode = "";
        content.innerHTML = "";
    }
}

function openResponseModal(incidentId) {
    containIncidentDirect(incidentId);
}

// 9b. Direct Incident Containment & Authorization
async function containIncidentDirect(incidentId) {
    showToast(`Enforcing firewall block on ${incidentId}...`, "info");
    try {
        const res = await fetch(`/api/incidents/${incidentId}/contain/`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ analyst_name: "Yash (SOC Analyst)" })
        });
        const data = await res.json();
        if (data.success) {
            showToast(`Incident ${incidentId} blocked on firewall! Threat dropped.`, "success");
            lastIncidentsJson = "";
            refreshAllData();
        } else {
            showToast(`Block failed: ${data.error}`, "error");
        }
    } catch (e) {
        showToast("Block network request failed", "error");
    }
}

function blockIncidentDirect(incidentId) {
    return containIncidentDirect(incidentId);
}

async function allowIncidentDirect(incidentId) {
    showToast(`Authorizing traffic & whitelisting ${incidentId}...`, "info");
    try {
        const res = await fetch(`/api/incidents/${incidentId}/allow/`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ analyst_name: "Yash (SOC Analyst)" })
        });
        const data = await res.json();
        if (data.success) {
            showToast(`Incident ${incidentId} whitelisted and marked as ALLOWED!`, "success");
            lastIncidentsJson = "";
            refreshAllData();
        } else {
            showToast(`Allow action failed: ${data.error}`, "error");
        }
    } catch (e) {
        showToast("Allow network request failed", "error");
    }
}

// 9c. Reset SOC Environment to Baseline
async function resetSOCEnvironment() {
    if (!confirm("Are you sure you want to reset the SOC environment?\n\nThis will clear all simulated logs, alerts, incidents, and responses, and restore a clean baseline state.")) {
        return;
    }
    showToast("Resetting SOC platform to clean baseline...", "info");
    try {
        const res = await fetch("/api/reset/", {
            method: "POST",
            headers: { "Content-Type": "application/json" }
        });
        const data = await res.json();
        if (data.success) {
            for (const k in openInlineDetails) delete openInlineDetails[k];
            lastIncidentsJson = "";
            showToast(data.message, "success");
            refreshAllData();
        } else {
            showToast(`Reset failed: ${data.error || 'Server error'}`, "error");
        }
    } catch (e) {
        showToast("Reset network request failed", "error");
    }
}

// ==========================================================================
// Incident Popup Modal & Employee Assignment Handlers
// ==========================================================================

const SOC_EMPLOYEES = [
    "Unassigned",
    "Yash Bhosle (Lead SOC Analyst)",
    "Alex Rivera (Senior Threat Hunter)",
    "Sarah Chen (Incident Response Lead)",
    "Priya Sharma (Security Operations Analyst)",
    "David Miller (Tier-1 SOC Specialist)"
];

async function openIncidentModal(incidentId) {
    const modal = document.getElementById("incident-detail-modal");
    const titleEl = document.getElementById("modal-inc-title");
    const subTitleEl = document.getElementById("modal-inc-id-subtitle");
    const bodyEl = document.getElementById("incident-modal-body");
    if (!modal || !bodyEl) return;

    bodyEl.innerHTML = `<div style="text-align: center; padding: 2.5rem; color: var(--text-dim);"><span class="pulse-dot"></span> Loading incident ${escapeHtml(incidentId)} telemetry and response records...</div>`;
    modal.classList.add("active");

    try {
        const res = await fetch(`/api/incidents/${incidentId}/`);
        if (!res.ok) {
            bodyEl.innerHTML = `<div style="color: var(--accent-red); padding: 1.5rem;">Failed to load incident details.</div>`;
            return;
        }
        const inc = await res.json();
        renderIncidentModalContent(inc);
    } catch (e) {
        bodyEl.innerHTML = `<div style="color: var(--accent-red); padding: 1.5rem;">Network error fetching incident details.</div>`;
    }
}

function renderIncidentModalContent(inc) {
    const titleEl = document.getElementById("modal-inc-title");
    const subTitleEl = document.getElementById("modal-inc-id-subtitle");
    const bodyEl = document.getElementById("incident-modal-body");
    if (!bodyEl) return;

    if (titleEl) titleEl.innerText = inc.title;
    if (subTitleEl) subTitleEl.innerText = `Incident ID: ${inc.incident_id} | Ingested: ${inc.created_at_formatted || 'Real-time Stream'}`;

    const isBlocked = inc.status === 'CONTAINED';
    const isAllowed = inc.status === 'RESOLVED';
    const sevClass = getSeverityBadgeClass(inc.severity);
    const statusClass = isBlocked ? 'badge-low' : (isAllowed ? 'badge-info' : 'badge-critical');

    // Build employee dropdown options
    const currentAssignee = inc.assigned_to || "Unassigned";
    const employeeOptions = SOC_EMPLOYEES.map(emp => {
        const selected = emp === currentAssignee ? "selected" : "";
        return `<option value="${escapeHtml(emp)}" ${selected}>${escapeHtml(emp)}</option>`;
    }).join("");

    // Build response audit logs
    let auditHtml = "";
    if (inc.responses && inc.responses.length > 0) {
        inc.responses.forEach(r => {
            const isAllow = r.action_type === 'ALLOW_TRAFFIC';
            const actionColor = isAllow ? 'var(--accent-green)' : 'var(--accent-cyan)';
            auditHtml += `
                <div style="background: #080c14; border: 1px solid var(--border-subtle); border-radius: 6px; padding: 0.65rem 0.85rem; margin-bottom: 0.5rem;">
                    <div style="display: flex; justify-content: space-between; align-items: center;">
                        <span style="font-weight: 600; font-size: 0.82rem; color: ${actionColor};">${escapeHtml(r.action_type_display || r.action_type)}</span>
                        <span class="badge ${r.status === 'EXECUTED' ? 'badge-low' : 'badge-warning'}" style="font-size: 0.7rem;">${escapeHtml(r.status)}</span>
                    </div>
                    <div class="log-snippet" style="margin-top: 0.35rem; font-size: 0.76rem;">${escapeHtml(r.execution_log || 'Action executed successfully.')}</div>
                </div>
            `;
        });
    } else {
        auditHtml = `<div style="color: var(--text-dim); font-size: 0.8rem;">No remediation actions executed yet. Choose Block or Allow below.</div>`;
    }

    bodyEl.innerHTML = `
        <!-- 1. Employee Assignment Dropdown Bar -->
        <div style="background: rgba(15, 23, 42, 0.7); border: 1px solid var(--border-subtle); border-radius: 8px; padding: 0.85rem 1.1rem; margin-bottom: 1rem; display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 0.75rem;">
            <div style="display: flex; align-items: center; gap: 0.5rem;">
                <label for="assignee-select-${inc.incident_id}" style="font-size: 0.85rem; font-weight: 600; color: #e2e8f0;">Assigned Analyst / Responder:</label>
            </div>
            <div style="display: flex; align-items: center; gap: 0.65rem; flex-wrap: wrap;">
                <select id="assignee-select-${inc.incident_id}" onchange="assignIncidentEmployee('${inc.incident_id}', this.value)" style="background: #080c14; border: 1px solid var(--accent-cyan); color: #fff; padding: 0.45rem 0.85rem; border-radius: 6px; font-size: 0.85rem; font-weight: 500; cursor: pointer;">
                    ${employeeOptions}
                </select>
                <span id="assignee-badge-${inc.incident_id}" class="badge badge-info" style="font-size: 0.76rem; padding: 0.3rem 0.6rem;">
                    Assigned: ${escapeHtml(currentAssignee)}
                </span>
            </div>
        </div>

        <!-- 2. Metrics & Telemetry Banner -->
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr)); gap: 0.75rem; margin-bottom: 1rem;">
            <div style="background: var(--bg-card); padding: 0.65rem 0.85rem; border-radius: 6px; border: 1px solid var(--border-subtle);">
                <div style="font-size: 0.7rem; color: var(--text-dim); text-transform: uppercase;">Severity</div>
                <div style="margin-top: 0.25rem;"><span class="badge ${sevClass}">${inc.severity}</span></div>
            </div>
            <div style="background: var(--bg-card); padding: 0.65rem 0.85rem; border-radius: 6px; border: 1px solid var(--border-subtle);">
                <div style="font-size: 0.7rem; color: var(--text-dim); text-transform: uppercase;">Risk Score</div>
                <div style="font-size: 1.1rem; font-weight: 700; color: #fff; font-family: var(--font-mono); margin-top: 0.15rem;">${inc.risk_score}/100</div>
            </div>
            <div style="background: var(--bg-card); padding: 0.65rem 0.85rem; border-radius: 6px; border: 1px solid var(--border-subtle);">
                <div style="font-size: 0.7rem; color: var(--text-dim); text-transform: uppercase;">Lifecycle Status</div>
                <div style="margin-top: 0.25rem;"><span class="badge ${statusClass}">${inc.status}</span></div>
            </div>
            <div style="background: var(--bg-card); padding: 0.65rem 0.85rem; border-radius: 6px; border: 1px solid var(--border-subtle);">
                <div style="font-size: 0.7rem; color: var(--text-dim); text-transform: uppercase;">Attacker IP</div>
                <div class="ip-text" style="font-weight: 600; margin-top: 0.25rem;">${escapeHtml(inc.source_ip)}</div>
            </div>
            <div style="background: var(--bg-card); padding: 0.65rem 0.85rem; border-radius: 6px; border: 1px solid var(--border-subtle);">
                <div style="font-size: 0.7rem; color: var(--text-dim); text-transform: uppercase;">Target Asset</div>
                <div style="font-size: 0.85rem; font-weight: 600; color: #fff; margin-top: 0.25rem;">${escapeHtml(inc.affected_asset)}</div>
            </div>
            <div style="background: var(--bg-card); padding: 0.65rem 0.85rem; border-radius: 6px; border: 1px solid var(--border-subtle);">
                <div style="font-size: 0.7rem; color: var(--text-dim); text-transform: uppercase;">MITRE Tactic</div>
                <div style="font-size: 0.82rem; color: var(--accent-amber); font-weight: 600; margin-top: 0.25rem;">${escapeHtml(inc.mitre_tactic)}</div>
            </div>
        </div>

        <!-- 3. Threat Summary & Recommended Action -->
        <div style="background: var(--bg-card); border: 1px solid var(--border-subtle); border-radius: 8px; padding: 0.9rem 1.1rem; margin-bottom: 1rem;">
            <div style="font-size: 0.85rem; font-weight: 600; color: #fff; margin-bottom: 0.35rem;">Threat Summary</div>
            <div style="font-size: 0.82rem; color: var(--text-muted); line-height: 1.5;">${escapeHtml(inc.summary)}</div>
            <div style="margin-top: 0.65rem; padding-top: 0.65rem; border-top: 1px solid rgba(255,255,255,0.06);">
                <span style="font-size: 0.78rem; font-weight: 600; color: var(--accent-cyan);">Recommended Response: </span>
                <span style="font-size: 0.8rem; color: #cbd5e1;">${escapeHtml(inc.recommended_action)}</span>
            </div>
        </div>

        <!-- 4. Interactive Remediation Action Buttons -->
        <div style="background: rgba(15, 23, 42, 0.9); border: 1px solid var(--border-subtle); border-radius: 8px; padding: 0.85rem 1.1rem; margin-bottom: 1rem; display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 0.65rem;">
            <div style="font-size: 0.85rem; font-weight: 600; color: #fff;">Analyst Remediation Actions:</div>
            <div style="display: flex; gap: 0.5rem; flex-wrap: wrap;">
                <button class="btn-primary" style="background: linear-gradient(135deg, #e11d48, #be123c); font-size: 0.8rem; padding: 0.45rem 0.95rem; border-radius: 6px; cursor: pointer;" onclick="modalActionBlock('${inc.incident_id}')">
                    Block Source IP
                </button>
                <button class="btn-success" style="background: linear-gradient(135deg, #059669, #10b981); font-size: 0.8rem; padding: 0.45rem 0.95rem; border-radius: 6px; cursor: pointer;" onclick="modalActionAllow('${inc.incident_id}')">
                    Allow Traffic
                </button>
                <button class="btn-primary" style="background: linear-gradient(135deg, #4f46e5, #7c3aed); font-size: 0.8rem; padding: 0.45rem 0.95rem; border-radius: 6px; cursor: pointer;" onclick="modalRunAI('${inc.incident_id}')">
                    Run Gemini AI Analysis
                </button>
                <button class="btn-primary" style="background: #374151; font-size: 0.8rem; padding: 0.45rem 0.95rem; border-radius: 6px; cursor: pointer;" onclick="closeIncidentModal()">
                    Close
                </button>
            </div>
        </div>

        <!-- 5. Inline Gemini AI Assessment Section inside Modal -->
        <div id="modal-ai-section-${inc.incident_id}" style="background: rgba(30, 41, 59, 0.7); border: 1px solid rgba(139, 92, 246, 0.45); border-radius: 8px; padding: 0.9rem 1.15rem; margin-bottom: 1rem; display: none;">
            <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 0.5rem;">
                <div style="display: flex; align-items: center; gap: 0.5rem;">
                    <strong style="color: #c084fc; font-size: 0.88rem;">Gemini AI Threat Assessment</strong>
                </div>
                <span class="pulse-dot"></span>
            </div>
            <div id="modal-ai-text-${inc.incident_id}" style="font-size: 0.84rem; line-height: 1.6; color: #f1f5f9; padding: 0.35rem 0;">
                Consulting Google Gemini AI for live assessment...
            </div>
        </div>

        <!-- 6. Response Execution Audit Trail -->
        <div style="background: var(--bg-card); border: 1px solid var(--border-subtle); border-radius: 8px; padding: 0.9rem 1.1rem;">
            <div style="font-size: 0.85rem; font-weight: 600; color: #fff; margin-bottom: 0.5rem;">Enforcement Execution Audit Trail</div>
            <div id="modal-audit-trail">${auditHtml}</div>
        </div>
    `;
}

function closeIncidentModal() {
    const modal = document.getElementById("incident-detail-modal");
    if (modal) modal.classList.remove("active");
}

async function assignIncidentEmployee(incidentId, employeeName) {
    showToast(`Assigning ${incidentId} to ${employeeName}...`, "info");
    try {
        const res = await fetch(`/api/incidents/${incidentId}/`, {
            method: "PATCH",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ assigned_to: employeeName })
        });
        const data = await res.json();
        const badge = document.getElementById(`assignee-badge-${incidentId}`);
        if (badge) badge.innerText = `Assigned: ${data.assigned_to || employeeName}`;
        showToast(`Incident ${incidentId} assigned to ${employeeName}!`, "success");
        lastIncidentsJson = "";
        refreshAllData();
    } catch (e) {
        showToast("Failed to assign incident", "error");
    }
}

async function modalActionBlock(incidentId) {
    await containIncidentDirect(incidentId);
    try {
        const res = await fetch(`/api/incidents/${incidentId}/`);
        if (res.ok) {
            const inc = await res.json();
            renderIncidentModalContent(inc);
        }
    } catch (e) {}
}

async function modalActionAllow(incidentId) {
    await allowIncidentDirect(incidentId);
    try {
        const res = await fetch(`/api/incidents/${incidentId}/`);
        if (res.ok) {
            const inc = await res.json();
            renderIncidentModalContent(inc);
        }
    } catch (e) {}
}

async function modalRunAI(incidentId) {
    const aiSec = document.getElementById(`modal-ai-section-${incidentId}`);
    const aiText = document.getElementById(`modal-ai-text-${incidentId}`);
    if (!aiSec || !aiText) return;

    aiSec.style.display = "block";
    aiText.innerHTML = `<span class="pulse-dot"></span> Consulting Google Gemini AI for live 4-line incident assessment...`;

    try {
        const res = await fetch("/api/ai-assist/", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ incident_id: incidentId })
        });
        const data = await res.json();
        let rawText = data.analysis_markdown || data.fallback_analysis?.analysis_markdown || "No analysis available.";
        const lines = rawText.split("\n").map(l => l.trim()).filter(l => l.length > 0).slice(0, 4);
        const formatted = lines.map(line => `<div style="margin-bottom: 0.35rem; color: #f1f5f9; font-size: 0.84rem; line-height: 1.6;">${escapeHtml(line)}</div>`).join("");

        aiText.innerHTML = `
            <div style="background: rgba(30, 41, 59, 0.75); border-left: 3px solid #a855f7; border-radius: 4px; padding: 0.7rem 0.95rem;">
                ${formatted}
            </div>
        `;
    } catch (e) {
        aiText.innerHTML = `<span style="color: var(--accent-red);">Error retrieving Gemini AI assessment.</span>`;
    }
}

async function viewIncidentAudit(incidentId) {
    openIncidentModal(incidentId);
}

function closeModal() {
    closeIncidentModal();
}

// Helpers
function getSeverityBadgeClass(sev) {
    switch (sev) {
        case 'CRITICAL': return 'badge-critical';
        case 'HIGH': return 'badge-high';
        case 'MEDIUM': return 'badge-medium';
        case 'LOW': return 'badge-low';
        default: return 'badge-info';
    }
}

function showToast(message, type = "info") {
    const container = document.getElementById("toast-container");
    if (!container) return;
    const toast = document.createElement("div");
    toast.className = "toast";
    if (type === "error") toast.style.borderLeftColor = "var(--accent-red)";
    if (type === "success") toast.style.borderLeftColor = "var(--accent-green)";
    toast.innerText = message;
    container.appendChild(toast);
    setTimeout(() => {
        toast.remove();
    }, 4500);
}

function escapeHtml(str) {
    if (!str) return "";
    return String(str)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

/* ==========================================================================
   Gemini AI SOC Copilot & Incident Triage Handlers
   ========================================================================== */

// 1. Run Live AI Analysis in Dedicated Tab (Direct, Integrated Gemini Engine)
async function runAIAssist(targetIncidentId = null) {
    const placeholder = document.getElementById("ai-placeholder");
    const loading = document.getElementById("ai-loading");
    const results = document.getElementById("ai-results");
    const content = document.getElementById("ai-markdown-content");
    const sourceBadge = document.getElementById("ai-result-source");
    const timeSpan = document.getElementById("ai-result-timestamp");

    if (placeholder) placeholder.style.display = "none";
    if (results) results.style.display = "none";
    if (loading) loading.style.display = "block";

    try {
        const res = await fetch("/api/ai-assist/", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ incident_id: targetIncidentId })
        });
        const data = await res.json();
        if (loading) loading.style.display = "none";

        let markdownText = "";
        if (data.analysis_markdown) {
            markdownText = data.analysis_markdown;
        } else if (data.fallback_analysis && data.fallback_analysis.analysis_markdown) {
            markdownText = data.fallback_analysis.analysis_markdown;
            showToast("Gemini API error. Showing heuristic analysis.", "error");
        } else {
            markdownText = "No analysis generated. Check API key and network connectivity.";
        }

        // Render Markdown to HTML using marked.js if available, or basic format
        let htmlOutput = "";
        if (window.marked && typeof window.marked.parse === 'function') {
            htmlOutput = window.marked.parse(markdownText);
        } else {
            htmlOutput = markdownText.replace(/\n/g, "<br>");
        }

        if (content) content.innerHTML = htmlOutput;
        if (sourceBadge) sourceBadge.innerText = data.source || "Google Gemini AI";
        if (timeSpan) timeSpan.innerText = data.timestamp || "";
        if (results) results.style.display = "block";

        showToast("AI SOC Threat Assessment complete!", "success");
    } catch (e) {
        if (loading) loading.style.display = "none";
        if (placeholder) placeholder.style.display = "block";
        showToast("Failed to communicate with AI assist API", "error");
    }
}

// 2. Open AI Assist (Routed to inline row or copilot tab, zero popup window)
function openAIAssistModal(incidentId = null) {
    if (incidentId) {
        toggleInlineAI(incidentId, 'full');
    } else {
        switchTab('ai-copilot');
        runAIAssist();
    }
}

function closeAIModal() {
    const modal = document.getElementById("ai-modal");
    if (modal) modal.classList.remove("active");
}
// AI Copilot handlers complete

/* ==========================================================================
   Detection Rules Management Handlers
   ========================================================================== */

async function fetchRules() {
    try {
        const res = await fetch("/api/rules/");
        if (!res.ok) return;
        const rules = await res.json();
        const tbody = document.getElementById("rules-table-body");
        if (!tbody) return;

        if (rules.length === 0) {
            tbody.innerHTML = `<tr><td colspan="9" style="text-align:center; color: var(--text-dim);">No detection rules found. Click "Add Detection Rule" to create one.</td></tr>`;
            return;
        }

        let html = "";
        rules.forEach(r => {
            const sevClass = getSeverityBadgeClass(r.severity);
            const typeBadge = r.is_builtin 
                ? `<span class="badge badge-info" style="font-size: 0.7rem;">Built-in</span>` 
                : `<span class="badge badge-medium" style="background: rgba(6, 182, 212, 0.2); color: var(--accent-cyan); border: 1px solid var(--accent-cyan); font-size: 0.7rem;">Custom</span>`;
            
            const statusBtn = r.is_enabled
                ? `<button class="btn-success" style="padding: 0.25rem 0.6rem; font-size: 0.72rem;" onclick="toggleRuleStatus('${r.rule_id}', true)">Active</button>`
                : `<button class="btn-primary" style="background: #4b5563; padding: 0.25rem 0.6rem; font-size: 0.72rem;" onclick="toggleRuleStatus('${r.rule_id}', false)">Disabled</button>`;

            const deleteBtn = !r.is_builtin
                ? `<button class="btn-primary" style="background: #dc2626; padding: 0.25rem 0.6rem; font-size: 0.72rem;" onclick="deleteRule('${r.rule_id}')">🗑️ Delete</button>`
                : `<span style="font-size: 0.72rem; color: var(--text-dim);">Protected</span>`;

            // Condition logic display
            let logicDesc = [];
            if (r.event_type_match) logicDesc.push(`Event: <code>${escapeHtml(r.event_type_match)}</code>`);
            if (r.keyword_pattern) logicDesc.push(`Keyword: <code>"${escapeHtml(r.keyword_pattern)}"</code>`);
            if (r.threshold_count > 1) logicDesc.push(`Threshold: &gt;=${r.threshold_count} in ${r.time_window_minutes}m`);
            const logicStr = logicDesc.length > 0 ? logicDesc.join(" &bull; ") : "Generic Signature";

            html += `
                <tr>
                    <td class="mono-cell" style="font-weight: 700; color: #fff;">${escapeHtml(r.rule_id)}</td>
                    <td>
                        <div style="font-weight: 600; font-size: 0.85rem;">${escapeHtml(r.name)}</div>
                        <div style="font-size: 0.72rem; color: var(--text-dim); max-width: 320px;">${escapeHtml(r.description)}</div>
                    </td>
                    <td><span class="badge badge-info">${escapeHtml(r.category.replace('_', ' '))}</span></td>
                    <td><span class="badge ${sevClass}">${r.severity}</span></td>
                    <td style="font-size: 0.75rem; color: var(--text-muted);">${logicStr}</td>
                    <td class="mono-cell" style="font-weight: 700; color: #fff;">+${r.risk_weight}</td>
                    <td>${typeBadge}</td>
                    <td>${statusBtn}</td>
                    <td>${deleteBtn}</td>
                </tr>
            `;
        });

        tbody.innerHTML = html;
    } catch (e) {
        console.warn("Rules fetch failed:", e);
    }
}

function openAddRuleModal() {
    const modal = document.getElementById("add-rule-modal");
    if (modal) modal.classList.add("active");
}

function closeAddRuleModal() {
    const modal = document.getElementById("add-rule-modal");
    if (modal) modal.classList.remove("active");
}

async function submitNewRule(event) {
    event.preventDefault();

    const name = document.getElementById("rule-name-input")?.value.trim();
    const severity = document.getElementById("rule-severity-select")?.value;
    const category = document.getElementById("rule-category-select")?.value;
    const event_type_match = document.getElementById("rule-event-type-input")?.value.trim();
    const keyword_pattern = document.getElementById("rule-keyword-input")?.value.trim();
    const threshold_count = parseInt(document.getElementById("rule-threshold-input")?.value || 1);
    const time_window_minutes = parseInt(document.getElementById("rule-window-input")?.value || 5);
    const risk_weight = parseInt(document.getElementById("rule-risk-input")?.value || 30);
    const description = document.getElementById("rule-desc-input")?.value.trim();

    if (!name) {
        showToast("Rule name is required", "error");
        return;
    }

    try {
        const res = await fetch("/api/rules/", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                name,
                severity,
                category,
                event_type_match,
                keyword_pattern,
                threshold_count,
                time_window_minutes,
                risk_weight,
                description
            })
        });

        const data = await res.json();
        if (res.ok) {
            closeAddRuleModal();
            document.getElementById("add-rule-form")?.reset();
            showToast(`Rule ${data.rule.rule_id} created & activated!`, "success");
            fetchRules();
        } else {
            showToast(`Error: ${data.error || "Failed to create rule"}`, "error");
        }
    } catch (e) {
        showToast("Network request failed while saving rule", "error");
    }
}

async function toggleRuleStatus(ruleId, currentStatus) {
    try {
        const res = await fetch(`/api/rules/${ruleId}/`, {
            method: "PATCH",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ is_enabled: !currentStatus })
        });
        if (res.ok) {
            showToast(`Rule ${ruleId} ${!currentStatus ? "activated" : "disabled"}`, "success");
            fetchRules();
        }
    } catch (e) {
        showToast("Failed to toggle rule", "error");
    }
}

async function deleteRule(ruleId) {
    if (!confirm(`Are you sure you want to delete custom rule ${ruleId}?`)) return;

    try {
        const res = await fetch(`/api/rules/${ruleId}/`, {
            method: "DELETE"
        });
        if (res.ok) {
            showToast(`Rule ${ruleId} deleted successfully`, "success");
            fetchRules();
        } else {
            const data = await res.json();
            showToast(data.error || "Cannot delete rule", "error");
        }
    } catch (e) {
        showToast("Failed to delete rule", "error");
    }
}


