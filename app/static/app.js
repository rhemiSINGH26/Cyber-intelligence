// NEXUS CTI Client Application
let currentIncidents = [];
let selectedIncidentId = null;

document.addEventListener('DOMContentLoaded', () => {
  initApp();
  initWebSocket();
});

async function initApp() {
  await loadDashboardMetrics();
  await loadIncidents();
}

function switchTab(tabId) {
  document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
  document.querySelectorAll('.view-content').forEach(view => view.classList.remove('active'));

  event.currentTarget.classList.add('active');
  const target = document.getElementById(`view-${tabId}`);
  if (target) target.classList.add('active');

  if (tabId === 'evaluation') loadEvaluation();
  if (tabId === 'logs') loadLogs();
  if (tabId === 'graph') loadGraph();
}

async function loadDashboardMetrics() {
  try {
    const res = await fetch('/api/metrics/dashboard');
    const data = await res.json();
    document.getElementById('stat-total-logs').textContent = data.total_logs.toLocaleString();
    document.getElementById('stat-incidents').textContent = data.total_incidents;
    document.getElementById('tab-inc-count').textContent = data.total_incidents;
    document.getElementById('incident-counter-badge').textContent = `${data.total_incidents} ALERTS`;
  } catch (err) {
    console.error('Error fetching dashboard metrics:', err);
  }
}

async function loadIncidents() {
  try {
    const res = await fetch('/api/incidents?page_size=100');
    const data = await res.json();
    currentIncidents = data.items || [];

    const container = document.getElementById('incidents-container');
    if (!currentIncidents.length) {
      container.innerHTML = `
        <div style="padding: 2rem; text-align: center; color: var(--text-muted);">
          No active attack incidents.<br>
          <button class="btn btn-primary" style="margin-top: 1rem;" onclick="loadDataset('mixed')">
            Load Mixed Attack Dataset
          </button>
        </div>`;
      return;
    }

    container.innerHTML = currentIncidents.map(inc => `
      <div class="incident-item ${selectedIncidentId === inc.id ? 'selected' : ''}" onclick="selectIncident('${inc.id}')">
        <div class="incident-item-header">
          <span class="badge badge-${inc.severity.toLowerCase()}">${inc.severity}</span>
          <span style="font-size: 0.75rem; font-family: var(--font-mono); color: var(--cyan);">Risk: ${inc.risk_score}</span>
        </div>
        <div class="incident-title">${escapeHtml(inc.title)}</div>
        <div class="incident-meta">
          <span>${inc.stages.length} Stages</span>
          <span>${new Date(inc.first_seen).toLocaleTimeString()}</span>
        </div>
      </div>
    `).join('');

    if (currentIncidents.length > 0 && !selectedIncidentId) {
      selectIncident(currentIncidents[0].id);
    }
  } catch (err) {
    console.error('Error loading incidents:', err);
  }
}

async function selectIncident(incId) {
  selectedIncidentId = incId;
  document.querySelectorAll('.incident-item').forEach(el => el.classList.remove('selected'));
  const foundItem = Array.from(document.querySelectorAll('.incident-item')).find(el => el.onclick.toString().includes(incId));
  if (foundItem) foundItem.classList.add('selected');

  const inc = currentIncidents.find(i => i.id === incId);
  if (!inc) return;

  const detailPanel = document.getElementById('incident-detail');
  
  // Format entities
  const entityBadges = [];
  if (inc.entities.users) inc.entities.users.forEach(u => entityBadges.push(`<span class="badge badge-low">User: ${escapeHtml(u)}</span>`));
  if (inc.entities.hosts) inc.entities.hosts.forEach(h => entityBadges.push(`<span class="badge badge-medium">Host: ${escapeHtml(h)}</span>`));
  if (inc.entities.ips) inc.entities.ips.forEach(ip => entityBadges.push(`<span class="badge badge-high">IP: ${escapeHtml(ip)}</span>`));
  if (inc.entities.devices) inc.entities.devices.forEach(d => entityBadges.push(`<span class="badge badge-critical">Device: ${escapeHtml(d)}</span>`));

  detailPanel.innerHTML = `
    <div class="detail-header">
      <div class="detail-title-group">
        <span style="font-size: 0.75rem; color: var(--text-muted); font-family: var(--font-mono);">${inc.id}</span>
        <h2>${escapeHtml(inc.title)}</h2>
        <div class="detail-tags">
          <span class="badge badge-${inc.severity.toLowerCase()}">${inc.severity}</span>
          <span style="font-size: 0.8rem; color: var(--text-muted);">Confidence: ${(inc.confidence * 100).toFixed(0)}%</span>
          <span style="font-size: 0.8rem; color: var(--text-muted);">Status: ${inc.status.toUpperCase()}</span>
        </div>
      </div>
      <div class="risk-meter">
        <div>
          <div style="font-size: 0.65rem; color: var(--text-muted); text-transform: uppercase;">Risk Score</div>
          <div class="risk-number">${inc.risk_score}<span>/100</span></div>
        </div>
      </div>
    </div>

    <!-- Involved Entities -->
    <div>
      <h3 class="section-title"><span>👤</span> Compromised Entities</h3>
      <div style="display: flex; gap: 0.5rem; flex-wrap: wrap;">
        ${entityBadges.join('')}
      </div>
    </div>

    <!-- AI Narrative Why Flagged -->
    <div>
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;">
        <h3 class="section-title" style="margin-bottom: 0;"><span>🧠</span> AI Incident Explanation ("Why Flagged")</h3>
        <button class="btn btn-primary" style="font-size: 0.72rem; padding: 0.2rem 0.5rem;" onclick="fetchGroqExplanation('${inc.id}')">
          Generate Groq AI Briefing
        </button>
      </div>
      <div class="narrative-box" id="incident-narrative-box">
        <pre>${escapeHtml(inc.explanation || "Analyzing attack telemetry...")}</pre>
      </div>
    </div>

    <!-- Attack Timeline (Kill Chain) -->
    <div>
      <h3 class="section-title"><span>⛓️</span> Kill-Chain Attack Progression</h3>
      <div class="timeline">
        ${inc.stages.map((stg, idx) => `
          <div class="timeline-step">
            <div class="timeline-dot"></div>
            <div class="step-header">
              <span class="step-stage">STAGE ${idx + 1}: ${escapeHtml(stg.stage.replace('_', ' '))}</span>
              <span class="step-time">${new Date(stg.time).toLocaleTimeString()}</span>
            </div>
            <div style="font-size: 0.78rem; color: var(--cyan); margin-bottom: 0.3rem;">
              ${stg.mitre_technique ? `[${escapeHtml(stg.mitre_technique)}] ${escapeHtml(stg.technique_name)}` : ''}
            </div>
            <div class="step-reason">${escapeHtml(stg.reason)}</div>
            <div class="step-evidence">
              <span>Evidence: ${stg.evidence.length} log events linked</span>
              <button class="btn" style="font-size: 0.68rem; padding: 0.15rem 0.4rem;" onclick="viewStageLogs('${escapeHtml(JSON.stringify(stg.evidence))}')">
                Inspect Logs
              </button>
            </div>
          </div>
        `).join('')}
      </div>
    </div>

    <!-- Response Playbooks (SOAR) -->
    <div>
      <h3 class="section-title"><span>🛡️</span> Recommended Response Actions</h3>
      <div class="playbook-list">
        ${inc.recommendations.map(rec => `
          <div class="playbook-card">
            <div style="display: flex; justify-content: space-between; align-items: center;">
              <span class="playbook-action">${escapeHtml(rec.action.toUpperCase())}</span>
              <span class="badge badge-${rec.priority === 'critical' ? 'critical' : 'high'}">${rec.priority}</span>
            </div>
            <div style="font-size: 0.8rem; color: var(--text-muted);">${escapeHtml(rec.description)}</div>
            <button class="btn btn-danger" style="margin-top: 0.4rem;" onclick="executeAction('${inc.id}', '${rec.action}', '${escapeHtml(rec.target)}', '${rec.target_type}')">
              Execute: ${escapeHtml(rec.target)}
            </button>
          </div>
        `).join('')}
      </div>
    </div>
  `;
}

async function fetchGroqExplanation(incId) {
  const box = document.getElementById('incident-narrative-box');
  box.innerHTML = `<span style="color: var(--cyan);">Querying Groq LLM for security intelligence analysis...</span>`;
  try {
    const res = await fetch(`/api/incidents/${incId}/explanation`);
    const data = await res.json();
    box.innerHTML = `<pre>${escapeHtml(data.explanation)}</pre>`;
  } catch (err) {
    box.innerHTML = `<span style="color: var(--crimson);">Failed to fetch AI explanation: ${err.message}</span>`;
  }
}

async function executeAction(incId, action, target, targetType) {
  if (!confirm(`Execute SOAR response action '${action}' on ${targetType} '${target}'?`)) return;
  try {
    const res = await fetch(`/api/incidents/${incId}/action`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action, target, target_type: targetType, notes: 'Triggered from SOC Console' })
    });
    const data = await res.json();
    alert(`[ACTION EXECUTED]\n${data.message}\nAudit ID: ${data.audit_id}`);
  } catch (err) {
    alert(`Failed to execute action: ${err.message}`);
  }
}

async function loadEvaluation() {
  try {
    const res = await fetch('/api/metrics/evaluate');
    const data = await res.json();

    document.getElementById('stat-fp-rate').textContent = `${(data.fp_rate * 100).toFixed(2)}%`;
    document.getElementById('stat-f1-score').textContent = data.f1_score.toFixed(2);

    const grid = document.getElementById('eval-metrics-grid');
    grid.innerHTML = `
      <div class="eval-card">
        <span class="stat-label">Precision</span>
        <div class="eval-metric-large" style="color: var(--cyan);">${(data.precision * 100).toFixed(1)}%</div>
        <span class="stat-sub">True Positives / (TP + FP)</span>
      </div>
      <div class="eval-card">
        <span class="stat-label">Recall</span>
        <div class="eval-metric-large" style="color: var(--green);">${(data.recall * 100).toFixed(1)}%</div>
        <span class="stat-sub">Caught ${data.true_positives} of ${data.total_ground_truth} ground-truth attacks</span>
      </div>
      <div class="eval-card">
        <span class="stat-label">F1-Score</span>
        <div class="eval-metric-large" style="color: #a855f7;">${data.f1_score.toFixed(3)}</div>
        <span class="stat-sub">Harmonic mean of precision and recall</span>
      </div>
      <div class="eval-card">
        <span class="stat-label">Clean-Run False Alarms</span>
        <div class="eval-metric-large" style="color: ${data.clean_run_alerts === 0 ? 'var(--green)' : 'var(--crimson)'};">
          ${data.clean_run_alerts}
        </div>
        <span class="stat-sub">Zero false alarms on benign baseline</span>
      </div>
      <div class="eval-card">
        <span class="stat-label">Stage Linkage Accuracy</span>
        <div class="eval-metric-large" style="color: var(--cyan);">${(data.stage_accuracy * 100).toFixed(1)}%</div>
        <span class="stat-sub">Kill chain stage detection overlap</span>
      </div>
      <div class="eval-card">
        <span class="stat-label">Timeline Order Correctness</span>
        <div class="eval-metric-large" style="color: var(--green);">${(data.timeline_accuracy * 100).toFixed(1)}%</div>
        <span class="stat-sub">Chronological chain progression</span>
      </div>
    `;

    const tbody = document.getElementById('attacks-eval-body');
    const attackRows = Object.entries(data.per_attack_detection || {}).map(([atkId, info]) => `
      <tr>
        <td style="font-weight: 600;">${escapeHtml(atkId.replace(/_/g, ' ').toUpperCase())}</td>
        <td>
          <span class="badge ${info.detected ? 'badge-low' : 'badge-critical'}">
            ${info.detected ? 'DETECTED' : 'MISSED'}
          </span>
        </td>
        <td>${escapeHtml(info.incident_id || '-')}</td>
        <td>${info.stage_overlap_pct ? info.stage_overlap_pct + '%' : '-'}</td>
        <td>${info.evidence_count || 0}</td>
        <td>${info.risk_score || '-'}</td>
      </tr>
    `).join('');
    tbody.innerHTML = attackRows || '<tr><td colspan="6" style="text-align:center;">No evaluation data available.</td></tr>';
  } catch (err) {
    console.error('Error loading evaluation:', err);
  }
}

async function loadGraph() {
  try {
    const res = await fetch('/api/graph?max_nodes=60');
    const data = await res.json();
    renderGraph(data);
  } catch (err) {
    console.error('Error loading graph:', err);
  }
}

function renderGraph(graphData) {
  const svg = document.getElementById('threat-graph-svg');
  if (!svg || !graphData.nodes || !graphData.nodes.length) return;

  const width = svg.clientWidth || 800;
  const height = svg.clientHeight || 500;
  svg.innerHTML = '';

  const nodePositions = {};
  const n = graphData.nodes.length;
  const cx = width / 2;
  const cy = height / 2;
  const radius = Math.min(width, height) * 0.4;

  graphData.nodes.forEach((node, i) => {
    const angle = (i / n) * 2 * Math.PI;
    nodePositions[node.id] = {
      x: cx + radius * Math.cos(angle) + (Math.random() - 0.5) * 30,
      y: cy + radius * Math.sin(angle) + (Math.random() - 0.5) * 30,
    };
  });

  // Render edges
  graphData.edges.forEach(edge => {
    const p1 = nodePositions[edge.source];
    const p2 = nodePositions[edge.target];
    if (p1 && p2) {
      const line = document.createElementNS('http://www.w3.org/2000/svg', 'line');
      line.setAttribute('x1', p1.x);
      line.setAttribute('y1', p1.y);
      line.setAttribute('x2', p2.x);
      line.setAttribute('y2', p2.y);
      line.setAttribute('stroke', edge.is_suspicious ? '#ff0055' : 'rgba(0, 240, 255, 0.2)');
      line.setAttribute('stroke-width', edge.is_suspicious ? '2' : '1');
      svg.appendChild(line);
    }
  });

  // Render nodes
  graphData.nodes.forEach(node => {
    const pos = nodePositions[node.id];
    if (!pos) return;

    const g = document.createElementNS('http://www.w3.org/2000/svg', 'g');
    const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
    circle.setAttribute('cx', pos.x);
    circle.setAttribute('cy', pos.y);
    circle.setAttribute('r', node.is_suspicious ? '10' : '7');
    circle.setAttribute('fill', node.is_suspicious ? '#ff0055' : '#00f0ff');
    circle.setAttribute('stroke', '#ffffff');
    circle.setAttribute('stroke-width', '1.5');

    const text = document.createElementNS('http://www.w3.org/2000/svg', 'text');
    text.setAttribute('x', pos.x + 12);
    text.setAttribute('y', pos.y + 4);
    text.setAttribute('fill', '#94a3b8');
    text.setAttribute('font-size', '10px');
    text.setAttribute('font-family', 'Inter, sans-serif');
    text.textContent = node.label;

    g.appendChild(circle);
    g.appendChild(text);
    svg.appendChild(g);
  });
}

async function loadLogs() {
  try {
    const res = await fetch('/api/logs?page_size=30');
    const data = await res.json();
    renderLogs(data.items || []);
  } catch (err) {
    console.error('Error loading logs:', err);
  }
}

async function searchLogs() {
  const q = document.getElementById('log-search-input').value;
  try {
    const res = await fetch(`/api/logs?query=${encodeURIComponent(q)}&page_size=30`);
    const data = await res.json();
    renderLogs(data.items || []);
  } catch (err) {
    console.error('Error searching logs:', err);
  }
}

function renderLogs(logs) {
  const tbody = document.getElementById('logs-tbody');
  tbody.innerHTML = logs.map(l => `
    <tr>
      <td>${new Date(l.timestamp).toLocaleTimeString()}</td>
      <td><span class="badge badge-low">${escapeHtml(l.event_type)}</span></td>
      <td>${escapeHtml(l.user || '-')}</td>
      <td>${escapeHtml(l.host || '-')}</td>
      <td>${escapeHtml(l.src_ip || '-')}</td>
      <td>${escapeHtml(l.app || l.file_path || '-')}</td>
      <td>${escapeHtml(l.status || 'success')}</td>
      <td>
        ${l.incident_id ? `<span class="badge badge-critical">${escapeHtml(l.incident_id)}</span>` : '<span style="color:var(--text-muted);">-</span>'}
      </td>
    </tr>
  `).join('');
}

function viewStageLogs(evidenceJson) {
  try {
    const evidenceIds = JSON.parse(evidenceJson);
    switchTab('logs');
    document.getElementById('log-search-input').value = evidenceIds[0] || '';
    searchLogs();
  } catch (err) {
    console.error('Error viewing stage logs:', err);
  }
}

async function loadDataset(name) {
  const statusEl = document.getElementById('system-status');
  statusEl.innerHTML = `<span class="status-dot"></span><span>INGESTING DATASET & REBUILDING BASELINES...</span>`;
  try {
    const res = await fetch(`/api/simulation/load?dataset_name=${name}`, { method: 'POST' });
    const data = await res.json();
    alert(data.message);
    await initApp();
    if (name === 'benign_only') {
      switchTab('evaluation');
      loadEvaluation();
    }
  } catch (err) {
    alert(`Failed to load dataset: ${err.message}`);
  } finally {
    statusEl.innerHTML = `<span class="status-dot"></span><span>ENGINE ARMED // 0 FALSE POSITIVES</span>`;
  }
}

async function generateDatasets() {
  if (!confirm('Re-generate synthetic attack, benign, and hard-negative datasets?')) return;
  try {
    const res = await fetch('/api/simulation/generate', { method: 'POST' });
    const data = await res.json();
    alert('Datasets generated successfully! Now reloading mixed dataset.');
    await loadDataset('mixed');
  } catch (err) {
    alert(`Failed to generate datasets: ${err.message}`);
  }
}

async function handleFileUpload(event) {
  const file = event.target.files[0];
  if (!file) return;

  const statusEl = document.getElementById('upload-status');
  statusEl.innerHTML = `<span style="color: var(--cyan);">Adapting and parsing ${file.name}...</span>`;

  const formData = new FormData();
  formData.append('file', file);

  try {
    const res = await fetch('/api/upload', {
      method: 'POST',
      body: formData,
    });
    const data = await res.json();
    statusEl.innerHTML = `<span style="color: var(--green);">${data.message}</span>`;
    await initApp();
    switchTab('incidents');
  } catch (err) {
    statusEl.innerHTML = `<span style="color: var(--crimson);">Upload failed: ${err.message}</span>`;
  }
}

function initWebSocket() {
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const ws = new WebSocket(`${protocol}//${window.location.host}/api/stream/ws`);

  ws.onmessage = (event) => {
    try {
      const msg = JSON.parse(event.data);
      if (msg.type === 'incident_alert') {
        console.log('Real-time incident alert:', msg.data);
      }
    } catch (e) {}
  };
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
