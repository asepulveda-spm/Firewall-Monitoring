/**
 * Firewall Monitor — Enhanced Front-End Application
 * Features: Health scores, jitter, sparklines, uptime bars, search/filter, sound alerts
 */

// ─── Global State ──────────────────────────────────────────────────────────
const socket = io();
const hostsMap = new Map();
let activeModalHost = null;
let historyChart = null;
let currentRange = '1h';
let logsRange = '24h';
let soundEnabled = true;
let lastScanTime = Date.now();

// DOM Cache
const majorGrid = document.getElementById('majorBranchesGrid');
const satelliteGrid = document.getElementById('satelliteBranchesGrid');
const majorCountEl = document.getElementById('majorCount');
const satelliteCountEl = document.getElementById('satelliteCount');
const headerClockEl = document.getElementById('headerClock');
const statTotalHosts = document.getElementById('statTotalHosts');
const statOnlineCount = document.getElementById('statOnlineCount');
const statAvgHealth = document.getElementById('statAvgHealth');
const statActiveOutages = document.getElementById('statActiveOutages');
const statOutagesCard = document.getElementById('statOutagesCard');
const historyModal = document.getElementById('historyModal');
const closeModalBtn = document.getElementById('closeModal');
const overallLogsModal = document.getElementById('overallLogsModal');
const closeOverallLogsBtn = document.getElementById('closeOverallLogsModal');
const searchInput = document.getElementById('searchInput');
const refreshText = document.getElementById('refreshText');

// ─── Clock & Timers ────────────────────────────────────────────────────────
function startClock() {
  setInterval(() => {
    headerClockEl.textContent = new Date().toLocaleTimeString([], { hour:'2-digit', minute:'2-digit', second:'2-digit' });
  }, 1000);
}

function startDowntimeTicker() {
  setInterval(() => {
    const now = new Date();
    hostsMap.forEach((host, hostname) => {
      if (host.is_down && host.down_since) {
        let ds = host.down_since;
        if (!ds.includes('T')) ds = ds.replace(' ', 'T');
        const diff = Math.max(0, Math.floor((now - new Date(ds)) / 1000));
        host.downtime_duration = diff;
        const el = document.querySelector(`[data-ticker-hostname="${hostname}"]`);
        if (el) el.textContent = formatDuration(diff);
      }
    });
  }, 1000);
}

function startRefreshCountdown() {
  setInterval(() => {
    const elapsed = Math.floor((Date.now() - lastScanTime) / 1000);
    const remaining = Math.max(0, 10 - elapsed);
    refreshText.textContent = `Next scan in ${remaining}s`;
  }, 1000);
}

function formatDuration(seconds) {
  if (!seconds && seconds !== 0) return '--';
  const hrs = Math.floor(seconds / 3600);
  const mins = Math.floor((seconds % 3600) / 60);
  const secs = seconds % 60;
  const pad = n => String(n).padStart(2, '0');
  if (hrs > 0) return `${pad(hrs)}h ${pad(mins)}m ${pad(secs)}s`;
  if (mins > 0) return `${pad(mins)}m ${pad(secs)}s`;
  return `${secs}s`;
}

// ─── Sound Alert ───────────────────────────────────────────────────────────
function playAlertSound() {
  if (!soundEnabled) return;
  try {
    const ctx = new (window.AudioContext || window.webkitAudioContext)();
    const osc = ctx.createOscillator();
    const gain = ctx.createGain();
    osc.connect(gain); gain.connect(ctx.destination);
    osc.type = 'sine'; osc.frequency.value = 880;
    gain.gain.setValueAtTime(0.3, ctx.currentTime);
    gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.5);
    osc.start(); osc.stop(ctx.currentTime + 0.5);
  } catch(e) {}
}

function toggleSound() {
  soundEnabled = !soundEnabled;
  const btn = document.getElementById('soundToggleBtn');
  btn.classList.toggle('muted', !soundEnabled);
  showToast(soundEnabled ? 'Alert sounds enabled' : 'Alert sounds muted', 'warning');
}

// ─── Socket.IO Events ──────────────────────────────────────────────────────
socket.on('host:init', (data) => {
  const host = {
    id: data.host.id,
    hostname: data.host.hostname,
    label: data.host.label,
    console_url: data.host.console_url,
    branch_type: data.host.branch_type,
    recentPings: data.recentPings || [],
    stats: data.stats || { total:0, lost:0, min_ms:null, avg_ms:null, max_ms:null },
    is_down: data.is_down,
    down_since: data.down_since,
    downtime_duration: data.downtime_duration || 0,
    current_state: data.current_state || { alive:true, ping_alive:true, console_alive:true },
    jitter: data.jitter || 0,
    health_score: data.health_score || 100,
  };
  hostsMap.set(host.hostname, host);
  renderFirewallCard(host);
  updateSummaryStats();
});

socket.on('ping:result', (data) => {
  lastScanTime = Date.now();
  const host = hostsMap.get(data.hostname);
  if (!host) return;
  host.recentPings.push({
    timestamp: data.timestamp, latency_ms: data.latency,
    ping_alive: data.ping_alive, console_alive: data.console_alive, alive: data.alive
  });
  if (host.recentPings.length > 60) host.recentPings.shift();
  host.current_state = { alive: data.alive, ping_alive: data.ping_alive, console_alive: data.console_alive };
  host.jitter = data.jitter || 0;
  host.health_score = data.health_score || 100;
  if (host.stats) { host.stats.total++; if (!data.alive) host.stats.lost++; }
  updateCardUI(host, data.latency);
  updateSummaryStats();
  if (activeModalHost === data.hostname) {
    appendHistoryChartPoint(data.timestamp, data.latency, data.alive);
    refreshModalStats(data.hostname);
  }
});

socket.on('host:down', (data) => {
  const host = hostsMap.get(data.hostname);
  if (!host) return;
  host.is_down = true; host.down_since = data.timestamp; host.downtime_duration = 0;
  host.current_state.alive = false;
  const card = document.getElementById(`card-${host.hostname.replace(/\./g, '-')}`);
  if (card) {
    card.classList.add('firewall-card--down');
    let ticker = card.querySelector('.firewall-card__downtime-ticker');
    if (!ticker) {
      ticker = document.createElement('div');
      ticker.className = 'firewall-card__downtime-ticker';
      ticker.innerHTML = `<span class="firewall-card__downtime-label">OFFLINE</span><span class="firewall-card__downtime-value" data-ticker-hostname="${host.hostname}">0s</span>`;
      const details = card.querySelector('.firewall-card__details');
      card.insertBefore(ticker, details);
    }
  }
  playAlertSound();
  showToast(`FIREWALL DOWN: ${host.label}`, 'error');
  updateSummaryStats();
  if (activeModalHost === data.hostname) {
    document.getElementById('modalStatusPill').className = 'status-pill status-pill--down';
    document.getElementById('modalStatusPill').textContent = 'OFFLINE';
    loadDowntimeLogs(host.hostname);
  }
});

socket.on('host:up', (data) => {
  const host = hostsMap.get(data.hostname);
  if (!host) return;
  host.is_down = false; host.down_since = null; host.downtime_duration = 0;
  host.current_state.alive = true;
  const card = document.getElementById(`card-${host.hostname.replace(/\./g, '-')}`);
  if (card) {
    card.classList.remove('firewall-card--down');
    const ticker = card.querySelector('.firewall-card__downtime-ticker');
    if (ticker) ticker.remove();
  }
  showToast(`RECOVERED: ${host.label}`, 'success');
  updateSummaryStats();
  if (activeModalHost === data.hostname) {
    document.getElementById('modalStatusPill').className = 'status-pill status-pill--up';
    document.getElementById('modalStatusPill').textContent = 'ONLINE';
    loadDowntimeLogs(host.hostname);
  }
});

socket.on('host:added', (data) => {
  showToast(`Added: ${data.label}`, 'success');
  setTimeout(() => window.location.reload(), 1000);
});

socket.on('host:removed', (data) => {
  showToast('Firewall removed', 'warning');
  const card = document.getElementById(`card-${data.hostname.replace(/\./g, '-')}`);
  if (card) card.remove();
  hostsMap.delete(data.hostname);
  updateSummaryStats();
});

socket.on('host:updated', (data) => {
  const oldHostname = data.old_hostname;
  const hostData = data.host;
  const oldHost = hostsMap.get(oldHostname);
  if (!oldHost) return;
  if (oldHostname !== hostData.hostname) {
    hostsMap.delete(oldHostname);
    const oldCard = document.getElementById(`card-${oldHostname.replace(/\./g, '-')}`);
    if (oldCard) oldCard.remove();
  }
  const updated = { ...oldHost, id: hostData.id, hostname: hostData.hostname, label: hostData.label, console_url: hostData.console_url, branch_type: hostData.branch_type };
  hostsMap.set(hostData.hostname, updated);
  renderFirewallCard(updated);
  updateSummaryStats();
  showToast(`Updated: ${hostData.label}`, 'success');
  if (activeModalHost === oldHostname) { historyModal.classList.remove('active'); activeModalHost = null; }
});

socket.on('connect', () => {
  document.getElementById('connectionStatus').querySelector('.status-dot').className = 'status-dot';
  document.getElementById('connectionStatus').querySelector('.status-text').textContent = 'Connected';
});
socket.on('disconnect', () => {
  document.getElementById('connectionStatus').querySelector('.status-dot').className = 'status-dot status-dot--off';
  document.getElementById('connectionStatus').querySelector('.status-text').textContent = 'Disconnected';
  showToast('Connection lost', 'error');
});

// ─── Health Score Color ────────────────────────────────────────────────────
function getHealthColor(score) {
  if (score >= 90) return '#10b981';
  if (score >= 70) return '#f59e0b';
  return '#ef4444';
}

function getUptimeClass(pct) {
  if (pct >= 99) return '';
  if (pct >= 90) return 'firewall-card__uptime-fill--warning';
  return 'firewall-card__uptime-fill--critical';
}

// ─── Sparkline Drawing ─────────────────────────────────────────────────────
function drawSparkline(canvas, dataPoints) {
  const ctx = canvas.getContext('2d');
  const w = canvas.width = canvas.offsetWidth * 2;
  const h = canvas.height = 56;
  ctx.clearRect(0, 0, w, h);

  const valid = dataPoints.filter(d => d.latency_ms !== null && d.alive);
  if (valid.length < 2) return;

  const values = valid.map(d => d.latency_ms);
  const maxVal = Math.max(...values, 1);
  const minVal = Math.min(...values, 0);
  const range = maxVal - minVal || 1;

  ctx.beginPath();
  ctx.strokeStyle = 'rgba(59, 130, 246, 0.6)';
  ctx.lineWidth = 1.5;

  for (let i = 0; i < valid.length; i++) {
    const x = (i / (valid.length - 1)) * w;
    const y = h - ((values[i] - minVal) / range) * (h - 4) - 2;
    if (i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
  }
  ctx.stroke();

  // Fill gradient
  const lastX = w;
  const lastY = h - ((values[values.length - 1] - minVal) / range) * (h - 4) - 2;
  ctx.lineTo(lastX, h); ctx.lineTo(0, h); ctx.closePath();
  const grad = ctx.createLinearGradient(0, 0, 0, h);
  grad.addColorStop(0, 'rgba(59, 130, 246, 0.15)');
  grad.addColorStop(1, 'rgba(59, 130, 246, 0.0)');
  ctx.fillStyle = grad; ctx.fill();
}

// ─── Render Card ───────────────────────────────────────────────────────────
function renderFirewallCard(host) {
  const safeId = host.hostname.replace(/\./g, '-');
  const existing = document.getElementById(`card-${safeId}`);
  if (existing) existing.remove();

  const isDown = host.is_down;
  const state = host.current_state;
  const hasConsole = !!host.console_url && host.console_url.includes(':4444');
  const healthScore = host.health_score || 100;
  const circumference = 2 * Math.PI * 15;
  const offset = circumference - (healthScore / 100) * circumference;
  const healthColor = getHealthColor(healthScore);

  // Uptime calc
  let uptimePct = 100;
  if (host.stats && host.stats.total > 0) {
    uptimePct = ((1 - host.stats.lost / host.stats.total) * 100);
  }
  const uptimeClass = getUptimeClass(uptimePct);

  // Latest latency
  let latency = 'N/A';
  if (host.recentPings.length > 0) {
    const last = host.recentPings[host.recentPings.length - 1];
    if (last.alive && last.latency_ms !== null) latency = `${last.latency_ms.toFixed(1)}ms`;
  }

  let downtimeHtml = '';
  if (isDown) {
    downtimeHtml = `<div class="firewall-card__downtime-ticker"><span class="firewall-card__downtime-label">OFFLINE</span><span class="firewall-card__downtime-value" data-ticker-hostname="${host.hostname}">${formatDuration(host.downtime_duration)}</span></div>`;
  }

  const card = document.createElement('div');
  card.id = `card-${safeId}`;
  card.className = `firewall-card ${isDown ? 'firewall-card--down' : ''}`;
  card.dataset.branchType = host.branch_type;
  card.dataset.label = host.label.toLowerCase();
  card.dataset.hostname = host.hostname;

  card.innerHTML = `
    <div class="firewall-card__header">
      <div class="firewall-card__title-grp">
        <span class="firewall-card__name">${host.label}</span>
        <span class="firewall-card__ip">${host.hostname}</span>
      </div>
      <div class="firewall-card__status-group">
        <div class="firewall-card__status">
          <span class="firewall-card__dot ${isDown ? 'firewall-card__dot--down' : 'firewall-card__dot--up'}"></span>
          <span class="firewall-card__label-status ${isDown ? 'firewall-card__label-status--down' : 'firewall-card__label-status--up'}">
            ${isDown ? 'OFFLINE' : 'ONLINE'}
          </span>
        </div>
        <div class="firewall-card__health-ring">
          <svg viewBox="0 0 36 36">
            <circle class="ring-bg" cx="18" cy="18" r="15"/>
            <circle class="ring-fg" cx="18" cy="18" r="15" stroke="${healthColor}"
              stroke-dasharray="${circumference}" stroke-dashoffset="${offset}"/>
          </svg>
          <span class="firewall-card__health-score" data-val="health">${healthScore}</span>
        </div>
      </div>
    </div>
    ${downtimeHtml}
    <div class="firewall-card__sparkline"><canvas data-sparkline="${host.hostname}"></canvas></div>
    <div class="firewall-card__uptime-bar">
      <div class="firewall-card__uptime-header">
        <span class="firewall-card__uptime-label">UPTIME (1H)</span>
        <span class="firewall-card__uptime-pct" data-val="uptime">${uptimePct.toFixed(1)}%</span>
      </div>
      <div class="firewall-card__uptime-track">
        <div class="firewall-card__uptime-fill ${uptimeClass}" style="width:${uptimePct}%" data-val="uptime-bar"></div>
      </div>
    </div>
    <div class="firewall-card__details">
      <div class="firewall-card__detail-item">
        <span class="firewall-card__detail-label">PING</span>
        <span class="firewall-card__detail-val ${state.ping_alive ? 'firewall-card__detail-val--up' : 'firewall-card__detail-val--down'}" data-val="ping-status">${state.ping_alive ? 'UP' : 'DOWN'}</span>
      </div>
      <div class="firewall-card__detail-item">
        <span class="firewall-card__detail-label">CONSOLE</span>
        <span class="firewall-card__detail-val ${!hasConsole ? '' : (state.console_alive ? 'firewall-card__detail-val--up' : 'firewall-card__detail-val--down')}" data-val="console-status">${!hasConsole ? 'N/A' : (state.console_alive ? 'UP' : 'DOWN')}</span>
      </div>
      <div class="firewall-card__detail-item">
        <span class="firewall-card__detail-label">LATENCY</span>
        <span class="firewall-card__detail-val firewall-card__detail-val--mono" data-val="latency">${latency}</span>
      </div>
      <div class="firewall-card__detail-item">
        <span class="firewall-card__detail-label">JITTER</span>
        <span class="firewall-card__detail-val firewall-card__detail-val--mono" data-val="jitter">${host.jitter.toFixed(1)}ms</span>
      </div>
    </div>
    <div class="firewall-card__actions">
      <button class="firewall-card__btn firewall-card__btn--scan" onclick="triggerSingleScan('${host.hostname}', this)" title="Scan now">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" width="11" height="11" class="scan-icon">
          <path d="M21.5 2v6h-6M21.34 15.57a10 10 0 1 1-.57-8.38l5.67-5.67"/>
        </svg>Scan
      </button>
      <button class="firewall-card__btn" onclick="openDetailsModal('${host.hostname}')" title="Details">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" width="11" height="11">
          <polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>
        </svg>History
      </button>
      <a href="${host.console_url && host.console_url.startsWith('http') ? host.console_url : '#'}" target="_blank"
         class="firewall-card__btn firewall-card__btn--console ${host.console_url && host.console_url.startsWith('http') ? '' : 'firewall-card__btn--disabled'}" title="Console">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" width="11" height="11">
          <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/>
          <polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/>
        </svg>Console
      </a>
    </div>
  `;

  if (host.branch_type === 'MAJOR') {
    const loading = majorGrid.querySelector('.grid-loading'); if (loading) loading.remove();
    majorGrid.appendChild(card);
  } else {
    const loading = satelliteGrid.querySelector('.grid-loading'); if (loading) loading.remove();
    satelliteGrid.appendChild(card);
  }

  // Draw sparkline after DOM insertion
  setTimeout(() => {
    const canvas = card.querySelector(`[data-sparkline="${host.hostname}"]`);
    if (canvas && host.recentPings.length > 1) drawSparkline(canvas, host.recentPings);
  }, 50);
}

// ─── Update Card (no full re-render) ──────────────────────────────────────
function updateCardUI(host, latency) {
  const safeId = host.hostname.replace(/\./g, '-');
  const card = document.getElementById(`card-${safeId}`);
  if (!card) return;

  const isDown = host.is_down;
  const state = host.current_state;
  const hasConsole = !!host.console_url && host.console_url.includes(':4444');

  // Status dot & label
  const dot = card.querySelector('.firewall-card__dot');
  if (dot) dot.className = `firewall-card__dot ${isDown ? 'firewall-card__dot--down' : 'firewall-card__dot--up'}`;
  const lbl = card.querySelector('.firewall-card__label-status');
  if (lbl) { lbl.className = `firewall-card__label-status ${isDown ? 'firewall-card__label-status--down' : 'firewall-card__label-status--up'}`; lbl.textContent = isDown ? 'OFFLINE' : 'ONLINE'; }

  // Ping/Console
  const pingEl = card.querySelector('[data-val="ping-status"]');
  if (pingEl) { pingEl.className = `firewall-card__detail-val ${state.ping_alive ? 'firewall-card__detail-val--up' : 'firewall-card__detail-val--down'}`; pingEl.textContent = state.ping_alive ? 'UP' : 'DOWN'; }
  const consEl = card.querySelector('[data-val="console-status"]');
  if (consEl) {
    if (!hasConsole) { consEl.className = 'firewall-card__detail-val'; consEl.textContent = 'N/A'; }
    else { consEl.className = `firewall-card__detail-val ${state.console_alive ? 'firewall-card__detail-val--up' : 'firewall-card__detail-val--down'}`; consEl.textContent = state.console_alive ? 'UP' : 'DOWN'; }
  }

  // Latency & Jitter
  const latEl = card.querySelector('[data-val="latency"]');
  if (latEl) latEl.textContent = (state.ping_alive && latency !== null) ? `${latency.toFixed(1)}ms` : 'N/A';
  const jitEl = card.querySelector('[data-val="jitter"]');
  if (jitEl) jitEl.textContent = `${host.jitter.toFixed(1)}ms`;

  // Health ring
  const healthEl = card.querySelector('[data-val="health"]');
  if (healthEl) healthEl.textContent = host.health_score;
  const ringFg = card.querySelector('.ring-fg');
  if (ringFg) {
    const circ = 2 * Math.PI * 15;
    ringFg.setAttribute('stroke-dashoffset', circ - (host.health_score / 100) * circ);
    ringFg.setAttribute('stroke', getHealthColor(host.health_score));
  }

  // Uptime bar
  let uptimePct = 100;
  if (host.stats && host.stats.total > 0) uptimePct = (1 - host.stats.lost / host.stats.total) * 100;
  const uptimeEl = card.querySelector('[data-val="uptime"]');
  if (uptimeEl) uptimeEl.textContent = `${uptimePct.toFixed(1)}%`;
  const barEl = card.querySelector('[data-val="uptime-bar"]');
  if (barEl) { barEl.style.width = `${uptimePct}%`; barEl.className = `firewall-card__uptime-fill ${getUptimeClass(uptimePct)}`; }

  // Sparkline refresh
  const canvas = card.querySelector(`[data-sparkline="${host.hostname}"]`);
  if (canvas && host.recentPings.length > 1) drawSparkline(canvas, host.recentPings);
}

// ─── Summary Stats ─────────────────────────────────────────────────────────
function updateSummaryStats() {
  const total = hostsMap.size;
  statTotalHosts.textContent = total;
  let online = 0, outages = 0, majorTotal = 0, satTotal = 0, healthSum = 0;

  hostsMap.forEach((host) => {
    if (!host.is_down) online++;
    else outages++;
    if (host.branch_type === 'MAJOR') majorTotal++;
    else satTotal++;
    healthSum += host.health_score || 100;
  });

  statOnlineCount.textContent = `${online} / ${total}`;
  statActiveOutages.textContent = outages;
  statAvgHealth.textContent = total > 0 ? Math.round(healthSum / total) : '--';
  majorCountEl.textContent = `${majorTotal} Devices`;
  satelliteCountEl.textContent = `${satTotal} Devices`;

  if (outages > 0) statOutagesCard.classList.add('stat-card--active-outage');
  else statOutagesCard.classList.remove('stat-card--active-outage');
}

// ─── Search & Filter ───────────────────────────────────────────────────────
searchInput.addEventListener('input', applyFilters);
document.querySelectorAll('.filter-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    applyFilters();
  });
});

function applyFilters() {
  const query = searchInput.value.toLowerCase().trim();
  const activeFilter = document.querySelector('.filter-btn.active').dataset.filter;

  document.querySelectorAll('.firewall-card').forEach(card => {
    const label = card.dataset.label || '';
    const hostname = card.dataset.hostname || '';
    const branchType = (card.dataset.branchType || '').toLowerCase();
    const isDown = card.classList.contains('firewall-card--down');

    let matchSearch = !query || label.includes(query) || hostname.includes(query);
    let matchFilter = true;
    if (activeFilter === 'major') matchFilter = branchType === 'major';
    else if (activeFilter === 'satellite') matchFilter = branchType === 'satellite';
    else if (activeFilter === 'down') matchFilter = isDown;

    card.classList.toggle('hidden', !(matchSearch && matchFilter));
  });
}

// ─── Details Modal ─────────────────────────────────────────────────────────
function openDetailsModal(hostname) {
  const host = hostsMap.get(hostname);
  if (!host) return;
  activeModalHost = hostname;

  const modalTitleView = document.getElementById('modalTitleView');
  const modalTitleEdit = document.getElementById('modalTitleEdit');
  const modalActionsView = document.getElementById('modalActionsView');
  const modalActionsEdit = document.getElementById('modalActionsEdit');

  modalTitleView.style.display = 'block'; modalTitleEdit.style.display = 'none';
  modalActionsView.style.display = 'flex'; modalActionsEdit.style.display = 'none';

  document.getElementById('modalTitle').textContent = `${host.label} Firewall`;
  document.getElementById('modalSubtitle').textContent = `IP: ${host.hostname} | Port: ${host.console_url.includes(':4444') ? '4444' : 'N/A'}`;
  const badge = document.getElementById('modalBranchBadge');
  badge.className = `branch-badge ${host.branch_type === 'MAJOR' ? 'branch-badge--major' : 'branch-badge--satellite'}`;
  badge.textContent = host.branch_type;
  const pill = document.getElementById('modalStatusPill');
  pill.className = `status-pill ${host.is_down ? 'status-pill--down' : 'status-pill--up'}`;
  pill.textContent = host.is_down ? 'OFFLINE' : 'ONLINE';

  const link = document.getElementById('modalConsoleLink');
  if (host.console_url && host.console_url.startsWith('http')) { link.href = host.console_url; link.style.display = 'inline-flex'; }
  else link.style.display = 'none';

  document.getElementById('modalDeleteBtn').onclick = () => removeHost(hostname);
  document.getElementById('modalEditBtn').onclick = () => {
    modalTitleView.style.display = 'none'; modalTitleEdit.style.display = 'block';
    modalActionsView.style.display = 'none'; modalActionsEdit.style.display = 'flex';
    document.getElementById('editLabelInput').value = host.label;
    document.getElementById('editBranchTypeSelect').value = host.branch_type;
    document.getElementById('editUrlInput').value = host.console_url;
  };
  document.getElementById('modalCancelBtn').onclick = () => {
    modalTitleView.style.display = 'block'; modalTitleEdit.style.display = 'none';
    modalActionsView.style.display = 'flex'; modalActionsEdit.style.display = 'none';
  };
  document.getElementById('modalSaveBtn').onclick = async () => {
    const newLabel = document.getElementById('editLabelInput').value.trim();
    const newUrl = document.getElementById('editUrlInput').value.trim();
    const newBranch = document.getElementById('editBranchTypeSelect').value;
    if (!newLabel || !newUrl) { showToast('Label and URL required', 'error'); return; }
    const btn = document.getElementById('modalSaveBtn');
    btn.disabled = true; btn.textContent = 'Saving...';
    try {
      const res = await fetch(`/api/hosts/${host.id}`, { method:'PUT', headers:{'Content-Type':'application/json'}, body: JSON.stringify({label:newLabel, console_url:newUrl, branch_type:newBranch}) });
      if (res.ok) { historyModal.classList.remove('active'); activeModalHost = null; }
      else { const d = await res.json(); showToast(d.error || 'Update failed', 'error'); }
    } catch(e) { showToast('API error', 'error'); }
    finally { btn.disabled = false; btn.textContent = 'Save Changes'; }
  };

  // Modal health stats
  document.getElementById('modalStatJitter').textContent = `${host.jitter.toFixed(1)}ms`;
  document.getElementById('modalStatHealth').textContent = host.health_score;

  loadHistoryChart(hostname, currentRange);
  loadDowntimeLogs(hostname);
  historyModal.classList.add('active');
}

closeModalBtn.onclick = () => { historyModal.classList.remove('active'); activeModalHost = null; };

// ─── Chart & History ───────────────────────────────────────────────────────
document.getElementById('timeRange').addEventListener('click', (e) => {
  if (!e.target.classList.contains('time-range__btn')) return;
  document.querySelectorAll('#timeRange .time-range__btn').forEach(b => b.classList.remove('active'));
  e.target.classList.add('active');
  currentRange = e.target.dataset.range;
  if (activeModalHost) loadHistoryChart(activeModalHost, currentRange);
});

async function loadHistoryChart(hostname, range) {
  try {
    const res = await fetch(`/api/history/${hostname}?range=${range}`);
    const data = await res.json();
    updateModalStatsEl(data.stats);
    const labels = [], latencies = [], states = [];
    data.history.forEach(pt => {
      labels.push(new Date(pt.timestamp));
      latencies.push(pt.alive && pt.latency_ms !== null ? pt.latency_ms : null);
      states.push(pt.alive);
    });
    drawChart(labels, latencies, states);
  } catch(e) { console.error('Chart load failed:', e); }
}

function updateModalStatsEl(stats) {
  if (!stats || stats.total === 0) {
    document.getElementById('modalStatMin').textContent = '--';
    document.getElementById('modalStatAvg').textContent = '--';
    document.getElementById('modalStatMax').textContent = '--';
    document.getElementById('modalStatLoss').textContent = '0.0%';
    return;
  }
  document.getElementById('modalStatMin').textContent = stats.min_ms !== null ? `${stats.min_ms.toFixed(1)}ms` : '--';
  document.getElementById('modalStatAvg').textContent = stats.avg_ms !== null ? `${stats.avg_ms.toFixed(1)}ms` : '--';
  document.getElementById('modalStatMax').textContent = stats.max_ms !== null ? `${stats.max_ms.toFixed(1)}ms` : '--';
  document.getElementById('modalStatLoss').textContent = `${((stats.lost / stats.total) * 100).toFixed(1)}%`;
}

function refreshModalStats(hostname) {
  fetch(`/api/history/${hostname}?range=${currentRange}`).then(r=>r.json()).then(d=>updateModalStatsEl(d.stats)).catch(()=>{});
}

function drawChart(labels, latencies, states) {
  const ctx = document.getElementById('historyChart').getContext('2d');
  if (historyChart) historyChart.destroy();
  const grad = ctx.createLinearGradient(0, 0, 0, 220);
  grad.addColorStop(0, 'rgba(59, 130, 246, 0.4)');
  grad.addColorStop(1, 'rgba(59, 130, 246, 0.0)');
  const dataPoints = latencies.map((val, i) => ({ x: labels[i], y: val }));

  historyChart = new Chart(ctx, {
    type: 'line',
    data: { datasets: [{ label:'Latency', data: dataPoints, borderColor:'#3b82f6', borderWidth:2, backgroundColor: grad, fill:true, tension:0.15, spanGaps:false,
      pointRadius: (c) => (c.dataIndex >= 0 && states[c.dataIndex] === 0) ? 4 : 0,
      pointBackgroundColor: (c) => (c.dataIndex >= 0 && states[c.dataIndex] === 0) ? '#ef4444' : '#3b82f6',
      pointBorderColor: '#fff', pointHoverRadius: 5
    }]},
    options: { responsive:true, maintainAspectRatio:false, plugins:{legend:{display:false}},
      scales: {
        x: { type:'time', time:{unit:'minute', displayFormats:{minute:'HH:mm',hour:'HH:mm'}}, grid:{color:'rgba(59,130,246,0.05)'}, ticks:{color:'#94a3b8',font:{size:9}} },
        y: { grid:{color:'rgba(59,130,246,0.05)'}, ticks:{color:'#94a3b8',font:{size:9}}, title:{display:true,text:'ms',color:'#64748b',font:{size:9}} }
      }
    }
  });
}

function appendHistoryChartPoint(timestamp, latency, alive) {
  if (!historyChart) return;
  historyChart.data.datasets[0].data.push({ x: new Date(timestamp), y: alive && latency !== null ? latency : null });
  if (historyChart.data.datasets[0].data.length > 100) historyChart.data.datasets[0].data.shift();
  historyChart.update('none');
}

// ─── Downtime Logs ─────────────────────────────────────────────────────────
async function loadDowntimeLogs(hostname) {
  const wrap = document.getElementById('downtimeTimeline');
  wrap.innerHTML = '<div class="downtime-empty">Loading...</div>';
  try {
    const res = await fetch(`/api/downtimes/${hostname}?range=${currentRange}`);
    const downtimes = await res.json();
    if (downtimes.length === 0) { wrap.innerHTML = '<div class="downtime-empty">No downtime events</div>'; return; }
    wrap.innerHTML = '';
    downtimes.reverse().forEach(log => {
      const isOngoing = !log.ended_at;
      const item = document.createElement('div');
      item.className = `downtime-event ${isOngoing ? 'downtime-event--ongoing' : ''}`;
      let durStr = 'Active';
      let cls = 'downtime-event__duration--ongoing';
      if (!isOngoing && log.duration_seconds !== null) {
        const m = Math.floor(log.duration_seconds / 60), s = log.duration_seconds % 60;
        durStr = m > 0 ? `${m}m ${s}s` : `${s}s`; cls = '';
      }
      item.innerHTML = `<span class="downtime-event__dot ${isOngoing?'downtime-event__dot--ongoing':''}"></span><div class="downtime-event__time"><strong>Down:</strong> ${log.started_at}<br><strong>Up:</strong> ${isOngoing?'Ongoing':log.ended_at}</div><span class="downtime-event__duration ${cls}">${durStr}</span>`;
      wrap.appendChild(item);
    });
  } catch(e) { wrap.innerHTML = '<div class="downtime-empty">Load failed</div>'; }
}

// ─── Overall Logs Modal ────────────────────────────────────────────────────
function openOverallLogs() { loadOverallLogs(logsRange); overallLogsModal.classList.add('active'); }
closeOverallLogsBtn.onclick = () => { overallLogsModal.classList.remove('active'); };

document.getElementById('overallLogsRange').addEventListener('click', (e) => {
  if (!e.target.classList.contains('time-range__btn')) return;
  document.querySelectorAll('#overallLogsRange .time-range__btn').forEach(b => b.classList.remove('active'));
  e.target.classList.add('active');
  logsRange = e.target.dataset.range;
  loadOverallLogs(logsRange);
});

async function loadOverallLogs(range) {
  const tbody = document.getElementById('overallLogsTableBody');
  tbody.innerHTML = '<tr><td colspan="6" class="logs-empty">Loading...</td></tr>';
  try {
    const res = await fetch(`/api/overall/logs?range=${range}`);
    const logs = await res.json();
    if (logs.length === 0) {
      tbody.innerHTML = '<tr><td colspan="6" class="logs-empty">No outages in this range</td></tr>';
      document.getElementById('ovTotalEvents').textContent = '0';
      document.getElementById('ovHostsAffected').textContent = '0';
      document.getElementById('ovTotalDowntime').textContent = '0m';
      document.getElementById('ovLongestOutage').textContent = '--';
      return;
    }
    tbody.innerHTML = '';
    const hostsSet = new Set(); let totalSec = 0, maxSec = 0;
    logs.forEach(log => {
      hostsSet.add(log.hostname);
      const isOngoing = !log.ended_at;
      let durStr = 'Ongoing';
      if (!isOngoing && log.duration_seconds !== null) {
        totalSec += log.duration_seconds;
        if (log.duration_seconds > maxSec) maxSec = log.duration_seconds;
        const m = Math.floor(log.duration_seconds / 60), s = log.duration_seconds % 60;
        durStr = m > 0 ? `${m}m ${s}s` : `${s}s`;
      }
      const row = document.createElement('tr');
      row.className = `logs-row ${isOngoing ? 'logs-row--ongoing' : ''}`;
      row.innerHTML = `<td class="logs-td logs-td--label">${log.label}</td><td class="logs-td"><span class="branch-badge ${log.branch_type==='MAJOR'?'branch-badge--major':'branch-badge--satellite'}">${log.branch_type}</span></td><td class="logs-td"><span class="status-pill ${isOngoing?'status-pill--down':'status-pill--up'}">${isOngoing?'OFFLINE':'RESTORED'}</span></td><td class="logs-td logs-td--mono">${log.started_at}</td><td class="logs-td logs-td--mono">${isOngoing?'--':log.ended_at}</td><td class="logs-td logs-td--mono ${isOngoing?'logs-td--duration-ongoing':'logs-td--duration'}">${durStr}</td>`;
      tbody.appendChild(row);
    });
    document.getElementById('ovTotalEvents').textContent = logs.length;
    document.getElementById('ovHostsAffected').textContent = hostsSet.size;
    const mins = Math.floor(totalSec / 60);
    document.getElementById('ovTotalDowntime').textContent = mins > 60 ? `${Math.floor(mins/60)}h ${mins%60}m` : `${mins}m`;
    document.getElementById('ovLongestOutage').textContent = maxSec > 60 ? `${Math.floor(maxSec/60)}m` : `${maxSec}s`;
  } catch(e) { tbody.innerHTML = '<tr><td colspan="6" class="logs-empty">Load failed</td></tr>'; }
}

// ─── Form & Actions ────────────────────────────────────────────────────────
document.getElementById('addHostForm').onsubmit = async (e) => {
  e.preventDefault();
  const labelInput = document.getElementById('labelInput');
  const urlInput = document.getElementById('urlInput');
  const typeSelect = document.getElementById('branchTypeSelect');
  const label = labelInput.value.trim(), console_url = urlInput.value.trim(), branch_type = typeSelect.value;
  if (!label || !console_url) return;
  try {
    const res = await fetch('/api/hosts', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({label, console_url, branch_type}) });
    const data = await res.json();
    if (!res.ok) showToast(data.error || 'Failed', 'error');
    else { labelInput.value = ''; urlInput.value = ''; }
  } catch(e) { showToast('API connection failed', 'error'); }
};

async function removeHost(hostname) {
  if (!confirm('Remove this firewall from monitoring?')) return;
  try {
    const res = await fetch(`/api/hosts/${hostname}`, { method:'DELETE' });
    if (res.ok) { historyModal.classList.remove('active'); activeModalHost = null; }
    else showToast('Remove failed', 'error');
  } catch(e) { showToast('API error', 'error'); }
}

function exportAllCSV() { window.location.href = '/api/export/all'; }

async function triggerScanAll() {
  const btn = document.getElementById('scanAllBtn');
  if (btn.disabled) return;
  btn.disabled = true;
  btn.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" width="14" height="14" class="scan-icon animate-spin" style="margin-right:2px;"><path d="M21.5 2v6h-6M21.34 15.57a10 10 0 1 1-.57-8.38l5.67-5.67"/></svg>Scanning...`;
  showToast('Scanning all branches...', 'warning');
  try {
    const res = await fetch('/api/check/all', { method:'POST' });
    if (res.ok) { showToast('Scan complete', 'success'); lastScanTime = Date.now(); }
    else showToast('Scan failed', 'error');
  } catch(e) { showToast('API error', 'error'); }
  finally {
    btn.disabled = false;
    btn.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" width="14" height="14" class="scan-icon" style="margin-right:2px;"><path d="M21.5 2v6h-6M21.34 15.57a10 10 0 1 1-.57-8.38l5.67-5.67"/></svg>Scan All`;
  }
}

async function triggerSingleScan(hostname, btn) {
  if (btn.disabled) return;
  const orig = btn.innerHTML;
  btn.disabled = true;
  btn.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" width="11" height="11" class="scan-icon animate-spin"><path d="M21.5 2v6h-6M21.34 15.57a10 10 0 1 1-.57-8.38l5.67-5.67"/></svg>...`;
  try {
    const res = await fetch(`/api/check/${hostname}`, { method:'POST' });
    if (res.ok) showToast(`Scanned ${hostname}`, 'success');
    else showToast('Check failed', 'error');
  } catch(e) { showToast('Error', 'error'); }
  finally { btn.disabled = false; btn.innerHTML = orig; }
}

// ─── Toast ─────────────────────────────────────────────────────────────────
function showToast(message, type = 'success') {
  const container = document.getElementById('toastContainer');
  const toast = document.createElement('div');
  toast.className = `toast toast--${type}`;
  let icon = '';
  if (type === 'success') icon = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>`;
  else if (type === 'error') icon = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>`;
  else icon = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`;
  toast.innerHTML = `${icon}<span>${message}</span>`;
  container.appendChild(toast);
  setTimeout(() => { toast.classList.add('toast-exit'); toast.addEventListener('animationend', () => toast.remove()); }, 4000);
}

// ─── Init ──────────────────────────────────────────────────────────────────
startClock();
startDowntimeTicker();
startRefreshCountdown();
console.log('[+] Firewall Monitor Enhanced — Initialized');
