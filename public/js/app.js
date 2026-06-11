/**
 * Firewall Monitor — Front-End Application Logic
 * Integrates Socket.IO real-time streams, Chart.js, and Live Downtime Ticking.
 */

// Global State
const socket = io();
const hostsMap = new Map(); // hostname -> full host state object
let activeModalHost = null; // hostname of the currently inspected host in modal
let historyChart = null;
let currentRange = '1h';
let logsRange = '24h';

// DOM Elements Cache
const majorGrid = document.getElementById('majorBranchesGrid');
const satelliteGrid = document.getElementById('satelliteBranchesGrid');
const majorCountEl = document.getElementById('majorCount');
const satelliteCountEl = document.getElementById('satelliteCount');
const headerClockEl = document.getElementById('headerClock');

const statTotalHosts = document.getElementById('statTotalHosts');
const statMajorUptime = document.getElementById('statMajorUptime');
const statSatelliteUptime = document.getElementById('statSatelliteUptime');
const statActiveOutages = document.getElementById('statActiveOutages');
const statOutagesCard = document.getElementById('statOutagesCard');

// Modals
const historyModal = document.getElementById('historyModal');
const closeModalBtn = document.getElementById('closeModal');
const overallLogsModal = document.getElementById('overallLogsModal');
const closeOverallLogsBtn = document.getElementById('closeOverallLogsModal');

// ─── Real-Time Clock ───────────────────────────────────────────────────────
function startClock() {
  setInterval(() => {
    const now = new Date();
    headerClockEl.textContent = now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  }, 1000);
}

// ─── Live Downtime Ticking Loop ───────────────────────────────────────────
function startDowntimeTicker() {
  setInterval(() => {
    const now = new Date();
    hostsMap.forEach((host, hostname) => {
      if (host.is_down && host.down_since) {
        // Calculate diff
        const downDate = new Date(host.down_since);
        // Replace spaces with 'T' if SQLite format is 'YYYY-MM-DD HH:MM:SS'
        // to make it ISO compliant for cross-browser parsing (e.g. Safari)
        let formattedDownSince = host.down_since;
        if (!formattedDownSince.includes('T')) {
          formattedDownSince = formattedDownSince.replace(' ', 'T');
        }
        const parsedDownDate = new Date(formattedDownSince);
        
        const diffSeconds = Math.max(0, Math.floor((now.getTime() - parsedDownDate.getTime()) / 1000));
        
        // Update model state
        host.downtime_duration = diffSeconds;
        
        // Update UI Card Ticker
        const tickerValEl = document.querySelector(`[data-ticker-hostname="${hostname}"]`);
        if (tickerValEl) {
          tickerValEl.textContent = formatDuration(diffSeconds);
        }
      }
    });
  }, 1000);
}

// Format duration helper (seconds -> string)
function formatDuration(seconds) {
  if (!seconds && seconds !== 0) return '--';
  const hrs = Math.floor(seconds / 3600);
  const mins = Math.floor((seconds % 3600) / 60);
  const secs = seconds % 60;

  const pad = (num) => String(num).padStart(2, '0');

  if (hrs > 0) {
    return `${pad(hrs)}h ${pad(mins)}m ${pad(secs)}s`;
  } else if (mins > 0) {
    return `${pad(mins)}m ${pad(secs)}s`;
  } else {
    return `${secs}s`;
  }
}

// ─── Socket.IO Subscriptions ───────────────────────────────────────────────

// Receive initial data for each host
socket.on('host:init', (data) => {
  const host = {
    id: data.host.id,
    hostname: data.host.hostname,
    label: data.host.label,
    console_url: data.host.console_url,
    branch_type: data.host.branch_type,
    recentPings: data.recentPings || [],
    stats: data.stats || { total: 0, lost: 0, min_ms: null, avg_ms: null, max_ms: null },
    is_down: data.is_down,
    down_since: data.down_since,
    downtime_duration: data.downtime_duration || 0,
    current_state: data.current_state || { alive: true, ping_alive: true, console_alive: true }
  };

  hostsMap.set(host.hostname, host);
  renderFirewallCard(host);
  updateSummaryStats();
});

// Update specific check result
socket.on('ping:result', (data) => {
  const host = hostsMap.get(data.hostname);
  if (!host) return;

  // Append new data point to recent pings (max 60)
  host.recentPings.push({
    timestamp: data.timestamp,
    latency_ms: data.latency,
    ping_alive: data.ping_alive,
    console_alive: data.console_alive,
    alive: data.alive
  });
  if (host.recentPings.length > 60) {
    host.recentPings.shift();
  }

  // Update current state
  host.current_state = {
    alive: data.alive,
    ping_alive: data.ping_alive,
    console_alive: data.console_alive
  };

  // Recalculate quick average/uptime
  if (host.stats) {
    host.stats.total++;
    if (!data.alive) host.stats.lost++;
    // We update stats values in real-time
  }

  // Update card UI values directly
  updateCardUI(host, data.latency);
  updateSummaryStats();

  // If detailed modal is open for this host, update details
  if (activeModalHost === data.hostname) {
    appendHistoryChartPoint(data.timestamp, data.latency, data.alive);
    refreshModalStats(data.hostname);
  }
});

// Outage started
socket.on('host:down', (data) => {
  const host = hostsMap.get(data.hostname);
  if (!host) return;

  host.is_down = true;
  host.down_since = data.timestamp;
  host.downtime_duration = 0;
  host.current_state.alive = false;

  const card = document.getElementById(`card-${host.hostname.replace(/\./g, '-')}`);
  if (card) {
    card.classList.add('firewall-card--down');
    // Inject ticker HTML if not exists
    let ticker = card.querySelector('.firewall-card__downtime-ticker');
    if (!ticker) {
      ticker = document.createElement('div');
      ticker.className = 'firewall-card__downtime-ticker';
      ticker.innerHTML = `
        <span class="firewall-card__downtime-label">OFFLINE DOWNTIME</span>
        <span class="firewall-card__downtime-value" data-ticker-hostname="${host.hostname}">0s</span>
      `;
      const detailsGrid = card.querySelector('.firewall-card__details');
      card.insertBefore(ticker, detailsGrid);
    }
  }

  showToast(`Firewall DOWN: ${host.label}`, 'error');
  updateSummaryStats();

  if (activeModalHost === data.hostname) {
    document.getElementById('modalStatusPill').className = 'status-pill status-pill--down';
    document.getElementById('modalStatusPill').textContent = 'OFFLINE';
    loadDowntimeLogs(host.hostname);
  }
});

// Outage resolved
socket.on('host:up', (data) => {
  const host = hostsMap.get(data.hostname);
  if (!host) return;

  host.is_down = false;
  host.down_since = null;
  host.downtime_duration = 0;
  host.current_state.alive = true;

  const card = document.getElementById(`card-${host.hostname.replace(/\./g, '-')}`);
  if (card) {
    card.classList.remove('firewall-card--down');
    const ticker = card.querySelector('.firewall-card__downtime-ticker');
    if (ticker) ticker.remove();
  }

  showToast(`Firewall RECOVERED: ${host.label}`, 'success');
  updateSummaryStats();

  if (activeModalHost === data.hostname) {
    document.getElementById('modalStatusPill').className = 'status-pill status-pill--up';
    document.getElementById('modalStatusPill').textContent = 'ONLINE';
    loadDowntimeLogs(host.hostname);
  }
});

socket.on('host:added', (data) => {
  showToast(`Added Firewall: ${data.label}`, 'success');
  // Full refresh to ensure clean database loads
  setTimeout(() => window.location.reload(), 1000);
});

socket.on('host:removed', (data) => {
  showToast(`Removed Firewall`, 'warning');
  const cardId = `card-${data.hostname.replace(/\./g, '-')}`;
  const card = document.getElementById(cardId);
  if (card) card.remove();
  hostsMap.delete(data.hostname);
  updateSummaryStats();
});

socket.on('host:updated', (data) => {
  const oldHostname = data.old_hostname;
  const hostData = data.host;
  
  const oldHost = hostsMap.get(oldHostname);
  if (!oldHost) return;

  // Delete old card if hostname (IP) changed
  if (oldHostname !== hostData.hostname) {
    hostsMap.delete(oldHostname);
    const oldCardId = `card-${oldHostname.replace(/\./g, '-')}`;
    const oldCard = document.getElementById(oldCardId);
    if (oldCard) oldCard.remove();
  }

  // Merge state
  const updatedHost = {
    ...oldHost,
    id: hostData.id,
    hostname: hostData.hostname,
    label: hostData.label,
    console_url: hostData.console_url,
    branch_type: hostData.branch_type
  };

  hostsMap.set(hostData.hostname, updatedHost);
  
  // Re-render card
  renderFirewallCard(updatedHost);
  updateSummaryStats();

  showToast(`Updated: ${hostData.label}`, 'success');

  // If modal was active on the old host, close it
  if (activeModalHost === oldHostname) {
    historyModal.classList.remove('active');
    activeModalHost = null;
  }
});

socket.on('connect', () => {
  document.getElementById('connectionStatus').querySelector('.status-dot').className = 'status-dot';
  document.getElementById('connectionStatus').querySelector('.status-text').textContent = 'Connected';
});

socket.on('disconnect', () => {
  document.getElementById('connectionStatus').querySelector('.status-dot').className = 'status-dot status-dot--off';
  document.getElementById('connectionStatus').querySelector('.status-text').textContent = 'Disconnected';
  showToast('Connection to monitoring server lost', 'error');
});


// ─── Render UI Components ─────────────────────────────────────────────────

// Render a new card into the grids
function renderFirewallCard(host) {
  const safeId = host.hostname.replace(/\./g, '-');
  const existingCard = document.getElementById(`card-${safeId}`);
  if (existingCard) existingCard.remove();

  const isDown = host.is_down;
  const state = host.current_state;
  const isConsoleApplicable = !!host.console_url && host.console_url.includes(':4444');

  // Build card elements
  const card = document.createElement('div');
  card.id = `card-${safeId}`;
  card.className = `firewall-card ${isDown ? 'firewall-card--down' : ''}`;

  let downtimeTickerHtml = '';
  if (isDown) {
    downtimeTickerHtml = `
      <div class="firewall-card__downtime-ticker">
        <span class="firewall-card__downtime-label">OFFLINE DOWNTIME</span>
        <span class="firewall-card__downtime-value" data-ticker-hostname="${host.hostname}">${formatDuration(host.downtime_duration)}</span>
      </div>
    `;
  }

  // Latency display
  let latestLatency = 'N/A';
  if (host.recentPings.length > 0) {
    const last = host.recentPings[host.recentPings.length - 1];
    if (last.alive && last.latency_ms !== null) {
      latestLatency = `${last.latency_ms.toFixed(1)} ms`;
    }
  }

  // Calculate Uptime percentage
  let uptimePct = '100.0%';
  if (host.stats && host.stats.total > 0) {
    const pct = ((1 - host.stats.lost / host.stats.total) * 100);
    uptimePct = `${pct.toFixed(1)}%`;
  }

  card.innerHTML = `
    <div class="firewall-card__header">
      <div class="firewall-card__title-grp">
        <span class="firewall-card__name">${host.label}</span>
        <span class="firewall-card__ip">${host.hostname}</span>
      </div>
      <div class="firewall-card__status">
        <span class="firewall-card__dot ${isDown ? 'firewall-card__dot--down' : 'firewall-card__dot--up'}"></span>
        <span class="firewall-card__label-status ${isDown ? 'firewall-card__label-status--down' : 'firewall-card__label-status--up'}">
          ${isDown ? 'OFFLINE' : 'ONLINE'}
        </span>
      </div>
    </div>

    ${downtimeTickerHtml}

    <div class="firewall-card__details">
      <div class="firewall-card__detail-item">
        <span class="firewall-card__detail-label">ICMP PING</span>
        <span class="firewall-card__detail-val ${state.ping_alive ? 'firewall-card__detail-val--up' : 'firewall-card__detail-val--down'}" data-val="ping-status">
          ${state.ping_alive ? 'ONLINE' : 'DOWN'}
        </span>
      </div>
      <div class="firewall-card__detail-item">
        <span class="firewall-card__detail-label">WEB CONSOLE</span>
        <span class="firewall-card__detail-val ${!isConsoleApplicable ? '' : (state.console_alive ? 'firewall-card__detail-val--up' : 'firewall-card__detail-val--down')}" data-val="console-status">
          ${!isConsoleApplicable ? 'N/A' : (state.console_alive ? 'ONLINE' : 'DOWN')}
        </span>
      </div>
      <div class="firewall-card__detail-item">
        <span class="firewall-card__detail-label">LATENCY</span>
        <span class="firewall-card__detail-val firewall-card__detail-val--mono" data-val="latency">${latestLatency}</span>
      </div>
    </div>

    <div class="firewall-card__actions">
      <button class="firewall-card__btn firewall-card__btn--scan" onclick="triggerSingleScan('${host.hostname}', this)" title="Scan firewall health now">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" width="12" height="12" class="scan-icon">
          <path d="M21.5 2v6h-6M21.34 15.57a10 10 0 1 1-.57-8.38l5.67-5.67"/>
        </svg>
        Scan
      </button>
      <button class="firewall-card__btn" onclick="openDetailsModal('${host.hostname}')" title="Uptime charts & details">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" width="12" height="12">
          <polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>
        </svg>
        History
      </button>
      <a href="${host.console_url && host.console_url.startsWith('http') ? host.console_url : '#'}" 
         target="_blank" 
         class="firewall-card__btn firewall-card__btn--console ${host.console_url && host.console_url.startsWith('http') ? '' : 'firewall-card__btn--disabled'}" 
         title="Open Web Admin Console">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" width="12" height="12">
          <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/>
          <polyline points="15 3 21 3 21 9"/>
          <line x1="10" y1="14" x2="21" y2="3"/>
        </svg>
        Console
      </a>
    </div>
  `;

  // Append to correct grid
  if (host.branch_type === 'MAJOR') {
    // Clear loading placeholder on first item
    const loading = majorGrid.querySelector('.grid-loading');
    if (loading) loading.remove();
    majorGrid.appendChild(card);
  } else {
    const loading = satelliteGrid.querySelector('.grid-loading');
    if (loading) loading.remove();
    satelliteGrid.appendChild(card);
  }
}

// Update specific fields of card instead of rewriting whole node (avoids UI flicker)
function updateCardUI(host, latency) {
  const safeId = host.hostname.replace(/\./g, '-');
  const card = document.getElementById(`card-${safeId}`);
  if (!card) return;

  const isDown = host.is_down;
  const state = host.current_state;

  // Dot & label status
  const dot = card.querySelector('.firewall-card__dot');
  if (dot) {
    dot.className = `firewall-card__dot ${isDown ? 'firewall-card__dot--down' : 'firewall-card__dot--up'}`;
  }

  const labelStatus = card.querySelector('.firewall-card__label-status');
  if (labelStatus) {
    labelStatus.className = `firewall-card__label-status ${isDown ? 'firewall-card__label-status--down' : 'firewall-card__label-status--up'}`;
    labelStatus.textContent = isDown ? 'OFFLINE' : 'ONLINE';
  }

  // Update check items
  const pingVal = card.querySelector('[data-val="ping-status"]');
  if (pingVal) {
    pingVal.className = `firewall-card__detail-val ${state.ping_alive ? 'firewall-card__detail-val--up' : 'firewall-card__detail-val--down'}`;
    pingVal.textContent = state.ping_alive ? 'ONLINE' : 'DOWN';
  }

  const isConsoleApplicable = !!host.console_url && host.console_url.includes(':4444');
  const consoleVal = card.querySelector('[data-val="console-status"]');
  if (consoleVal) {
    if (!isConsoleApplicable) {
      consoleVal.className = 'firewall-card__detail-val';
      consoleVal.textContent = 'N/A';
    } else {
      consoleVal.className = `firewall-card__detail-val ${state.console_alive ? 'firewall-card__detail-val--up' : 'firewall-card__detail-val--down'}`;
      consoleVal.textContent = state.console_alive ? 'ONLINE' : 'DOWN';
    }
  }

  // Update latency
  const latencyVal = card.querySelector('[data-val="latency"]');
  if (latencyVal) {
    latencyVal.textContent = (state.ping_alive && latency !== null) ? `${latency.toFixed(1)} ms` : 'N/A';
  }
}

// ─── Dashboard Summary Stats ──────────────────────────────────────────────
function updateSummaryStats() {
  const total = hostsMap.size;
  statTotalHosts.textContent = total;

  let majorTotal = 0;
  let majorUp = 0;
  let satelliteTotal = 0;
  let satelliteUp = 0;
  let outages = 0;

  hostsMap.forEach((host) => {
    if (host.branch_type === 'MAJOR') {
      majorTotal++;
      if (!host.is_down) majorUp++;
    } else {
      satelliteTotal++;
      if (!host.is_down) satelliteUp++;
    }

    if (host.is_down) {
      outages++;
    }
  });

  majorCountEl.textContent = `${majorTotal} Devices`;
  satelliteCountEl.textContent = `${satelliteTotal} Devices`;

  statMajorUptime.textContent = `${majorUp} / ${majorTotal}`;
  statSatelliteUptime.textContent = `${satelliteUp} / ${satelliteTotal}`;
  statActiveOutages.textContent = outages;

  // Glow summary card red if there is an active outage!
  if (outages > 0) {
    statOutagesCard.classList.add('stat-card--active-outage');
  } else {
    statOutagesCard.classList.remove('stat-card--active-outage');
  }
}


// ─── Details / Chart History Modal ────────────────────────────────────────

function openDetailsModal(hostname) {
  const host = hostsMap.get(hostname);
  if (!host) return;

  activeModalHost = hostname;

  // Cache view/edit wrappers
  const modalTitleView = document.getElementById('modalTitleView');
  const modalTitleEdit = document.getElementById('modalTitleEdit');
  const modalActionsView = document.getElementById('modalActionsView');
  const modalActionsEdit = document.getElementById('modalActionsEdit');

  const editLabelInput = document.getElementById('editLabelInput');
  const editBranchSelect = document.getElementById('editBranchTypeSelect');
  const editUrlInput = document.getElementById('editUrlInput');

  // Reset to view mode first
  modalTitleView.style.display = 'block';
  modalTitleEdit.style.display = 'none';
  modalActionsView.style.display = 'flex';
  modalActionsEdit.style.display = 'none';

  // Set modal text
  document.getElementById('modalTitle').textContent = `${host.label} Firewall`;
  document.getElementById('modalSubtitle').textContent = `IP/Host: ${host.hostname} | Port: ${host.console_url.includes(':4444') ? '4444' : 'N/A'}`;
  
  // Set badge styles
  const badge = document.getElementById('modalBranchBadge');
  badge.className = `branch-badge ${host.branch_type === 'MAJOR' ? 'branch-badge--major' : 'branch-badge--satellite'}`;
  badge.textContent = host.branch_type;

  const statusPill = document.getElementById('modalStatusPill');
  statusPill.className = `status-pill ${host.is_down ? 'status-pill--down' : 'status-pill--up'}`;
  statusPill.textContent = host.is_down ? 'OFFLINE' : 'ONLINE';

  // Config web console link
  const link = document.getElementById('modalConsoleLink');
  if (host.console_url && host.console_url.startsWith('http')) {
    link.href = host.console_url;
    link.style.display = 'inline-flex';
  } else {
    link.style.display = 'none';
  }

  // Config Action Buttons
  document.getElementById('modalDeleteBtn').onclick = () => removeHost(hostname);

  document.getElementById('modalEditBtn').onclick = () => {
    // Swap header and actions to edit input elements
    modalTitleView.style.display = 'none';
    modalTitleEdit.style.display = 'block';
    modalActionsView.style.display = 'none';
    modalActionsEdit.style.display = 'flex';

    editLabelInput.value = host.label;
    editBranchSelect.value = host.branch_type;
    editUrlInput.value = host.console_url;
  };

  document.getElementById('modalCancelBtn').onclick = () => {
    // Return to view mode
    modalTitleView.style.display = 'block';
    modalTitleEdit.style.display = 'none';
    modalActionsView.style.display = 'flex';
    modalActionsEdit.style.display = 'none';
  };

  document.getElementById('modalSaveBtn').onclick = async () => {
    const newLabel = editLabelInput.value.trim();
    const newUrl = editUrlInput.value.trim();
    const newBranchType = editBranchSelect.value;

    if (!newLabel || !newUrl) {
      showToast('Label and IP/URL are required', 'error');
      return;
    }

    const saveBtn = document.getElementById('modalSaveBtn');
    saveBtn.disabled = true;
    saveBtn.textContent = 'Saving...';

    try {
      const res = await fetch(`/api/hosts/${host.id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          label: newLabel,
          console_url: newUrl,
          branch_type: newBranchType
        })
      });

      const resData = await res.json();
      if (res.ok) {
        // Close modal
        historyModal.classList.remove('active');
        activeModalHost = null;
      } else {
        showToast(resData.error || 'Failed to update firewall', 'error');
      }
    } catch (err) {
      console.error(err);
      showToast('Failed to connect to API', 'error');
    } finally {
      saveBtn.disabled = false;
      saveBtn.textContent = 'Save Changes';
    }
  };

  // Initialize detailed charts & tables
  loadHistoryChart(hostname, currentRange);
  loadDowntimeLogs(hostname);

  historyModal.classList.add('active');
}

closeModalBtn.onclick = () => {
  historyModal.classList.remove('active');
  activeModalHost = null;
};

// Handle history time range buttons click
document.getElementById('timeRange').addEventListener('click', (e) => {
  if (e.target.classList.contains('time-range__btn')) {
    document.querySelectorAll('#timeRange .time-range__btn').forEach(b => b.classList.remove('active'));
    e.target.classList.add('active');
    currentRange = e.target.dataset.range;
    if (activeModalHost) {
      loadHistoryChart(activeModalHost, currentRange);
    }
  }
});

// Fetch history from DB and draw chart
async function loadHistoryChart(hostname, range) {
  try {
    const res = await fetch(`/api/history/${hostname}?range=${range}`);
    const data = await res.json();
    
    // Refresh basic stats in modal
    updateModalStatsEl(data.stats);

    const labels = [];
    const latencies = [];
    const states = []; // Track connection states for styling

    data.history.forEach(pt => {
      labels.push(new Date(pt.timestamp));
      latencies.push(pt.alive && pt.latency_ms !== null ? pt.latency_ms : null);
      states.push(pt.alive);
    });

    drawChart(labels, latencies, states);
  } catch (err) {
    console.error('Failed to load history chart:', err);
  }
}

function updateModalStatsEl(stats) {
  if (!stats || stats.total === 0) {
    document.getElementById('modalStatMin').textContent = '--';
    document.getElementById('modalStatAvg').textContent = '--';
    document.getElementById('modalStatMax').textContent = '--';
    document.getElementById('modalStatLoss').textContent = '0.0%';
    return;
  }
  
  document.getElementById('modalStatMin').textContent = stats.min_ms !== null ? `${stats.min_ms.toFixed(1)} ms` : '--';
  document.getElementById('modalStatAvg').textContent = stats.avg_ms !== null ? `${stats.avg_ms.toFixed(1)} ms` : '--';
  document.getElementById('modalStatMax').textContent = stats.max_ms !== null ? `${stats.max_ms.toFixed(1)} ms` : '--';
  
  const lossPct = (stats.lost / stats.total) * 100;
  document.getElementById('modalStatLoss').textContent = `${lossPct.toFixed(1)}%`;
}

function refreshModalStats(hostname) {
  // Triggers stats endpoints reload
  fetch(`/api/history/${hostname}?range=${currentRange}`)
    .then(r => r.json())
    .then(data => updateModalStatsEl(data.stats))
    .catch(console.error);
}

// Chart.js implementation
function drawChart(labels, latencies, states) {
  const ctx = document.getElementById('historyChart').getContext('2d');
  
  if (historyChart) {
    historyChart.destroy();
  }

  // Create customized charts gradient
  const grad = ctx.createLinearGradient(0, 0, 0, 240);
  grad.addColorStop(0, 'rgba(59, 130, 246, 0.45)');
  grad.addColorStop(1, 'rgba(59, 130, 246, 0.00)');

  // Build timeouts markers (display breaks clearly)
  const dataPoints = latencies.map((val, idx) => {
    return { x: labels[idx], y: val };
  });

  historyChart = new Chart(ctx, {
    type: 'line',
    data: {
      datasets: [{
        label: 'Ping Latency',
        data: dataPoints,
        borderColor: '#3b82f6',
        borderWidth: 2,
        backgroundColor: grad,
        fill: true,
        tension: 0.15,
        spanGaps: false, // Breaks lines during timeouts (Red marker lines)
        pointRadius: (context) => {
          // Highlight timeouts in red
          const idx = context.dataIndex;
          if (idx >= 0 && states[idx] === 0) return 4;
          return 0; // hide normal points
        },
        pointBackgroundColor: (context) => {
          const idx = context.dataIndex;
          return (idx >= 0 && states[idx] === 0) ? '#ef4444' : '#3b82f6';
        },
        pointBorderColor: '#ffffff',
        pointHoverRadius: 5
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false }
      },
      scales: {
        x: {
          type: 'time',
          time: {
            unit: 'minute',
            displayFormats: {
              minute: 'HH:mm',
              hour: 'HH:mm'
            }
          },
          grid: { color: 'rgba(59, 130, 246, 0.05)' },
          ticks: { color: '#94a3b8', font: { size: 10 } }
        },
        y: {
          grid: { color: 'rgba(59, 130, 246, 0.05)' },
          ticks: { color: '#94a3b8', font: { size: 10 } },
          title: { display: true, text: 'Latency (ms)', color: '#64748b', font: { size: 10 } }
        }
      }
    }
  });
}

function appendHistoryChartPoint(timestamp, latency, alive) {
  if (!historyChart) return;
  const timeDate = new Date(timestamp);
  historyChart.data.datasets[0].data.push({
    x: timeDate,
    y: alive && latency !== null ? latency : null
  });
  // Keep size constrained
  if (historyChart.data.datasets[0].data.length > 100) {
    historyChart.data.datasets[0].data.shift();
  }
  historyChart.update('none'); // silent update
}

// Load downtime logs for single host
async function loadDowntimeLogs(hostname) {
  const wrap = document.getElementById('downtimeTimeline');
  wrap.innerHTML = '<div class="downtime-empty">Loading logs...</div>';
  
  try {
    const res = await fetch(`/api/downtimes/${hostname}?range=${currentRange}`);
    const downtimes = await res.json();
    
    if (downtimes.length === 0) {
      wrap.innerHTML = '<div class="downtime-empty">No logged downtime events in this range</div>';
      return;
    }

    wrap.innerHTML = '';
    // Display newest first
    downtimes.reverse().forEach(log => {
      const item = document.createElement('div');
      const isOngoing = !log.ended_at;
      item.className = `downtime-event ${isOngoing ? 'downtime-event--ongoing' : ''}`;
      
      const started = log.started_at;
      const ended = isOngoing ? 'Ongoing Outage' : log.ended_at;

      let durStr = 'Active';
      let ongoingClass = 'downtime-event__duration--ongoing';
      if (!isOngoing && log.duration_seconds !== null) {
        const m = Math.floor(log.duration_seconds / 60);
        const s = log.duration_seconds % 60;
        durStr = m > 0 ? `${m}m ${s}s` : `${s}s`;
        ongoingClass = '';
      }

      item.innerHTML = `
        <span class="downtime-event__dot ${isOngoing ? 'downtime-event__dot--ongoing' : ''}"></span>
        <div class="downtime-event__time">
          <strong>Down:</strong> ${started}<br>
          <strong>Up:</strong> ${ended}
        </div>
        <span class="downtime-event__duration ${ongoingClass}">${durStr}</span>
      `;
      wrap.appendChild(item);
    });
  } catch (err) {
    console.error('Failed to load downtime timeline:', err);
    wrap.innerHTML = '<div class="downtime-empty">Failed to load outage records</div>';
  }
}


// ─── System-Wide Downtime Logs Modal ────────────────────────────────

function openOverallLogs() {
  loadOverallLogs(logsRange);
  overallLogsModal.classList.add('active');
}

closeOverallLogsBtn.onclick = () => {
  overallLogsModal.classList.remove('active');
};

// Filter buttons click on logs modal
document.getElementById('overallLogsRange').addEventListener('click', (e) => {
  if (e.target.classList.contains('time-range__btn')) {
    document.querySelectorAll('#overallLogsRange .time-range__btn').forEach(b => b.classList.remove('active'));
    e.target.classList.add('active');
    logsRange = e.target.dataset.range;
    loadOverallLogs(logsRange);
  }
});

async function loadOverallLogs(range) {
  const tbody = document.getElementById('overallLogsTableBody');
  tbody.innerHTML = '<tr><td colspan="6" class="logs-empty">Loading records...</td></tr>';

  try {
    const res = await fetch(`/api/overall/logs?range=${range}`);
    const logs = await res.json();

    if (logs.length === 0) {
      tbody.innerHTML = '<tr><td colspan="6" class="logs-empty">No outages logged in this range</td></tr>';
      document.getElementById('ovTotalEvents').textContent = '0';
      document.getElementById('ovHostsAffected').textContent = '0';
      document.getElementById('ovTotalDowntime').textContent = '0m';
      document.getElementById('ovLongestOutage').textContent = '--';
      return;
    }

    tbody.innerHTML = '';
    
    // Stats calculation
    const hostsSet = new Set();
    let totalSeconds = 0;
    let maxSeconds = 0;
    let longestOutageStr = '--';

    logs.forEach((log, index) => {
      hostsSet.add(log.hostname);
      const isOngoing = !log.ended_at;
      
      let durationStr = 'Ongoing';
      if (!isOngoing && log.duration_seconds !== null) {
        totalSeconds += log.duration_seconds;
        if (log.duration_seconds > maxSeconds) {
          maxSeconds = log.duration_seconds;
          const mins = Math.floor(maxSeconds / 60);
          longestOutageStr = mins > 0 ? `${mins} mins` : `${maxSeconds} secs`;
        }
        
        const m = Math.floor(log.duration_seconds / 60);
        const s = log.duration_seconds % 60;
        durationStr = m > 0 ? `${m}m ${s}s` : `${s}s`;
      }

      const row = document.createElement('tr');
      row.className = `logs-row ${isOngoing ? 'logs-row--ongoing' : ''}`;
      
      row.innerHTML = `
        <td class="logs-td logs-td--label">${log.label}</td>
        <td class="logs-td"><span class="branch-badge ${log.branch_type === 'MAJOR' ? 'branch-badge--major' : 'branch-badge--satellite'}">${log.branch_type}</span></td>
        <td class="logs-td"><span class="status-pill ${isOngoing ? 'status-pill--down' : 'status-pill--up'}">${isOngoing ? 'OFFLINE' : 'RESTORED'}</span></td>
        <td class="logs-td logs-td--mono">${log.started_at}</td>
        <td class="logs-td logs-td--mono">${isOngoing ? '--' : log.ended_at}</td>
        <td class="logs-td logs-td--mono ${isOngoing ? 'logs-td--duration-ongoing' : 'logs-td--duration'}">${durationStr}</td>
      `;
      tbody.appendChild(row);
    });

    // Write summary numbers
    document.getElementById('ovTotalEvents').textContent = logs.length;
    document.getElementById('ovHostsAffected').textContent = hostsSet.size;
    
    const overallMins = Math.floor(totalSeconds / 60);
    document.getElementById('ovTotalDowntime').textContent = overallMins > 60 
      ? `${Math.floor(overallMins / 60)}h ${overallMins % 60}m` 
      : `${overallMins}m`;

    document.getElementById('ovLongestOutage').textContent = longestOutageStr;

  } catch (err) {
    console.error('Failed to load system logs:', err);
    tbody.innerHTML = '<tr><td colspan="6" class="logs-empty">Failed to load server records</td></tr>';
  }
}


// ─── Actions & Forms Handlers ──────────────────────────────────────────────

// Form listener to add host
document.getElementById('addHostForm').onsubmit = async (e) => {
  e.preventDefault();
  
  const labelInput = document.getElementById('labelInput');
  const urlInput = document.getElementById('urlInput');
  const typeSelect = document.getElementById('branchTypeSelect');

  const label = labelInput.value.trim();
  const console_url = urlInput.value.trim();
  const branch_type = typeSelect.value;

  if (!label || !console_url) return;

  try {
    const res = await fetch('/api/hosts', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ label, console_url, branch_type })
    });
    
    const data = await res.json();
    if (!res.ok) {
      showToast(data.error || 'Failed to register branch', 'error');
    } else {
      labelInput.value = '';
      urlInput.value = '';
    }
  } catch (err) {
    console.error('Failed to save branch:', err);
    showToast('Failed to connect to monitor api', 'error');
  }
};

// Delete host
async function removeHost(hostname) {
  if (!confirm(`Are you sure you want to stop monitoring this firewall?`)) return;

  try {
    const res = await fetch(`/api/hosts/${hostname}`, { method: 'DELETE' });
    if (res.ok) {
      historyModal.classList.remove('active');
      activeModalHost = null;
    } else {
      showToast('Failed to remove firewall', 'error');
    }
  } catch (err) {
    console.error(err);
    showToast('Failed to communicate with removal endpoint', 'error');
  }
}

// Export Excel/CSV triggers
function exportAllCSV() {
  window.location.href = '/api/export/all';
}

// Trigger manual check on all active firewalls
async function triggerScanAll() {
  const btn = document.getElementById('scanAllBtn');
  if (btn.disabled) return;
  
  btn.disabled = true;
  btn.innerHTML = `
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" width="14" height="14" class="scan-icon animate-spin" style="margin-right: 2.2px;">
      <path d="M21.5 2v6h-6M21.34 15.57a10 10 0 1 1-.57-8.38l5.67-5.67"/>
    </svg>
    Scanning...
  `;
  showToast('Scanning all branches...', 'warning');

  try {
    const res = await fetch('/api/check/all', { method: 'POST' });
    const data = await res.json();
    if (res.ok) {
      showToast('Scan complete!', 'success');
      // Trigger a light reload of summary metrics
      updateSummaryStats();
    } else {
      showToast(data.error || 'Failed to check all hosts', 'error');
    }
  } catch (err) {
    console.error('Scan all failed:', err);
    showToast('Failed to connect to scan api', 'error');
  } finally {
    btn.disabled = false;
    btn.innerHTML = `
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" width="14" height="14" class="scan-icon" style="margin-right: 2px;">
        <path d="M21.5 2v6h-6M21.34 15.57a10 10 0 1 1-.57-8.38l5.67-5.67"/>
      </svg>
      Scan All
    `;
  }
}

// Trigger manual check on a single firewall card
async function triggerSingleScan(hostname, btn) {
  if (btn.disabled) return;
  const origHtml = btn.innerHTML;
  btn.disabled = true;
  btn.innerHTML = `
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" width="12" height="12" class="scan-icon animate-spin">
      <path d="M21.5 2v6h-6M21.34 15.57a10 10 0 1 1-.57-8.38l5.67-5.67"/>
    </svg>
    Scanning
  `;

  try {
    const res = await fetch(`/api/check/${hostname}`, { method: 'POST' });
    const data = await res.json();
    if (res.ok) {
      showToast(`Scan complete for ${hostname}`, 'success');
    } else {
      showToast(data.error || 'Check failed', 'error');
    }
  } catch (err) {
    console.error(err);
    showToast('Check failed', 'error');
  } finally {
    btn.disabled = false;
    btn.innerHTML = origHtml;
  }
}



// ─── Toast System Notification ─────────────────────────────────────────────
function showToast(message, type = 'success') {
  const container = document.getElementById('toastContainer');
  const toast = document.createElement('div');
  toast.className = `toast toast--${type}`;
  
  // Custom icons per type
  let icon = '';
  if (type === 'success') {
    icon = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>`;
  } else if (type === 'error') {
    icon = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>`;
  } else if (type === 'warning') {
    icon = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`;
  }

  toast.innerHTML = `
    ${icon}
    <span>${message}</span>
  `;

  container.appendChild(toast);

  // Auto exit timer
  setTimeout(() => {
    toast.classList.add('toast-exit');
    toast.addEventListener('animationend', () => toast.remove());
  }, 4500);
}


// ─── Initialization ────────────────────────────────────────────────────────
startClock();
startDowntimeTicker();
console.log('  [+] Firewall Monitor App Initialized');
