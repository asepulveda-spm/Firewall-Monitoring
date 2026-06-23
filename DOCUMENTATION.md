# FIREWALL MONITORING SYSTEM
## Technical Documentation

**Project:** Firewall Monitoring Dashboard  
**Version:** 2.0  
**Date:** June 2026  
**Department:** IT Department — SPM  
**Developer:** IT Infrastructure Team  

---

## 1. EXECUTIVE SUMMARY

The Firewall Monitoring System is a real-time network monitoring solution designed to continuously track the health and availability of enterprise firewall appliances deployed across multiple branch offices. The system performs dual health checks (ICMP Ping + TCP Port verification), provides a web-based dashboard for visualization, and sends automated alert notifications via Lark messaging platform.

---

## 2. SYSTEM ARCHITECTURE

### 2.1 High-Level Architecture Diagram

```
╔══════════════════════════════════════════════════════════════════════════╗
║                         SYSTEM ARCHITECTURE                             ║
╠══════════════════════════════════════════════════════════════════════════╣
║                                                                          ║
║  ┌─────────────────────────────────────────────────────────────────┐    ║
║  │               MONITORING SERVER (192.168.19.146)                  │    ║
║  │                                                                   │    ║
║  │  ┌─────────────┐  ┌─────────────┐  ┌──────────────────────┐    │    ║
║  │  │   Flask     │  │  Socket.IO  │  │  Monitoring Engine   │    │    ║
║  │  │   HTTP      │  │  WebSocket  │  │  ┌────────────────┐ │    │    ║
║  │  │   Server    │  │  Server     │  │  │ Thread Pool    │ │    │    ║
║  │  │   :5001     │  │  (Real-time)│  │  │ (18 parallel)  │ │    │    ║
║  │  └──────┬──────┘  └──────┬──────┘  │  └────────┬───────┘ │    │    ║
║  │         │                 │          │           │          │    │    ║
║  │         └────────┬────────┘          └───────────┼──────────┘    │    ║
║  │                  │                               │               │    ║
║  │         ┌────────▼────────────────────────────────▼──────────┐   │    ║
║  │         │              SQLite Database (WAL Mode)             │   │    ║
║  │         │  ┌────────┐ ┌──────────────┐ ┌───────────────┐    │   │    ║
║  │         │  │ hosts  │ │ ping_results │ │   downtimes   │    │   │    ║
║  │         │  └────────┘ └──────────────┘ └───────────────┘    │   │    ║
║  │         └────────────────────────────────────────────────────┘   │    ║
║  │                                                                   │    ║
║  │  ┌──────────────────┐         ┌─────────────────────────────┐   │    ║
║  │  │ Lark Notification│         │    Background Workers        │   │    ║
║  │  │ Queue (FIFO)     │         │  - Cleanup (hourly)          │   │    ║
║  │  │ 1.5s spacing     │         │  - Monitor Loop (10s cycle)  │   │    ║
║  │  └────────┬─────────┘         └─────────────────────────────┘   │    ║
║  │           │                                                       │    ║
║  └───────────┼───────────────────────────────────────────────────────┘    ║
║              │                                                            ║
║   ┌──────────▼──────────┐    ┌─────────────────────────────────────┐    ║
║   │    Lark Webhook     │    │         Web Browsers                 │    ║
║   │    (Bot API)        │    │  - Real-time Dashboard               │    ║
║   │    Notifications    │    │  - Charts & Graphs                   │    ║
║   └─────────────────────┘    │  - Export CSV                        │    ║
║                               └─────────────────────────────────────┘    ║
╚══════════════════════════════════════════════════════════════════════════╝
```

### 2.2 Component Diagram

```
┌──────────────────────────────────────────────────────────────┐
│                      server.py (Main Entry)                    │
├──────────────────────────────────────────────────────────────┤
│                                                                │
│  ┌─────────────────┐    ┌──────────────────────────────┐     │
│  │  Web Layer       │    │  Monitoring Layer             │     │
│  │                  │    │                               │     │
│  │  • Flask Routes  │    │  • ping_host()               │     │
│  │  • Socket.IO     │    │  • check_tcp_port()          │     │
│  │  • REST API      │    │  • run_single_check()        │     │
│  │  • Static Files  │    │  • monitoring_loop()         │     │
│  └────────┬─────────┘    │  • calculate_health_score()  │     │
│           │               │  • calculate_jitter()        │     │
│           │               └──────────────┬───────────────┘     │
│           │                              │                     │
│           └──────────────┬───────────────┘                     │
│                          │                                     │
│               ┌──────────▼──────────┐                          │
│               │      db.py          │                          │
│               │  (Database Layer)   │                          │
│               │                     │                          │
│               │  • get_connection() │                          │
│               │  • init_db()        │                          │
│               │  • record_ping()    │                          │
│               │  • start_downtime() │                          │
│               │  • end_downtime()   │                          │
│               │  • get_stats()      │                          │
│               │  • cleanup()        │                          │
│               └─────────────────────┘                          │
│                                                                │
│  ┌─────────────────────────────────────────────────────────┐  │
│  │  Notification Layer                                      │  │
│  │                                                          │  │
│  │  • send_lark_notification()  — Individual alerts         │  │
│  │  • send_startup_summary()    — Startup status report     │  │
│  │  • lark_queue (Queue)        — Sequential delivery       │  │
│  │  • _lark_worker()            — Background sender         │  │
│  └─────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────┘
```

---

## 3. NETWORK TOPOLOGY

### 3.1 Monitored Devices Map

```
                    ┌─────────────────────────────────┐
                    │     MONITORING SERVER            │
                    │     192.168.19.146:5001  │
                    │     (IT Department Network)      │
                    └───────────────┬─────────────────┘
                                    │
                ┌───────────────────┼───────────────────┐
                │                   │                   │
     ┌──────────▼──────────┐       │       ┌──────────▼──────────┐
     │   MAJOR BRANCHES    │       │       │ SATELLITE BRANCHES   │
     │   (7 Devices)       │       │       │ (11 Devices)         │
     └──────────┬──────────┘       │       └──────────┬──────────┘
                │                   │                   │
  ┌─────────────┼─────────────┐    │    ┌──────────────┼──────────────┐
  │             │             │    │    │              │              │
┌─▼──┐  ┌──────▼──────┐  ┌───▼┐   │  ┌─▼──┐   ┌──────▼──────┐  ┌───▼──┐
│PITX│  │PITX T3      │  │PAN │   │  │BAC │   │BATANGAS     │  │CALAM│
│T2  │  │192.168.235  │  │GAS │   │  │OLOD│   │192.168.85.1 │  │BA   │
│.208│  │.254:4444    │  │INAN│   │  │.25 │   │:4444        │  │.45.1│
│.254│  └─────────────┘  │.100│   │  │.1  │   └─────────────┘  │:4444│
│:444│                    │.1  │   │  └────┘                     └─────┘
└────┘                    │:444│   │
                          └────┘   │  ┌────┐  ┌────┐  ┌────┐  ┌─────┐
┌─────────┐  ┌────────┐  ┌─────┐  │  │CDO │  │GEN │  │MAL │  │PAGA │
│BEDROCK  │  │MAKATI  │  │CEBU │  │  │.30 │  │SAN │  │OLOS│  │DIAN │
│192.168  │  │192.168 │  │.51.1│  │  │.1  │  │.20 │  │.41 │  │.60.1│
│.71.1    │  │.16.6   │  │:4444│  │  │:444│  │.1  │  │.1  │  │:4444│
│:4444    │  │:4444   │  └─────┘  │  └────┘  └────┘  └────┘  └─────┘
└─────────┘  └────────┘           │
                                   │  ┌─────┐  ┌─────┐  ┌─────┐  ┌──────┐
┌─────────┐                        │  │PAMPA│  │TAGUM│  │ILO  │  │ZAMBO │
│DAVAO    │                        │  │NGA  │  │.62  │  │ILO  │  │ANGA  │
│192.168  │                        │  │.35.1│  │.254 │  │.83  │  │.55.1 │
│.240.254 │                        │  │:4444│  │:4444│  │.254 │  │:4444 │
│:4444    │                        │  └─────┘  └─────┘  └─────┘  └──────┘
└─────────┘                        │
                                   └─── All ports: TCP 4444 (HTTPS Console)
```

---

## 4. CODE DOCUMENTATION

### 4.1 server.py — Main Application Server

#### Purpose
The main entry point of the application. Runs a Flask web server with Socket.IO for real-time communication, manages background monitoring threads, and handles Lark notifications.

#### Key Functions

| Function | Description |
|----------|-------------|
| `parse_host_info(url_or_ip)` | Extracts hostname, port, and scheme from a URL or raw IP |
| `ping_host(hostname)` | Executes system ping command, returns (alive, latency_ms) |
| `check_tcp_port(hostname, port)` | Tests if TCP port is open via socket connection |
| `calculate_jitter(hostname)` | Computes average latency variation from last 30 samples |
| `calculate_health_score(hostname, host_id)` | Returns 0-100 score (uptime 60%, latency 25%, jitter 15%) |
| `run_single_check(host)` | Performs full health check on one firewall, records to DB, emits events |
| `send_lark_notification(host, status)` | Queues a Lark card notification for a device |
| `send_startup_summary(hosts)` | Sends individual UP/DOWN cards for all firewalls on startup |
| `monitoring_loop()` | Main loop — parallel checks every 10 seconds |
| `init_monitoring()` | Loads previous downtime state from DB on startup |
| `seed_defaults()` | Seeds the 18 default firewalls on fresh database |
| `safe_emit(event, data)` | Socket.IO emit wrapper that never crashes |

#### Monitoring Logic Flow

```
┌─────────────────────────────────────────────────────────────┐
│                    server.py EXECUTION FLOW                   │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  1. Load .env (LARK_WEBHOOK_URL)                             │
│  2. Initialize Flask + Socket.IO                              │
│  3. Start Lark worker thread (queue processor)               │
│  4. db.init_db() — create tables if needed                   │
│  5. seed_defaults() — seed 18 firewalls if empty             │
│  6. init_monitoring() — load previous DOWN states            │
│  7. Start cleanup_scheduler thread (hourly)                  │
│  8. Start monitoring_loop thread:                            │
│     │                                                        │
│     ├─ First scan (18 parallel threads)                      │
│     │     └─ Each thread: ping + TCP check + record DB       │
│     │                                                        │
│     ├─ send_startup_summary() → Lark cards for all hosts     │
│     │                                                        │
│     └─ LOOP every 10 seconds:                                │
│           └─ 18 parallel threads → check all firewalls       │
│                                                              │
│  9. socketio.run() — start web server on port 5001           │
│                                                               │
└─────────────────────────────────────────────────────────────┘
```

---

### 4.2 db.py — Database Layer

#### Purpose
Manages all SQLite database operations with thread-safe connections using thread-local storage and WAL (Write-Ahead Logging) mode for concurrent read/write performance.

#### Key Functions

| Function | Description |
|----------|-------------|
| `get_connection()` | Returns per-thread persistent SQLite connection |
| `init_db()` | Creates all tables and indexes |
| `add_host(hostname, label, ...)` | Registers a new firewall to monitor |
| `get_hosts()` | Returns all active firewalls |
| `record_ping(host_id, latency, ...)` | Stores a health check result |
| `start_downtime(host_id)` | Opens a downtime record (firewall went offline) |
| `end_downtime(host_id)` | Closes downtime record, calculates duration |
| `get_stats(host_id, range)` | Aggregates min/max/avg latency and packet loss |
| `get_history(host_id, range)` | Returns time-series ping data |
| `cleanup()` | Deletes records older than 7 days |

#### Database Configuration

```
PRAGMA journal_mode = WAL        → Concurrent reads during writes
PRAGMA synchronous = NORMAL      → Fast writes, crash-safe
PRAGMA busy_timeout = 10000      → Wait 10s if DB is locked
PRAGMA cache_size = -8000        → 8 MB memory cache
PRAGMA foreign_keys = ON         → Enforce referential integrity
```

---

### 4.3 public/js/app.js — Frontend Application

#### Purpose
Client-side JavaScript application that connects to the server via Socket.IO, renders firewall status cards with live data, draws sparkline charts, manages modals, and handles user interactions.

#### Key Components

| Component | Description |
|-----------|-------------|
| Socket.IO Listeners | `host:init`, `ping:result`, `host:down`, `host:up`, `host:added`, `host:removed` |
| `renderFirewallCard(host)` | Creates a full card DOM element with health ring, sparkline, stats |
| `updateCardUI(host, latency)` | Updates existing card without re-rendering (no flicker) |
| `drawSparkline(canvas, data)` | Draws smooth bezier-curve latency graph on canvas |
| `openDetailsModal(hostname)` | Opens history modal with Chart.js timeline |
| `applyFilters()` | Filters cards by search query and branch type |
| `showToast(msg, type)` | Displays notification popup |
| `playAlertSound()` | Web Audio API beep on outage |

#### Real-Time Data Flow (Frontend)

```
┌───────────────────────────────────────────────────────┐
│                   BROWSER (CLIENT)                      │
├───────────────────────────────────────────────────────┤
│                                                         │
│  Socket.IO Connection ──────────────────────────────┐  │
│                                                      │  │
│  Event: 'host:init'                                  │  │
│    └─→ hostsMap.set() → renderFirewallCard()         │  │
│                                                      │  │
│  Event: 'ping:result' (every 10s per host)           │  │
│    └─→ Update hostsMap → updateCardUI()              │  │
│         ├─→ Refresh health ring SVG                  │  │
│         ├─→ Redraw sparkline canvas                  │  │
│         ├─→ Update latency/jitter values             │  │
│         └─→ Update uptime bar width                  │  │
│                                                      │  │
│  Event: 'host:down'                                  │  │
│    └─→ Add red border + downtime ticker              │  │
│         └─→ playAlertSound() + showToast()           │  │
│                                                      │  │
│  Event: 'host:up'                                    │  │
│    └─→ Remove red border + ticker                    │  │
│         └─→ showToast('RECOVERED')                   │  │
│                                                      │  │
└───────────────────────────────────────────────────────┘
```

---

## 5. NOTIFICATION SYSTEM

### 5.1 Notification Rules

```
╔═══════════════════════════════════════════════════════════════╗
║              LARK NOTIFICATION DECISION TREE                  ║
╠═══════════════════════════════════════════════════════════════╣
║                                                               ║
║  ON SERVER START:                                             ║
║    → Send individual card per firewall (UP or DOWN)           ║
║                                                               ║
║  DURING OPERATION:                                            ║
║                                                               ║
║    Firewall status changes to DOWN?                           ║
║    ├── First time detected? ──── YES ──→ NOTIFY IMMEDIATELY  ║
║    │                                                          ║
║    └── Already known down? ──── Is it 8:00 AM or 5:00 PM?    ║
║                                  ├── YES → Send reminder      ║
║                                  └── NO  → Do nothing         ║
║                                                               ║
║    Firewall status changes to UP?                             ║
║    └── Was previously down? ──── YES ──→ NOTIFY IMMEDIATELY  ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
```

### 5.2 Notification Card Format

**DOWN Alert:**
```
┌──────────────────────────────────────────────────┐
│  🔴 DOWN ALERT [BEDROCK BRANCH]: 192.168.71.1   │  ← Red header
├──────────────────────────────────────────────────┤
│                                                    │
│  Host: BEDROCK (192.168.71.1)                     │
│  Status: OFFLINE 🔴                               │
│  Time: 2026-06-18 10:26:17                        │
│                                                    │
│  ┌────────────────┐                               │
│  │ Open Dashboard │                               │
│  └────────────────┘                               │
└──────────────────────────────────────────────────┘
```

**RECOVERY Alert:**
```
┌──────────────────────────────────────────────────┐
│  ✅ RECOVERED [BEDROCK BRANCH]: 192.168.71.1     │  ← Green header
├──────────────────────────────────────────────────┤
│                                                    │
│  Host: BEDROCK (192.168.71.1)                     │
│  Status: ONLINE ✅                                │
│  Down Since: 2026-06-18 10:26:17                  │
│  Restored: 2026-06-18 10:45:33                    │
│  Downtime: 19m 16s                                │
│                                                    │
│  ┌────────────────┐                               │
│  │ Open Dashboard │                               │
│  └────────────────┘                               │
└──────────────────────────────────────────────────┘
```

### 5.3 Rate Limiting Protection

```
┌─────────────────────────────────────────────────┐
│         NOTIFICATION QUEUE SYSTEM                 │
├─────────────────────────────────────────────────┤
│                                                   │
│  Thread 1 ──┐                                    │
│  Thread 2 ──┼──→ lark_queue (FIFO) ──→ Worker   │
│  Thread 3 ──┤         │                  │       │
│  ...        │         │            ┌─────▼─────┐ │
│  Thread 18 ─┘         │            │  POST to  │ │
│                        │            │  Lark API │ │
│                        │            │           │ │
│                        │            │ sleep(1.5)│ │
│                        │            │           │ │
│                        │            │  Next...  │ │
│                        │            └───────────┘ │
│                        │                          │
│  Guarantees:                                      │
│  • Sequential delivery (no race conditions)      │
│  • 1.5 second spacing (no rate-limit hits)       │
│  • Auto retry on HTTP 429                        │
│  • All notifications delivered                   │
│                                                   │
└─────────────────────────────────────────────────┘
```

---

## 6. HEALTH CHECK MECHANISM

### 6.1 Dual Verification Process

```
┌──────────────────────────────────────────────────────────────────┐
│              HEALTH CHECK: run_single_check(host)                  │
├──────────────────────────────────────────────────────────────────┤
│                                                                    │
│  Step 1: ICMP PING                                                │
│  ┌─────────────────────────────────────────────┐                  │
│  │ Command: ping -n 1 -w 3000 <hostname>       │                  │
│  │ Timeout: 3 seconds                           │                  │
│  │ Returns: (alive: bool, latency_ms: float)    │                  │
│  └─────────────────────────────────────────────┘                  │
│                                                                    │
│  Step 2: TCP PORT CHECK (if port 4444 detected)                   │
│  ┌─────────────────────────────────────────────┐                  │
│  │ socket.connect_ex((hostname, 4444))          │                  │
│  │ Timeout: 3 seconds                           │                  │
│  │ Returns: console_alive: bool                 │                  │
│  └─────────────────────────────────────────────┘                  │
│                                                                    │
│  Step 3: DETERMINE STATUS                                         │
│  ┌─────────────────────────────────────────────┐                  │
│  │ alive = ping_alive OR console_alive          │                  │
│  │ (Device is UP if EITHER check passes)        │                  │
│  └─────────────────────────────────────────────┘                  │
│                                                                    │
│  Step 4: RECORD & EMIT                                            │
│  ┌─────────────────────────────────────────────┐                  │
│  │ • db.record_ping() → Save to database        │                  │
│  │ • Track latency_history[] for jitter          │                  │
│  │ • Calculate health_score (0-100)              │                  │
│  │ • socketio.emit('ping:result') → Dashboard   │                  │
│  │ • If DOWN: start_downtime + notify Lark       │                  │
│  │ • If RECOVERED: end_downtime + notify Lark    │                  │
│  └─────────────────────────────────────────────┘                  │
│                                                                    │
└──────────────────────────────────────────────────────────────────┘
```

### 6.2 Health Score Algorithm

```
Health Score (0-100) = Uptime Score + Latency Score + Jitter Score

┌─────────────────────────────────────────────────────────┐
│  COMPONENT        │ WEIGHT │ FORMULA                     │
├───────────────────┼────────┼─────────────────────────────┤
│  Uptime           │  60%   │ (successful/total) × 60     │
│  Latency          │  25%   │ (1 - min(avg_ms,200)/200)×25│
│  Jitter           │  15%   │ (1 - min(jitter,50)/50) × 15│
└───────────────────┴────────┴─────────────────────────────┘

Examples:
  • 100% uptime, 5ms avg, 1ms jitter  → Score: 99
  • 95% uptime, 50ms avg, 10ms jitter → Score: 75
  • 80% uptime, 150ms avg, 40ms jitter → Score: 43
```

---

## 7. DATABASE SCHEMA DIAGRAM

```
┌─────────────────────────────────────────────────────────────────┐
│                     DATABASE: firewall_data.db                    │
│                     Engine: SQLite 3 (WAL Mode)                  │
├─────────────────────────────────────────────────────────────────┤
│                                                                   │
│  ┌─────────────────────────┐         ┌─────────────────────────┐│
│  │        hosts             │         │     ping_results         ││
│  ├─────────────────────────┤         ├─────────────────────────┤│
│  │ PK id        INTEGER    │ ◄───┐   │ PK id        INTEGER    ││
│  │    hostname  TEXT UNIQUE │     │   │ FK host_id   INTEGER  ──┼┘
│  │    label     TEXT        │     │   │    timestamp  DATETIME   │
│  │    console_url TEXT      │     │   │    latency_ms REAL       │
│  │    branch_type TEXT      │     │   │    ping_alive INTEGER    │
│  │    created_at DATETIME   │     │   │    console_alive INTEGER │
│  │    is_active  INTEGER    │     │   │    alive      INTEGER    │
│  └─────────────────────────┘     │   └─────────────────────────┘
│                                   │
│  ┌─────────────────────────┐     │   ┌─────────────────────────┐
│  │       downtimes          │     │   │   alert_thresholds       │
│  ├─────────────────────────┤     │   ├─────────────────────────┤
│  │ PK id        INTEGER    │     │   │ PK id        INTEGER    │
│  │ FK host_id   INTEGER  ──┼─────┤   │ FK host_id   INTEGER  ──┼─┐
│  │    started_at DATETIME  │     │   │    latency_ms INTEGER    │ │
│  │    ended_at   DATETIME  │     │   │    enabled    INTEGER    │ │
│  │    duration_s INTEGER   │     └───│    updated_at DATETIME   │ │
│  └─────────────────────────┘         └─────────────────────────┘ │
│                                                                    │
│  Indexes:                                                          │
│  • idx_ping_results_host_time ON ping_results(host_id, timestamp) │
│  • idx_downtimes_host ON downtimes(host_id, started_at)           │
│                                                                    │
└─────────────────────────────────────────────────────────────────┘
```

---

## 8. API ENDPOINTS

### 8.1 Host Management

| Method | Endpoint | Body | Response |
|--------|----------|------|----------|
| `GET` | `/api/hosts` | — | Array of all active hosts with stats |
| `POST` | `/api/hosts` | `{label, console_url, branch_type}` | Created host object |
| `PUT` | `/api/hosts/:id` | `{label, console_url, branch_type}` | Updated host object |
| `DELETE` | `/api/hosts/:hostname` | — | `{success: true}` |

### 8.2 Health Checks

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/check/all` | Scan all firewalls immediately |
| `POST` | `/api/check/:hostname` | Scan single firewall |

### 8.3 History & Logs

| Method | Endpoint | Query Params | Description |
|--------|----------|--------------|-------------|
| `GET` | `/api/history/:hostname` | `?range=1h\|6h\|24h\|7d` | Ping history + stats |
| `GET` | `/api/downtimes/:hostname` | `?range=1h\|6h\|24h\|7d` | Downtime events |
| `GET` | `/api/overall/logs` | `?range=1h\|6h\|24h\|7d` | All downtimes (all hosts) |

### 8.4 Export

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/export/all` | Full CSV report (all firewalls) |
| `GET` | `/api/export/host/:hostname` | Single firewall CSV |

---

## 9. SOCKET.IO EVENTS

### 9.1 Server → Client (Emitted Events)

| Event | Payload | When |
|-------|---------|------|
| `host:init` | `{host, recentPings, stats, is_down, current_state, jitter, health_score}` | On client connect |
| `ping:result` | `{hostname, timestamp, latency, ping_alive, console_alive, alive, jitter, health_score}` | Every check cycle |
| `host:down` | `{hostname, timestamp}` | First detection of outage |
| `host:up` | `{hostname, timestamp}` | Recovery from outage |
| `host:added` | `{id, hostname, label, ...}` | New firewall registered |
| `host:removed` | `{hostname}` | Firewall deactivated |
| `host:updated` | `{old_hostname, host}` | Configuration changed |

---

## 10. DEPLOYMENT GUIDE

### 10.1 Prerequisites

```
✓ Python 3.10 or newer
✓ pip (Python package manager)
✓ Network access to all firewall IPs
✓ Lark Bot webhook URL
✓ Windows Server or Desktop (recommended)
```

### 10.2 Step-by-Step Deployment

```
Step 1: Install Python packages
    > pip install -r requirements.txt

Step 2: Configure environment
    > copy .env.example .env
    > notepad .env
    (Set LARK_WEBHOOK_URL=https://open.larksuite.com/...)

Step 3: Run the server
    > python server.py

Step 4: Access dashboard
    → Browser: http://localhost:5001
    → Network: http://192.168.52.215:5001

Step 5: (Optional) Run as Windows Service
    → Use NSSM or Task Scheduler for auto-start
```

### 10.3 Running as Background Service (Task Scheduler)

```
Program:    python.exe
Arguments:  "C:\Users\IT Department\Documents\Firewall-Monitoring\server.py"
Start in:   C:\Users\IT Department\Documents\Firewall-Monitoring
Trigger:    At system startup
Settings:   Do not stop if running longer than 3 days
```

---

## 11. MAINTENANCE

### 11.1 Automatic Cleanup
- Database purges ping_results and downtimes older than **7 days** automatically (hourly)

### 11.2 Manual Database Reset
```powershell
# Stop the server first, then:
Remove-Item firewall_data.db, firewall_data.db-shm, firewall_data.db-wal
# Restart server — fresh database will be created
```

### 11.3 Adding New Firewalls
1. Use the web dashboard "Add" form, OR
2. Add to `DEFAULT_FIREWALLS` list in server.py (for fresh installs)

---

## 12. SECURITY CONSIDERATIONS

| Risk | Mitigation |
|------|-----------|
| Lark webhook URL exposure | Stored in `.env` file, excluded from Git via `.gitignore` |
| SQLite concurrent access | WAL mode + thread-local connections + busy_timeout |
| Dashboard access | Currently open — deploy behind VPN or add auth layer |
| Firewall credentials | System only pings/checks ports — no credentials stored |

---

## 13. FILE STRUCTURE

```
Firewall-Monitoring/
│
├── server.py              ← Main application (Flask + monitoring engine)
├── db.py                  ← SQLite database operations layer
├── requirements.txt       ← Python package dependencies
├── .env                   ← Environment secrets (NOT in Git)
├── .env.example           ← Template for .env file
├── .gitignore             ← Git exclusion rules
├── README.md              ← Quick-start guide
├── DOCUMENTATION.md       ← This file (full technical docs)
│
├── public/                ← Frontend static assets
│   ├── index.html         ← Dashboard HTML structure
│   ├── css/
│   │   └── style.css      ← Glassmorphic cyberpunk theme
│   └── js/
│       └── app.js         ← Frontend logic (Socket.IO + Charts)
│
└── firewall_data.db       ← SQLite database (auto-created, not in Git)
```

---

*End of Documentation*
