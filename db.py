"""
Firewall Monitoring Dashboard — SQLite Database Layer
Uses a persistent per-thread connection pool.
"""

import sqlite3
import os
import threading

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'firewall_data.db')

# Thread-local storage: one persistent connection per thread
_local = threading.local()


def get_connection():
    """Return a persistent per-thread SQLite connection."""
    conn = getattr(_local, 'conn', None)
    if conn is None:
        conn = sqlite3.connect(DB_PATH, timeout=30.0, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")   # faster writes, still safe
        conn.execute("PRAGMA cache_size=-8000")     # 8 MB page cache
        conn.execute("PRAGMA foreign_keys=ON")
        _local.conn = conn
    return conn


def init_db():
    """Initialize database schema."""
    conn = get_connection()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS hosts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            hostname TEXT UNIQUE NOT NULL,
            label TEXT,
            console_url TEXT,
            branch_type TEXT CHECK(branch_type IN ('MAJOR', 'SATELLITE')),
            created_at DATETIME DEFAULT (datetime('now', 'localtime')),
            is_active INTEGER DEFAULT 1
        );

        CREATE TABLE IF NOT EXISTS ping_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host_id INTEGER NOT NULL,
            timestamp DATETIME DEFAULT (datetime('now', 'localtime')),
            latency_ms REAL,
            ping_alive INTEGER NOT NULL,
            console_alive INTEGER NOT NULL,
            alive INTEGER NOT NULL,
            FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS downtimes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host_id INTEGER NOT NULL,
            started_at DATETIME NOT NULL,
            ended_at DATETIME,
            duration_seconds INTEGER,
            FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS alert_thresholds (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host_id INTEGER NOT NULL UNIQUE,
            latency_ms INTEGER NOT NULL DEFAULT 150,
            enabled INTEGER NOT NULL DEFAULT 0,
            updated_at DATETIME DEFAULT (datetime('now', 'localtime')),
            FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_ping_results_host_time
            ON ping_results(host_id, timestamp);
        CREATE INDEX IF NOT EXISTS idx_downtimes_host
            ON downtimes(host_id, started_at);
    """)
    conn.commit()


# ─── Host Management ───────────────────────────────────────────────────────

def add_host(hostname, label=None, console_url=None, branch_type='SATELLITE'):
    """Add a host to monitor. Returns the host dict."""
    conn = get_connection()
    conn.execute(
        """INSERT OR IGNORE INTO hosts (hostname, label, console_url, branch_type) 
           VALUES (?, ?, ?, ?)""",
        (hostname, label or hostname, console_url, branch_type)
    )
    conn.execute(
        "UPDATE hosts SET is_active = 1 WHERE hostname = ?",
        (hostname,)
    )
    conn.commit()
    return get_host_by_name(hostname)


def get_hosts():
    """Get all active hosts."""
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM hosts WHERE is_active = 1 ORDER BY branch_type DESC, label ASC"
    ).fetchall()
    return [dict(r) for r in rows]


def get_host_by_name(hostname):
    """Get a host by hostname (active or inactive)."""
    conn = get_connection()
    row = conn.execute(
        "SELECT * FROM hosts WHERE hostname = ? ORDER BY is_active DESC LIMIT 1", (hostname,)
    ).fetchone()
    return dict(row) if row else None


def remove_host(hostname):
    """Deactivate a host."""
    conn = get_connection()
    conn.execute(
        "UPDATE hosts SET is_active = 0 WHERE hostname = ?", (hostname,)
    )
    conn.commit()


def update_host(host_id, hostname, label, console_url, branch_type):
    """Update host configuration (label, URL/IP, branch_type)."""
    conn = get_connection()
    # Check if this new IP/hostname is already used by another host
    existing = conn.execute(
        "SELECT id FROM hosts WHERE hostname = ? AND id != ? AND is_active = 1",
        (hostname, host_id)
    ).fetchone()
    if existing:
        raise ValueError(f"IP/Host {hostname} is already monitored by another firewall.")
        
    conn.execute(
        """UPDATE hosts 
           SET hostname = ?, label = ?, console_url = ?, branch_type = ? 
           WHERE id = ?""",
        (hostname, label, console_url, branch_type, host_id)
    )
    conn.commit()
    # Get updated host
    row = conn.execute("SELECT * FROM hosts WHERE id = ?", (host_id,)).fetchone()
    return dict(row) if row else None



# ─── Ping Recording ────────────────────────────────────────────────────────

def record_ping(host_id, latency_ms, ping_alive, console_alive, alive):
    """Record a ping/console check result."""
    conn = get_connection()
    conn.execute(
        """INSERT INTO ping_results (host_id, latency_ms, ping_alive, console_alive, alive) 
           VALUES (?, ?, ?, ?, ?)""",
        (host_id, latency_ms, 1 if ping_alive else 0, 1 if console_alive else 0, 1 if alive else 0)
    )
    conn.commit()


def get_history(host_id, range_modifier):
    """Get check history for a time range."""
    conn = get_connection()
    rows = conn.execute(
        """SELECT timestamp, latency_ms, ping_alive, console_alive, alive
           FROM ping_results
           WHERE host_id = ? AND timestamp >= datetime('now', 'localtime', ?)
           ORDER BY timestamp ASC""",
        (host_id, range_modifier)
    ).fetchall()
    return [dict(r) for r in rows]


def get_latest_pings(host_id, count=60):
    """Get the latest N pings for a host."""
    conn = get_connection()
    rows = conn.execute(
        """SELECT timestamp, latency_ms, ping_alive, console_alive, alive
           FROM ping_results
           WHERE host_id = ?
           ORDER BY timestamp DESC
           LIMIT ?""",
        (host_id, count)
    ).fetchall()
    return [dict(r) for r in reversed(rows)]


def get_stats(host_id, range_modifier='-1 hour'):
    """Get statistics for a host in a time range."""
    conn = get_connection()
    row = conn.execute(
        """SELECT
            COUNT(*) as total,
            SUM(CASE WHEN alive = 0 THEN 1 ELSE 0 END) as lost,
            MIN(CASE WHEN ping_alive = 1 THEN latency_ms END) as min_ms,
            MAX(CASE WHEN ping_alive = 1 THEN latency_ms END) as max_ms,
            AVG(CASE WHEN ping_alive = 1 THEN latency_ms END) as avg_ms
           FROM ping_results
           WHERE host_id = ? AND timestamp >= datetime('now', 'localtime', ?)""",
        (host_id, range_modifier)
    ).fetchone()
    return dict(row) if row else None


# ─── Downtime Tracking ─────────────────────────────────────────────────────

def start_downtime(host_id):
    """Start a downtime event (if not already open)."""
    conn = get_connection()
    existing = conn.execute(
        "SELECT id FROM downtimes WHERE host_id = ? AND ended_at IS NULL",
        (host_id,)
    ).fetchone()
    if not existing:
        conn.execute(
            "INSERT INTO downtimes (host_id, started_at) VALUES (?, datetime('now', 'localtime'))",
            (host_id,)
        )
        conn.commit()


def end_downtime(host_id):
    """End an open downtime event."""
    conn = get_connection()
    conn.execute(
        """UPDATE downtimes
           SET ended_at = datetime('now', 'localtime'),
               duration_seconds = CAST(
                   (julianday('now', 'localtime') - julianday(started_at)) * 86400 AS INTEGER
               )
           WHERE host_id = ? AND ended_at IS NULL""",
        (host_id,)
    )
    conn.commit()


def has_open_downtime(host_id):
    """Check if a host has an ongoing downtime."""
    conn = get_connection()
    row = conn.execute(
        "SELECT id, started_at FROM downtimes WHERE host_id = ? AND ended_at IS NULL",
        (host_id,)
    ).fetchone()
    return dict(row) if row else None


def get_downtimes(host_id, range_modifier='-24 hours'):
    """Get downtime events for a time range."""
    conn = get_connection()
    rows = conn.execute(
        """SELECT started_at, ended_at, duration_seconds
           FROM downtimes
           WHERE host_id = ? AND started_at >= datetime('now', 'localtime', ?)
           ORDER BY started_at ASC""",
        (host_id, range_modifier)
    ).fetchall()
    return [dict(r) for r in rows]


def get_latest_closed_downtime(host_id):
    """Get the most recent completed downtime event for a host."""
    conn = get_connection()
    row = conn.execute(
        """SELECT started_at, ended_at, duration_seconds
           FROM downtimes
           WHERE host_id = ? AND ended_at IS NOT NULL
           ORDER BY ended_at DESC
           LIMIT 1""",
        (host_id,)
    ).fetchone()
    return dict(row) if row else None



# ─── Maintenance ────────────────────────────────────────────────────────────

def cleanup():
    """Delete old data (>7 days)."""
    conn = get_connection()
    conn.execute(
        "DELETE FROM ping_results WHERE timestamp < datetime('now', 'localtime', '-7 days')"
    )
    conn.execute(
        "DELETE FROM downtimes WHERE started_at < datetime('now', 'localtime', '-7 days') AND ended_at IS NOT NULL"
    )
    conn.commit()


# ─── Alert Thresholds ───────────────────────────────────────────────────────

def get_alert_threshold(host_id):
    """Get alert threshold for a host. Returns None if not set."""
    conn = get_connection()
    row = conn.execute(
        "SELECT latency_ms, enabled FROM alert_thresholds WHERE host_id = ?",
        (host_id,)
    ).fetchone()
    return dict(row) if row else None


def set_alert_threshold(host_id, latency_ms, enabled):
    """Insert or update alert threshold for a host."""
    conn = get_connection()
    conn.execute(
        """INSERT INTO alert_thresholds (host_id, latency_ms, enabled, updated_at)
           VALUES (?, ?, ?, datetime('now', 'localtime'))
           ON CONFLICT(host_id) DO UPDATE SET
               latency_ms = excluded.latency_ms,
               enabled = excluded.enabled,
               updated_at = excluded.updated_at""",
        (host_id, latency_ms, 1 if enabled else 0)
    )
    conn.commit()


def get_all_alert_thresholds():
    """Get all alert thresholds joined with hostname."""
    conn = get_connection()
    rows = conn.execute(
        """SELECT h.hostname, a.latency_ms, a.enabled
           FROM alert_thresholds a
           JOIN hosts h ON h.id = a.host_id""",
    ).fetchall()
    return [dict(r) for r in rows]
