"""
Firewall Monitoring Dashboard - Flask + Socket.IO Server
Real-time firewall health checker with TCP console port + ICMP ping checks,
downtime tracker, and branch-grouped status overview.
"""

import os
import re
import socket
import subprocess
import platform
import threading
import time
import sys
import json
import urllib.request
import urllib.parse
import urllib.error
from datetime import datetime

# Fix Windows console encoding
if sys.platform == 'win32':
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

from flask import Flask, request, jsonify, send_from_directory
from flask_socketio import SocketIO, emit

import db

# --- App Setup ---------------------------------------------------------------

app = Flask(__name__, static_folder='public', static_url_path='')
app.config['SECRET_KEY'] = 'firewall-monitoring-secret'

# Use threading mode - works reliably on Windows
socketio = SocketIO(
    app,
    cors_allowed_origins='*',
    async_mode='threading',
    ping_timeout=60,
    ping_interval=25,
    logger=False,
    engineio_logger=False,
)

PORT = int(os.environ.get('PORT', 3000))
CHECK_INTERVAL = 10  # check every 10 seconds (responsive firewall checks)
LARK_WEBHOOK_URL = "https://open.larksuite.com/open-apis/bot/v2/hook/1bce6561-7a37-40bc-9a9b-b72db594c990"

def safe_emit(event, data):
    """Emit a socket event, swallowing errors so monitoring threads never crash."""
    try:
        socketio.emit(event, data)
    except Exception as e:
        print(f"  [!] Socket Emit error ({event}): {e}", flush=True)


# --- Host & URL Parsing Utility ----------------------------------------------

def parse_host_info(url_or_ip):
    """
    Parses a URL or raw IP to extract target hostname (IP), port, and scheme.
    Example: 'https://192.168.85.1:4444/' -> ('192.168.85.1', 4444, 'https')
             '192.168.25.1' -> ('192.168.25.1', None, None)
    """
    val = url_or_ip.strip()
    if not (val.startswith('http://') or val.startswith('https://')):
        # Raw IP / Hostname
        return val, None, None
    try:
        parsed = urllib.parse.urlparse(val)
        hostname = parsed.hostname
        port = parsed.port
        if port is None:
            port = 443 if parsed.scheme == 'https' else 80
        return hostname, port, parsed.scheme
    except Exception:
        return val, None, None


# --- Health Checker Engine ---------------------------------------------------

ping_threads = {}    # hostname -> threading.Event (stop signal)
host_states = {}     # hostname -> {'alive': bool, 'ping_alive': bool, 'console_alive': bool}


def parse_ping_output(output):
    """Parse ping command output to extract latency."""
    match = re.search(r'time[=<](\d+\.?\d*)\s*ms', output, re.IGNORECASE)
    if match:
        return float(match.group(1))
    return None


def ping_host(hostname):
    """Ping a host once using system ping command."""
    try:
        param_count = '-n'
        param_timeout = '-w'
        timeout_val = '3000' # 3 seconds timeout

        if platform.system().lower() != 'windows':
            param_count = '-c'
            param_timeout = '-W'
            timeout_val = '3'

        cmd_kwargs = {
            'capture_output': True,
            'text': True,
            'timeout': 6,
        }
        if platform.system().lower() == 'windows':
            cmd_kwargs['creationflags'] = subprocess.CREATE_NO_WINDOW

        result = subprocess.run(
            ['ping', param_count, '1', param_timeout, timeout_val, hostname],
            **cmd_kwargs
        )

        output = result.stdout + result.stderr
        alive = result.returncode == 0
        latency = parse_ping_output(output) if alive else None

        return alive, latency

    except (subprocess.TimeoutExpired, Exception):
        return False, None


def check_tcp_port(hostname, port, timeout=3.0):
    """Check if a TCP port is open (used to check Firewall Web Consoles)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((hostname, port))
        s.close()
        return result == 0
    except Exception:
        return False


def format_downtime_duration(seconds):
    if seconds is None:
        return "Unknown"
    mins, secs = divmod(int(seconds), 60)
    hours, mins = divmod(mins, 60)
    if hours > 0:
        return f"{hours}h {mins}m {secs}s"
    elif mins > 0:
        return f"{mins}m {secs}s"
    else:
        return f"{secs}s"


def send_lark_notification(host, status, started_at=None, duration_seconds=None):
    """Send interactive card notifications to Lark webhook when a firewall changes status."""
    if not LARK_WEBHOOK_URL:
        return

    label = host.get('label', host.get('hostname'))
    hostname = host.get('hostname')
    branch_type = host.get('branch_type', 'SATELLITE')
    timestamp_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    if status == 'DOWN':
        title = "🚨 Firewall Outage Alert"
        color = "red"
        content = (
            f"**Device:** {label} ({hostname})\n"
            f"**Branch Type:** {branch_type}\n"
            f"**Status:** 🔴 OFFLINE / DOWN\n"
            f"**Outage Time:** {timestamp_str}\n\n"
            f"⚠️ *Please check network connectivity or console access immediately.*"
        )
    else:
        title = "✅ Firewall Recovery Notification"
        color = "green"
        dur_str = format_downtime_duration(duration_seconds)
        content = (
            f"**Device:** {label} ({hostname})\n"
            f"**Branch Type:** {branch_type}\n"
            f"**Status:** 🟢 ONLINE / RECOVERED\n"
            f"**Downtime Started:** {started_at or 'N/A'}\n"
            f"**Restored At:** {timestamp_str}\n"
            f"**Total Downtime:** {dur_str}\n\n"
            f"✔️ *System health check restored successfully.*"
        )

    payload = {
        "msg_type": "interactive",
        "card": {
            "config": {
                "wide_screen_mode": True
            },
            "header": {
                "title": {
                    "tag": "plain_text",
                    "content": title
                },
                "template": color
            },
            "elements": [
                {
                    "tag": "div",
                    "text": {
                        "tag": "lark_md",
                        "content": content
                    }
                }
            ]
        }
    }

    def post_request():
        try:
            import requests
            headers = {"Content-Type": "application/json"}
            res = requests.post(LARK_WEBHOOK_URL, json=payload, headers=headers, timeout=8)
            print(f"  [*] Lark Webhook Response: {res.status_code} - {res.text}", flush=True)
        except Exception as e:
            print(f"  [!] Failed to send Lark notification: {e}", flush=True)

    # Spawn thread to avoid blocking check flow
    threading.Thread(target=post_request, daemon=True).start()


def run_single_check(host):
    """Perform health checks on a firewall once (ICMP Ping + TCP Console Port)."""
    hostname = host['hostname']
    host_id = host['id']
    url_or_ip = host.get('console_url', '')
    
    # Parse URL port info
    _, port, _ = parse_host_info(url_or_ip or hostname)

    # 1. ICMP Ping check
    ping_alive, latency = ping_host(hostname)

    # 2. TCP Port Console Check
    if port:
        console_alive = check_tcp_port(hostname, port)
        # A firewall is UP if it responds to ping OR if its web admin port is open
        alive = ping_alive or console_alive
    else:
        console_alive = False
        alive = ping_alive

    # Record result in DB
    db.record_ping(host_id, latency, ping_alive, console_alive, alive)

    # Get previous state from memory or query DB
    prev_state = host_states.get(hostname)
    if prev_state is None:
        # Load from DB downtime history
        active_down = db.has_open_downtime(host_id)
        prev_state = {'alive': active_down is None}

    if prev_state.get('alive', True) and not alive:
        # Firewall went down
        db.start_downtime(host_id)
        safe_emit('host:down', {
            'hostname': hostname,
            'timestamp': datetime.now().isoformat()
        })
        print(f"  [!] FIREWALL DOWN: {host['label']} ({hostname})", flush=True)
        send_lark_notification(host, 'DOWN')

    elif not prev_state.get('alive', True) and alive:
        # Firewall recovered
        db.end_downtime(host_id)
        safe_emit('host:up', {
            'hostname': hostname,
            'timestamp': datetime.now().isoformat()
        })
        print(f"  [+] FIREWALL RECOVERED: {host['label']} ({hostname})", flush=True)
        
        # Fetch latest completed downtime to show duration and start time
        last_down = db.get_latest_closed_downtime(host_id)
        started_at = last_down.get('started_at') if last_down else None
        duration_seconds = last_down.get('duration_seconds') if last_down else None
        send_lark_notification(host, 'UP', started_at=started_at, duration_seconds=duration_seconds)

    state = {
        'alive': alive,
        'ping_alive': ping_alive,
        'console_alive': console_alive
    }
    host_states[hostname] = state

    # Emit real-time status data to clients
    safe_emit('ping:result', {
        'hostname': hostname,
        'timestamp': datetime.now().isoformat(),
        'latency': latency,
        'ping_alive': ping_alive,
        'console_alive': console_alive,
        'alive': alive,
    })
    
    return state


def get_current_host_state(host):
    """Retrieve host state from cache or compute it from database records."""
    hostname = host['hostname']
    if hostname in host_states:
        return host_states[hostname]
        
    active_down = db.has_open_downtime(host['id'])
    if active_down:
        state = {'alive': False, 'ping_alive': False, 'console_alive': False}
    else:
        recent = db.get_latest_pings(host['id'], 1)
        if recent:
            r = recent[0]
            state = {
                'alive': bool(r['alive']),
                'ping_alive': bool(r['ping_alive']),
                'console_alive': bool(r['console_alive'])
            }
        else:
            state = {'alive': True, 'ping_alive': True, 'console_alive': True}
            
    host_states[hostname] = state
    return state



# --- Static Files ------------------------------------------------------------

@app.route('/')
def index():
    return send_from_directory('public', 'index.html')


@app.route('/<path:path>')
def static_files(path):
    return send_from_directory('public', path)


# --- REST API ----------------------------------------------------------------

@app.route('/api/hosts', methods=['GET'])
def api_get_hosts():
    hosts = db.get_hosts()
    enriched = []
    for h in hosts:
        stats = db.get_stats(h['id'], '-1 hour')
        active_down = db.has_open_downtime(h['id'])
        
        # Calculate active downtime seconds if currently down
        down_since = None
        downtime_duration = 0
        if active_down:
            down_since = active_down['started_at']
            try:
                started_dt = datetime.strptime(down_since, '%Y-%m-%d %H:%M:%S')
                downtime_duration = int((datetime.now() - started_dt).total_seconds())
            except Exception:
                pass

        # Get latest check state
        current_state = get_current_host_state(h)

        enriched.append({
            **h,
            'stats': stats,
            'is_down': active_down is not None,
            'down_since': down_since,
            'downtime_duration': downtime_duration,
            'current_state': current_state
        })
    return jsonify(enriched)


@app.route('/api/hosts', methods=['POST'])
def api_add_host():
    data = request.get_json()
    if not data or not data.get('console_url'):
        return jsonify({'error': 'URL or IP is required'}), 400

    console_url = data['console_url'].strip()
    label = data.get('label', '').strip() or console_url
    branch_type = data.get('branch_type', 'SATELLITE').upper()
    if branch_type not in ('MAJOR', 'SATELLITE'):
        branch_type = 'SATELLITE'

    hostname, _, _ = parse_host_info(console_url)
    if not hostname:
        return jsonify({'error': 'Invalid URL or IP address'}), 400

    existing = db.get_host_by_name(hostname)
    if existing and existing.get('is_active'):
        return jsonify({'error': f'Firewall with IP/Host {hostname} is already being monitored'}), 409

    host = db.add_host(hostname, label, console_url, branch_type)
    if host:
        safe_emit('host:added', host)
        # Run an initial check for this new host in a background thread
        threading.Thread(target=run_single_check, args=(host,)).start()
        return jsonify(host), 201
    else:
        return jsonify({'error': 'Failed to add host'}), 500


@app.route('/api/hosts/<path:hostname>', methods=['DELETE'])
def api_delete_host(hostname):
    db.remove_host(hostname)
    safe_emit('host:removed', {'hostname': hostname})
    return jsonify({'success': True})


@app.route('/api/hosts/<int:host_id>', methods=['PUT'])
def api_update_host(host_id):
    """Update firewall configuration details (label, IP/Console URL, branch type)."""
    data = request.get_json()
    if not data or not data.get('console_url'):
        return jsonify({'error': 'URL or IP is required'}), 400

    console_url = data['console_url'].strip()
    label = data.get('label', '').strip() or console_url
    branch_type = data.get('branch_type', 'SATELLITE').upper()
    if branch_type not in ('MAJOR', 'SATELLITE'):
        branch_type = 'SATELLITE'

    hostname, _, _ = parse_host_info(console_url)
    if not hostname:
        return jsonify({'error': 'Invalid URL or IP address'}), 400

    try:
        # Get old hostname so we can manage host_states cache
        conn = db.get_connection()
        old_row = conn.execute("SELECT hostname FROM hosts WHERE id = ?", (host_id,)).fetchone()
        old_hostname = old_row['hostname'] if old_row else None

        updated = db.update_host(host_id, hostname, label, console_url, branch_type)
        if updated:
            h_dict = dict(updated)
            
            # Update cache keys
            if old_hostname and old_hostname in host_states:
                state = host_states.pop(old_hostname)
                host_states[hostname] = state
            
            # Broadcast the update
            safe_emit('host:updated', {
                'old_hostname': old_hostname,
                'host': h_dict
            })
            
            # Immediately scan the updated firewall
            threading.Thread(target=run_single_check, args=(h_dict,)).start()
            
            return jsonify(h_dict), 200
        else:
            return jsonify({'error': 'Firewall not found'}), 404
    except ValueError as ve:
        return jsonify({'error': str(ve)}), 409
    except Exception as e:
        return jsonify({'error': f'Failed to update: {str(e)}'}), 500



@app.route('/api/check/all', methods=['POST'])
def api_check_all():
    """Trigger manual scan for all active firewalls in parallel."""
    hosts = db.get_hosts()
    threads = []
    results = {}

    def worker(h):
        state = run_single_check(h)
        results[h['hostname']] = state

    for h in hosts:
        t = threading.Thread(target=worker, args=(h,))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    return jsonify({'success': True, 'results': results})


@app.route('/api/check/<path:hostname>', methods=['POST'])
def api_check_single(hostname):
    """Trigger manual scan for a single firewall."""
    host = db.get_host_by_name(hostname)
    if not host:
        return jsonify({'error': 'Firewall not found'}), 404
    state = run_single_check(host)
    return jsonify({'success': True, 'state': state})



@app.route('/api/history/<path:hostname>', methods=['GET'])
def api_get_history(hostname):
    host = db.get_host_by_name(hostname)
    if not host:
        return jsonify({'error': 'Host not found'}), 404

    range_map = {
        '1h': '-1 hour',
        '6h': '-6 hours',
        '24h': '-24 hours',
        '7d': '-7 days',
    }
    range_modifier = range_map.get(request.args.get('range', '1h'), '-1 hour')
    history = db.get_history(host['id'], range_modifier)
    stats = db.get_stats(host['id'], range_modifier)
    return jsonify({'history': history, 'stats': stats})


@app.route('/api/downtimes/<path:hostname>', methods=['GET'])
def api_get_downtimes(hostname):
    host = db.get_host_by_name(hostname)
    if not host:
        return jsonify({'error': 'Host not found'}), 404

    range_map = {
        '1h': '-1 hour',
        '6h': '-6 hours',
        '24h': '-24 hours',
        '7d': '-7 days',
    }
    range_modifier = range_map.get(request.args.get('range', '24h'), '-24 hours')
    downtimes = db.get_downtimes(host['id'], range_modifier)
    return jsonify(downtimes)


@app.route('/api/alerts', methods=['GET'])
def api_get_alerts():
    return jsonify(db.get_all_alert_thresholds())


@app.route('/api/alerts/<path:hostname>', methods=['POST'])
def api_set_alert(hostname):
    host = db.get_host_by_name(hostname)
    if not host:
        return jsonify({'error': 'Host not found'}), 404

    data = request.get_json()
    if not data:
        return jsonify({'error': 'Invalid data'}), 400

    latency_ms = int(data.get('latency_ms', 150))
    enabled = bool(data.get('enabled', False))

    db.set_alert_threshold(host['id'], latency_ms, enabled)

    safe_emit('alert:updated', {
        'hostname': hostname,
        'latency_ms': latency_ms,
        'enabled': enabled,
    })

    return jsonify({'success': True})


@app.route('/api/overall/history', methods=['GET'])
def api_overall_history():
    range_map = {
        '1h': '-1 hour', '6h': '-6 hours',
        '24h': '-24 hours', '7d': '-7 days',
    }
    range_modifier = range_map.get(request.args.get('range', '1h'), '-1 hour')
    hosts = db.get_hosts()
    result = []
    for h in hosts:
        history = db.get_history(h['id'], range_modifier)
        stats   = db.get_stats(h['id'], range_modifier)
        result.append({
            'hostname': h['hostname'],
            'label':    h['label'],
            'branch_type': h['branch_type'],
            'history':  history,
            'stats':    stats,
        })
    return jsonify(result)


@app.route('/api/overall/logs', methods=['GET'])
def api_overall_logs():
    range_map = {
        '1h': '-1 hour', '6h': '-6 hours',
        '24h': '-24 hours', '7d': '-7 days',
    }
    range_modifier = range_map.get(request.args.get('range', '24h'), '-24 hours')
    hosts = db.get_hosts()
    result = []
    for h in hosts:
        downtimes = db.get_downtimes(h['id'], range_modifier)
        for d in downtimes:
            result.append({
                **d,
                'hostname': h['hostname'],
                'label': h['label'],
                'branch_type': h['branch_type']
            })
    # Sort all events newest first
    result.sort(key=lambda x: x['started_at'], reverse=True)
    return jsonify(result)


@app.route('/api/export/host/<path:hostname>', methods=['GET'])
def api_export_host(hostname):
    """Export a single host — ping history + downtime logs as CSV."""
    import csv, io
    from flask import Response
    host = db.get_host_by_name(hostname)
    if not host:
        return jsonify({'error': 'Host not found'}), 404

    range_modifier = '-3650 days' # all data

    history  = db.get_history(host['id'], range_modifier)
    stats    = db.get_stats(host['id'], range_modifier)
    downtimes = db.get_downtimes(host['id'], range_modifier)

    buf = io.StringIO()
    w = csv.writer(buf)

    # Host Info
    w.writerow(['# FIREWALL HOST INFO'])
    w.writerow(['hostname', 'label', 'branch_type', 'console_url', 'exported_at'])
    w.writerow([host['hostname'], host['label'], host['branch_type'], host['console_url'],
                datetime.now().strftime('%Y-%m-%d %H:%M:%S')])
    w.writerow([])

    # Summary Stats
    w.writerow(['# SUMMARY STATS (ALL TIME)'])
    w.writerow(['total_checks', 'lost_checks', 'min_latency_ms', 'avg_latency_ms', 'max_latency_ms', 'uptime_pct'])
    if stats and stats['total']:
        uptime = round((1 - stats['lost'] / stats['total']) * 100, 2)
        w.writerow([
            stats['total'], stats['lost'],
            round(stats['min_ms'], 2) if stats['min_ms'] else '',
            round(stats['avg_ms'], 2) if stats['avg_ms'] else '',
            round(stats['max_ms'], 2) if stats['max_ms'] else '',
            uptime,
        ])
    w.writerow([])

    # Check History
    w.writerow(['# CHECK HISTORY'])
    w.writerow(['timestamp', 'latency_ms', 'ping_status', 'console_status', 'overall_status'])
    for r in history:
        w.writerow([
            r['timestamp'], 
            r['latency_ms'] if r['latency_ms'] is not None else '',
            'UP' if r['ping_alive'] else 'DOWN',
            'UP' if r['console_alive'] else 'DOWN',
            'UP' if r['alive'] else 'DOWN'
        ])
    w.writerow([])

    # Downtime Events
    w.writerow(['# DOWNTIME LOGS'])
    w.writerow(['started_at', 'ended_at', 'duration_seconds', 'duration_readable', 'status'])
    for d in downtimes:
        duration_readable = ""
        if d['duration_seconds'] is not None:
            mins, secs = divmod(d['duration_seconds'], 60)
            hours, mins = divmod(mins, 60)
            if hours > 0:
                duration_readable = f"{hours}h {mins}m {secs}s"
            else:
                duration_readable = f"{mins}m {secs}s"

        w.writerow([
            d['started_at'],
            d['ended_at'] if d['ended_at'] else '',
            d['duration_seconds'] if d['duration_seconds'] is not None else '',
            duration_readable if d['ended_at'] else 'ONGOING',
            'ONGOING' if not d['ended_at'] else 'RESOLVED',
        ])

    safe_label = ''.join(c if c.isalnum() or c in '-_.' else '_' for c in host['label'])
    filename = f"{safe_label}_firewall_export.csv"
    buf.seek(0)
    return Response(
        buf.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': f'attachment; filename="{filename}"'}
    )


@app.route('/api/export/all', methods=['GET'])
def api_export_all():
    """Export ALL active hosts — history + downtime logs combined CSV."""
    import csv, io
    from flask import Response

    hosts = db.get_hosts()
    buf = io.StringIO()
    w = csv.writer(buf)

    w.writerow(['# FIREWALL MONITORING SYSTEM — FULL REPORT'])
    w.writerow(['exported_at', datetime.now().strftime('%Y-%m-%d %H:%M:%S')])
    w.writerow(['total_firewalls', len(hosts)])
    w.writerow([])

    for host in hosts:
        history   = db.get_history(host['id'], '-3650 days')
        stats     = db.get_stats(host['id'], '-3650 days')
        downtimes = db.get_downtimes(host['id'], '-3650 days')

        w.writerow([f'## FIREWALL: {host["label"]} ({host["hostname"]}) [{host["branch_type"]}]'])
        w.writerow(['console_url', host['console_url']])
        w.writerow([])

        # Summary
        w.writerow(['# SUMMARY'])
        w.writerow(['total_checks', 'lost_checks', 'min_latency_ms', 'avg_latency_ms', 'max_latency_ms', 'uptime_pct'])
        if stats and stats['total']:
            uptime = round((1 - stats['lost'] / stats['total']) * 100, 2)
            w.writerow([
                stats['total'], stats['lost'],
                round(stats['min_ms'], 2) if stats['min_ms'] else '',
                round(stats['avg_ms'], 2) if stats['avg_ms'] else '',
                round(stats['max_ms'], 2) if stats['max_ms'] else '',
                uptime,
            ])
        w.writerow([])

        # Downtime events
        w.writerow(['# DOWNTIME LOGS'])
        w.writerow(['started_at', 'ended_at', 'duration_seconds', 'status'])
        for d in downtimes:
            w.writerow([
                d['started_at'],
                d['ended_at'] if d['ended_at'] else '',
                d['duration_seconds'] if d['duration_seconds'] is not None else '',
                'ONGOING' if not d['ended_at'] else 'RESOLVED',
            ])
        w.writerow([])
        w.writerow(['─' * 60])
        w.writerow([])

    filename = f"firewall_full_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    buf.seek(0)
    return Response(
        buf.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': f'attachment; filename="{filename}"'}
    )


# --- Socket.IO Events -------------------------------------------------------

@socketio.on('connect')
def handle_connect():
    print(f"  [*] Client connected: {request.sid}", flush=True)
    hosts = db.get_hosts()
    for h in hosts:
        recent_pings = db.get_latest_pings(h['id'], 60)
        stats = db.get_stats(h['id'], '-1 hour')
        active_down = db.has_open_downtime(h['id'])
        
        down_since = None
        downtime_duration = 0
        if active_down:
            down_since = active_down['started_at']
            try:
                started_dt = datetime.strptime(down_since, '%Y-%m-%d %H:%M:%S')
                downtime_duration = int((datetime.now() - started_dt).total_seconds())
            except Exception:
                pass

        current_state = get_current_host_state(h)

        emit('host:init', {
            'host': h,
            'recentPings': recent_pings,
            'stats': stats,
            'is_down': active_down is not None,
            'down_since': down_since,
            'downtime_duration': downtime_duration,
            'current_state': current_state
        })

    # Send all alert thresholds
    thresholds = db.get_all_alert_thresholds()
    for t in thresholds:
        emit('alert:updated', t)


@socketio.on('disconnect')
def handle_disconnect():
    print(f"  [*] Client disconnected: {request.sid}", flush=True)


# --- Startup -----------------------------------------------------------------

DEFAULT_FIREWALLS = [
    # MAJOR BRANCHES
    {"label": "PITX T2", "console_url": "https://192.168.208.254:4444/webconsole/webpages/index.jsp#83940", "branch_type": "MAJOR"},
    {"label": "PITX T3", "console_url": "https://192.168.235.254:4444/webconsole/webpages/index.jsp#52508", "branch_type": "MAJOR"},
    {"label": "PANGASINAN", "console_url": "https://192.168.100.1:4444/webconsole/webpages/index.jsp#53062", "branch_type": "MAJOR"},
    {"label": "BEDROCK", "console_url": "https://192.168.74.254:4444/webconsole/webpages/index.jsp#80625", "branch_type": "MAJOR"},
    {"label": "MAKATI", "console_url": "https://192.168.16.6:4444/webconsole/webpages/login.jsp#71453", "branch_type": "MAJOR"},
    {"label": "CEBU", "console_url": "https://192.168.51.1:4444/webconsole/webpages/login.jsp#19369", "branch_type": "MAJOR"},
    {"label": "DAVAO", "console_url": "https://192.168.240.254:4444/webconsole/webpages/login.jsp", "branch_type": "MAJOR"},

    # SATELLITE BRANCHES
    {"label": "BACOLOD", "console_url": "192.168.25.1", "branch_type": "SATELLITE"},
    {"label": "BATANGAS", "console_url": "https://192.168.85.1:4444/", "branch_type": "SATELLITE"},
    {"label": "CALAMBA", "console_url": "https://192.168.45.1:4444/", "branch_type": "SATELLITE"},
    {"label": "CDO", "console_url": "https://192.168.30.1:4444/", "branch_type": "SATELLITE"},
    {"label": "GENSAN", "console_url": "https://192.168.20.1:4444/webconsole/webpages/login.jsp#75839", "branch_type": "SATELLITE"},
    {"label": "MALOLOS", "console_url": "https://192.168.41.1:4444/webconsole/webpages/login.jsp", "branch_type": "SATELLITE"},
    {"label": "PAGADIAN", "console_url": "https://192.168.60.1:4444/", "branch_type": "SATELLITE"},
    {"label": "PAMPANGA", "console_url": "https://192.168.35.1:4444/", "branch_type": "SATELLITE"},
    {"label": "TAGUM", "console_url": "https://192.168.62.254:4444/webconsole/webpages/login.jsp", "branch_type": "SATELLITE"},
    {"label": "ILO-ILO", "console_url": "https://192.168.83.254:4444/webconsole/webpages/login.jsp", "branch_type": "SATELLITE"},
    {"label": "ZAMBOANGA", "console_url": "https://192.168.55.1:4444/webconsole/webpages/login.jsp", "branch_type": "SATELLITE"},
]

def seed_defaults():
    """Seed predefined firewalls into the database."""
    hosts = db.get_hosts()
    if len(hosts) == 0:
        print("  [*] Seeding default firewalls...", flush=True)
        for fw in DEFAULT_FIREWALLS:
            hostname, _, _ = parse_host_info(fw["console_url"])
            db.add_host(hostname, fw["label"], fw["console_url"], fw["branch_type"])


def init_monitoring():
    """Trigger a one-time initial scan of all firewalls in parallel background threads upon server startup."""
    hosts = db.get_hosts()
    print(f"  [*] Running initial one-time scan of {len(hosts)} firewalls...", flush=True)
    for h in hosts:
        t = threading.Thread(target=run_single_check, args=(h,))
        t.start()
    print(f"  [*] Initial scan threads spawned for {len(hosts)} firewalls", flush=True)


def cleanup_scheduler():
    """Hourly worker to purge old SQLite rows."""
    while True:
        time.sleep(3600)
        db.cleanup()
        print("  [*] Database cleanup complete (purged data >7 days old)", flush=True)


def get_local_ip():
    """Retrieve primary LAN IP address of this host."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return "127.0.0.1"


# --- Main --------------------------------------------------------------------

if __name__ == '__main__':
    print("\n" + "=" * 60)
    print("  Firewall Monitoring Dashboard - Network Administration Tool")
    print("=" * 60, flush=True)

    # Initialize DB schema
    db.init_db()
    print("  [+] Database schema active", flush=True)

    # Seed initial firewall branch targets
    seed_defaults()

    # Launch staggered background threads for monitoring
    init_monitoring()

    # Launch cleanup timer thread
    cleanup_thread = threading.Thread(target=cleanup_scheduler, daemon=True)
    cleanup_thread.start()

    local_ip = get_local_ip()
    print(f"\n  Dashboard running at:")
    print(f"    - Local:   http://localhost:{PORT}")
    if local_ip and local_ip != "127.0.0.1":
        print(f"    - Network: http://{local_ip}:{PORT}")
    print()

    # Run the Flask-SocketIO server
    socketio.run(
        app,
        host='0.0.0.0',
        port=PORT,
        debug=False,
        use_reloader=False,
        allow_unsafe_werkzeug=True
    )
