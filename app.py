#!/usr/bin/env python3
from flask import Flask, render_template, jsonify, request
import sqlite3
import subprocess
from datetime import datetime

app = Flask(__name__)
DB_PATH = "/opt/wazuh-dashboard/events.db"

def query_db(sql, params=()):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(sql, params).fetchall()
    conn.close()
    return [dict(r) for r in rows]

def scalar_db(sql, params=()):
    conn = sqlite3.connect(DB_PATH)
    val = conn.execute(sql, params).fetchone()[0]
    conn.close()
    return val

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/events")
def get_events():
    hours    = request.args.get("hours",    24,   type=int)
    limit    = request.args.get("limit",    200,  type=int)
    severity = request.args.get("severity", "")
    server   = request.args.get("server",   "")
    category = request.args.get("category", "")

    where  = ["timestamp > datetime('now', ?)"]
    params = [f"-{hours} hours"]

    if severity:
        where.append("severity = ?"); params.append(severity)
    if server:
        where.append("server = ?");   params.append(server)
    if category:
        where.append("category = ?"); params.append(category)

    params.append(limit)
    sql = f"SELECT id,timestamp,server,event_id,category,label,severity,username,source_ip FROM events WHERE {' AND '.join(where)} ORDER BY timestamp DESC LIMIT ?"
    return jsonify(query_db(sql, params))

@app.route("/api/event/<int:event_id>")
def get_event_detail(event_id):
    rows = query_db("SELECT * FROM events WHERE id = ?", (event_id,))
    if not rows:
        return jsonify({}), 404
    return jsonify(rows[0])

@app.route("/api/stats")
def get_stats():
    today = datetime.utcnow().strftime("%Y-%m-%d")
    return jsonify({
        "total_today":    scalar_db("SELECT COUNT(*) FROM events WHERE timestamp LIKE ?", (f"{today}%",)),
        "failed_logins":  scalar_db("SELECT COUNT(*) FROM events WHERE category='login_fail' AND timestamp LIKE ?", (f"{today}%",)),
        "locked_accounts":scalar_db("SELECT COUNT(*) FROM events WHERE category='account_locked' AND timestamp LIKE ?", (f"{today}%",)),
        "critical_count": scalar_db("SELECT COUNT(*) FROM events WHERE severity='critical' AND timestamp LIKE ?", (f"{today}%",)),
        "servers":        [r["server"] for r in query_db("SELECT DISTINCT server FROM events ORDER BY server")],
    })

@app.route("/api/brute_force")
def get_brute_force():
    return jsonify(query_db("""
        SELECT source_ip, server, COUNT(*) AS attempt_count, MAX(timestamp) AS last_seen,
               GROUP_CONCAT(DISTINCT username) AS usernames
        FROM events
        WHERE category = 'login_fail'
          AND timestamp > datetime('now', '-15 minutes')
          AND source_ip NOT IN ('-', '')
        GROUP BY source_ip, server
        HAVING attempt_count >= 5
        ORDER BY attempt_count DESC
    """))

@app.route("/api/top_users")
def get_top_users():
    hours = request.args.get("hours", 24, type=int)
    return jsonify(query_db("""
        SELECT username, COUNT(*) AS event_count,
               SUM(CASE WHEN category='login_success' THEN 1 ELSE 0 END) AS success,
               SUM(CASE WHEN category='login_fail'    THEN 1 ELSE 0 END) AS failed
        FROM events
        WHERE timestamp > datetime('now', ?)
          AND username NOT IN ('-', '')
        GROUP BY username
        ORDER BY event_count DESC
        LIMIT 10
    """, (f"-{hours} hours",)))

@app.route("/api/update", methods=["POST"])
def run_update():
    try:
        result = subprocess.run(
            ["/opt/wazuh-dashboard/update.sh"],
            capture_output=True, text=True, timeout=60
        )
        output = result.stdout + result.stderr
        success = result.returncode == 0
        return jsonify({"success": success, "output": output})
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "output": "Güncelleme zaman aşımına uğradı (60s)."})
    except Exception as e:
        return jsonify({"success": False, "output": str(e)})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=False)
