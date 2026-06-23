from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import time
import os
import sys
import sqlite3

sys.path.append(
    os.path.join(os.path.dirname(__file__), "analysis")
)

from analyze import analyze_logs, classify_attack, analyze_file_logs

app = Flask(__name__)
CORS(app)

logs = []
blocked_ips = set()

# ===============================
# DATABASE
# ===============================
def init_db():
    conn = sqlite3.connect("ids.db")
    cursor = conn.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS attack_history(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        attack_time TEXT,
        attack_type TEXT,
        attacker_ip TEXT,
        request_rate REAL,
        unique_ips INTEGER
    )
    """)
    conn.commit()
    conn.close()

init_db()

# ===============================
# LOGGING
# ===============================
@app.before_request
def log_request():
    if request.path in ['/detect', '/stats', '/history', '/favicon.ico', '/reset', '/analyze_file']:
        return

    ip = request.headers.get('X-Forwarded-For', request.remote_addr)

    if ip in blocked_ips:
        return jsonify({"error": "IP Blocked"}), 403

    log_entry = {
        "ip": ip,
        "time": time.time(),
        "path": request.path,
        "agent": request.headers.get("User-Agent", "unknown")
    }
    logs.append(log_entry)

    try:
        with open("traffic.log", "a") as f:
            f.write(f"{ip},{log_entry['time']},{log_entry['path']}\n")
    except Exception as e:
        print("Log yazma hatası:", e)

# ===============================
# DASHBOARD
# ===============================
@app.route('/')
def home():
    return render_template("index.html")

# ===============================
# ATTACK DETECTION
# ===============================
@app.route('/detect')
def detect():
    current_time = time.time()
    recent_logs = [log for log in logs if current_time - log["time"] < 120]

    counter = analyze_logs(recent_logs)
    result = classify_attack(counter, recent_logs)

    if "types" not in result:
        result["types"] = []
    elif isinstance(result["types"], str):
        result["types"] = [result["types"]]

    if result.get("attack"):
        attackers = result.get("attackers", [])
        for ip in attackers:
            blocked_ips.add(ip)

        conn = sqlite3.connect("ids.db")
        cursor = conn.cursor()

        for attack_type in result["types"]:
            for ip in attackers:
                cursor.execute("""
                INSERT INTO attack_history (attack_time, attack_type, attacker_ip, request_rate, unique_ips)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    time.strftime("%Y-%m-%d %H:%M:%S"),
                    attack_type,
                    ip,
                    result.get("rate", 0),
                    result.get("unique_ips", 0)
                ))
        conn.commit()
        conn.close()

    return jsonify(result)

# ===============================
# STATS
# ===============================
@app.route('/stats')
def stats():
    current_time = time.time()
    recent_logs = [log for log in logs if current_time - log["time"] < 120]

    counter = analyze_logs(recent_logs)
    top_ip = None
    if counter:
        top_ip = counter.most_common(1)[0]

    return jsonify({
        "total_logs": len(logs),
        "recent_logs": len(recent_logs),
        "unique_ips": len(set([log["ip"] for log in logs])),
        "blocked_ips": len(blocked_ips),
        "top_ip": top_ip
    })

# ===============================
# DATABASE HISTORY (Tam Zaman Dönüşümlü Filtre)
# ===============================
@app.route('/history')
def history():
    start_param = request.args.get('start')
    end_param = request.args.get('end')

    conn = sqlite3.connect("ids.db")
    cursor = conn.cursor()

    query = "SELECT attack_time, attack_type, attacker_ip, request_rate, unique_ips FROM attack_history"
    conditions = []
    params = []

    # SQLite strftime fonksiyonu ile veritabanındaki boşluklu veriyi ve query'deki T'li veriyi normalize edip karşılaştırıyoruz
    if start_param:
        conditions.append("strftime('%Y-%m-%d %H:%M:%S', attack_time) >= strftime('%Y-%m-%d %H:%M:%S', ?)")
        params.append(start_param)
    if end_param:
        conditions.append("strftime('%Y-%m-%d %H:%M:%S', attack_time) <= strftime('%Y-%m-%d %H:%M:%S', ?)")
        params.append(end_param)

    if conditions:
        query += " WHERE " + " AND ".join(conditions)

    query += " ORDER BY id DESC LIMIT 50"

    cursor.execute(query, params)
    rows = cursor.fetchall()
    conn.close()

    history_data = []
    for row in rows:
        history_data.append({
            "time": row[0],
            "type": row[1],
            "ip": row[2],
            "rate": row[3],
            "unique_ips": row[4]
        })

    return jsonify(history_data)

# ===============================
# FILE ANALYSIS & RESET & START
# ===============================
@app.route('/analyze_file')
def analyze_file():
    if os.path.exists("traffic.log"):
        return jsonify(analyze_file_logs("traffic.log"))
    return jsonify({"error": "Log file not found"})

@app.route('/reset')
def reset():
    global logs, blocked_ips
    logs = []
    blocked_ips = set()
    conn = sqlite3.connect("ids.db")
    cursor = conn.cursor()
    cursor.execute("DELETE FROM attack_history")
    conn.commit()
    conn.close()
    return jsonify({"status": "System Reset"})

if __name__ == '__main__':
    app.run(debug=True, port=5000)