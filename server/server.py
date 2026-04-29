from flask import Flask, request, jsonify
import time
import os
import sys

# analysis klasörünü ekle
sys.path.append(os.path.join(os.path.dirname(__file__), "analysis"))

from analyze import analyze_logs, classify_attack, analyze_file_logs

app = Flask(__name__)

logs = []


#  TÜM ENDPOINTLERDEN LOG AL 
@app.before_request
def log_request():
    ip = request.headers.get('X-Forwarded-For', request.remote_addr)

    log_entry = {
        "ip": ip,
        "time": time.time(),
        "path": request.path,
        "agent": request.headers.get("User-Agent", "unknown")
    }

    logs.append(log_entry)

    # DOSYAYA YAZ
    with open("traffic.log", "a") as f:
        f.write(f"{ip},{log_entry['time']},{log_entry['path']}\n")


@app.route('/')
def home():
    return "Server running"


@app.route('/detect')
def detect():
    current_time = time.time()

    # son 30 saniye analiz
    recent_logs = [log for log in logs if current_time - log["time"] < 30]

    counter = analyze_logs(recent_logs)
    result = classify_attack(counter, recent_logs)

    # GERÇEK ZAMANLI UYARI
    if result.get("attack"):
        print(" ATTACK DETECTED:", result)

    return jsonify(result)


#  İSTATİSTİK
@app.route('/stats')
def stats():
    return jsonify({
        "total_logs": len(logs),
        "recent_logs": len([log for log in logs if time.time() - log["time"] < 30]),
        "unique_ips": len(set([log["ip"] for log in logs]))
    })


#  DOSYADAN ANALİZ
@app.route('/analyze_file')
def analyze_file():
    result = analyze_file_logs("traffic.log")
    return jsonify(result)


@app.route('/reset')
def reset():
    logs.clear()
    return {"status": "cleared"}


if __name__ == '__main__':
    app.run(debug=True)