from flask import Flask, request, jsonify
import time
import os
import sys

# analysis klasörünü ekle
sys.path.append(os.path.join(os.path.dirname(__file__), "analysis"))

from analyze import analyze_logs, classify_attack

app = Flask(__name__)

logs = []


@app.route('/')
def home():
    # ✅ SADECE BURADA OLMALI
    ip = request.headers.get('X-Forwarded-For', request.remote_addr)

    logs.append({
        "ip": ip,
        "time": time.time()
    })

    return "Server running"


@app.route('/detect')
def detect():
    current_time = time.time()

    recent_logs = [log for log in logs if current_time - log["time"] < 10]

    counter = analyze_logs(recent_logs)
    result = classify_attack(counter, recent_logs)

    return jsonify(result)


@app.route('/reset')
def reset():
    logs.clear()
    return {"status": "cleared"}


if __name__ == '__main__':
    app.run(debug=True)