from flask import Flask, request, jsonify, render_template
from flask_cors import CORS # Dış erişim ve dashboard iletişimi için
import time
import os
import sys

# 1. Klasör Yolunu Ayarla: server/analysis içindeki modülleri bulabilmesi için
sys.path.append(os.path.join(os.path.dirname(__file__), "analysis"))

try:
    from analyze import analyze_logs, classify_attack, analyze_file_logs
except ImportError:
    print("HATA: analyze.py modülü bulunamadı. Klasör yapısını kontrol edin.")

app = Flask(__name__)
CORS(app) # Tarayıcıdan gelen isteklere izin ver

logs = []

# 2. Log Kayıt Fonksiyonu
@app.before_request
def log_request():
    # Dashboard'un kendi veri çekme isteklerini loglama (sonsuz döngüyü önler)
    if request.path in ['/detect', '/stats', '/favicon.ico'] or request.path.startswith('/static'):
        return

    ip = request.headers.get('X-Forwarded-For', request.remote_addr)

    log_entry = {
        "ip": ip,
        "time": time.time(),
        "path": request.path,
        "agent": request.headers.get("User-Agent", "unknown")
    }

    logs.append(log_entry)

    # DOSYAYA YAZ (server/traffic.log)
    try:
        with open("traffic.log", "a") as f:
            f.write(f"{ip},{log_entry['time']},{log_entry['path']}\n")
    except Exception as e:
        print(f"Dosya yazma hatası: {e}")

# 3. Dashboard Ana Sayfası
@app.route('/')
def home():
    # server/templates/index.html dosyasını döndürür
    return render_template("index.html")

# 4. Analiz ve Tespit Endpoint'i
@app.route('/detect')
def detect():
    current_time = time.time()
    # Son 30 saniyelik veriyi analiz et
    recent_logs = [log for log in logs if current_time - log["time"] < 120]

    counter = analyze_logs(recent_logs)
    result = classify_attack(counter, recent_logs)

    if result.get("attack"):
        print(f" SALDIRI TESPİTİ: {result.get('types')}")

    return jsonify(result)

# 5. Dashboard İstatistikleri
@app.route('/stats')
def stats():
    current_time = time.time()
    recent_logs_count = len([log for log in logs if current_time - log["time"] < 120])
    
    return jsonify({
        "total_logs": len(logs),
        "recent_logs": recent_logs_count,
        "unique_ips": len(set([log["ip"] for log in logs]))
    })

# 6. Log Dosyasından Analiz
@app.route('/analyze_file')
def analyze_file():
    if os.path.exists("traffic.log"):
        result = analyze_file_logs("traffic.log")
        return jsonify(result)
    return jsonify({"error": "Log dosyası bulunamadı."}), 404

# 7. Sistemi Sıfırla
@app.route('/reset')
def reset():
    global logs
    logs = []
    return jsonify({"status": "Bellek temizlendi"})

if __name__ == '__main__':
    # Flask sunucusunu başlat
    print("--------------------------------------")
    print(" IDS Sunucusu Aktif")
    print(" Dashboard: http://127.0.0.1:5000")
    print("--------------------------------------")
    app.run(debug=True, port=5000)