from collections import Counter


def analyze_logs(logs):
    ips = [log["ip"] for log in logs]
    return Counter(ips)


def classify_attack(counter, logs, threshold=20):
    if not logs:
        return {"attack": False, "type": "No Data"}

    total_requests = len(logs)
    unique_ips = len(counter)

    times = sorted([log["time"] for log in logs])
    duration = max(times) - min(times) if len(times) > 1 else 1

    request_rate = total_requests / duration if duration > 0 else total_requests

    intervals = [t2 - t1 for t1, t2 in zip(times, times[1:])]
    avg_interval = sum(intervals) / len(intervals) if intervals else 0

    unique_ratio = unique_ips / total_requests if total_requests > 0 else 0

    attackers = [ip for ip, count in counter.items() if count > threshold]

    if not attackers:
        return {
            "attack": False,
            "type": "Normal Traffic",
            "request_rate": round(request_rate, 2)
        }

    if len(attackers) == 1:
        if request_rate > 100:
            attack_type = "High Rate DoS"
        elif avg_interval > 0.5:
            attack_type = "Slow DoS"
        else:
            attack_type = "DoS"

        return {
            "attack": True,
            "type": attack_type,
            "ip": attackers[0],
            "rate": round(request_rate, 2)
        }

    else:
        if unique_ratio > 0.5:
            attack_type = "Highly Distributed DDoS"
        elif request_rate > 200:
            attack_type = "DDoS Flood Attack"
        else:
            attack_type = "Distributed Attack"

        return {
            "attack": True,
            "type": attack_type,
            "attackers": attackers,
            "rate": round(request_rate, 2)
        }