from collections import Counter


def analyze_logs(logs):
    ips = [log["ip"] for log in logs]
    return Counter(ips)


def classify_attack(counter, logs, threshold=20):

    if not logs:
        return {
            "attack": False,
            "types": ["No Data"]
        }

    total_requests = len(logs)

    unique_ips = len(counter)

    times = sorted([log["time"] for log in logs])

    duration = max(times) - min(times) if len(times) > 1 else 1

    request_rate = total_requests / duration if duration > 0 else total_requests

    paths = [log.get("path", "/") for log in logs]
    path_counts = Counter(paths)

    most_targeted = max(path_counts, key=path_counts.get)

    agents = [log.get("agent", "unknown") for log in logs]

    unique_agents = len(set(agents))

    attackers = [ip for ip, count in counter.items() if count > threshold]

    attack_types = []

    if attackers:

        if "login" in most_targeted:
            attack_types.append("Brute Force Attack")

        if "/api" in most_targeted:
            attack_types.append("API Abuse Attack")

        if unique_agents < 2:
            attack_types.append("Bot Attack")

        if request_rate < 10:
            attack_types.append("Slow DoS")

        if unique_ips == 1:
            attack_types.append("DoS")

        if unique_ips > 5 and request_rate > 100:
            attack_types.append("DDoS Flood")

        if not attack_types:
            attack_types.append("Distributed Attack")

        return {
            "attack": True,
            "types": attack_types,
            "rate": round(request_rate, 2),
            "unique_ips": unique_ips,
            "attackers": attackers
        }

    return {
        "attack": False,
        "types": ["Normal Traffic"]
    }


def analyze_file_logs(filename):

    try:

        with open(filename, "r") as f:
            lines = f.readlines()

        ips = [line.split(",")[0] for line in lines]

        counter = Counter(ips)

        return {
            "total_requests": len(lines),
            "unique_ips": len(counter),
            "top_ip": counter.most_common(1)[0] if counter else None
        }

    except FileNotFoundError:
        return {
            "error": "Log file not found"
        }