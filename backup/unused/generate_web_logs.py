import json
import random
import time
from datetime import datetime, timedelta

output_file = "/home/huynn/Desktop/prj3/datasets/logs.json"
num_records = 2000

# Attack signatures
sqli_payloads = ["' OR 1=1 --", "UNION SELECT 1,2,3", "admin' --", "1; DROP TABLE users"]
xss_payloads = ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "javascript:alert(1)"]
traversal_payloads = ["../../etc/passwd", "..\\..\\windows\\win.ini", "/proc/self/environ"]
scanners = ["Nmap Scripting Engine", "Nikto", "Sqlmap", "BurpSuite"]
user_agents = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
    "Mozilla/5.0 (Linux; Android 10; SM-G981B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.162 Mobile Safari/537.36",
]

# Target paths
paths = ["/login", "/search", "/admin", "/profil", "/api/v1/users", "/index.html", "/contact"]

def generate_log():
    timestamp = (datetime.now() - timedelta(minutes=random.randint(0, 1440))).isoformat()
    client_ip = f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}"
    
    # 20% malicious traffic
    is_attack = random.random() < 0.2
    
    if is_attack:
        attack_type = random.choice(["SQLi", "XSS", "Traversal", "Scan"])
        if attack_type == "SQLi":
            method = "GET"
            path = random.choice(paths) + "?q=" + random.choice(sqli_payloads)
            status = random.choice([200, 500])
            ua = random.choice(user_agents)
        elif attack_type == "XSS":
            method = "POST"
            path = random.choice(paths)
            status = 200
            ua = random.choice(user_agents)
        elif attack_type == "Traversal":
            method = "GET"
            path = random.choice(paths) + "?file=" + random.choice(traversal_payloads)
            status = 403
            ua = random.choice(user_agents)
        else: # Scan
            method = "GET"
            path = "/"
            status = 404
            ua = random.choice(scanners)
    else:
        attack_type = "Normal"
        method = random.choice(["GET", "POST"])
        path = random.choice(paths)
        status = random.choice([200, 200, 200, 301, 302, 404])
        ua = random.choice(user_agents)

    log_entry = {
        "@timestamp": timestamp,
        "source": {"ip": client_ip},
        "http": {
            "request": {"method": method, "original": path},
            "response": {"status_code": status},
            "user_agent": {"original": ua}
        },
        "event": {
            "dataset": "apache.access",
            "category": ["web"],
            "type": ["access"],
            "outcome": "success" if status < 400 else "failure"
        },
        "tags": [attack_type] if is_attack else []
    }
    
    return json.dumps({"index": {"_index": "siem-logs-web"}}) + "\n" + json.dumps(log_entry) + "\n"

with open(output_file, "w") as f:
    for _ in range(num_records):
        f.write(generate_log())

print(f"Generated {num_records} logs to {output_file}")
