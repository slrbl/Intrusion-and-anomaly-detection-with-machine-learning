import random
from datetime import datetime, timedelta

# User agents (including some suspicious ones)
user_agents = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Unknown; Linux x86_64) AppleWebKit/534.34 (KHTML, like Gecko) PhantomJS/1.9.8 Safari/534.34",
    "sqlmap/1.4.9#stable",
    "curl/7.68.0",
    "Nmap Scripting Engine"
]

# IPs (some legitimate, some potentially malicious)
ips = [
    "54.175.105.120", "185.220.101.45", "198.51.100.23", "203.0.113.5",
    "89.248.165.66", "103.21.244.0", "192.168.1.101", "10.0.0.23"
]

# Paths with normal and malicious content
paths = [
    "/", "/login", "/admin", "/wp-login.php", "/phpmyadmin",
    "/.env", "/config.php", "/index.php?id=1' OR '1'='1", "/search?q=<script>alert(1)</script>"
]

# Status codes
status_codes = [200, 301, 403, 404, 500]

# Function to generate one log line
def create_log_line(ip, timestamp, method, path, status, size, user_agent):
    return f'{ip} - - [{timestamp}] "{method} {path} HTTP/1.1" {status} {size} "-" "{user_agent}"'

# Generate 300 lines
log_lines = []
start_time = datetime.now()

for _ in range(300):
    ip = random.choice(ips)
    time_offset = timedelta(seconds=random.randint(0, 86400))
    timestamp = (start_time - time_offset).strftime("%d/%b/%Y:%H:%M:%S -0700")
    method = random.choice(["GET", "POST"])
    path = random.choice(paths)
    status = random.choice(status_codes)
    size = random.randint(100, 20000)
    user_agent = random.choice(user_agents)
    log_lines.append(create_log_line(ip, timestamp, method, path, status, size, user_agent))

# Write to file
with open("apache_log_formatted.txt", "w") as f:
    f.write("\n".join(log_lines))
