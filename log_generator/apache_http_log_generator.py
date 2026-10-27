import random
from datetime import datetime, timedelta

NORMAL_IPS = ["203.0.113.10", "203.0.113.11", "203.0.113.12", "198.51.100.20"]
NORMAL_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
]
NORMAL_PATHS = [
    ("GET", "/", 200, 4200),
    ("GET", "/products", 200, 8100),
    ("GET", "/products/42", 200, 5600),
    ("GET", "/search?q=shoes", 200, 3900),
    ("GET", "/cart", 200, 2100),
    ("POST", "/login", 302, 180),
    ("GET", "/about", 200, 2400),
    ("GET", "/favicon.ico", 200, 900),
]

# A few unusual requests buried in ordinary traffic, for detection tests.
ATTACKS = [
    ("185.199.108.153", "GET", "/index.php?id=1'+OR+'1'%3D'1", 500, 120, "sqlmap/1.7.8#stable"),
    ("185.199.108.153", "GET", "/search?q=<script>alert(1)</script>", 200, 240, "Mozilla/5.0 (compatible; scanner)"),
    ("45.33.32.156", "GET", "/.env", 404, 196, "curl/8.5.0"),
    ("45.33.32.156", "GET", "/wp-login.php", 404, 210, "Mozilla/5.0 (compatible; Nmap Scripting Engine)"),
    ("91.240.118.84", "GET", "/admin/../../etc/passwd", 400, 140, "python-requests/2.31.0"),
    ("91.240.118.84", "POST", "/xmlrpc.php", 404, 320, "Mozilla/5.0"),
    ("77.88.55.77", "GET", "/products?id=1&union=select&from=users", 500, 260, "sqlmap/1.7.8#stable"),
    ("77.88.55.77", "GET", "/backup/site.sql", 404, 180, "curl/8.5.0"),
]


def line(ip, timestamp, method, path, status, size, user_agent):
    return (
        f'{ip} - - [{timestamp}] "{method} {path} HTTP/1.1" '
        f'{status} {size} "-" "{user_agent}"'
    )


def main():
    random.seed(21)
    start = datetime(2026, 10, 21, 8, 0, 0)
    combined = []

    for i in range(800):
        method, path, status, size = random.choice(NORMAL_PATHS)
        if random.random() < 0.04:
            status = 404
            path = "/missing-page"
        combined.append((
            start + timedelta(seconds=i * 30),
            random.choice(NORMAL_IPS),
            method,
            path,
            status,
            max(80, size + random.randint(-80, 80)),
            random.choice(NORMAL_AGENTS),
        ))

    for offset, attack in enumerate(ATTACKS):
        ip, method, path, status, size, user_agent = attack
        combined.append((
            start + timedelta(seconds=12000 + offset * 47),
            ip,
            method,
            path,
            status,
            size,
            user_agent,
        ))

    combined.sort(key=lambda item: item[0])
    rendered = []
    for when, ip, method, path, status, size, user_agent in combined:
        stamp = when.strftime("%d/%b/%Y:%H:%M:%S +0000")
        rendered.append(line(ip, stamp, method, path, status, size, user_agent))

    output = "apache_access_test.log"
    with open(output, "w") as handle:
        handle.write("\n".join(rendered) + "\n")
    print(f"Wrote {len(rendered)} lines to {output} ({len(ATTACKS)} unusual requests)")


if __name__ == "__main__":
    main()
