"""The decoy services.

* shell: a Telnet-style login on a fake Ubuntu database server. Weak passwords are
  "accepted" so the attacker reveals what they do next; every command gets a plausible
  answer and is logged.
* http: a fake admin panel login page that logs every request, path and submitted
  credential.

Nothing is ever executed: commands are only matched against canned responses.
"""
import asyncio
import time
import uuid

from honeypot.events import EventLog

HOSTNAME = "srv-db01"
BANNER = "Ubuntu 20.04.6 LTS\r\n\r\n"
WEAK = {("root", "123456"), ("root", "root"), ("admin", "admin"), ("admin", "password"),
        ("ubuntu", "ubuntu"), ("pi", "raspberry")}
MAX_LOGIN_ATTEMPTS = 5
IDLE_TIMEOUT = 60

FAKE = {
    "whoami": "root",
    "id": "uid=0(root) gid=0(root) groups=0(root)",
    "pwd": "/root",
    "hostname": HOSTNAME,
    "uname": "Linux",
    "uname -a": f"Linux {HOSTNAME} 5.4.0-174-generic #193-Ubuntu SMP x86_64 GNU/Linux",
    "ls": "backup.sql  db_config.ini  scripts",
    "ls -la": ("total 32\ndrwx------ 5 root root 4096 Oct 20 09:12 .\n"
               "-rw-r--r-- 1 root root 8421 Oct 19 22:01 backup.sql\n"
               "-rw------- 1 root root  312 Oct 12 10:44 db_config.ini\n"
               "drwxr-xr-x 2 root root 4096 Oct 12 10:40 scripts"),
    "cat /etc/passwd": ("root:x:0:0:root:/root:/bin/bash\n"
                        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
                        "mysql:x:112:118:MySQL Server,,,:/nonexistent:/bin/false"),
    "cat db_config.ini": "[mysql]\nhost=10.0.3.15\nuser=app\npassword=Spring2024!",
    "ps aux": "root 1 0.0 0.1 168 ? Ss 09:00 0:02 /sbin/init\n"
              "mysql 812 0.4 6.2 1765 ? Ssl 09:00 4:11 /usr/sbin/mysqld",
    "w": " 10:41:07 up 21 days,  2:03,  1 user,  load average: 0.08, 0.05, 0.01",
    "ifconfig": "eth0: inet 10.0.3.21  netmask 255.255.255.0  broadcast 10.0.3.255",
    "nproc": "4",
    "free -m": "Mem: 7962 2210 3011 12 2740 5402",
}


def respond(command: str) -> str:
    cmd = command.strip()
    if cmd in FAKE:
        return FAKE[cmd]
    first = cmd.split()[0] if cmd else ""
    if first in ("wget", "curl"):
        return "Connecting... connected.\nHTTP request sent, awaiting response... 200 OK\n" \
               "Saving to: 'payload'\n\n100%[===================>] 1.21M  --.-KB/s    in 0.3s"
    if first in ("chmod", "cd", "export", "history", "unset", "echo", "rm", "mkdir", "crontab",
                 "nohup", "sudo"):
        return ""
    if first in ("apt", "apt-get", "yum"):
        return "E: Could not open lock file /var/lib/dpkg/lock-frontend"
    return f"-bash: {first}: command not found" if first else ""


class Shell:
    def __init__(self, log: EventLog):
        self.log = log

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        ip = writer.get_extra_info("peername")[0]
        session, started = uuid.uuid4().hex[:12], time.monotonic()
        self.log.write("shell", session, ip, "connect")

        async def ask(prompt: str) -> str | None:
            writer.write(prompt.encode())
            await writer.drain()
            line = await asyncio.wait_for(reader.readline(), IDLE_TIMEOUT)
            return line.decode(errors="replace").strip() if line else None

        try:
            writer.write(BANNER.encode())
            user = None
            for _ in range(MAX_LOGIN_ATTEMPTS):
                name = await ask(f"{HOSTNAME} login: ")
                password = await ask("Password: ") if name is not None else None
                if name is None or password is None:
                    return
                ok = (name, password) in WEAK
                self.log.write("shell", session, ip, "login", user=name, password=password,
                               success=ok)
                if ok:
                    user = name
                    break
                writer.write(b"\r\nLogin incorrect\r\n")
            if user is None:
                return
            writer.write(b"Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-174-generic x86_64)"
                         b"\r\n\r\n")
            while True:
                command = await ask(f"{user}@{HOSTNAME}:~# ")
                if command is None or command in ("exit", "logout"):
                    return
                self.log.write("shell", session, ip, "command", command=command)
                out = respond(command)
                writer.write((out.replace("\n", "\r\n") + ("\r\n" if out else "")).encode())
        except (TimeoutError, ConnectionError):
            pass
        finally:
            self.log.write("shell", session, ip, "disconnect",
                           duration=round(time.monotonic() - started, 2))
            writer.close()


LOGIN_PAGE = """<!doctype html><html><head><title>Admin Panel - Sign in</title></head>
<body><h2>DataCore Admin Panel</h2><form method="post" action="/login">
<input name="username" placeholder="Username"><input name="password" type="password">
<button>Sign in</button></form></body></html>"""


class Http:
    def __init__(self, log: EventLog):
        self.log = log

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        ip = writer.get_extra_info("peername")[0]
        try:
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 10)
            lines = head.decode(errors="replace").split("\r\n")
            method, path, _ = (lines[0].split(" ") + ["", "", ""])[:3]
            headers = {k.strip().lower(): v.strip() for k, _, v in
                       (line.partition(":") for line in lines[1:] if ":" in line)}
            length = min(int(headers.get("content-length", "0") or 0), 65536)
            body = (await reader.readexactly(length)).decode(errors="replace") if length else ""
            if path in ("/", "/admin", "/login") and method == "GET":
                status, page = "200 OK", LOGIN_PAGE
            elif path == "/login" and method == "POST":
                status, page = "401 Unauthorized", "Invalid username or password"
            else:
                status, page = "404 Not Found", "Not Found"
            self.log.write("http", ip, ip, "request", method=method, path=path[:500],
                           body=body[:500], user_agent=headers.get("user-agent", "")[:200],
                           status=int(status[:3]))
            data = page.encode()
            writer.write(f"HTTP/1.1 {status}\r\nServer: nginx/1.18.0 (Ubuntu)\r\n"
                         f"Content-Type: text/html\r\nContent-Length: {len(data)}\r\n"
                         f"Connection: close\r\n\r\n".encode() + data)
            await writer.drain()
        except (TimeoutError, asyncio.IncompleteReadError, ConnectionError, ValueError):
            pass
        finally:
            writer.close()


async def serve(log: EventLog, host: str = "0.0.0.0", shell_port: int = 2323,
                http_port: int = 8088):
    shell = await asyncio.start_server(Shell(log).handle, host, shell_port)
    http = await asyncio.start_server(Http(log).handle, host, http_port)
    print(f"Honeypot listening: shell on {host}:{shell_port}, http on {host}:{http_port}")
    async with shell, http:
        await asyncio.gather(shell.serve_forever(), http.serve_forever())
