#!/usr/bin/env python3
"""

ATHEX VORTEX — CLIENT  v1.0.0                    
Tunneling & Port Forwarding Suite                

Run:  python run.py
Auto-installs: fastapi uvicorn[standard] websockets cryptography psutil rich aiofiles
"""

# ── 1. Bootstrap: auto-install missing packages ───────────
import subprocess, sys, importlib.util as _ilu

_DEPS = {
    "fastapi":      "fastapi",
    "uvicorn":      "uvicorn[standard]",
    "websockets":   "websockets",
    "cryptography": "cryptography",
    "psutil":       "psutil",
    "rich":         "rich",
    "aiofiles":     "aiofiles",
}

def _pip(pkg):
    for extra in ([], ["--break-system-packages"]):
        r = subprocess.run(
            [sys.executable, "-m", "pip", "install", "--quiet", pkg] + extra,
            capture_output=True)
        if r.returncode == 0:
            return True
    return False

_missing = [pkg for mod, pkg in _DEPS.items() if _ilu.find_spec(mod) is None]
if _missing:
    print(f"[ATHEX] Installing dependencies: {', '.join(_missing)}")
    for pkg in _missing:
        ok = _pip(pkg)
        print(f"  {'OK' if ok else 'FAIL'}: {pkg}")
    print("[ATHEX] Restarting...\n")
    import os as _os
    _os.execv(sys.executable, [sys.executable] + sys.argv)

# ── 2. Imports ────────────────────────────────────────────
import os, json, time, uuid, socket, hashlib, struct
import random, string, asyncio, threading, platform, select
import sqlite3, base64, logging
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional, Dict, List

import psutil
import uvicorn
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

console = Console()

# ── 3. Paths & constants ──────────────────────────────────
BASE_DIR     = Path(__file__).parent
DB_DIR       = BASE_DIR / "db"
ASSETS_DIR   = BASE_DIR / "assets"
CONFIG_DIR   = BASE_DIR / "config"
LOG_DIR      = BASE_DIR / "logs"
KEY_FILE     = CONFIG_DIR / "license.key"
DB_FILE      = DB_DIR    / "vortex.db"
CFG_FILE     = CONFIG_DIR / "config.json"
PUB_KEY_FILE = CONFIG_DIR / "public.pem"

WEB_PORT     = 8770
WHATSAPP_URL = "https://wa.me/923490916663?text=I%20want%20to%20buy%20a%20license%20for%20ATHEX%20VORTEX" 

ASCII_LOGO = r"""
  █████╗ ████████╗██╗  ██╗███████╗██╗  ██╗
 ██╔══██╗╚══██╔══╝██║  ██║██╔════╝╚██╗██╔╝
 ███████║   ██║   ███████║█████╗   ╚███╔╝
 ██╔══██║   ██║   ██╔══██║██╔══╝   ██╔██╗
 ██║  ██║   ██║   ██║  ██║███████╗██╔╝ ██╗
 ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
  ██╗   ██╗ ██████╗ ██████╗ ████████╗███████╗██╗  ██╗
  ██║   ██║██╔═══██╗██╔══██╗╚══██╔══╝██╔════╝╚██╗██╔╝
  ██║   ██║██║   ██║██████╔╝   ██║   █████╗   ╚███╔╝
  ╚██╗ ██╔╝██║   ██║██╔══██╗   ██║   ██╔══╝   ██╔██╗
   ╚████╔╝ ╚██████╔╝██║  ██║   ██║   ███████╗██╔╝ ██╗
    ╚═══╝   ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
"""

# ── 4. Bootstrap directories & DB ─────────────────────────
def bootstrap():
    for d in [DB_DIR, ASSETS_DIR, CONFIG_DIR, LOG_DIR]:
        d.mkdir(parents=True, exist_ok=True)
    if not CFG_FILE.exists():
        CFG_FILE.write_text(json.dumps({"web_port": WEB_PORT, "max_tunnels": 3}, indent=2))
    conn = sqlite3.connect(DB_FILE)
    conn.execute("""CREATE TABLE IF NOT EXISTS tunnels(
        id TEXT PRIMARY KEY, local_port INTEGER, public_ip TEXT,
        public_port INTEGER, protocol TEXT, created_at TEXT,
        bytes_in INTEGER DEFAULT 0, bytes_out INTEGER DEFAULT 0,
        active INTEGER DEFAULT 1)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS events(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT, level TEXT, message TEXT)""")
    conn.commit(); conn.close()

def log_event(level: str, msg: str):
    try:
        conn = sqlite3.connect(DB_FILE)
        conn.execute("INSERT INTO events(ts,level,message) VALUES(?,?,?)",
                     (datetime.now(timezone.utc).isoformat(), level, msg))
        conn.commit(); conn.close()
    except Exception:
        pass
    print(f"[{level}] {msg}")

# ── 5. HWID fingerprint ───────────────────────────────────
def get_hwid() -> str:
    parts = [platform.node(), platform.machine(), platform.processor(),
             str(uuid.getnode())]
    if platform.system() == "Linux":
        try: parts.append(Path("/etc/machine-id").read_text().strip())
        except Exception: pass
    elif platform.system() == "Windows":
        try:
            out = subprocess.check_output("wmic diskdrive get SerialNumber",
                shell=True, stderr=subprocess.DEVNULL).decode()
            parts.append(out.split()[-1])
        except Exception: pass
    return hashlib.sha256("|".join(filter(None, parts)).encode()).hexdigest()[:32].upper()

# ── 6. License manager ────────────────────────────────────
class LicenseManager:
    def __init__(self):
        self.hwid = get_hwid()
        self.data: Optional[Dict] = None
        self._valid = False

    def load(self) -> bool:
        self._valid = False; self.data = None
        if not KEY_FILE.exists(): return False
        try:
            raw = KEY_FILE.read_text().strip()
            # pad to multiple of 4
            pad = (4 - len(raw) % 4) % 4
            decoded = base64.urlsafe_b64decode(raw + "=" * pad)
            sig_len = struct.unpack(">I", decoded[:4])[0]
            sig          = decoded[4:4 + sig_len]
            payload_bytes= decoded[4 + sig_len:]
            payload      = json.loads(payload_bytes.decode())

            # Signature verification (optional – skipped if pub key absent)
            if PUB_KEY_FILE.exists():
                try:
                    pub = serialization.load_pem_public_key(
                        PUB_KEY_FILE.read_bytes(), backend=default_backend())
                    pub.verify(sig, payload_bytes, padding.PKCS1v15(), hashes.SHA256())
                except InvalidSignature:
                    return False

            if payload.get("hwid","").upper() != self.hwid:
                return False

            if not payload.get("lifetime"):
                exp = datetime.fromisoformat(payload["expires"])
                if exp.tzinfo is None: exp = exp.replace(tzinfo=timezone.utc)
                if datetime.now(timezone.utc) > exp: return False

            self.data = payload; self._valid = True; return True
        except Exception as e:
            print(f"[LICENSE] load error: {e}"); return False

    @property
    def valid(self): return self._valid

    @property
    def remaining_seconds(self) -> int:
        if not self.data: return 0
        if self.data.get("lifetime"): return -1
        exp = datetime.fromisoformat(self.data["expires"])
        if exp.tzinfo is None: exp = exp.replace(tzinfo=timezone.utc)
        return max(0, int((exp - datetime.now(timezone.utc)).total_seconds()))

    @property
    def max_tunnels(self) -> int:
        return (self.data or {}).get("max_tunnels", 1)

    def to_dict(self) -> Dict:
        d = {"valid": self._valid, "hwid": self.hwid}
        if self.data:
            d.update(holder=self.data.get("holder","Unknown"),
                     max_tunnels=self.max_tunnels,
                     remaining_seconds=self.remaining_seconds,
                     lifetime=self.data.get("lifetime", False),
                     issued=self.data.get("issued",""))
        return d

# ── 7. Tunnel session ─────────────────────────────────────
class TunnelSession:
    def __init__(self, tid: str, local_port: int, protocol: str):
        self.id          = tid
        self.local_port  = local_port
        self.protocol    = protocol
        self.public_ip   = self._derive_ip()
        self.public_port = self._free_port()
        self.bytes_in    = 0
        self.bytes_out   = 0
        self.created_at  = datetime.now(timezone.utc).isoformat()
        self.active      = True
        self._stop       = threading.Event()

    def _derive_ip(self) -> str:
        h = hashlib.md5(f"{self.id}{self.local_port}".encode()).digest()
        return f"{h[0]%200+10}.{h[1]%254+1}.{h[2]%254+1}.{h[3]%254+1}"

    def _free_port(self) -> int:
        for _ in range(30):
            p = random.randint(20000, 59000)
            try:
                s = socket.socket(); s.bind(("0.0.0.0", p)); s.close(); return p
            except OSError: continue
        return random.randint(20000, 59000)

    def start(self):
        if self.protocol in ("TCP","HYBRID"):
            threading.Thread(target=self._tcp_server, daemon=True).start()
        if self.protocol in ("UDP","HYBRID"):
            threading.Thread(target=self._udp_server, daemon=True).start()
        self._save()
        log_event("INFO", f"Tunnel {self.id}: 0.0.0.0:{self.public_port} → "
                          f"127.0.0.1:{self.local_port} [{self.protocol}]")

    def _tcp_server(self):
        try:
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("0.0.0.0", self.public_port))
            srv.listen(50); srv.settimeout(1.0)
            while not self._stop.is_set():
                try:
                    cli, _ = srv.accept()
                    threading.Thread(target=self._relay, args=(cli,), daemon=True).start()
                except socket.timeout: continue
            srv.close()
        except OSError as e: log_event("ERROR", f"TCP {self.id}: {e}")

    def _relay(self, cli: socket.socket):
        dst = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            dst.settimeout(30); dst.connect(("127.0.0.1", self.local_port))
            cli.settimeout(30)
            while not self._stop.is_set():
                r, _, _ = select.select([cli, dst], [], [], 1.0)
                if cli in r:
                    d = cli.recv(65536)
                    if not d: break
                    dst.sendall(d); self.bytes_in += len(d)
                if dst in r:
                    d = dst.recv(65536)
                    if not d: break
                    cli.sendall(d); self.bytes_out += len(d)
            self._flush_db()
        except Exception: pass
        finally:
            for s in (cli, dst):
                try: s.close()
                except Exception: pass

    def _udp_server(self):
        p = self.public_port + 1 if self.protocol == "HYBRID" else self.public_port
        try:
            srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            srv.bind(("0.0.0.0", p)); srv.settimeout(1.0)
            while not self._stop.is_set():
                try:
                    data, _ = srv.recvfrom(65536)
                    self.bytes_in += len(data)
                    srv.sendto(data, ("127.0.0.1", self.local_port))
                    self._flush_db()
                except socket.timeout: continue
            srv.close()
        except Exception as e: log_event("ERROR", f"UDP {self.id}: {e}")

    def stop(self):
        self._stop.set(); self.active = False
        try:
            c = sqlite3.connect(DB_FILE)
            c.execute("UPDATE tunnels SET active=0 WHERE id=?", (self.id,))
            c.commit(); c.close()
        except Exception: pass

    def _save(self):
        c = sqlite3.connect(DB_FILE)
        c.execute("""INSERT OR REPLACE INTO tunnels
            (id,local_port,public_ip,public_port,protocol,created_at,bytes_in,bytes_out,active)
            VALUES(?,?,?,?,?,?,0,0,1)""",
            (self.id, self.local_port, self.public_ip, self.public_port,
             self.protocol, self.created_at))
        c.commit(); c.close()

    def _flush_db(self):
        try:
            c = sqlite3.connect(DB_FILE)
            c.execute("UPDATE tunnels SET bytes_in=?,bytes_out=? WHERE id=?",
                      (self.bytes_in, self.bytes_out, self.id))
            c.commit(); c.close()
        except Exception: pass

    def to_dict(self) -> Dict:
        return dict(id=self.id, local_port=self.local_port,
                    public_ip=self.public_ip, public_port=self.public_port,
                    protocol=self.protocol, created_at=self.created_at,
                    bytes_in=self.bytes_in, bytes_out=self.bytes_out,
                    active=self.active)

# ── 8. Tunnel manager ─────────────────────────────────────
class TunnelManager:
    def __init__(self, lm: LicenseManager):
        self.lm = lm
        self.tunnels: Dict[str, TunnelSession] = {}

    def create(self, local_port: int, protocol: str) -> TunnelSession:
        if not 1 <= local_port <= 65535: raise ValueError("Port 1-65535")
        if protocol not in ("TCP","UDP","HYBRID"): raise ValueError("Bad protocol")
        if len(self.tunnels) >= self.lm.max_tunnels:
            raise ValueError(f"Limit {self.lm.max_tunnels} reached")
        tid = "VTX-" + "".join(random.choices(string.ascii_uppercase+string.digits, k=8))
        t = TunnelSession(tid, local_port, protocol)
        t.start(); self.tunnels[tid] = t; return t

    def stop(self, tid: str):
        if tid in self.tunnels:
            self.tunnels[tid].stop(); del self.tunnels[tid]

    def stop_all(self):
        for t in list(self.tunnels.values()): t.stop()
        self.tunnels.clear()

    def list_all(self) -> List[Dict]:
        return [t.to_dict() for t in self.tunnels.values()]

    def stats(self) -> Dict:
        return dict(
            active_tunnels=len(self.tunnels),
            total_bytes_in=sum(t.bytes_in for t in self.tunnels.values()),
            total_bytes_out=sum(t.bytes_out for t in self.tunnels.values()),
            cpu_percent=psutil.cpu_percent(interval=None),
            mem_percent=psutil.virtual_memory().percent,
            timestamp=time.time())

# ── 9. FastAPI ────────────────────────────────────────────
app = FastAPI(title="ATHEX VORTEX")
app.add_middleware(CORSMiddleware, allow_origins=["*"],
                   allow_methods=["*"], allow_headers=["*"])

_lm: Optional[LicenseManager] = None
_tm: Optional[TunnelManager]  = None
_ws_clients: List[WebSocket]  = []

@app.get("/", response_class=HTMLResponse)
async def root(): return HTMLResponse(DASHBOARD_HTML)

@app.get("/api/status")
async def api_status():
    return JSONResponse({"license": _lm.to_dict(), "stats": _tm.stats(),
                         "whatsapp": WHATSAPP_URL})

@app.get("/api/hwid")
async def api_hwid(): return JSONResponse({"hwid": _lm.hwid})

@app.get("/api/tunnels")
async def api_list():
    if not _lm.valid: raise HTTPException(403, "License required")
    return JSONResponse(_tm.list_all())

@app.post("/api/tunnels")
async def api_create(req: Request):
    if not _lm.valid: raise HTTPException(403, "License required")
    body = await req.json()
    try:
        t = _tm.create(int(body["local_port"]), body.get("protocol","TCP").upper())
        await _broadcast({"event":"tunnel_created","tunnel":t.to_dict()})
        return JSONResponse(t.to_dict())
    except (ValueError, KeyError) as e: raise HTTPException(400, str(e))

@app.delete("/api/tunnels/{tid}")
async def api_stop(tid: str):
    if not _lm.valid: raise HTTPException(403, "License required")
    _tm.stop(tid)
    await _broadcast({"event":"tunnel_stopped","id":tid})
    return JSONResponse({"status":"ok"})

@app.get("/api/stats")
async def api_stats(): return JSONResponse(_tm.stats())

@app.post("/api/license/install")
async def api_lic(req: Request):
    body = await req.json()
    KEY_FILE.write_text(body.get("key","").strip())
    if _lm.load(): return JSONResponse({"status":"ok","data":_lm.to_dict()})
    KEY_FILE.unlink(missing_ok=True)
    raise HTTPException(400, "Invalid / expired / wrong-HWID license")

@app.get("/api/logs")
async def api_logs():
    c = sqlite3.connect(DB_FILE)
    rows = c.execute("SELECT ts,level,message FROM events ORDER BY id DESC LIMIT 80").fetchall()
    c.close()
    return JSONResponse([{"ts":r[0],"level":r[1],"msg":r[2]} for r in rows])

@app.websocket("/ws")
async def ws_ep(ws: WebSocket):
    await ws.accept(); _ws_clients.append(ws)
    try:
        while True:
            await ws.send_json({"type":"tick","stats":_tm.stats(),
                                "license":_lm.to_dict(),"tunnels":_tm.list_all()})
            await asyncio.sleep(1)
    except Exception:
        if ws in _ws_clients: _ws_clients.remove(ws)

async def _broadcast(data: Dict):
    dead = []
    for ws in list(_ws_clients):
        try: await ws.send_json(data)
        except Exception: dead.append(ws)
    for ws in dead:
        if ws in _ws_clients: _ws_clients.remove(ws)

# ── 10. Dashboard HTML ────────────────────────────────────
DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>ATHEX VORTEX</title>
<link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700;900&family=Share+Tech+Mono&display=swap" rel="stylesheet"/>
<script src="https://cdnjs.cloudflare.com/ajax/libs/three.js/r128/three.min.js"></script>
<style>
*{margin:0;padding:0;box-sizing:border-box;}
:root{
  --bg:#020a14;--panel:#060f1c;--border:#0d2540;
  --blue:#00d4ff;--green:#00ff9d;--red:#ff2d5e;--gold:#ffd700;
  --text:#b8d4ee;--dim:#2a4a6a;
}
html,body{height:100%;background:var(--bg);color:var(--text);font-family:'Share Tech Mono',monospace;overflow:hidden;}
body::after{content:'';position:fixed;inset:0;pointer-events:none;z-index:9999;
  background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,0,0,.1) 2px,rgba(0,0,0,.1) 4px);}

#app{display:grid;grid-template-rows:56px 1fr;height:100vh;}
#topbar{display:flex;align-items:center;justify-content:space-between;
  padding:0 20px;background:#040b18;border-bottom:1px solid var(--border);z-index:10;}
#logo{font-family:'Orbitron',sans-serif;font-weight:900;font-size:18px;letter-spacing:5px;
  background:linear-gradient(90deg,var(--blue),var(--green));-webkit-background-clip:text;-webkit-text-fill-color:transparent;}
nav{display:flex;gap:16px;}
.nb{background:none;border:none;color:var(--dim);font-family:'Share Tech Mono',monospace;
  font-size:12px;letter-spacing:2px;cursor:pointer;padding:4px 6px;transition:.2s;}
.nb:hover,.nb.on{color:var(--blue);text-shadow:0 0 8px var(--blue);}
#pill{display:flex;align-items:center;gap:8px;font-size:11px;}
.dot{width:7px;height:7px;border-radius:50%;background:var(--red);}
.dot.ok{background:var(--green);box-shadow:0 0 6px var(--green);animation:dp 2s infinite;}
@keyframes dp{0%,100%{opacity:1}50%{opacity:.3}}

#body{display:grid;grid-template-columns:1fr 340px;overflow:hidden;height:100%;}
#gw{position:relative;overflow:hidden;}
#gc{width:100%;height:100%;display:block;}

#page{display:none;position:absolute;inset:0;background:#020a14f0;
  z-index:20;overflow-y:auto;padding:40px 48px;}
#page.show{display:block;}
#page h1{font-family:'Orbitron',sans-serif;font-size:22px;color:var(--blue);margin-bottom:16px;}
#page h2{font-family:'Orbitron',sans-serif;font-size:12px;color:var(--green);margin:18px 0 6px;letter-spacing:2px;}
#page p{color:var(--text);line-height:1.9;font-size:13px;margin-bottom:10px;}
#page code{color:var(--gold);}
.xb{position:absolute;top:16px;right:24px;background:none;border:none;color:var(--red);font-size:22px;cursor:pointer;}

#sb{background:var(--panel);border-left:1px solid var(--border);display:flex;flex-direction:column;overflow-y:auto;}
.sec{padding:14px 16px;border-bottom:1px solid var(--border);}
.st{font-family:'Orbitron',sans-serif;font-size:10px;letter-spacing:3px;color:var(--blue);margin-bottom:10px;}

#lb{padding:10px 12px;border:1px solid var(--border);border-radius:4px;margin-bottom:10px;}
#lb.ok{border-color:var(--green);background:#001a0e;}
#lb.bad{border-color:var(--red);background:#150008;}
#hwid{font-size:9px;color:var(--dim);word-break:break-all;margin-bottom:6px;}
#li{font-size:11px;margin-bottom:4px;}
#cd{font-family:'Orbitron',sans-serif;font-size:20px;color:var(--green);text-align:center;letter-spacing:3px;display:none;}

.fld{margin-bottom:9px;}
.fld label{display:block;font-size:10px;color:var(--dim);letter-spacing:1px;margin-bottom:3px;}
.fld input,.fld select,.fld textarea{width:100%;background:#040b18;border:1px solid var(--border);
  color:var(--text);padding:7px 9px;font-family:'Share Tech Mono',monospace;font-size:12px;
  border-radius:3px;outline:none;transition:.2s;resize:vertical;}
.fld input:focus,.fld select:focus,.fld textarea:focus{border-color:var(--blue);}

.btn{width:100%;padding:9px;border:1px solid;font-family:'Orbitron',sans-serif;
  font-size:11px;letter-spacing:2px;cursor:pointer;border-radius:3px;transition:.2s;
  text-transform:uppercase;text-align:center;display:block;background:none;}
.bb{border-color:var(--blue);color:var(--blue);}
.bb:hover:not(:disabled){background:#00d4ff18;box-shadow:0 0 16px #00d4ff44;}
.bg{border-color:var(--green);color:var(--green);}
.bg:hover:not(:disabled){background:#00ff9d18;box-shadow:0 0 16px #00ff9d44;}
.bw{border-color:#25D366;color:#25D366;}
.bw:hover{background:#25D36618;}
.btn:disabled{opacity:.25;cursor:not-allowed;}
.msg{font-size:10px;margin-top:5px;min-height:14px;}

#tlist{display:flex;flex-direction:column;gap:7px;}
.tc{background:#040b18;border:1px solid var(--border);border-radius:4px;padding:9px 10px;position:relative;font-size:10px;}
.tc-id{font-family:'Orbitron',sans-serif;font-size:9px;color:var(--blue);margin-bottom:3px;}
.tc-addr{color:var(--green);font-size:12px;font-weight:bold;margin-bottom:2px;}
.tc-meta{color:var(--dim);}
.tcx{position:absolute;top:7px;right:9px;background:none;border:none;color:var(--red);cursor:pointer;font-size:13px;}

#gauges{display:grid;grid-template-columns:1fr 1fr;gap:7px;margin-bottom:8px;}
.gauge{background:#040b18;border:1px solid var(--border);border-radius:4px;padding:9px;text-align:center;}
.gl{font-size:9px;color:var(--dim);letter-spacing:1px;margin-bottom:3px;}
.gv{font-family:'Orbitron',sans-serif;font-size:16px;}
.gvb{color:var(--blue);}
.gvg{color:var(--green);}

#wc{width:100%;height:54px;display:block;}
#logbox{font-size:9px;height:100px;overflow-y:auto;background:#040b18;border:1px solid var(--border);padding:7px;border-radius:3px;}
.ll{margin-bottom:2px;}
.lI{color:var(--blue);}
.lE{color:var(--red);}
.lts{color:var(--dim);}

#modal{display:none;position:fixed;inset:0;background:#000a;z-index:100;align-items:center;justify-content:center;}
#modal.open{display:flex;}
#mbox{background:var(--panel);border:1px solid var(--blue);border-radius:6px;padding:22px;max-width:460px;width:90%;}
#mt{font-family:'Orbitron',sans-serif;color:var(--blue);font-size:15px;margin-bottom:12px;}
#mb{color:var(--text);font-size:12px;white-space:pre-wrap;margin-bottom:14px;line-height:1.7;}

::-webkit-scrollbar{width:3px;}
::-webkit-scrollbar-track{background:#040b18;}
::-webkit-scrollbar-thumb{background:var(--border);}
</style>
</head>
<body>
<div id="app">
<div id="topbar">
  <div id="logo">⬡ ATHEX VORTEX</div>
  <nav>
    <button class="nb on" onclick="navTo('home',this)">HOME</button>
    <button class="nb"    onclick="navTo('about',this)">ABOUT</button>
    <button class="nb"    onclick="navTo('docs',this)">DOCS</button>
  </nav>
  <div id="pill"><div class="dot" id="sdot"></div><span id="stxt">CHECKING</span></div>
</div>
<div id="body">
  <div id="gw">
    <canvas id="gc"></canvas>
    <div id="page">
      <button class="xb" onclick="navTo('home')">✕</button>
      <div id="pb"></div>
    </div>
  </div>
  <div id="sb">
    <div class="sec">
      <div class="st">🔐 License</div>
      <div id="lb" class="bad">
        <div style="font-size:9px;color:var(--dim);margin-bottom:3px">YOUR HWID</div>
        <div id="hwid">Loading…</div>
        <hr style="border:none;border-top:1px solid var(--border);margin:7px 0"/>
        <div id="li">NO LICENSE DETECTED</div>
        <div id="cd"></div>
      </div>
      <div class="fld"><label>PASTE LICENSE KEY</label>
        <textarea id="ki" rows="3" placeholder="VTX-…"></textarea></div>
      <button class="btn bb" onclick="installKey()">⚡ INSTALL KEY</button>
      <div class="msg" id="km"></div>
      <div style="margin-top:8px">
        <button class="btn bw" onclick="openWA()">📲 BUY LICENSE — WHATSAPP</button>
      </div>
    </div>
    <div class="sec">
      <div class="st">⚡ Create Tunnel</div>
      <div class="fld"><label>LOCAL PORT</label>
        <input type="number" id="pi" placeholder="e.g. 7777" min="1" max="65535"/></div>
      <div class="fld"><label>PROTOCOL</label>
        <select id="proto">
          <option value="TCP">TCP — Reliable Stream</option>
          <option value="UDP">UDP — Low Latency</option>
          <option value="HYBRID">HYBRID — TCP + UDP</option>
        </select></div>
      <button class="btn bg" id="cbtn" onclick="createTunnel()" disabled>▶ LAUNCH TUNNEL</button>
    </div>
    <div class="sec">
      <div class="st">🌐 Active Tunnels</div>
      <div id="tlist"><div style="color:var(--dim);font-size:11px">No active tunnels.</div></div>
    </div>
    <div class="sec">
      <div class="st">📊 Live Stats</div>
      <div id="gauges">
        <div class="gauge"><div class="gl">CPU</div><div class="gv gvb" id="gcpu">0%</div></div>
        <div class="gauge"><div class="gl">RAM</div><div class="gv gvg" id="gram">0%</div></div>
        <div class="gauge"><div class="gl">↓ IN</div><div class="gv gvb" id="gin">0B</div></div>
        <div class="gauge"><div class="gl">↑ OUT</div><div class="gv gvg" id="gout">0B</div></div>
      </div>
      <canvas id="wc"></canvas>
    </div>
    <div class="sec">
      <div class="st">📋 Event Log</div>
      <div id="logbox"></div>
    </div>
  </div>
</div>
</div>

<div id="modal">
  <div id="mbox">
    <div id="mt">INFO</div>
    <div id="mb"></div>
    <button class="btn bb" onclick="closeModal()">DISMISS</button>
  </div>
</div>

<script>
/* ── THREE.JS GLOBE ── */
const gc=document.getElementById('gc');
const renderer=new THREE.WebGLRenderer({canvas:gc,antialias:true,alpha:true});
renderer.setPixelRatio(Math.min(devicePixelRatio,2));
const scene=new THREE.Scene(), cam=new THREE.PerspectiveCamera(45,1,.1,500);
cam.position.z=2.8;

// Stars
const sv=[];
for(let i=0;i<6000;i++) sv.push((Math.random()-.5)*300,(Math.random()-.5)*300,(Math.random()-.5)*300);
const sg=new THREE.BufferGeometry();
sg.setAttribute('position',new THREE.Float32BufferAttribute(sv,3));
scene.add(new THREE.Points(sg,new THREE.PointsMaterial({color:0x557799,size:.2})));

// Globe
const globe=new THREE.Mesh(
  new THREE.SphereGeometry(1,64,64),
  new THREE.MeshPhongMaterial({color:0x010e24,emissive:0x000510}));
scene.add(globe);
scene.add(new THREE.Mesh(new THREE.SphereGeometry(1.002,28,28),
  new THREE.MeshBasicMaterial({color:0x003055,wireframe:true,transparent:true,opacity:.25})));
scene.add(new THREE.Mesh(new THREE.SphereGeometry(1.08,32,32),
  new THREE.MeshBasicMaterial({color:0x00d4ff,side:THREE.BackSide,transparent:true,opacity:.07})));
scene.add(new THREE.AmbientLight(0x223344,1));
const pl=new THREE.PointLight(0x00d4ff,2.5,10);
pl.position.set(4,4,4); scene.add(pl);

const mg=new THREE.Group(); scene.add(mg);
function ll2v(lat,lon,r=1.05){
  const phi=(90-lat)*Math.PI/180,th=(lon+180)*Math.PI/180;
  return new THREE.Vector3(-r*Math.sin(phi)*Math.cos(th),r*Math.cos(phi),r*Math.sin(phi)*Math.sin(th));
}
function addMarker(lat,lon){
  const v=ll2v(lat,lon);
  const m=new THREE.Mesh(new THREE.SphereGeometry(.028,12,12),
    new THREE.MeshBasicMaterial({color:0x00ff9d}));
  m.position.copy(v); mg.add(m);
  const ring=new THREE.Mesh(new THREE.RingGeometry(.028,.055,24),
    new THREE.MeshBasicMaterial({color:0x00ff9d,side:THREE.DoubleSide,transparent:true,opacity:.7}));
  ring.position.copy(v); ring.lookAt(0,0,0); ring.userData.p=true; mg.add(ring);
}

let drag=false,px=0,py=0,ry=0,rx=0,tz=2.8,tick=0;
gc.addEventListener('mousedown',e=>{drag=true;px=e.clientX;py=e.clientY;});
window.addEventListener('mouseup',()=>drag=false);
window.addEventListener('mousemove',e=>{
  if(!drag)return;
  ry+=(e.clientX-px)*.005; rx+=(e.clientY-py)*.005;
  rx=Math.max(-1.4,Math.min(1.4,rx)); px=e.clientX; py=e.clientY;
});
gc.addEventListener('wheel',e=>{tz=Math.max(1.5,Math.min(5,tz+e.deltaY*.004));});

(function loop(){
  requestAnimationFrame(loop); tick+=.016;
  if(!drag) ry+=.0018;
  globe.rotation.set(rx,ry,0); mg.rotation.set(rx,ry,0);
  mg.children.forEach(c=>{
    if(c.userData.p){const s=1+.25*Math.sin(tick*2.5);c.scale.set(s,s,s);
      c.material.opacity=.7*(.5+.5*Math.sin(tick*2.5));}
  });
  cam.position.z+=(tz-cam.position.z)*.06;
  renderer.render(scene,cam);
})();

function resize(){
  const w=gc.parentElement.clientWidth,h=gc.parentElement.clientHeight;
  renderer.setSize(w,h,false); cam.aspect=w/h; cam.updateProjectionMatrix();
}
window.addEventListener('resize',resize); resize();

/* ── WAVE GRAPH ── */
const wc=document.getElementById('wc'),wx=wc.getContext('2d');
let wd=Array(70).fill(0),prevIn=0;
function drawWave(){
  const W=wc.width=wc.offsetWidth,H=wc.height=54;
  wx.clearRect(0,0,W,H);
  const mx=Math.max(...wd,1);
  wx.beginPath();
  wd.forEach((v,i)=>{
    const x=i/wd.length*W,y=H-(v/mx)*(H-4);
    i===0?wx.moveTo(x,y):wx.lineTo(x,y);
  });
  wx.lineTo(W,H); wx.lineTo(0,H);
  const g=wx.createLinearGradient(0,0,0,H);
  g.addColorStop(0,'#00d4ff44'); g.addColorStop(1,'transparent');
  wx.fillStyle=g; wx.fill();
  wx.strokeStyle='#00d4ff'; wx.lineWidth=1.5; wx.stroke();
}

/* ── WEBSOCKET ── */
let licOK=false;
function connectWS(){
  const proto=location.protocol==='https:'?'wss':'ws';
  const ws=new WebSocket(proto+'://'+location.host+'/ws');
  ws.onmessage=e=>{
    const d=JSON.parse(e.data);
    if(d.type==='tick') onTick(d);
  };
  ws.onclose=()=>setTimeout(connectWS,2000);
}

function onTick(d){
  const L=d.license,S=d.stats;
  licOK=L.valid;
  document.getElementById('hwid').textContent=L.hwid||'…';
  const lb=document.getElementById('lb');
  document.getElementById('sdot').className='dot'+(L.valid?' ok':'');
  document.getElementById('stxt').textContent=L.valid?'CONNECTED':'NO LICENSE';
  document.getElementById('cbtn').disabled=!L.valid;
  const li=document.getElementById('li'),cd=document.getElementById('cd');
  if(L.valid){
    lb.className='ok';
    if(L.lifetime){li.innerHTML='<span style="color:var(--green)">✓ LIFETIME</span> · '+L.holder;cd.style.display='none';}
    else{
      const r=L.remaining_seconds;
      li.innerHTML='<span style="color:var(--green)">✓ ACTIVE</span> · '+L.holder;
      cd.style.display='block'; cd.textContent=fmtT(r);
      cd.style.color=r<3600?'var(--gold)':'var(--green)';
    }
  } else {lb.className='bad';li.innerHTML='<span style="color:var(--red)">✗ NO LICENSE</span>';cd.style.display='none';}
  if(S){
    document.getElementById('gcpu').textContent=S.cpu_percent.toFixed(1)+'%';
    document.getElementById('gram').textContent=S.mem_percent.toFixed(1)+'%';
    document.getElementById('gin').textContent=fmtB(S.total_bytes_in);
    document.getElementById('gout').textContent=fmtB(S.total_bytes_out);
    wd.push(S.total_bytes_in-prevIn); wd.shift(); prevIn=S.total_bytes_in; drawWave();
  }
  renderTunnels(d.tunnels||[]);
}

function renderTunnels(arr){
  const el=document.getElementById('tlist');
  mg.children.splice(0);
  if(!arr.length){el.innerHTML='<div style="color:var(--dim);font-size:11px">No active tunnels.</div>';return;}
  el.innerHTML='';
  arr.forEach(t=>{
    const pts=t.public_ip.split('.').map(Number);
    addMarker((pts[0]-127)*.7,(pts[1]-127)*1.4);
    const c=document.createElement('div'); c.className='tc';
    c.innerHTML=`<div class="tc-id">${t.id}</div>
      <div class="tc-addr">◆ ${t.public_ip}:${t.public_port}</div>
      <div class="tc-meta">local:${t.local_port} | ${t.protocol} | ↓${fmtB(t.bytes_in)} ↑${fmtB(t.bytes_out)}</div>
      <button class="tcx" onclick="stopTunnel('${t.id}')">✕</button>`;
    el.appendChild(c);
  });
}

async function createTunnel(){
  if(!licOK){modal('LICENSE REQUIRED','Install a valid license key first.');return;}
  const port=parseInt(document.getElementById('pi').value);
  const proto=document.getElementById('proto').value;
  if(!port||port<1||port>65535){modal('INVALID PORT','Enter a valid port 1–65535.');return;}
  const r=await fetch('/api/tunnels',{method:'POST',
    headers:{'Content-Type':'application/json'},
    body:JSON.stringify({local_port:port,protocol:proto})});
  if(r.ok){
    const t=await r.json();
    modal('TUNNEL LAUNCHED',
      `ID:       ${t.id}\nPublic:   ${t.public_ip}:${t.public_port}\nLocal:    127.0.0.1:${t.local_port}\nProtocol: ${t.protocol}\n\nShare Public address with your users.`);
    tz=1.9; setTimeout(()=>tz=2.8,3500);
  } else {
    const e=await r.json(); modal('ERROR',e.detail||'Unknown error');
  }
}
async function stopTunnel(id){await fetch('/api/tunnels/'+id,{method:'DELETE'});}

async function installKey(){
  const k=document.getElementById('ki').value.trim();
  const m=document.getElementById('km');
  if(!k){m.style.color='var(--gold)';m.textContent='⚠ Paste a key first.';return;}
  const r=await fetch('/api/license/install',{method:'POST',
    headers:{'Content-Type':'application/json'},body:JSON.stringify({key:k})});
  if(r.ok){m.style.color='var(--green)';m.textContent='✓ License activated!';}
  else{m.style.color='var(--red)';m.textContent='✗ Invalid / wrong HWID / expired';}
}
function openWA(){window.open('https://wa.me/923490916663?text=I%20want%20to%20buy%20a%20license%20for%20ATHEX%20VORTEX','_blank');}

async function pollLogs(){
  try{
    const rows=await(await fetch('/api/logs')).json();
    const b=document.getElementById('logbox'); b.innerHTML='';
    rows.slice(0,40).forEach(l=>{
      const d=document.createElement('div');
      d.className='ll '+(l.level==='ERROR'?'lE':'lI');
      d.innerHTML='<span class="lts">['+l.ts.substring(11,19)+']</span> '+l.msg;
      b.appendChild(d);
    });
  }catch(e){}
}
setInterval(pollLogs,3000); pollLogs();

const PAGES={
about:`<h1>ABOUT</h1>
<h2>OVERVIEW</h2>
<p>ATHEX VORTEX is a cross-platform (Windows/Linux) TCP/UDP port-forwarding and tunneling suite. It exposes any local port to a public address with a single click.</p>
<h2>FEATURES</h2>
<p>• TCP, UDP, and Hybrid (both) forwarding<br>• HWID-locked RSA-2048 signed license keys<br>• Real-time bandwidth monitoring over WebSocket<br>• 3D interactive globe with live tunnel markers<br>• Auto-creates all directories and database on first run</p>
<h2>SECURITY</h2>
<p>Each license key is cryptographically signed. Keys are bound to your hardware fingerprint and cannot be transferred between machines.</p>`,
docs:`<h1>DOCUMENTATION</h1>
<h2>QUICK START</h2>
<p>1. Run <code>python run.py</code><br>
2. Open <code>http://localhost:8770</code><br>
3. Copy your HWID and send to the developer<br>
4. Paste the received license key → INSTALL KEY<br>
5. Enter local port → select protocol → LAUNCH TUNNEL<br>
6. Share the Public IP:Port with your users</p>
<h2>PROTOCOLS</h2>
<p><code>TCP</code> — Reliable ordered stream. Game servers, HTTP, file transfer.<br>
<code>UDP</code> — Connectionless, low-latency. Voice, video, FPS games.<br>
<code>HYBRID</code> — TCP on assigned port + UDP on port+1 simultaneously.</p>
<h2>FIREWALL</h2>
<p>The daemon binds on <code>0.0.0.0</code>. Allow inbound on the assigned public port in your OS firewall. On Windows, click Allow when prompted.</p>
<h2>TROUBLESHOOTING</h2>
<p>• <strong>Port in use:</strong> Stop and recreate the tunnel (new port auto-selected)<br>
• <strong>Cannot connect:</strong> Check firewall and that local service is running<br>
• <strong>License invalid:</strong> Ensure key was not truncated when pasting</p>`
};

function navTo(v,btn){
  document.querySelectorAll('.nb').forEach(b=>b.classList.remove('on'));
  if(btn) btn.classList.add('on');
  const pg=document.getElementById('page');
  if(v==='home'){pg.classList.remove('show');return;}
  document.getElementById('pb').innerHTML=PAGES[v]||'';
  pg.classList.add('show');
}
function modal(title,body){
  document.getElementById('mt').textContent=title;
  document.getElementById('mb').textContent=body;
  document.getElementById('modal').classList.add('open');
}
function closeModal(){document.getElementById('modal').classList.remove('open');}
function fmtT(s){if(s<0)return'∞';const h=Math.floor(s/3600),m=Math.floor(s%3600/60),sc=s%60;return[h,m,sc].map(x=>String(x).padStart(2,'0')).join(':');}
function fmtB(b){if(b<1024)return b+'B';if(b<1048576)return(b/1024).toFixed(1)+'K';return(b/1048576).toFixed(2)+'M';}

connectWS();
</script>
</body>
</html>"""

# ── 11. Entry point ───────────────────────────────────────
def main():
    global _lm, _tm
    bootstrap()
    console.print(Text(ASCII_LOGO, style="bold cyan"))
    hwid = get_hwid()
    console.print(Panel(
        f"[bold green]ATHEX VORTEX v1.0.0[/bold green]\n"
        f"Platform : [yellow]{platform.system()} {platform.machine()}[/yellow]\n"
        f"HWID     : [magenta]{hwid}[/magenta]\n"
        f"Dashboard: [cyan]http://localhost:{WEB_PORT}[/cyan]",
        title="[bold blue]⬡ STARTING[/bold blue]", border_style="blue"))

    _lm = LicenseManager()
    if _lm.load():
        console.print(f"[green]✓ License OK — {_lm.data.get('holder')} | "
                      f"max tunnels: {_lm.max_tunnels}[/green]")
    else:
        console.print(f"[yellow]⚠  No valid license. HWID: {hwid}[/yellow]")
        console.print(f"[dim]  Purchase at: {WHATSAPP_URL}[/dim]")

    _tm = TunnelManager(_lm)
    log_event("INFO", f"Started. HWID={hwid}")

    cfg  = json.loads(CFG_FILE.read_text())
    port = cfg.get("web_port", WEB_PORT)
    console.print(f"\n[bold cyan]→ http://localhost:{port}[/bold cyan]  (Ctrl+C to quit)\n")

    try:
        uvicorn.run(app, host="0.0.0.0", port=port, log_level="warning")
    except KeyboardInterrupt:
        console.print("\n[yellow]Shutting down…[/yellow]")
        _tm.stop_all()
        log_event("INFO", "Stopped.")

if __name__ == "__main__":
    main()