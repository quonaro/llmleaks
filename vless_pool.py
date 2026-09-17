"""
VLESS proxy rotation via a local sing-box core.

VLESS links can't be fed to HTTP clients directly — they need a core that
speaks the protocol. This module spawns sing-box with N local `mixed`
inbounds (HTTP CONNECT + SOCKS5 on one port, works with aiohttp and
requests without PySocks), each routed to its own VLESS outbound.
ProxyPool then rotates plain http://127.0.0.1:PORT proxies.

Usage:
    pool = VlessPool.from_file("vless.txt")
    pool.start()
    proxies = pool.proxies()          # ["http://127.0.0.1:20800", ...]
    ...
    pool.stop()
"""

import atexit
import json
import os
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.parse


class VlessError(Exception):
    pass


def parse_vless(link: str) -> dict:
    """vless://UUID@host:port?key=val&...#name  →  normalized spec dict."""
    link = link.strip()
    if not link.startswith("vless://"):
        raise VlessError(f"not a vless link: {link[:40]}")
    u = urllib.parse.urlparse(link)
    q = {k: v[0] for k, v in urllib.parse.parse_qs(u.query).items()}
    if not u.username or not u.hostname or not u.port:
        raise VlessError(f"malformed vless link: {link[:60]}")
    return {
        "uuid": urllib.parse.unquote(u.username),
        "server": u.hostname,
        "port": u.port,
        "name": urllib.parse.unquote(u.fragment or u.hostname),
        # transport
        "type": q.get("type", "tcp"),               # tcp|ws|grpc|http|httpupgrade
        "path": urllib.parse.unquote(q.get("path", "/")),
        "host": q.get("host", ""),
        "service_name": q.get("serviceName", q.get("service_name", "")),
        "header_type": q.get("headerType", ""),
        # security
        "security": q.get("security", "none"),      # none|tls|reality
        "sni": q.get("sni", q.get("servername", "")),
        "fp": q.get("fp", "chrome"),
        "alpn": q.get("alpn", ""),
        "pbk": q.get("pbk", ""),                    # reality public key
        "sid": q.get("sid", ""),                    # reality short id
        "flow": q.get("flow", ""),                  # xtls-rprx-vision
        "insecure": q.get("allowInsecure", "0") in ("1", "true"),
    }


def _tls_block(s: dict) -> dict | None:
    if s["security"] not in ("tls", "reality"):
        return None
    tls = {"enabled": True,
           "server_name": s["sni"] or s["server"],
           "insecure": s["insecure"],
           "utls": {"enabled": True, "fingerprint": s["fp"]}}
    if s["alpn"]:
        tls["alpn"] = s["alpn"].split(",")
    if s["security"] == "reality":
        tls["reality"] = {"enabled": True,
                          "public_key": s["pbk"],
                          "short_id": s["sid"]}
    return tls


def _transport_block(s: dict) -> dict | None:
    t = s["type"]
    if t == "tcp":
        if s["header_type"] == "http":  # raw TCP with HTTP camouflage
            return {"type": "http", "method": "GET", "path": s["path"],
                    "host": [s["host"]] if s["host"] else []}
        return None
    if t == "ws":
        out = {"type": "ws", "path": s["path"]}
        if s["host"]:
            out["headers"] = {"Host": s["host"]}
        return out
    if t == "grpc":
        return {"type": "grpc", "service_name": s["service_name"]}
    if t == "httpupgrade":
        return {"type": "httpupgrade", "host": s["host"], "path": s["path"]}
    if t == "http":
        return {"type": "http", "host": [s["host"]] if s["host"] else [],
                "path": s["path"]}
    return None


def _vless_outbound(s: dict, tag: str) -> dict:
    out = {"type": "vless", "tag": tag,
           "server": s["server"], "server_port": s["port"],
           "uuid": s["uuid"]}
    if s["flow"]:
        out["flow"] = s["flow"]
    tls = _tls_block(s)
    if tls:
        out["tls"] = tls
    tr = _transport_block(s)
    if tr:
        out["transport"] = tr
    return out


def build_config(links: list[str], base_port: int = 20800) -> tuple[dict, list]:
    """sing-box config + list of http://127.0.0.1:port proxies."""
    inbounds, outbounds, rules, proxies = [], [], [], []
    for i, link in enumerate(links):
        spec = parse_vless(link)
        port = base_port + i
        in_tag, out_tag = f"in-{i}", f"vless-{i}"
        inbounds.append({"type": "mixed", "tag": in_tag,
                         "listen": "127.0.0.1", "listen_port": port})
        outbounds.append(_vless_outbound(spec, out_tag))
        rules.append({"inbound": in_tag, "action": "route",
                      "outbound": out_tag})
        proxies.append(f"http://127.0.0.1:{port}")
    outbounds.append({"type": "direct", "tag": "direct"})
    cfg = {
        "log": {"level": "warn", "timestamp": False},
        "inbounds": inbounds,
        "outbounds": outbounds,
        "route": {"rules": rules, "final": "direct",
                  "auto_detect_interface": True},
    }
    return cfg, proxies


def _port_open(port: int, host: str = "127.0.0.1", timeout: float = 0.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


class VlessPool:
    """Manages a sing-box subprocess exposing one local proxy per link."""

    def __init__(self, links: list[str], base_port: int = 20800,
                 binary: str = "sing-box"):
        self.links = [ln.strip() for ln in links
                      if ln.strip() and not ln.startswith("#")]
        self.base_port = base_port
        self.binary = binary
        self._proc = None
        self._cfg_path = None
        self._proxies = []

    @classmethod
    def from_file(cls, path: str, **kw) -> "VlessPool":
        with open(path, encoding="utf-8") as f:
            return cls(f.readlines(), **kw)

    def available(self) -> bool:
        return bool(shutil.which(self.binary))

    def start(self, wait: float = 15.0) -> list:
        if not self.links:
            return []
        if not self.available():
            raise VlessError(f"{self.binary} not found in PATH")
        cfg, self._proxies = build_config(self.links, self.base_port)
        fd, self._cfg_path = tempfile.mkstemp(prefix="dfh-vless-",
                                              suffix=".json")
        with os.fdopen(fd, "w") as f:
            json.dump(cfg, f)
        # validate before spawning — surfaces config errors immediately
        chk = subprocess.run([self.binary, "check", "-c", self._cfg_path],
                             capture_output=True, text=True, timeout=10)
        if chk.returncode != 0:
            raise VlessError(f"sing-box config invalid: {chk.stderr.strip()}")
        self._proc = subprocess.Popen(
            [self.binary, "run", "-c", self._cfg_path],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        atexit.register(self.stop)
        # wait for all inbounds to accept connections
        deadline = time.time() + wait
        for p in range(self.base_port, self.base_port + len(self.links)):
            while time.time() < deadline and not _port_open(p):
                if self._proc.poll() is not None:
                    raise VlessError("sing-box exited during startup")
                time.sleep(0.15)
        return self._proxies

    def proxies(self) -> list:
        return list(self._proxies)

    def healthy(self) -> list:
        """Proxies whose local inbound port still accepts TCP."""
        return [p for p in self._proxies
                if _port_open(int(p.rsplit(":", 1)[1]))]

    def stop(self):
        if self._proc and self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.kill()
        self._proc = None
        if self._cfg_path and os.path.exists(self._cfg_path):
            os.unlink(self._cfg_path)
            self._cfg_path = None
