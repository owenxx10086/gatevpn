#!/usr/bin/env python3
from __future__ import annotations

import base64
import csv
import json
import os
import queue
import re
import select
import shlex
import socket
import subprocess
import threading
import time
import urllib.parse
import urllib.request
import ssl
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
import concurrent.futures
import sys
import uuid

# 强制限制 socket 仅解析 IPv4 避免部分环境由于 IPv6 DNS 超时导致卡顿
_orig_getaddrinfo = socket.getaddrinfo
def _ipv4_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
    if family == 0:
        family = socket.AF_INET
    return _orig_getaddrinfo(host, port, family, type, proto, flags)
socket.getaddrinfo = _ipv4_getaddrinfo

import vpn_utils
import proxy_server

# ==================== 核心环境参数与路径定义 ====================
ROOT_DIR = Path(__file__).resolve().parent
DATA_DIR = ROOT_DIR / "vpngate_data"
DATA_DIR.mkdir(exist_ok=True)

NODES_FILE = DATA_DIR / "nodes.json"
UI_CONFIG_FILE = DATA_DIR / "ui_config.json"
AUTH_FILE = DATA_DIR / "auth.json"

# 核心抓取源 URL 定义
API_URL = "https://www.vpngate.net/api/iphone/"
API_URL_FALLBACK = "http://130.158.6.83/api/iphone/" # 筑波大学官方直连备用IP出口
VPNBOOK_OPENVPN_URL = os.environ.get("VPNBOOK_OPENVPN_URL", "https://www.vpnbook.com/freevpn/openvpn")
IPSPEED_OPENVPN_URL = os.environ.get("IPSPEED_OPENVPN_URL", "https://ipspeed.info/free-openvpn.php")

LOCAL_PROXY_HOST = "127.0.0.1"
LOCAL_PROXY_PORT = 7928
UI_HOST = "0.0.0.0"
UI_PORT = 8787

DEFAULT_NODE_SOURCES = os.environ.get("DEFAULT_NODE_SOURCES", "vpngate,vpnbook,ipspeed,fdciabdul")
TARGET_IP_TYPES_ENV = os.environ.get("TARGET_IP_TYPES", "residential")
AUTO_RISK_MODE = os.environ.get("AUTO_RISK_MODE", "balanced")

AUTO_TEST_INITIAL_BATCH = int(os.environ.get("AUTO_TEST_INITIAL_BATCH", "8"))
AUTO_TEST_WORKERS = int(os.environ.get("AUTO_TEST_WORKERS", "8"))
MAX_SCAN_ROWS = int(os.environ.get("MAX_SCAN_ROWS", "100"))

raw_nodes_queue = queue.Queue()
nodes_lock = threading.RLock()

# 全局核心状态机
current_active_vpn_process = None
current_connected_node_ip = None
vpn_connection_lock = threading.Lock()
last_collector_run_time = 0

def load_ui_config() -> dict[str, Any]:
    if UI_CONFIG_FILE.exists():
        try:
            return json.loads(UI_CONFIG_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {}

def save_ui_config(cfg: dict[str, Any]):
    try:
        UI_CONFIG_FILE.write_text(json.dumps(cfg, indent=2, ensure_ascii=False), encoding="utf-8")
    except Exception as e:
        print(f"[配置] 存储界面配置失败: {e}", flush=True)

def load_nodes() -> list[dict[str, Any]]:
    if NODES_FILE.exists():
        try:
            return json.loads(NODES_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass
    return []

def save_nodes(nodes: list[dict[str, Any]]):
    try:
        NODES_FILE.write_text(json.dumps(nodes, indent=2, ensure_ascii=False), encoding="utf-8")
    except Exception as e:
        print(f"[数据] 存储节点队列失败: {e}", flush=True)

def load_auth_config() -> dict[str, Any]:
    if AUTH_FILE.exists():
        try:
            return json.loads(AUTH_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {"username": "admin", "password": str(uuid.uuid4())[:8], "secret_path": "console", "port": UI_PORT}

def http_get_with_retry(url: str, timeout: int = 15) -> str:
    """高级网络请求发生器：自带混淆型User-Agent并主动豁免SSL不安全证书校验"""
    ctx = ssl._create_unverified_context()
    req = urllib.request.Request(url, headers={
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5'
    })
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as response:
        return response.read().decode('utf-8', errors='replace')

# ==================== 4 个数据来源加固拉取模块 ====================

def fetch_vpngate() -> list[dict[str, Any]]:
    nodes = []
    print("[采集器] 正在拉取 vpngate 官方 CSV 数据流...", flush=True)
    text = ""
    try:
        text = http_get_with_retry(API_URL, timeout=12)
    except Exception as e:
        print(f"[警告] vpngate 主域名请求失败({e})，正在切入官方直连备用IP通道...", flush=True)
        try:
            text = http_get_with_retry(API_URL_FALLBACK, timeout=12)
        except Exception as ex:
            print(f"[严重错误] vpngate 备用链路同样沦陷: {ex}", flush=True)
            return []

    try:
        lines = text.splitlines()
        if len(lines) < 3:
            return []
        csv_data = "\n".join(lines[1:-1])
        reader = csv.DictReader(csv_data.splitlines())
        for row in reader:
            ip = row.get("IP")
            config_b64 = row.get("OpenVPN_ConfigData_Base64")
            if not ip or not config_b64:
                continue
            nodes.append({
                "source": "vpngate",
                "ip": ip,
                "hostname": row.get("HostName", ip),
                "country": row.get("CountryLong", "Unknown"),
                "ping": int(row.get("Ping", 9999)) if row.get("Ping") else 9999,
                "score": float(row.get("Score", 0)) if row.get("Score") else 0.0,
                "config": config_b64.strip().replace("\r", "").replace("\n", ""),
                "is_active": None,
                "discovered_at": int(time.time())
            })
    except Exception as e:
        print(f"[错误] vpngate 数据流解析失败: {e}", flush=True)
    return nodes

def fetch_vpnbook() -> list[dict[str, Any]]:
    nodes = []
    print("[采集器] 正在扫描 vpnbook 节点...", flush=True)
    try:
        html = http_get_with_retry(VPNBOOK_OPENVPN_URL, timeout=15)
        matches = re.findall(r'href="([^"]+\.ovpn)"', html, re.IGNORECASE)
        if not matches:
            print("[信息] vpnbook 触发了防爬防护，启动底层静态集群注入适配...", flush=True)
            matches = ["/freevpn/vpnbook-openvpn-us1.ovpn", "/freevpn/vpnbook-openvpn-us2.ovpn", "/freevpn/vpnbook-openvpn-ca1.ovpn", "/freevpn/vpnbook-openvpn-de1.ovpn"]
            
        for path in set(matches):
            full_url = urllib.parse.urljoin(VPNBOOK_OPENVPN_URL, path)
            nodes.append({
                "source": "vpnbook",
                "ip": f"vpnbook_{uuid.uuid4().hex[:6]}",
                "hostname": path.split("/")[-1],
                "country": "US/EU Mix",
                "ping": 9999,
                "score": 5.0,
                "config_url": full_url,
                "is_active": None,
                "discovered_at": int(time.time())
            })
    except Exception as e:
        print(f"[错误] vpnbook 来源解析异常: {e}", flush=True)
    return nodes

def fetch_ipspeed() -> list[dict[str, Any]]:
    nodes = []
    print("[采集器] 正在探测 ipspeed 镜像点...", flush=True)
    try:
        html = http_get_with_retry(IPSPEED_OPENVPN_URL, timeout=15)
        matches = re.findall(r'href="([^"]+\.ovpn)"', html, re.IGNORECASE)
        for path in set(matches):
            full_url = urllib.parse.urljoin(IPSPEED_OPENVPN_URL, path)
            nodes.append({
                "source": "ipspeed",
                "ip": f"ipspeed_{uuid.uuid4().hex[:6]}",
                "hostname": path.split("/")[-1],
                "country": "Asia/Pacific",
                "ping": 9999,
                "score": 5.0,
                "config_url": full_url,
                "is_active": None,
                "discovered_at": int(time.time())
            })
    except Exception as e:
        print(f"[错误] ipspeed 采集异常: {e}", flush=True)
    return nodes

def fetch_fdciabdul() -> list[dict[str, Any]]:
    cdn_mirror_url = "https://fastly.jsdelivr.net/gh/fdciabdul/Vpngate-Scraper-API@main/json/data.json"
    nodes = []
    print("[采集器] 正在通过 jsDelivr 高速海外加速链同步 fdciabdul 拓扑数据...", flush=True)
    try:
        raw_data = http_get_with_retry(cdn_mirror_url, timeout=20)
        data_list = json.loads(raw_data)
        
        if not isinstance(data_list, list):
            return []

        for item in data_list:
            ip = item.get("IP")
            config_b64 = item.get("OpenVPN_ConfigData_Base64")
            if not ip or not config_b64:
                continue
            
            nodes.append({
                "source": "fdciabdul",
                "ip": ip,
                "hostname": item.get("HostName", ip),
                "country": item.get("CountryLong", "Unknown"),
                "ping": int(item.get("Ping", 9999)) if item.get("Ping") else 9999,
                "score": float(item.get("Score", 0)) if item.get("Score") else 0.0,
                "config": config_b64.strip().replace("\r", "").replace("\n", ""),
                "is_active": None,
                "discovered_at": int(time.time())
            })
    except Exception as e:
        print(f"[错误] fdciabdul 加速通道解析失败: {e}", flush=True)
    return nodes

# ==================== 自动化安全并发调度流水线 ====================

def collector_loop():
    global last_collector_run_time
    while True:
        try:
            ui_cfg = load_ui_config()
            enabled_sources_str = ui_cfg.get("node_sources") or DEFAULT_NODE_SOURCES
            enabled_sources = [s.strip() for s in enabled_sources_str.split(",") if s.strip()]
            
            all_fetched = []
            
            if "vpngate" in enabled_sources:
                try: all_fetched.extend(fetch_vpngate())
                except Exception: pass
            if "vpnbook" in enabled_sources:
                try: all_fetched.extend(fetch_vpnbook())
                except Exception: pass
            if "ipspeed" in enabled_sources:
                try: all_fetched.extend(fetch_ipspeed())
                except Exception: pass
            if "fdciabdul" in enabled_sources:
                try: all_fetched.extend(fetch_fdciabdul())
                except Exception: pass
                
            if all_fetched:
                with nodes_lock:
                    current_nodes = load_nodes()
                    current_map = {n["ip"]: n for n in current_nodes if "ip" in n}
                    
                    new_count = 0
                    for node in all_fetched:
                        ip = node["ip"]
                        if ip not in current_map:
                            current_nodes.append(node)
                            raw_nodes_queue.put(node)
                            new_count += 1
                    
                    if new_count > 0:
                        save_nodes(current_nodes)
            
            last_collector_run_time = int(time.time())
        except Exception as e:
            print(f"[严重错误] 核心数据归集器遭遇异常: {e}", flush=True)
            
        time.sleep(1800)

# ==================== 节点生存性与风控画像扫描 ====================

def check_single_node(node: dict[str, Any]) -> bool:
    if "config" not in node and "config_url" in node:
        try:
            ctx = ssl._create_unverified_context()
            req = urllib.request.Request(node["config_url"], headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
                content = resp.read()
                node["config"] = base64.b64encode(content).decode('utf-8')
        except Exception:
            return False

    if not node.get("config"):
        return False
    return True

def background_proxy_checker():
    while True:
        try:
            batch = []
            while len(batch) < AUTO_TEST_INITIAL_BATCH:
                try:
                    node = raw_nodes_queue.get(timeout=2)
                    batch.append(node)
                except queue.Empty:
                    break
            
            if not batch:
                time.sleep(5)
                continue

            with concurrent.futures.ThreadPoolExecutor(max_workers=AUTO_TEST_WORKERS) as executor:
                futures = {executor.submit(check_single_node, n): n for n in batch}
                for future in concurrent.futures.as_completed(futures):
                    node = futures[future]
                    try:
                        is_ok = future.result()
                        node["is_active"] = is_ok
                        if is_ok and not node["ip"].startswith("vpnbook") and not node["ip"].startswith("ipspeed"):
                            vpn_utils.enrich_ip_info([node["ip"]])
                    except Exception:
                        node["is_active"] = False
            
            with nodes_lock:
                current = load_nodes()
                current_map = {n["ip"]: n for n in current}
                for b_node in batch:
                    if b_node["ip"] in current_map:
                        current_map[b_node["ip"]].update(b_node)
                save_nodes(current)
                
        except Exception as e:
            print(f"[严重错误] 扫描检查组件遇到异常: {e}", flush=True)

def active_node_pinger():
    while True:
        try:
            with nodes_lock:
                nodes = load_nodes()
            active_nodes = [n for n in nodes if n.get("is_active") is True]
            if active_nodes:
                ips_to_ping = [n["ip"] for n in active_nodes[:MAX_SCAN_ROWS] if not n["ip"].startswith("vpnbook") and not n["ip"].startswith("ipspeed")]
                if ips_to_ping:
                    vpn_utils.enrich_ip_info(ips_to_ping)
        except Exception:
            pass
        time.sleep(300)

# ==================== 下游 OpenVPN 实际链路控制中心 ====================

def stop_current_vpn_connection():
    global current_active_vpn_process, current_connected_node_ip
    with vpn_connection_lock:
        if current_active_vpn_process:
            try:
                current_active_vpn_process.terminate()
                current_active_vpn_process.wait(timeout=5)
            except Exception:
                try: current_active_vpn_process.kill()
                except Exception: pass
            current_active_vpn_process = None
        current_connected_node_ip = None
        proxy_server.set_global_upstream_proxy(None, None)

def start_vpn_connection_for_node(node: dict[str, Any]) -> bool:
    global current_active_vpn_process, current_connected_node_ip
    stop_current_vpn_connection()
    
    config_b64 = node.get("config")
    if not config_b64 and "config_url" in node:
        check_single_node(node)
        config_b64 = node.get("config")
        
    if not config_b64:
        return False
        
    with vpn_connection_lock:
        try:
            ovpn_data = base64.b64decode(config_b64)
            ovpn_str = ovpn_data.decode("utf-8", errors="ignore")
            if "auth-user-pass" in ovpn_str and "vpnbook" in node["source"]:
                ovpn_str = ovpn_str.replace("auth-user-pass", "auth-user-pass vpnbook_auth.txt")
                (ROOT_DIR / "vpnbook_auth.txt").write_text("vpnbook\nrepo82re\n", encoding="utf-8")

            tmp_ovpn = DATA_DIR / "current_running.ovpn"
            tmp_ovpn.write_text(ovpn_str, encoding="utf-8")
            
            cmd = ["openvpn", "--config", str(tmp_ovpn), "--dev", "tun0", "--management", "127.0.0.1", "11115"]
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1, cwd=str(ROOT_DIR))
            
            success = False
            start_t = time.time()
            while time.time() - start_t < 25:
                if proc.poll() is not None:
                    break
                r, _, _ = select.select([proc.stdout], [], [], 0.5)
                if r:
                    line = proc.stdout.readline()
                    if not line:
                        break
                    if "Initialization Sequence Completed" in line:
                        success = True
                        break
                        
            if success and proc.poll() is None:
                current_active_vpn_process = proc
                current_connected_node_ip = node["ip"]
                proxy_server.set_global_upstream_proxy(LOCAL_PROXY_HOST, LOCAL_PROXY_PORT)
                return True
            else:
                try: proc.terminate()
                except Exception: pass
                return False
        except Exception as e:
            print(f"[错误] 链路管理器遭遇故障: {e}", flush=True)
            return False

# ==================== 面板可视化控制核心中间件 ====================

class DashboardHTTPHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass 

    def _check_auth(self) -> bool:
        auth_cfg = load_auth_config()
        secret_path = auth_cfg.get("secret_path", "console")
        if not self.path.startswith(f"/{secret_path}"):
            self.send_response(HTTPStatus.NOT_FOUND)
            self.end_headers()
            return False
            
        auth_header = self.headers.get('Authorization')
        if not auth_header:
            self.send_response(HTTPStatus.UNAUTHORIZED)
            self.send_header('WWW-Authenticate', 'Basic realm="Gateway Console"')
            self.end_headers()
            return False
            
        try:
            encoded_cred = auth_header.split(' ', 1)[1]
            decoded_cred = base64.b64decode(encoded_cred).decode('utf-8')
            username, password = decoded_cred.split(':', 1)
            if username == auth_cfg.get("username") and password == auth_cfg.get("password"):
                return True
        except Exception:
            pass
            
        self.send_response(HTTPStatus.UNAUTHORIZED)
        self.send_header('WWW-Authenticate', 'Basic realm="Gateway Console"')
        self.end_headers()
        return False

    def do_GET(self):
        if not self._check_auth():
            return
            
        auth_cfg = load_auth_config()
        sec = auth_cfg.get("secret_path", "console")
        url_parsed = urllib.parse.urlparse(self.path)
        path = url_parsed.path

        if path == f"/{sec}" or path == f"/{sec}/" or path == f"/{sec}/index.html":
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            
            with nodes_lock:
                nodes = load_nodes()
            ui_cfg = load_ui_config()
            
            stats = {"vpngate": 0, "vpnbook": 0, "ipspeed": 0, "fdciabdul": 0}
            active_count = 0
            for n in nodes:
                s = n.get("source", "unknown")
                if s in stats:
                    stats[s] += 1
                if n.get("is_active") is True:
                    active_count += 1
                    
            # 预解包当前配置中已经启用的来源
            sources_input = ui_cfg.get("node_sources") or DEFAULT_NODE_SOURCES
            enabled_sources = [s.strip() for s in sources_input.split(",") if s.strip()]
            
            ip_types_input = ui_cfg.get("target_ip_types") or TARGET_IP_TYPES_ENV
            risk_mode_input = ui_cfg.get("risk_mode") or AUTO_RISK_MODE
            
            global current_connected_node_ip
            conn_status = f"<span style='color:green;font-weight:bold;'>已连接：{current_connected_node_ip}</span>" if current_connected_node_ip else "<span style='color:orange;'>未接入（全局代理守候中）</span>"

            html = f"""<!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <title>Eianun多源免费落地IP网关控制台</title>
                <style>
                    body {{ font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif; background:#f0f4f8; margin:0; padding:20px; color:#222; }}
                    .box {{ max-width:1100px; margin:0 auto; background:#fff; padding:25px; border-radius:12px; box-shadow:0 4px 15px rgba(0,0,0,0.06); }}
                    h1 {{ color:#0f172a; border-bottom:2px solid #e2e8f0; padding-bottom:12px; margin-top:0; font-size:24px; }}
                    .stats-bar {{ display:grid; grid-template-columns: repeat(4, 1fr); gap:15px; margin:20px 0; }}
                    .stat-card {{ background:#f8fafc; padding:15px; border-radius:8px; border-left:4px solid #3b82f6; text-align:center; }}
                    .stat-card h3 {{ margin:0; font-size:13px; color:#64748b; text-transform:uppercase; }}
                    .stat-card p {{ margin:5px 0 0 0; font-size:26px; font-weight:bold; color:#1e3a8a; }}
                    .control-panel {{ background:#f1f5f9; padding:20px; border-radius:8px; margin-bottom:20px; border:1px solid #cbd5e1; }}
                    .field {{ margin-bottom:15px; }}
                    label {{ display:block; font-weight:bold; margin-bottom:5px; color:#334155; }}
                    .checkbox-group {{ display:flex; flex-wrap:wrap; gap:20px; margin-top:8px; background:#fff; padding:12px; border-radius:6px; border:1px solid #cbd5e1; }}
                    .checkbox-label {{ font-weight:normal !important; display:flex; align-items:center; gap:6px; cursor:pointer; color:#1e293b; }}
                    input[type="text"], select {{ width:100%; padding:10px; border:1px solid #cbd5e1; border-radius:6px; font-size:14px; box-sizing:border-box; }}
                    .btn {{ background:#2563eb; color:#fff; border:none; padding:10px 20px; border-radius:6px; cursor:pointer; font-weight:bold; font-size:14px; }}
                    .btn:hover {{ background:#1d4ed8; }}
                    .btn-danger {{ background:#dc2626; }}
                    .btn-danger:hover {{ background:#b91c1c; }}
                    table {{ width:100%; border-collapse:collapse; margin-top:20px; }}
                    th, td {{ padding:12px; text-align:left; border-bottom:1px solid #e2e8f0; font-size:14px; }}
                    th {{ background:#f8fafc; color:#475569; }}
                    .badge {{ padding:4px 8px; border-radius:20px; font-size:12px; font-weight:bold; }}
                    .active-bg {{ background:#dcfce7; color:#16a34a; }}
                    .pending-bg {{ background:#fef3c7; color:#d97706; }}
                </style>
            </head>
            <body>
                <div class="box">
                    <h1>🌐 Eianun 落地网关管理控制台</h1>
                    <div style="background:#f8fafc; padding:15px; border-radius:8px; margin-bottom:25px; border-left:5px solid #10b981;">
                        <b>当前网关链路状态：</b> {conn_status}
                    </div>

                    <h2>全源底层节点池实时感知 (全网活跃存活数: {active_count})</h2>
                    <div class="stats-bar">
                        <div class="stat-card" style="border-left-color:#3b82f6;">
                            <h3>1. 官方 VPNGate</h3>
                            <p>{stats['vpngate']}</p>
                        </div>
                        <div class="stat-card" style="border-left-color:#10b981;">
                            <h3>2. VPNBook 节点</h3>
                            <p>{stats['vpnbook']}</p>
                        </div>
                        <div class="stat-card" style="border-left-color:#f59e0b;">
                            <h3>3. IPSpeed 镜像</h3>
                            <p>{stats['ipspeed']}</p>
                        </div>
                        <div class="stat-card" style="border-left-color:#8b5cf6;">
                            <h3>4. fdciabdul 总库 (新)</h3>
                            <p>{stats['fdciabdul']}</p>
                        </div>
                    </div>

                    <div class="control-panel">
                        <form method="POST" action="/{sec}/save-config">
                            <div class="field">
                                <label>1. 已启用的分布式网址节点来源 (直接勾选切换):</label>
                                <div class="checkbox-group">
                                    <label class="checkbox-label"><input type="checkbox" name="source_vpngate" value="vpngate" {"checked" if "vpngate" in enabled_sources else ""}> 1. 官方 VPNGate</label>
                                    <label class="checkbox-label"><input type="checkbox" name="source_vpnbook" value="vpnbook" {"checked" if "vpnbook" in enabled_sources else ""}> 2. VPNBook 节点</label>
                                    <label class="checkbox-label"><input type="checkbox" name="source_ipspeed" value="ipspeed" {"checked" if "ipspeed" in enabled_sources else ""}> 3. IPSpeed 镜像</label>
                                    <label class="checkbox-label"><input type="checkbox" name="source_fdciabdul" value="fdciabdul" {"checked" if "fdciabdul" in enabled_sources else ""}> 4. fdciabdul 总库</label>
                                </div>
                            </div>
                            <div class="field">
                                <label>2. 落地出口匹配的目标 IP 类型 (residential / datacenter / all):</label>
                                <input type="text" name="target_ip_types" value="{ip_types_input}">
                            </div>
                            <div class="field">
                                <label>3. 自动化全智能风险拦截策略 (strict / balanced / loose):</label>
                                <select name="risk_mode">
                                    <option value="strict" {"selected" if risk_mode_input=="strict" else ""}>Strict (严格风控阻断)</option>
                                    <option value="balanced" {"selected" if risk_mode_input=="balanced" else ""}>Balanced (标准均衡过滤)</option>
                                    <option value="loose" {"selected" if risk_mode_input=="loose" else ""}>Loose (放行所有探测链路)</option>
                                </select>
                            </div>
                            <input type="submit" class="btn" value="提交并重载系统调度策略">
                        </form>
                    </div>

                    <div style="margin:20px 0; display:flex; gap:10px;">
                        <button class="btn" onclick="location.href='/{sec}/api/cron-trigger'">⚡ 强制触发后台全源再抓取</button>
                        <button class="btn btn-danger" onclick="location.href='/{sec}/api/disconnect'">🔌 断开当前物理链路</button>
                    </div>

                    <h2>高权重就绪节点视图透视 (Top 15)</h2>
                    <table>
                        <thead>
                            <tr>
                                <th>单项来源</th>
                                <th>IP 地址</th>
                                <th>物理归属</th>
                                <th>基准权重</th>
                                <th>质量校验</th>
                                <th>手动切换出口</th>
                            </tr>
                        </thead>
                        <tbody>
            """
            for n in nodes[:15]:
                badge = "<span class='badge active-bg'>已就绪</span>" if n.get("is_active") is True else "<span class='badge pending-bg'>检测中/离线</span>"
                html += f"""
                            <tr>
                                <td><b>{n.get('source')}</b></td>
                                <td>{n.get('ip')}</td>
                                <td>{n.get('country')}</td>
                                <td>{n.get('score')}</td>
                                <td>{badge}</td>
                                <td><a href='/{sec}/api/connect?ip={n.get('ip')}' style='color:#2563eb;text-decoration:none;font-weight:bold;'>👉 切到此出口</a></td>
                            </tr>
                """
            html += """
                        </tbody>
                    </table>
                </div>
            </body>
            </html>
            """
            self.wfile.write(html.encode("utf-8"))

        elif path == f"/{sec}/api/cron-trigger":
            threading.Thread(target=fetch_fdciabdul, daemon=True).start()
            threading.Thread(target=fetch_vpngate, daemon=True).start()
            threading.Thread(target=fetch_vpnbook, daemon=True).start()
            self.send_response(HTTPStatus.SEE_OTHER)
            self.send_header("Location", f"/{sec}")
            self.end_headers()

        elif path == f"/{sec}/api/disconnect":
            stop_current_vpn_connection()
            self.send_response(HTTPStatus.SEE_OTHER)
            self.send_header("Location", f"/{sec}")
            self.end_headers()

        elif path == f"/{sec}/api/connect":
            params = urllib.parse.parse_qs(url_parsed.query)
            target_ip = params.get("ip", [""])[0]
            with nodes_lock:
                nodes = load_nodes()
            target_node = next((n for n in nodes if n["ip"] == target_ip), None)
            
            if target_node:
                threading.Thread(target=start_vpn_connection_for_node, args=(target_node,), daemon=True).start()
                time.sleep(2) 
                
            self.send_response(HTTPStatus.SEE_OTHER)
            self.send_header("Location", f"/{sec}")
            self.end_headers()

    def do_POST(self):
        if not self._check_auth():
            return
            
        auth_cfg = load_auth_config()
        sec = auth_cfg.get("secret_path", "console")
        
        if self.path == f"/{sec}/save-config":
            length = int(self.headers['Content-Length'])
            raw_post = self.rfile.read(length).decode('utf-8')
            params = urllib.parse.parse_qs(raw_post)
            
            cfg = load_ui_config()
            
            # 【高级更新逻辑】：动态提取选中的复选框选项并组装
            selected_sources = []
            if "source_vpngate" in params: selected_sources.append("vpngate")
            if "source_vpnbook" in params: selected_sources.append("vpnbook")
            if "source_ipspeed" in params: selected_sources.append("ipspeed")
            if "source_fdciabdul" in params: selected_sources.append("fdciabdul")
            
            # 如果极端情况下用户取消了所有勾选，默认拉起全部，防止系统死锁
            cfg["node_sources"] = ",".join(selected_sources) if selected_sources else DEFAULT_NODE_SOURCES
            cfg["target_ip_types"] = params.get("target_ip_types", [""])[0]
            cfg["risk_mode"] = params.get("risk_mode", [""])[0]
            save_ui_config(cfg)
            
            self.send_response(HTTPStatus.SEE_OTHER)
            self.send_header("Location", f"/{sec}")
            self.end_headers()

# ==================== 网关内核整体主启动入口 ====================

def main():
    print("==========================================================", flush=True)
    print("         Eianun 多源聚合自动落地代理网关 面板UI已升级...", flush=True)
    print("==========================================================", flush=True)

    threading.Thread(target=proxy_server.start_proxy_server, args=(LOCAL_PROXY_HOST, LOCAL_PROXY_PORT), daemon=True).start()
    
    gateway_ready = False
    for _ in range(20):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.settimeout(0.5)
            s.connect((LOCAL_PROXY_HOST, LOCAL_PROXY_PORT))
            gateway_ready = True
            break
        except Exception:
            time.sleep(0.5)
        finally:
            try: s.close()
            except Exception: pass

    threading.Thread(target=collector_loop, daemon=True).start()
    threading.Thread(target=background_proxy_checker, daemon=True).start()
    threading.Thread(target=active_node_pinger, daemon=True).start()
    
    auth_cfg = load_auth_config()
    ui_host = load_ui_config().get("host", UI_HOST)
    ui_port = int(load_ui_config().get("port") or auth_cfg.get("port") or UI_PORT)
    
    server = ThreadingHTTPServer((ui_host, ui_port), DashboardHTTPHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        stop_current_vpn_connection()

if __name__ == "__main__":
    main()
