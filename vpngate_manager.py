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

API_URL = "https://www.vpngate.net/api/iphone/"
API_URL_FALLBACK = "https://gate.hongloan81727.workers.dev/"
VPNBOOK_OPENVPN_URL = os.environ.get("VPNBOOK_OPENVPN_URL", "https://www.vpnbook.com/freevpn/openvpn")
IPSPEED_OPENVPN_URL = os.environ.get("IPSPEED_OPENVPN_URL", "https://ipspeed.info/free-openvpn.php")
# 修复 VPNBook 模板下载被 GFW 墙的问题，改用 jsDelivr CDN
VPNBOOK_TEMPLATE_OVPN_URLS = os.environ.get(
    "VPNBOOK_TEMPLATE_OVPN_URLS",
    "https://fastly.jsdelivr.net/gh/Sadaqaty/VPNed-Wifi-Access-Point@main/vpnbook-openvpn-us16/vpnbook-us16-tcp443.ovpn"
)
_vpnbook_template_config_cache = ""
NODE_SOURCES_ENV = os.environ.get("NODE_SOURCES") or os.environ.get("VPN_NODE_SOURCES") or ""
DEFAULT_NODE_SOURCES = os.environ.get("DEFAULT_NODE_SOURCES", "vpngate,vpnbook,ipspeed,fdciabdul")
VPNBOOK_PROTOCOLS = os.environ.get("VPNBOOK_PROTOCOLS", "tcp443")
VPNBOOK_AUTO_TEST = os.environ.get("VPNBOOK_AUTO_TEST", "0").strip().lower() in {"1", "true", "yes", "on"}
VPNBOOK_ONLY_SAFE_AUTO_TEST_LIMIT = max(1, int(os.environ.get("VPNBOOK_ONLY_SAFE_AUTO_TEST_LIMIT", "1")))
VPNBOOK_SAFE_TEST_ONLY = os.environ.get("VPNBOOK_SAFE_TEST_ONLY", "1").strip().lower() in {"1", "true", "yes", "on"}
VPNBOOK_CONNECT_TIMEOUT_SECONDS = int(os.environ.get("VPNBOOK_CONNECT_TIMEOUT_SECONDS", "25"))
FETCH_INTERVAL_SECONDS = int(os.environ.get("FETCH_INTERVAL_SECONDS", "960"))
CHECK_INTERVAL_SECONDS = int(os.environ.get("CHECK_INTERVAL_SECONDS", "960"))
TARGET_VALID_NODES = int(os.environ.get("TARGET_VALID_NODES", "3"))
MAX_SCAN_ROWS = int(os.environ.get("MAX_SCAN_ROWS", "300"))
OPENVPN_TEST_TIMEOUT_SECONDS = int(os.environ.get("OPENVPN_TEST_TIMEOUT_SECONDS", "35"))
OPENVPN_CMD = os.environ.get("OPENVPN_CMD", "openvpn")
OPENVPN_AUTH_USER = os.environ.get("OPENVPN_AUTH_USER", "vpn")
OPENVPN_AUTH_PASS = os.environ.get("OPENVPN_AUTH_PASS", "vpn")
LOCAL_PROXY_HOST = os.environ.get("LOCAL_PROXY_HOST", "127.0.0.1")
LOCAL_PROXY_PORT = int(os.environ.get("LOCAL_PROXY_PORT", "7928"))
UI_HOST = os.environ.get("UI_HOST", "0.0.0.0")
UI_PORT = int(os.environ.get("UI_PORT", "8787"))
INVALID_BACKOFF_SECONDS = int(os.environ.get("INVALID_BACKOFF_SECONDS", str(30 * 60)))
STRICT_COUNTRY_FAILOVER = os.environ.get("STRICT_COUNTRY_FAILOVER", "1").strip().lower() not in {"0", "false", "no", "off"}
TARGET_COUNTRIES_ENV = os.environ.get("VPNGATE_TARGET_COUNTRIES") or os.environ.get("TARGET_COUNTRIES") or os.environ.get("TARGET_COUNTRY") or ""
MAX_AUTO_FRAUD_SCORE = int(os.environ.get("MAX_AUTO_FRAUD_SCORE", "25"))
AUTO_RISK_MODE = os.environ.get("AUTO_RISK_MODE", "balanced").strip().lower()
if AUTO_RISK_MODE not in {"strict", "balanced", "loose"}:
    AUTO_RISK_MODE = "balanced"
AUTO_MIN_KEEP_RUNNING = os.environ.get("AUTO_MIN_KEEP_RUNNING", "1").strip().lower() not in {"0", "false", "no", "off"}
ALLOW_RISKY_IP_CONNECT = os.environ.get("ALLOW_RISKY_IP_CONNECT", "0").strip().lower() in {"1", "true", "yes", "on"}
ALLOW_MANUAL_RISKY_CONNECT = os.environ.get("ALLOW_MANUAL_RISKY_CONNECT", "1").strip().lower() not in {"0", "false", "no", "off"}
TARGET_IP_TYPES_ENV = os.environ.get("TARGET_IP_TYPES") or os.environ.get("AUTO_IP_TYPES") or os.environ.get("TARGET_IP_TYPE") or ""
STRICT_IP_TYPE_FILTER = os.environ.get("STRICT_IP_TYPE_FILTER", "0").strip().lower() in {"1", "true", "yes", "on"}
AUTO_TEST_ALL_NODES = os.environ.get("AUTO_TEST_ALL_NODES", "1").strip().lower() not in {"0", "false", "no", "off"}
AUTO_TEST_MAX_NODES = int(os.environ.get("AUTO_TEST_MAX_NODES", "0")) 
AUTO_TEST_WORKERS = max(1, int(os.environ.get("AUTO_TEST_WORKERS", "8")))
AUTO_TEST_INITIAL_BATCH = max(1, int(os.environ.get("AUTO_TEST_INITIAL_BATCH", "8")))
OPENVPN_BATCH_TEST_TIMEOUT_SECONDS = int(os.environ.get("OPENVPN_BATCH_TEST_TIMEOUT_SECONDS", "12"))
INITIAL_QUALITY_SCAN_BEFORE_CONNECT = os.environ.get("INITIAL_QUALITY_SCAN_BEFORE_CONNECT", "1").strip().lower() not in {"0", "false", "no", "off"}
INITIAL_QUALITY_SCAN_MAX_NODES = int(os.environ.get("INITIAL_QUALITY_SCAN_MAX_NODES", "80"))
AUTO_SELECT_BEST_NODE_ENV = os.environ.get("AUTO_SELECT_BEST_NODE")
AUTO_SELECT_BEST_NODE = (AUTO_SELECT_BEST_NODE_ENV or "1").strip().lower() not in {"0", "false", "no", "off"}
AUTO_SELECT_COOLDOWN_SECONDS = int(os.environ.get("AUTO_SELECT_COOLDOWN_SECONDS", "600"))
AUTO_SWITCH_MIN_FRAUD_DELTA = int(os.environ.get("AUTO_SWITCH_MIN_FRAUD_DELTA", "20"))
AUTO_SWITCH_MIN_LATENCY_DELTA_MS = int(os.environ.get("AUTO_SWITCH_MIN_LATENCY_DELTA_MS", "300"))
AUTO_SELECT_ALLOW_ACTIVE_SWITCH = os.environ.get("AUTO_SELECT_ALLOW_ACTIVE_SWITCH", "0").strip().lower() in {"1", "true", "yes", "on"}
PROXY_FAIL_GRACE_SECONDS = int(os.environ.get("PROXY_FAIL_GRACE_SECONDS", "75"))
PROXY_FAIL_AUTO_SWITCH_THRESHOLD = max(1, int(os.environ.get("PROXY_FAIL_AUTO_SWITCH_THRESHOLD", "3")))
AUTO_SWITCH_RETRY_COOLDOWN_SECONDS = max(10, int(os.environ.get("AUTO_SWITCH_RETRY_COOLDOWN_SECONDS", "45")))

ROOT_DIR = Path(sys.executable).resolve().parent if globals().get("__compiled__") else Path(__file__).resolve().parent
DATA_DIR = Path(os.environ["VPNGATE_DATA_DIR"]).resolve() if os.environ.get("VPNGATE_DATA_DIR") else ROOT_DIR / "vpngate_data"
CONFIG_DIR = DATA_DIR / "configs"
NODES_FILE = DATA_DIR / "nodes.json"
STATE_FILE = DATA_DIR / "state.json"
AUTH_FILE = DATA_DIR / "vpngate_auth.txt"

lock = threading.RLock()
active_sessions: dict[str, float] = {}
active_openvpn_process: subprocess.Popen[str] | None = None
active_openvpn_node_id = ""
is_connecting = True
last_active_ping_time = 0.0
last_active_latency = 0

def ensure_dirs() -> None:
    DATA_DIR.mkdir(exist_ok=True)
    CONFIG_DIR.mkdir(exist_ok=True)
    if not AUTH_FILE.exists():
        AUTH_FILE.write_text(f"{OPENVPN_AUTH_USER}\n{OPENVPN_AUTH_PASS}\n", encoding="utf-8")
        try:
            AUTH_FILE.chmod(0o600)
        except OSError:
            pass

def write_json(path: Path, data: Any) -> None:
    with lock:
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(path)

def read_json(path: Path, default: Any) -> Any:
    with lock:
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return default

import hashlib
import random

def generate_random_password() -> str:
    import string
    chars = string.ascii_letters + string.digits
    while True:
        pwd = "".join(random.choices(chars, k=12))
        has_lower = any(c.islower() for c in pwd)
        has_upper = any(c.isupper() for c in pwd)
        has_digit = any(c.isdigit() for c in pwd)
        if has_lower and has_upper and has_digit:
            return pwd

def generate_random_username() -> str:
    import string
    chars = string.ascii_letters + string.digits
    while True:
        uname = "".join(random.choices(chars, k=12))
        if uname[0].isalpha():
            has_lower = any(c.islower() for c in uname)
            has_upper = any(c.isupper() for c in uname)
            has_digit = any(c.isdigit() for c in uname)
            if has_lower and has_upper and has_digit:
                return uname

def load_ui_config() -> dict[str, Any]:
    with lock:
        auth_file = DATA_DIR / "ui_auth.json"
        config = {
            "username": "",
            "secret_path": "EJsW2EeBo9lY",
            "password": "",
            "host": "0.0.0.0",
            "port": 8787,
            "target_countries": TARGET_COUNTRIES_ENV,
            "target_ip_types": TARGET_IP_TYPES_ENV or "residential",
            "auto_select_best_node": AUTO_SELECT_BEST_NODE,
            "node_sources": NODE_SOURCES_ENV or DEFAULT_NODE_SOURCES,
            "auto_select_allow_active_switch": AUTO_SELECT_ALLOW_ACTIVE_SWITCH
        }
        updated = False
        if auth_file.exists():
            try:
                data = json.loads(auth_file.read_text(encoding="utf-8"))
                for key, val in data.items():
                    config[key] = val
                current_sources = normalize_node_sources_input(config.get("node_sources"))
                if current_sources in ["vpngate,vpnbook", "vpngate,vpnbook,ipspeed"] and not NODE_SOURCES_ENV:
                    config["node_sources"] = DEFAULT_NODE_SOURCES
                    updated = True
            except Exception:
                pass
        if TARGET_COUNTRIES_ENV:
            config["target_countries"] = TARGET_COUNTRIES_ENV
        if TARGET_IP_TYPES_ENV:
            config["target_ip_types"] = TARGET_IP_TYPES_ENV
        if AUTO_SELECT_BEST_NODE_ENV is not None and AUTO_SELECT_BEST_NODE_ENV.strip():
            config["auto_select_best_node"] = AUTO_SELECT_BEST_NODE
        if NODE_SOURCES_ENV:
            config["node_sources"] = NODE_SOURCES_ENV
        
        if not config.get("username"):
            config["username"] = generate_random_username()
            updated = True
            
        if not config.get("password"):
            config["password"] = generate_random_password()
            updated = True
            
        if not auth_file.exists() or updated:
            try:
                DATA_DIR.mkdir(exist_ok=True, parents=True)
                auth_file.write_text(json.dumps(config, ensure_ascii=False, indent=2), encoding="utf-8")
            except Exception:
                pass
                
        return config


def split_target_countries(value: Any) -> list[str]:
    if isinstance(value, list):
        raw = ",".join(str(item) for item in value)
    else:
        raw = str(value or "")
    return [item.strip() for item in re.split(r"[,，;；|/\s]+", raw) if item.strip()]

def normalize_country_token(value: Any) -> str:
    return re.sub(r"[^0-9a-z\u4e00-\u9fff]+", "", str(value or "").strip().lower())

COUNTRY_CANONICAL_ALIASES: dict[str, list[str]] = {
    "US": ["United States", "USA", "United States of America", "America", "美国", "美國"],
    "JP": ["Japan", "日本"],
    "KR": ["Korea Republic of", "Korea", "Republic of Korea", "South Korea", "韩国", "韓國", "南韩", "南韓"],
    "GB": ["United Kingdom", "UK", "Great Britain", "Britain", "England", "英国", "英國"],
    "CA": ["Canada", "加拿大"],
    "DE": ["Germany", "德国", "德國"],
    "FR": ["France", "法国", "法國"],
    "NL": ["Netherlands", "荷兰", "荷蘭"],
    "RU": ["Russian Federation", "Russia", "Russian", "俄罗斯", "俄羅斯"],
    "AU": ["Australia", "澳大利亚", "澳洲"],
    "TW": ["Taiwan", "Taiwan Province of China", "台湾", "台灣"],
    "HK": ["Hong Kong", "香港"],
    "SG": ["Singapore", "新加坡"],
    "TH": ["Thailand", "泰国", "泰國"],
    "VN": ["Viet Nam", "Vietnam", "越南"],
    "CN": ["China", "中国", "中國"],
    "PL": ["Poland", "波兰", "波蘭"],
    "RO": ["Romania", "罗马尼亚", "羅馬尼亞"],
    "CO": ["Colombia", "哥伦比亚", "哥倫比亞"],
    "ID": ["Indonesia", "印度尼西亚", "印尼"],
    "PE": ["Peru", "秘鲁", "秘魯"],
    "MM": ["Myanmar", "Burma", "缅甸", "緬甸"],
    "IN": ["India", "印度"],
    "MY": ["Malaysia", "马来西亚", "馬來西亞"],
    "PH": ["Philippines", "菲律宾", "菲律賓"],
    "BR": ["Brazil", "巴西"],
    "AR": ["Argentina", "阿根廷"],
    "CL": ["Chile", "智利"],
    "MX": ["Mexico", "墨西哥"],
    "ES": ["Spain", "西班牙"],
    "IT": ["Italy", "意大利"],
    "SE": ["Sweden", "瑞典"],
    "NO": ["Norway", "挪威"],
    "FI": ["Finland", "芬兰", "芬蘭"],
    "DK": ["Denmark", "丹麦", "丹麥"],
    "CH": ["Switzerland", "瑞士"],
    "BE": ["Belgium", "比利时", "比利時"],
    "AT": ["Austria", "奥地利", "奧地利"],
    "IE": ["Ireland", "爱尔兰", "愛爾蘭"],
    "PT": ["Portugal", "葡萄牙"],
    "GR": ["Greece", "希腊", "希臘"],
    "CZ": ["Czech Republic", "Czechia", "捷克"],
    "HU": ["Hungary", "匈牙利"],
    "TR": ["Turkey", "Türkiye", "土耳其"],
    "UA": ["Ukraine", "乌克兰", "烏克蘭"],
}
COUNTRY_CODE_TO_EN: dict[str, str] = {code: aliases[0] for code, aliases in COUNTRY_CANONICAL_ALIASES.items()}
_COUNTRY_ALIAS_INDEX: dict[str, str] = {}
for _code, _aliases in COUNTRY_CANONICAL_ALIASES.items():
    _COUNTRY_ALIAS_INDEX[normalize_country_token(_code)] = _code
    for _alias in _aliases:
        _COUNTRY_ALIAS_INDEX[normalize_country_token(_alias)] = _code

def canonical_country_code(*values: Any) -> str:
    for value in values:
        text = str(value or "").strip()
        if not text:
            continue
        token = normalize_country_token(text)
        if token in _COUNTRY_ALIAS_INDEX:
            return _COUNTRY_ALIAS_INDEX[token]
        if len(text) == 2 and text.upper() in COUNTRY_CODE_TO_EN:
            return text.upper()
    return ""

def canonical_country_display(country_short: Any = "", country_value: Any = "") -> str:
    code = canonical_country_code(country_short, country_value)
    if code:
        english = COUNTRY_CODE_TO_EN.get(code, code)
        return vpn_utils.COUNTRY_TRANSLATIONS.get(english, english)
    country = str(country_value or "").strip()
    return vpn_utils.COUNTRY_TRANSLATIONS.get(country, vpn_utils.COUNTRY_TRANSLATIONS.get(country.strip(), country))

def canonicalize_country_fields(country_short: Any = "", country_value: Any = "") -> tuple[str, str]:
    code = canonical_country_code(country_short, country_value)
    display = canonical_country_display(code or country_short, country_value)
    return code or str(country_short or "").strip(), display

def normalize_target_countries_input(value: Any) -> str:
    result: list[str] = []
    seen: set[str] = set()
    for item in split_target_countries(value):
        token = normalize_country_token(item)
        if token and token not in seen:
            result.append(item)
            seen.add(token)
    return ",".join(result)


def split_node_sources(value: Any) -> list[str]:
    raw = str(value or "")
    aliases = {
        "vpngate": "vpngate", "vpn_gate": "vpngate", "gate": "vpngate", "vg": "vpngate", "筑波": "vpngate",
        "vpnbook": "vpnbook", "book": "vpnbook", "vb": "vpnbook",
        "ipspeed": "ipspeed", "ip_speed": "ipspeed", "speed": "ipspeed", "is": "ipspeed",
        "fdciabdul": "fdciabdul", "github": "fdciabdul", "fdci": "fdciabdul"
    }
    result: list[str] = []
    seen: set[str] = set()
    for part in re.split(r"[,，;；|/\s]+", raw):
        token = part.strip().lower().replace("-", "_")
        if not token:
            continue
        canonical = aliases.get(token, token)
        if canonical in {"all", "全部", "*"}:
            canonical = "vpngate,vpnbook,ipspeed,fdciabdul"
        for item in str(canonical).split(","):
            item = item.strip()
            if item in {"vpngate", "vpnbook", "ipspeed", "fdciabdul"} and item not in seen:
                result.append(item)
                seen.add(item)
    return result or ["vpngate", "vpnbook", "ipspeed", "fdciabdul"]

def normalize_node_sources_input(value: Any) -> str:
    return ",".join(split_node_sources(value))

def get_node_sources() -> list[str]:
    cfg = load_ui_config()
    return split_node_sources(NODE_SOURCES_ENV or cfg.get("node_sources") or DEFAULT_NODE_SOURCES)

def node_sources_display(value: Any) -> str:
    labels = {"vpngate": "VPNGate", "vpnbook": "VPNBook", "ipspeed": "IPSpeed", "fdciabdul": "FDCIAbdul"}
    return " + ".join(labels.get(x, x) for x in split_node_sources(value))

def get_target_countries() -> list[str]:
    cfg = load_ui_config()
    return split_target_countries(cfg.get("target_countries") or TARGET_COUNTRIES_ENV)

IP_TYPE_ALIASES: dict[str, tuple[str, ...]] = {
    "residential": ("residential", "住宅", "家宽", "原生", "home", "isp", "clean_residential"),
    "mobile": ("mobile", "移动", "手机", "蜂窝"),
    "normal": ("normal", "普通", "unknown", "未知", "空", "未识别", ""),
    "hosting": ("hosting", "datacenter", "data_center", "dc", "机房", "数据中心", "服务器", "vps", "cloud"),
    "proxy": ("proxy", "代理", "vpn"),
    "tor": ("tor", "洋葱"),
}

def normalize_ip_type_token(value: Any) -> str:
    token = str(value or "").strip().lower().replace(" ", "_").replace("-", "_")
    if token in {"all", "any", "全部", "不限", "任意", "*"}:
        return "all"
    for canonical, aliases in IP_TYPE_ALIASES.items():
        if token in {str(a).strip().lower().replace(" ", "_").replace("-", "_") for a in aliases}:
            return canonical
    return token

def split_target_ip_types(value: Any) -> list[str]:
    if isinstance(value, (list, tuple, set)):
        raw_parts = [str(x).strip() for x in value]
    else:
        raw_parts = re.split(r"[,，;；\s]+", str(value or ""))
    result: list[str] = []
    seen: set[str] = set()
    for part in raw_parts:
        token = normalize_ip_type_token(part)
        if not token:
            continue
        if token == "all":
            return []
        if token not in seen:
            result.append(token)
            seen.add(token)
    return result

def normalize_target_ip_types_input(value: Any) -> str:
    if isinstance(value, str):
        raw_parts = re.split(r"[,，;；\s]+", value)
        if any(normalize_ip_type_token(part) == "all" for part in raw_parts if part.strip()):
            return "all"
    types = split_target_ip_types(value)
    return ",".join(types)

def get_target_ip_types() -> list[str]:
    cfg = load_ui_config()
    return split_target_ip_types(cfg.get("target_ip_types") or TARGET_IP_TYPES_ENV or "residential")

def ip_type_display(value: Any) -> str:
    token = normalize_ip_type_token(value)
    return {
        "residential": "住宅IP",
        "mobile": "移动IP",
        "normal": "普通/未知",
        "hosting": "机房IP",
        "proxy": "代理IP",
        "tor": "Tor出口",
    }.get(token, str(value or ""))


def parse_bool_setting(value: Any, default: bool = True) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "on", "enable", "enabled", "开启"}:
        return True
    if text in {"0", "false", "no", "off", "disable", "disabled", "关闭"}:
        return False
    return default

def get_auto_select_best_node() -> bool:
    if AUTO_SELECT_BEST_NODE_ENV is not None and AUTO_SELECT_BEST_NODE_ENV.strip():
        return AUTO_SELECT_BEST_NODE
    cfg = load_ui_config()
    return parse_bool_setting(cfg.get("auto_select_best_node"), AUTO_SELECT_BEST_NODE)

def get_auto_select_allow_active_switch() -> bool:
    cfg = load_ui_config()
    return parse_bool_setting(cfg.get("auto_select_allow_active_switch"), AUTO_SELECT_ALLOW_ACTIVE_SWITCH)

def active_connection_looks_healthy(active_node: dict[str, Any] | None = None) -> bool:
    if not active_openvpn_running():
        return False
    state = read_json(STATE_FILE, {})
    now = time.time()
    connected_at = float(state.get("active_connected_at") or 0)
    if connected_at and now - connected_at < PROXY_FAIL_GRACE_SECONDS:
        return True
    fail_count = int(state.get("proxy_fail_count") or 0)
    if fail_count >= PROXY_FAIL_AUTO_SWITCH_THRESHOLD:
        return False
    if active_node and str(active_node.get("probe_status") or "available").lower() == "unavailable":
        return False
    return True

def target_ip_types_display(value: Any) -> str:
    types = split_target_ip_types(value)
    if not types:
        return "全部类型"
    label = "、".join(ip_type_display(t) for t in types)
    if STRICT_IP_TYPE_FILTER:
        return f"{label}硬过滤"
    return f"{label}优先"

def node_matches_target_ip_types(node: dict[str, Any], target_types: list[str]) -> bool:
    if not target_types:
        return True
    ip_type = normalize_ip_type_token(node.get("ip_type") or "unknown")
    quality = normalize_ip_type_token(node.get("quality") or "")
    node_tokens = {ip_type, quality}
    if quality in {"clean_residential", "residential"}:
        node_tokens.add("residential")
    if quality in {"datacenter", "hosting"}:
        node_tokens.add("hosting")
    if not node_has_risk_data(node) and "normal" in target_types:
        node_tokens.add("normal")
    return any(t in node_tokens for t in target_types)

def row_country_tokens(row: dict[str, str]) -> set[str]:
    country_long = (row.get("CountryLong") or "").strip()
    country_short = (row.get("CountryShort") or "").strip()
    country_zh = vpn_utils.COUNTRY_TRANSLATIONS.get(country_long, vpn_utils.COUNTRY_TRANSLATIONS.get(country_long.strip(), country_long))
    tokens = {country_short, country_long, country_zh}
    code = canonical_country_code(country_short, country_long, country_zh)
    if code:
        tokens.add(code)
        tokens.update(COUNTRY_CANONICAL_ALIASES.get(code, []))
    return {normalize_country_token(token) for token in tokens if token}

def row_matches_target_countries(row: dict[str, str], targets: list[str]) -> bool:
    if not targets:
        return True
    row_tokens = row_country_tokens(row)
    for target in targets:
        token = normalize_country_token(target)
        if token and token in row_tokens:
            return True
    return False

def node_country_tokens(node: dict[str, Any]) -> set[str]:
    country_short = str(node.get("country_short") or "").strip()
    country = str(node.get("country") or "").strip()
    tokens = {country_short, country}
    reverse_translations = {normalize_country_token(v): k for k, v in vpn_utils.COUNTRY_TRANSLATIONS.items()}
    if normalize_country_token(country) in reverse_translations:
        tokens.add(reverse_translations[normalize_country_token(country)])
    code = canonical_country_code(country_short, country)
    if code:
        tokens.add(code)
        tokens.update(COUNTRY_CANONICAL_ALIASES.get(code, []))
    return {normalize_country_token(token) for token in tokens if token}

def node_matches_target_countries(node: dict[str, Any], targets: list[str]) -> bool:
    if not targets:
        return True
    node_tokens = node_country_tokens(node)
    for target in targets:
        token = normalize_country_token(target)
        if token and token in node_tokens:
            return True
    return False

def node_has_risk_data(node: dict[str, Any]) -> bool:
    risk_level = str(node.get("risk_level") or "").lower()
    return bool(
        risk_level in {"clean", "low", "medium", "high", "blocked"}
        or node.get("risk_sources")
        or node.get("fraud_flags")
        or node.get("blacklist_hits")
    )

def node_fraud_score(node: dict[str, Any], unknown: int = 50) -> int:
    val = node.get("fraud_score")
    if val in (None, ""):
        return unknown
    return parse_int(val)

def node_is_clean_for_connect(node: dict[str, Any]) -> bool:
    if ALLOW_RISKY_IP_CONNECT:
        return True
    if not node_has_risk_data(node):
        return False
    if parse_int(node.get("blacklist_count")) > 0:
        return False
    if node_fraud_score(node, unknown=100) > MAX_AUTO_FRAUD_SCORE:
        return False
    if str(node.get("risk_level") or "").lower() in {"medium", "high", "blocked"}:
        return False
    if str(node.get("ip_type") or "").lower() in {"proxy", "hosting", "tor"}:
        return False
    return True

def node_ip_priority_rank(node: dict[str, Any]) -> int:
    ip_type = str(node.get("ip_type") or "").strip().lower()
    quality = str(node.get("quality") or "").strip().lower()
    risk_level = str(node.get("risk_level") or "").strip().lower()
    blacklist_count = parse_int(node.get("blacklist_count"))
    fraud_score = node_fraud_score(node, unknown=50)

    if blacklist_count > 0 or risk_level in {"high", "blocked"}:
        return 99
    if fraud_score > MAX_AUTO_FRAUD_SCORE and not ALLOW_RISKY_IP_CONNECT:
        return 90
    if ip_type == "residential" and quality in {"clean_residential", "", "normal", "residential"} and risk_level in {"clean", ""}:
        return 0
    if ip_type == "residential":
        return 1
    if ip_type == "mobile" or quality == "mobile":
        return 2
    if quality in {"", "normal"} and ip_type in {"", "unknown"}:
        return 5
    if ip_type == "hosting" or quality in {"hosting", "datacenter"}:
        return 8
    if ip_type in {"proxy", "tor"} or quality in {"proxy", "risky"}:
        return 9
    return 6

def node_sort_key(node: dict[str, Any]) -> tuple[int, int, int, int, int]:
    return (
        node_ip_priority_rank(node),
        node_fraud_score(node, unknown=50),
        parse_int(node.get("latency_ms")) or 999999,
        parse_int(node.get("ping")) or 999999,
        -parse_int(node.get("score")),
    )

def node_auto_fallback_key(node: dict[str, Any]) -> tuple[int, int, int, int, int, int]:
    risk_level = str(node.get("risk_level") or "unknown").lower()
    ip_type = normalize_ip_type_token(node.get("ip_type") or "unknown")
    blacklist_count = parse_int(node.get("blacklist_count"))
    fraud_score = node_fraud_score(node, unknown=80)

    risk_rank = 0
    if blacklist_count > 0:
        risk_rank += 80 + min(blacklist_count, 9)
    if risk_level == "blocked":
        risk_rank += 70
    elif risk_level == "high":
        risk_rank += 45
    elif risk_level == "medium":
        risk_rank += 25
    elif risk_level in {"unknown", ""}:
        risk_rank += 15
    if ip_type in {"proxy", "tor"}:
        risk_rank += 35
    elif ip_type in {"hosting", "datacenter"}:
        risk_rank += 20
    elif ip_type == "mobile":
        risk_rank += 5
    elif ip_type == "residential":
        risk_rank -= 10

    return (
        risk_rank,
        fraud_score,
        node_ip_priority_rank(node),
        parse_int(node.get("latency_ms")) or 999999,
        parse_int(node.get("ping")) or 999999,
        -parse_int(node.get("score")),
    )

DEFAULT_IP_TYPE_FALLBACK_ORDER = ["residential", "mobile", "normal", "hosting", "proxy", "tor"]

def ip_type_preference_order(preferred_types: list[str]) -> list[str]:
    if not preferred_types:
        return list(DEFAULT_IP_TYPE_FALLBACK_ORDER)
    order: list[str] = []
    seen: set[str] = set()
    for item in preferred_types:
        token = normalize_ip_type_token(item)
        if token and token != "all" and token not in seen:
            order.append(token)
            seen.add(token)
    if STRICT_IP_TYPE_FILTER:
        return order
    for item in DEFAULT_IP_TYPE_FALLBACK_ORDER:
        if item not in seen:
            order.append(item)
            seen.add(item)
    return order

def tiered_ip_type_candidates(candidates: list[dict[str, Any]], preferred_types: list[str]) -> tuple[list[dict[str, Any]], str]:
    if not candidates:
        return [], "无候选节点"
    if not preferred_types:
        pool = list(candidates)
        pool.sort(key=node_auto_fallback_key)
        return pool, "全部类型按综合风险/延迟排序"

    if STRICT_IP_TYPE_FILTER:
        pool = [n for n in candidates if node_matches_target_ip_types(n, preferred_types)]
        pool.sort(key=node_auto_fallback_key)
        return pool, f"严格 IP 类型过滤：{target_ip_types_display(preferred_types)}"

    used_ids: set[str] = set()
    for ip_type in ip_type_preference_order(preferred_types):
        tier = []
        for node in candidates:
            node_key = str(node.get("id") or id(node))
            if node_key in used_ids:
                continue
            if node_matches_target_ip_types(node, [ip_type]):
                tier.append(node)
                used_ids.add(node_key)
        if tier:
            tier.sort(key=node_auto_fallback_key)
            return tier, f"IP 类型优先级命中：{ip_type_display(ip_type)}"

    pool = list(candidates)
    pool.sort(key=node_auto_fallback_key)
    return pool, "未识别 IP 类型，按综合风险/延迟兜底"

def choose_auto_failover_candidates(scoped_candidates: list[dict[str, Any]], all_candidates: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], str]:
    target_ip_types = get_target_ip_types()
    ip_type_label = target_ip_types_display(target_ip_types)

    if STRICT_IP_TYPE_FILTER:
        scoped_pool = [n for n in scoped_candidates if node_matches_target_ip_types(n, target_ip_types)] if target_ip_types else list(scoped_candidates)
        all_pool = [n for n in all_candidates if node_matches_target_ip_types(n, target_ip_types)] if target_ip_types else list(all_candidates)
    else:
        scoped_pool = list(scoped_candidates)
        all_pool = list(all_candidates)

    clean_scoped = [n for n in scoped_pool if node_is_clean_for_connect(n)]
    clean_all = [n for n in all_pool if node_is_clean_for_connect(n)]

    if AUTO_RISK_MODE == "loose" or ALLOW_RISKY_IP_CONNECT:
        candidates, tier_reason = tiered_ip_type_candidates(scoped_pool, target_ip_types)
        if not candidates and not STRICT_COUNTRY_FAILOVER:
            candidates, tier_reason = tiered_ip_type_candidates(all_pool, target_ip_types)
            if candidates:
                return candidates, f"宽松模式跨地区兜底；{tier_reason}"
        if candidates:
            return candidates, f"宽松模式：{tier_reason}"
        return [], f"没有可用节点；IP 类型策略 {ip_type_label}"

    clean_candidates, clean_tier_reason = tiered_ip_type_candidates(clean_scoped, target_ip_types)
    if clean_candidates:
        clean_candidates.sort(key=node_sort_key)
        return clean_candidates, f"优先选择同地区干净节点；{clean_tier_reason}"

    if not STRICT_COUNTRY_FAILOVER:
        clean_cross, cross_reason = tiered_ip_type_candidates(clean_all, target_ip_types)
        if clean_cross:
            clean_cross.sort(key=node_sort_key)
            return clean_cross, f"同地区无干净节点，跨地区选择干净节点；{cross_reason}"

    if AUTO_RISK_MODE == "strict" and not AUTO_MIN_KEEP_RUNNING:
        return [], f"严格模式：没有符合阈值的干净节点；IP 类型策略 {ip_type_label}"

    fallback_pool = scoped_pool
    fallback_candidates, fallback_reason = tiered_ip_type_candidates(fallback_pool, target_ip_types)
    if fallback_candidates:
        return fallback_candidates, f"保活兜底：无干净 IP，按同地区 IP 类型优先级逐级选择；{fallback_reason}"

    if not STRICT_COUNTRY_FAILOVER:
        fallback_candidates, fallback_reason = tiered_ip_type_candidates(all_pool, target_ip_types)
        if fallback_candidates:
            return fallback_candidates, f"跨地区保活兜底：按 IP 类型优先级逐级选择；{fallback_reason}"

    return [], "没有可用节点；将继续后台拉取/检测"

def get_failover_targets(active_node: dict[str, Any] | None = None) -> list[str]:
    configured = get_target_countries()
    if configured:
        return configured
    state = read_json(STATE_FILE, {})
    saved = state.get("failover_country_short") or state.get("failover_country") or ""
    if saved:
        return split_target_countries(saved)
    if active_node:
        country_short = active_node.get("country_short") or ""
        country = active_node.get("country") or ""
        return split_target_countries(country_short or country)
    return []

def set_failover_scope_from_node(node: dict[str, Any]) -> None:
    country_short = str(node.get("country_short") or "").strip()
    country = str(node.get("country") or "").strip()
    set_state(
        failover_country_short=country_short,
        failover_country=country,
        failover_country_display=country or country_short or "未固定",
        strict_country_failover=STRICT_COUNTRY_FAILOVER,
    )

def auto_selection_key_summary(node: dict[str, Any]) -> str:
    return (
        f"IP类型 {ip_type_display(node.get('ip_type') or node.get('quality') or 'unknown')} / "
        f"欺诈值 {node.get('fraud_score', '未知')} / "
        f"黑名单 {node.get('blacklist_count', 0)} / "
        f"延迟 {node.get('latency_ms') or node.get('ping') or '-'} ms"
    )

def should_switch_to_better_node(active_node: dict[str, Any] | None, best_node: dict[str, Any]) -> tuple[bool, str]:
    if not active_node:
        return True, "当前没有活动节点"
    if best_node.get("id") == active_node.get("id"):
        return False, "当前节点已经是本轮优选节点"

    active_status = str(active_node.get("probe_status") or "").lower()
    if active_status not in {"available", ""}:
        return True, "当前活动节点状态异常"

    active_blacklist = parse_int(active_node.get("blacklist_count"))
    best_blacklist = parse_int(best_node.get("blacklist_count"))
    if best_blacklist < active_blacklist:
        return True, f"候选节点黑名单命中更少：{active_blacklist} -> {best_blacklist}"

    active_ip_rank = node_ip_priority_rank(active_node)
    best_ip_rank = node_ip_priority_rank(best_node)
    if best_ip_rank + 1 < active_ip_rank:
        return True, f"候选节点 IP 类型/风控等级明显更优：{auto_selection_key_summary(active_node)} -> {auto_selection_key_summary(best_node)}"

    active_fraud = node_fraud_score(active_node, unknown=80)
    best_fraud = node_fraud_score(best_node, unknown=80)
    if active_fraud - best_fraud >= AUTO_SWITCH_MIN_FRAUD_DELTA:
        return True, f"候选节点欺诈值明显更低：{active_fraud} -> {best_fraud}"

    active_risk = str(active_node.get("risk_level") or "unknown").lower()
    best_risk = str(best_node.get("risk_level") or "unknown").lower()
    risk_order = {"clean": 0, "low": 1, "unknown": 2, "medium": 3, "high": 4, "blocked": 5}
    if risk_order.get(best_risk, 2) + 1 < risk_order.get(active_risk, 2):
        return True, f"候选节点风险等级明显更低：{active_risk} -> {best_risk}"

    active_latency = parse_int(active_node.get("latency_ms")) or parse_int(active_node.get("ping")) or 999999
    best_latency = parse_int(best_node.get("latency_ms")) or parse_int(best_node.get("ping")) or 999999
    if best_ip_rank <= active_ip_rank and best_fraud <= active_fraud and active_latency - best_latency >= AUTO_SWITCH_MIN_LATENCY_DELTA_MS:
        return True, f"候选节点延迟明显更低：{active_latency} ms -> {best_latency} ms"

    return False, "候选节点没有明显优于当前活动节点，避免频繁跳节点"

def optimize_active_node_after_tests(reason: str = "") -> str:
    if not get_auto_select_best_node():
        return "自动优选已关闭"

    with lock:
        nodes = read_json(NODES_FILE, [])
        active_node = next((n for n in nodes if n.get("id") == active_openvpn_node_id or n.get("active")), None)
        available = [n for n in nodes if n.get("probe_status") == "available"]

    if not available:
        msg = "自动优选：暂无已检测可用节点"
        set_state(last_auto_select_message=msg)
        return msg

    failover_targets = get_failover_targets(active_node)
    scoped = [n for n in available if node_matches_target_countries(n, failover_targets)] if failover_targets else list(available)
    candidates, candidate_reason = choose_auto_failover_candidates(scoped, available)
    if not candidates:
        msg = f"自动优选：没有符合当前地区/IP策略的可用节点；{candidate_reason}"
        set_state(last_auto_select_message=msg)
        return msg

    best_node = candidates[0]
    should_switch, switch_reason = should_switch_to_better_node(active_node, best_node)
    if not should_switch:
        msg = f"自动优选：保持当前节点；{switch_reason}；策略：{candidate_reason}"
        set_state(last_auto_select_message=msg)
        return msg

    if active_connection_looks_healthy(active_node) and not get_auto_select_allow_active_switch():
        msg = (
            f"非中断检测：发现更优节点 {best_node.get('id')}，但当前出口正常运行，"
            "不会为了检测/优选而主动断开重连；仅在当前节点失效时自动故障转移。"
        )
        set_state(last_auto_select_message=msg, last_check_message=msg)
        return msg

    state = read_json(STATE_FILE, {})
    now = time.time()
    last_switch = float(state.get("last_auto_select_switch_at") or 0)
    if active_openvpn_running() and last_switch > 0 and now - last_switch < AUTO_SELECT_COOLDOWN_SECONDS:
        left = int(AUTO_SELECT_COOLDOWN_SECONDS - (now - last_switch))
        msg = f"自动优选：发现更优节点 {best_node.get('id')}，但冷却中，约 {left} 秒后再自动切换；原因：{switch_reason}"
        set_state(last_auto_select_message=msg)
        return msg

    clean_ok = node_is_clean_for_connect(best_node)
    msg = (
        f"自动优选：从全部已检测节点中选择 {best_node.get('id')}；"
        f"{auto_selection_key_summary(best_node)}；原因：{switch_reason}；策略：{candidate_reason}"
    )
    print(f"[自动优选] {msg}", flush=True)
    log_to_json("INFO", "VPN", msg)
    set_state(last_auto_select_message=msg, last_check_message=msg, last_auto_select_switch_at=now)
    try:
        return connect_node(best_node["id"], update_failover_scope=False, allow_auto_risky=not clean_ok)
    except Exception as e:
        err = f"自动优选切换失败：{e}"
        print(f"[自动优选] {err}", flush=True)
        log_to_json("WARNING", "VPN", err)
        set_state(last_auto_select_message=err, last_check_message=err)
        return err

def get_session_token(password: str, username: str = "admin") -> str:
    salt = "eianun_vpngate_secure_salt_2026"
    return hashlib.sha256((username + ":" + password + salt).encode("utf-8")).hexdigest()

def cleanup_old_logs(logs_dir: Path) -> None:
    try:
        now = time.time()
        three_days_sec = 3 * 24 * 60 * 60
        for path in logs_dir.glob("*.json"):
            match = re.match(r"^(\d{4}-\d{2}-\d{2})\.json$", path.name)
            if match:
                date_str = match.group(1)
                try:
                    file_time = time.mktime(time.strptime(date_str, "%Y-%m-%d"))
                    today_str = time.strftime("%Y-%m-%d", time.localtime())
                    today_time = time.mktime(time.strptime(today_str, "%Y-%m-%d"))
                    if today_time - file_time >= three_days_sec:
                        path.unlink()
                        print(f"[清理] 已删除3天前的旧日志文件: {path.name}", flush=True)
                except Exception:
                    if now - path.stat().st_mtime > three_days_sec:
                        path.unlink()
    except Exception as e:
        print(f"[清理错误] 清理旧日志失败: {e}", flush=True)

def log_to_json(level: str, module: str, message: str) -> None:
    try:
        logs_dir = DATA_DIR / "logs"
        logs_dir.mkdir(exist_ok=True, parents=True)
        date_str = time.strftime("%Y-%m-%d", time.localtime())
        log_file = logs_dir / f"{date_str}.json"
        entry = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
            "level": level,
            "module": module,
            "message": message
        }
        with open(log_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        cleanup_old_logs(logs_dir)
    except Exception as e:
        print(f"[Log Error] Failed to write JSON log: {e}", flush=True)

def set_state(**updates: Any) -> None:
    state = get_state()
    state.update(updates)
    write_json(STATE_FILE, state)

def get_state() -> dict[str, Any]:
    global active_openvpn_node_id, is_connecting
    state = read_json(STATE_FILE, {})
    state["active_openvpn_node_id"] = active_openvpn_node_id
    state["is_connecting"] = is_connecting
    state.setdefault("api_url", API_URL)
    state.setdefault("target_valid_nodes", TARGET_VALID_NODES)
    state.setdefault("fetch_interval_seconds", FETCH_INTERVAL_SECONDS)
    state.setdefault("check_interval_seconds", CHECK_INTERVAL_SECONDS)
    state.setdefault("local_proxy", f"http://{LOCAL_PROXY_HOST}:{LOCAL_PROXY_PORT}")
    state.setdefault("last_fetch_status", "not_started")
    state.setdefault("last_check_message", "")
    state.setdefault("blacklisted_nodes", 0)
    
    ui_cfg = load_ui_config()
    state["username"] = ui_cfg.get("username", "admin")
    state["port"] = ui_cfg.get("port", 8787)
    state["secret_path"] = ui_cfg.get("secret_path", "EJsW2EeBo9lY")
    target_countries = normalize_target_countries_input(ui_cfg.get("target_countries") or TARGET_COUNTRIES_ENV)
    target_ip_types = normalize_target_ip_types_input(ui_cfg.get("target_ip_types") or TARGET_IP_TYPES_ENV or "residential")
    state["target_countries"] = target_countries
    state["target_countries_display"] = target_countries or "全部地区"
    state["target_ip_types"] = target_ip_types
    state["target_ip_types_display"] = target_ip_types_display(target_ip_types)
    state["node_sources"] = normalize_node_sources_input(ui_cfg.get("node_sources") or NODE_SOURCES_ENV or DEFAULT_NODE_SOURCES)
    state["node_sources_display"] = node_sources_display(state["node_sources"])
    state.setdefault("failover_country_short", "")
    state.setdefault("failover_country", "")
    state.setdefault("failover_country_display", target_countries or "未固定")
    state["strict_country_failover"] = STRICT_COUNTRY_FAILOVER
    state["max_auto_fraud_score"] = MAX_AUTO_FRAUD_SCORE
    state["auto_risk_mode"] = AUTO_RISK_MODE
    state["auto_min_keep_running"] = AUTO_MIN_KEEP_RUNNING
    state["strict_ip_type_filter"] = STRICT_IP_TYPE_FILTER
    state["allow_risky_ip_connect"] = ALLOW_RISKY_IP_CONNECT
    state["allow_manual_risky_connect"] = ALLOW_MANUAL_RISKY_CONNECT
    state["auto_test_all_nodes"] = AUTO_TEST_ALL_NODES
    state["auto_test_max_nodes"] = AUTO_TEST_MAX_NODES
    state["auto_test_workers"] = AUTO_TEST_WORKERS
    state["vpnbook_auto_test"] = VPNBOOK_AUTO_TEST
    state["vpnbook_protocols"] = VPNBOOK_PROTOCOLS
    state["openvpn_batch_test_timeout_seconds"] = OPENVPN_BATCH_TEST_TIMEOUT_SECONDS
    state["auto_select_best_node"] = get_auto_select_best_node()
    state["auto_select_allow_active_switch"] = get_auto_select_allow_active_switch()
    state["auto_select_cooldown_seconds"] = AUTO_SELECT_COOLDOWN_SECONDS
    state["auto_switch_min_fraud_delta"] = AUTO_SWITCH_MIN_FRAUD_DELTA
    state["auto_switch_min_latency_delta_ms"] = AUTO_SWITCH_MIN_LATENCY_DELTA_MS
    state.setdefault("auto_test_total", 0)
    state.setdefault("auto_test_done", 0)
    state.setdefault("last_auto_select_switch_at", 0)
    state.setdefault("last_auto_select_message", "")
    state.setdefault("active_connected_at", 0)
    state.setdefault("proxy_fail_count", 0)
    state.setdefault("last_auto_switch_attempt_at", 0)
    state["proxy_fail_grace_seconds"] = PROXY_FAIL_GRACE_SECONDS
    state["proxy_fail_auto_switch_threshold"] = PROXY_FAIL_AUTO_SWITCH_THRESHOLD
    state["auto_switch_retry_cooldown_seconds"] = AUTO_SWITCH_RETRY_COOLDOWN_SECONDS
    
    return state

def safe_name(value: str) -> str:
    value = re.sub(r"[^A-Za-z0-9_.-]+", "_", value.strip())
    return value.strip("._") or "node"

def parse_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0

def resolve_ip_for_risk(host: str) -> str:
    host = str(host or "").strip()
    if not host:
        return ""
    try:
        socket.inet_aton(host)
        return host
    except OSError:
        pass
    try:
        return socket.gethostbyname(host)
    except Exception:
        return host

def http_get_bytes(url: str, timeout: int = 15, accept: str = "*/*") -> bytes:
    # 强制注入全局不安全证书豁免，以及高强度的真实浏览器伪装
    ctx = ssl._create_unverified_context()
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": accept,
            "Referer": "https://www.vpnbook.com/" if "vpnbook.com" in url else (IPSPEED_OPENVPN_URL if "ipspeed.info" in url else API_URL),
        },
    )
    with urllib.request.urlopen(request, timeout=timeout, context=ctx) as response:
        return response.read()

def fetch_api_text() -> str:
    try:
        return http_get_bytes(API_URL, timeout=12, accept="text/plain,*/*").decode("utf-8", errors="replace")
    except Exception as e:
        log_to_json("WARNING", "VPNGate", f"VPNGate 主域名请求失败 ({e})，正在切入备用 Worker 通道...")
        return http_get_bytes(API_URL_FALLBACK, timeout=15, accept="text/plain,*/*").decode("utf-8", errors="replace")

def parse_vpngate_rows(text: str) -> list[dict[str, str]]:
    lines = [line for line in text.splitlines() if line and not line.startswith("*")]
    if lines and lines[0].startswith("#"):
        lines[0] = lines[0][1:]
    return list(csv.DictReader(lines))

def decode_config(encoded: str) -> str:
    return base64.b64decode(encoded.encode("ascii"), validate=False).decode("utf-8", errors="replace")

def load_blacklist() -> dict[str, dict[str, Any]]:
    return {}

def mark_blacklisted(node: dict[str, Any], message: str) -> None:
    pass

def row_to_node(row: dict[str, str], config_text: str) -> dict[str, Any]:
    ip = row.get("IP", "")
    country_short = row.get("CountryShort", "")
    remote_host, remote_port, proto = vpn_utils.parse_remote(config_text, ip)
    node_id = safe_name("_".join([country_short or "XX", ip or remote_host, str(remote_port), proto]))
    config_path = CONFIG_DIR / f"{node_id}.ovpn"
    
    country_long = row.get("CountryLong", "")
    country_zh = vpn_utils.COUNTRY_TRANSLATIONS.get(country_long, vpn_utils.COUNTRY_TRANSLATIONS.get(country_long.strip(), country_long))
    return {
        "id": node_id,
        "source": "vpngate",
        "country": country_zh,
        "country_short": country_short,
        "host_name": row.get("HostName", ""),
        "auth_user": OPENVPN_AUTH_USER,
        "auth_pass": OPENVPN_AUTH_PASS,
        "ip": ip,
        "score": parse_int(row.get("Score")),
        "ping": parse_int(row.get("Ping")),
        "speed": parse_int(row.get("Speed")),
        "sessions": parse_int(row.get("NumVpnSessions")),
        "owner": "",
        "asn": "",
        "as_name": "",
        "location": "",
        "ip_type": "",
        "quality": "",
        "fraud_score": 0,
        "clean_score": 0,
        "risk_level": "unknown",
        "fraud_flags": [],
        "risk_sources": [],
        "blacklist_hits": [],
        "blacklist_count": 0,
        "ip_clean": False,
        "latency_ms": 0,
        "config_file": str(config_path),
        "config_text": config_text,
        "proto": proto,
        "remote_host": remote_host,
        "remote_port": remote_port,
        "fetched_at": time.time(),
        "probe_status": "not_checked",
        "probe_message": "",
        "probed_at": 0,
    }

def fetch_vpngate_candidates(target_countries: list[str], seen_keys: set[str]) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    target_display = normalize_target_countries_input(target_countries) or "全部地区"
    has_cache = len(cached_nodes()) > 0
    max_attempts = 1 if has_cache else 2
    log_to_json("INFO", "Main", f"开始拉取 VPNGate API 节点，地区过滤: {target_display} (最大尝试次数: {max_attempts})...")
    for i in range(max_attempts):
        if i > 0:
            time.sleep(1.5)
        try:
            api_text = fetch_api_text()
            rows = parse_vpngate_rows(api_text)
            matched_rows = 0
            filtered_rows = 0
            for row in rows:
                if not row_matches_target_countries(row, target_countries):
                    filtered_rows += 1
                    continue
                matched_rows += 1
                if matched_rows > MAX_SCAN_ROWS:
                    break
                ip = row.get("IP", "")
                if not ip or ip in seen_keys:
                    continue
                encoded = row.get("OpenVPN_ConfigData_Base64", "")
                if not encoded:
                    continue
                config_text = decode_config(encoded)
                node = row_to_node(row, config_text)
                node["source"] = "vpngate"
                candidates.append(node)
                seen_keys.add(ip)
            if target_countries:
                log_to_json("INFO", "Main", f"VPNGate 地区过滤 {target_display}: 匹配 {matched_rows} 行，跳过 {filtered_rows} 行")
            break
        except Exception as e:
            print(f"[fetch_vpngate_candidates] Fetch {i+1} failed: {e}", flush=True)
            log_to_json("WARNING", "Main", f"第 {i+1} 次拉取 VPNGate 节点失败: {e}")
            if i == max_attempts - 1:
                log_to_json("ERROR", "Main", f"VPNGate 节点拉取失败: {e}")
    return candidates

VPNBOOK_COUNTRIES: dict[str, tuple[str, str]] = {
    "us": ("US", "United States"),
    "ca": ("CA", "Canada"),
    "uk": ("GB", "United Kingdom"),
    "gb": ("GB", "United Kingdom"),
    "de": ("DE", "Germany"),
    "fr": ("FR", "France"),
    "pl": ("PL", "Poland"),
}

def vpnbook_protocol_parts(proto_name: str) -> tuple[str, int, str]:
    token = str(proto_name or "").strip().lower().replace("_", "").replace("-", "")
    if token in {"tcp443", "443", "tcp"}:
        return "tcp", 443, "tcp443"
    if token in {"tcp80", "80"}:
        return "tcp", 80, "tcp80"
    if token in {"udp53", "53", "udp"}:
        return "udp", 53, "udp53"
    if token in {"udp25000", "25000"}:
        return "udp", 25000, "udp25000"
    m = re.match(r"^(tcp|udp)(\d+)$", token)
    if m:
        return m.group(1), int(m.group(2)), f"{m.group(1)}{m.group(2)}"
    return "tcp", 443, "tcp443"

def extract_vpnbook_credentials(page_text: str) -> tuple[str, str]:
    username = "vpnbook"
    password = ""
    text = re.sub(r"<[^>]+>", " ", page_text)
    text = re.sub(r"\s+", " ", text)
    m_user = re.search(r"Username\s*(vpnbook)", text, re.I) or re.search(r"用户名\s*(vpnbook)", text, re.I)
    if m_user:
        username = m_user.group(1).strip()
    m_pass = re.search(r"Password\s*([A-Za-z0-9]{4,32})", text, re.I) or re.search(r"密码\s*([A-Za-z0-9]{4,32})", text, re.I)
    if m_pass:
        password = m_pass.group(1).strip()
    return username, password

def fetch_vpnbook_page() -> str:
    for url in [VPNBOOK_OPENVPN_URL, "https://www.vpnbook.com/zh/freevpn/openvpn"]:
        try:
            return http_get_bytes(url, timeout=15, accept="text/html,*/*").decode("utf-8", errors="replace")
        except Exception as exc:
            log_to_json("WARNING", "VPNBook", f"读取 VPNBook 页面失败 {url}: {exc}")
    return ""

def parse_vpnbook_servers(page_text: str) -> list[dict[str, str]]:
    found: list[dict[str, str]] = []
    seen: set[str] = set()
    for host in re.findall(r"\b((?:us|ca|uk|gb|de|fr|pl)\d+\.vpnbook\.com)\b", page_text, flags=re.I):
        host = host.lower()
        if host in seen:
            continue
        seen.add(host)
        prefix_match = re.match(r"([a-z]+)", host)
        prefix = prefix_match.group(1) if prefix_match else ""
        country_short, country_long = VPNBOOK_COUNTRIES.get(prefix, (prefix.upper() or "XX", prefix.upper() or "Unknown"))
        found.append({"host": host, "country_short": country_short, "country_long": country_long})
    return found

def looks_like_openvpn_config(text: str) -> bool:
    lower = (text or "").lower()
    return "client" in lower[:800] and "remote" in lower and ("<ca>" in lower or "-----begin certificate-----" in lower)

def sanitize_openvpn_config_for_eianun(config_text: str) -> str:
    dangerous_prefixes = (
        "redirect-gateway",
        "route",
        "route-ipv6",
        "dhcp-option",
        "pull-filter",
        "up",
        "down",
        "route-up",
        "iproute",
        "script-security",
        "block-outside-dns",
    )
    kept: list[str] = []
    for raw in config_text.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        stripped = raw.strip()
        lower = stripped.lower()
        if not stripped or stripped.startswith(("#", ";")):
            kept.append(raw)
            continue
        key = lower.split(None, 1)[0]
        if key in dangerous_prefixes:
            kept.append(f"# eianun removed unsafe directive: {stripped}")
            continue
        kept.append(raw)
    return "\n".join(kept).strip() + "\n"

def normalize_vpnbook_config_text(config_text: str, host: str, proto: str, port: int) -> str:
    text = sanitize_openvpn_config_for_eianun(config_text).replace("\r\n", "\n").replace("\r", "\n").strip() + "\n"
    text = re.sub(r"(?m)^proto\s+\S+", f"proto {proto}", text)
    if re.search(r"(?m)^remote\s+\S+\s+\d+(?:\s+\S+)?", text):
        text = re.sub(r"(?m)^remote\s+\S+\s+\d+(?:\s+\S+)?", f"remote {host} {port}", text, count=1)
    else:
        text = f"remote {host} {port}\n" + text
    if re.search(r"(?m)^auth-user-pass(?:\s+.+)?$", text):
        text = re.sub(r"(?m)^auth-user-pass(?:\s+.+)?$", "auth-user-pass", text, count=1)
    else:
        text = "auth-user-pass\n" + text
    return text

def fetch_vpnbook_template_config() -> str:
    global _vpnbook_template_config_cache
    if _vpnbook_template_config_cache:
        return _vpnbook_template_config_cache
    urls = [u.strip() for u in re.split(r"[,，;；\s]+", VPNBOOK_TEMPLATE_OVPN_URLS or "") if u.strip()]
    for url in urls:
        try:
            text = http_get_bytes(url, timeout=20, accept="application/x-openvpn-profile,text/plain,*/*").decode("utf-8", errors="replace")
            if looks_like_openvpn_config(text):
                _vpnbook_template_config_cache = text
                log_to_json("INFO", "VPNBook", f"已加载 VPNBook 模板配置: {url}")
                return text
            log_to_json("WARNING", "VPNBook", f"VPNBook 模板不像有效 OpenVPN 配置: {url}")
        except Exception as exc:
            log_to_json("WARNING", "VPNBook", f"加载 VPNBook 模板失败 {url}: {exc}")
    return ""

def try_download_vpnbook_config(host: str, proto_key: str) -> str:
    short_host = host.split(".")[0].lower()
    proto, port, normalized_proto_key = vpnbook_protocol_parts(proto_key)
    filename = f"vpnbook-{short_host}-{normalized_proto_key}.ovpn"
    quoted_host = urllib.parse.quote(short_host)
    quoted_proto = urllib.parse.quote(normalized_proto_key)
    urls = [
        f"https://www.vpnbook.com/freevpn/openvpn/{filename}",
        f"https://www.vpnbook.com/freevpn/openvpn/download/{filename}",
        f"https://www.vpnbook.com/free-openvpn-account/{filename}",
        f"https://www.vpnbook.com/free-openvpn-account/{filename}?download=1",
        f"https://www.vpnbook.com/openvpn/{filename}",
        f"https://www.vpnbook.com/{filename}",
        f"https://www.vpnbook.com/freevpn/openvpn/download?server={quoted_host}&protocol={quoted_proto}",
        f"https://www.vpnbook.com/freevpn/openvpn/download?server={quoted_host}.vpnbook.com&protocol={quoted_proto}",
        f"https://www.vpnbook.com/api/openvpn/config?server={quoted_host}&protocol={quoted_proto}",
    ]
    for url in urls:
        try:
            data = http_get_bytes(url, timeout=20, accept="application/x-openvpn-profile,text/plain,application/octet-stream,*/*")
            text = data.decode("utf-8", errors="replace")
            if looks_like_openvpn_config(text):
                return normalize_vpnbook_config_text(text, host, proto, port)
            if text.strip().lower().startswith("<!doctype") or "<html" in text[:500].lower():
                continue
        except Exception:
            continue

    template = fetch_vpnbook_template_config()
    if template:
        log_to_json("WARNING", "VPNBook", f"官方配置下载失败，使用 VPNBook 模板生成配置: {host} {normalized_proto_key}")
        return normalize_vpnbook_config_text(template, host, proto, port)
    return ""

def vpnbook_row_to_node(server: dict[str, str], proto_name: str, config_text: str, auth_user: str, auth_pass: str) -> dict[str, Any]:
    host = server["host"]
    proto, port, proto_key = vpnbook_protocol_parts(proto_name)
    country_short = server.get("country_short") or "XX"
    country_long = server.get("country_long") or country_short
    country_short, country_zh = canonicalize_country_fields(country_short, country_long)
    text = sanitize_openvpn_config_for_eianun(config_text)
    text = re.sub(r"(?m)^proto\s+\S+", f"proto {proto}", text)
    text = re.sub(r"(?m)^remote\s+\S+\s+\d+(?:\s+\S+)?", f"remote {host} {port}", text)
    if re.search(r"(?m)^auth-user-pass(?:\s+.+)?$", text):
        text = re.sub(r"(?m)^auth-user-pass(?:\s+.+)?$", "auth-user-pass", text)
    else:
        text = "auth-user-pass\n" + text
    remote_host, remote_port, parsed_proto = vpn_utils.parse_remote(text, host)
    node_id = safe_name("_".join(["VPNBOOK", country_short, host, str(remote_port or port), parsed_proto or proto]))
    config_path = CONFIG_DIR / f"{node_id}.ovpn"
    return {
        "id": node_id,
        "source": "vpnbook",
        "country": country_zh,
        "country_short": country_short,
        "host_name": host,
        "auth_user": auth_user or "vpnbook",
        "auth_pass": auth_pass,
        "ip": host,
        "score": 0,
        "ping": 0,
        "speed": 0,
        "sessions": 0,
        "owner": "",
        "asn": "",
        "as_name": "",
        "location": "",
        "ip_type": "",
        "quality": "",
        "fraud_score": 0,
        "clean_score": 0,
        "risk_level": "unknown",
        "fraud_flags": [],
        "risk_sources": [],
        "blacklist_hits": [],
        "blacklist_count": 0,
        "ip_clean": False,
        "latency_ms": 0,
        "config_file": str(config_path),
        "config_text": text,
        "proto": parsed_proto or proto,
        "remote_host": remote_host or host,
        "remote_port": remote_port or port,
        "fetched_at": time.time(),
        "probe_status": "not_checked",
        "probe_message": f"VPNBook source; auth user {auth_user}; password auto-fetched" if auth_pass else "VPNBook source; password fetch failed",
        "probed_at": 0,
    }

def fetch_vpnbook_candidates(target_countries: list[str], seen_keys: set[str]) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    page = fetch_vpnbook_page()
    if not page:
        return candidates
    auth_user, auth_pass = extract_vpnbook_credentials(page)
    if not auth_pass:
        log_to_json("WARNING", "VPNBook", "未能从 VPNBook 页面解析到密码，VPNBook 节点可能无法通过认证")
    servers = parse_vpnbook_servers(page)
    protocols = [p for p in re.split(r"[,，;；\s]+", VPNBOOK_PROTOCOLS) if p.strip()] or ["tcp443"]
    target_display = normalize_target_countries_input(target_countries) or "全部地区"
    log_to_json("INFO", "VPNBook", f"解析到 VPNBook OpenVPN 服务器 {len(servers)} 个，地区过滤: {target_display}")
    for server in servers:
        pseudo_row = {"CountryShort": server.get("country_short", ""), "CountryLong": server.get("country_long", "")}
        if not row_matches_target_countries(pseudo_row, target_countries):
            continue
        for proto_name in protocols:
            proto, port, proto_key = vpnbook_protocol_parts(proto_name)
            key = f"vpnbook:{server['host']}:{proto_key}"
            if key in seen_keys:
                continue
            config_text = try_download_vpnbook_config(server["host"], proto_key)
            if not config_text:
                log_to_json("WARNING", "VPNBook", f"未能下载 VPNBook 配置: {server['host']} {proto_key}")
                continue
            node = vpnbook_row_to_node(server, proto_key, config_text, auth_user, auth_pass)
            candidates.append(node)
            seen_keys.add(key)
            if len(candidates) >= MAX_SCAN_ROWS:
                break
        if len(candidates) >= MAX_SCAN_ROWS:
            break
    log_to_json("INFO", "VPNBook", f"成功获取 VPNBook 候选节点 {len(candidates)} 个")
    return candidates


IPSPEED_COUNTRY_CODES: dict[str, str] = {
    "canada": "CA", "colombia": "CO", "indonesia": "ID", "japan": "JP", "peru": "PE",
    "romania": "RO", "russian federation": "RU", "russia": "RU", "south korea": "KR",
    "korea republic of": "KR", "usa": "US", "united states": "US", "vietnam": "VN",
    "viet nam": "VN", "thailand": "TH", "united kingdom": "GB", "uk": "GB",
    "germany": "DE", "france": "FR", "netherlands": "NL", "australia": "AU",
}

def ipspeed_country_code(country_name: str) -> str:
    name = re.sub(r"\s+", " ", str(country_name or "").strip())
    return canonical_country_code(name) or IPSPEED_COUNTRY_CODES.get(name.lower(), name[:2].upper() if name else "XX")

def parse_ipspeed_rows(page_text: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()

    def add_row(country: str, href: str, ip: str, uptime: Any = 0, ping: Any = 0) -> None:
        ip = str(ip or "").strip()
        if not ip or ip in seen:
            return
        seen.add(ip)
        country = re.sub(r"\s+", " ", str(country or "Unknown")).strip() or "Unknown"
        rows.append({
            "country_long": country,
            "country_short": ipspeed_country_code(country),
            "ip": ip,
            "url": urllib.parse.urljoin(IPSPEED_OPENVPN_URL, href),
            "uptime_days": parse_int(uptime),
            "ping": parse_int(ping),
        })

    for row_html in re.findall(r"<tr[^>]*>(.*?)</tr>", page_text, flags=re.I | re.S):
        if ".ovpn" not in row_html.lower():
            continue
        link = re.search(r"href=[\"'](?P<href>[^\"']+\.ovpn)[\"'][^>]*>\s*(?P<label>[^<]*?(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\.ovpn)", row_html, flags=re.I | re.S)
        if not link:
            continue
        href = link.group("href")
        ip = link.group("ip")
        text = re.sub(r"<[^>]+>", " ", row_html)
        text = re.sub(r"\s+", " ", text).strip()
        country = "Unknown"
        uptime = 0
        ping = 0
        m = re.search(r"^\s*\d+\s+(?P<country>.+?)\s+" + re.escape(ip) + r"\.ovpn\s+(?P<uptime>\d+)\s*day\(s\)\s+(?P<ping>\d+|-)\s*ms", text, flags=re.I)
        if m:
            country = m.group("country")
            uptime = m.group("uptime")
            ping = m.group("ping")
        else:
            before = text.split(f"{ip}.ovpn", 1)[0]
            before = re.sub(r"^\s*\d+\s+", "", before).strip()
            if before:
                country = before
            tail = text.split(f"{ip}.ovpn", 1)[-1]
            m_tail = re.search(r"(?P<uptime>\d+)\s*day\(s\)\s+(?P<ping>\d+|-)\s*ms", tail, flags=re.I)
            if m_tail:
                uptime = m_tail.group("uptime")
                ping = m_tail.group("ping")
        add_row(country, href, ip, uptime, ping)

    if rows:
        return rows

    pattern = re.compile(
        r"(?P<country>[A-Za-z][A-Za-z\s]+?)\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\.ovpn\s+(?P<uptime>\d+)\s*day\(s\)\s*(?P<ping>\d+|-)?\s*ms",
        re.I,
    )
    for m in pattern.finditer(re.sub(r"<[^>]+>", " ", page_text)):
        ip = m.group("ip")
        add_row(m.group("country"), f"/ovpn/{ip}.ovpn", ip, m.group("uptime"), m.group("ping"))

    if not rows:
        for href, ip in re.findall(r"href=[\"']([^\"']*?(\d{1,3}(?:\.\d{1,3}){3})\.ovpn)[\"']", page_text, flags=re.I):
            add_row("Unknown", href, ip, 0, 0)
    return rows

def ipspeed_row_to_node(row: dict[str, Any], config_text: str) -> dict[str, Any]:
    ip = str(row.get("ip") or "")
    country_long = str(row.get("country_long") or "Unknown")
    country_short = str(row.get("country_short") or ipspeed_country_code(country_long) or "XX")
    country_short, country_zh = canonicalize_country_fields(country_short, country_long)
    text = sanitize_openvpn_config_for_eianun(config_text)
    remote_host, remote_port, proto = vpn_utils.parse_remote(text, ip)
    if not remote_host:
        remote_host = ip
    if not remote_port:
        remote_port = 443
    node_id = safe_name("_".join(["IPSPEED", country_short, ip or remote_host, str(remote_port), proto or "ovpn"]))
    config_path = CONFIG_DIR / f"{node_id}.ovpn"
    return {
        "id": node_id,
        "source": "ipspeed",
        "country": country_zh,
        "country_short": country_short,
        "host_name": ip,
        "auth_user": OPENVPN_AUTH_USER,
        "auth_pass": OPENVPN_AUTH_PASS,
        "ip": ip,
        "score": parse_int(row.get("uptime_days")),
        "ping": parse_int(row.get("ping")),
        "speed": 0,
        "sessions": 0,
        "owner": "",
        "asn": "",
        "as_name": "",
        "location": "",
        "ip_type": "",
        "quality": "",
        "fraud_score": 0,
        "clean_score": 0,
        "risk_level": "unknown",
        "fraud_flags": [],
        "risk_sources": [],
        "blacklist_hits": [],
        "blacklist_count": 0,
        "ip_clean": False,
        "latency_ms": 0,
        "config_file": str(config_path),
        "config_text": text,
        "proto": proto,
        "remote_host": remote_host,
        "remote_port": remote_port,
        "fetched_at": time.time(),
        "probe_status": "not_checked",
        "probe_message": "IPSpeed source; OpenVPN config fetched from ipspeed.info",
        "probed_at": 0,
    }

def fetch_ipspeed_candidates(target_countries: list[str], seen_keys: set[str]) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    target_display = normalize_target_countries_input(target_countries) or "全部地区"
    try:
        page_text = http_get_bytes(IPSPEED_OPENVPN_URL, timeout=18, accept="text/html,*/*").decode("utf-8", errors="replace")
        rows = parse_ipspeed_rows(page_text)
        matched = 0
        filtered = 0
        for row in rows:
            country_row = {"CountryShort": row.get("country_short", ""), "CountryLong": row.get("country_long", "")}
            if not row_matches_target_countries(country_row, target_countries):
                filtered += 1
                continue
            matched += 1
            if matched > MAX_SCAN_ROWS:
                break
            ip = str(row.get("ip") or "")
            key = f"ipspeed:{ip}"
            if not ip or key in seen_keys or ip in seen_keys:
                continue
            try:
                text = http_get_bytes(str(row.get("url")), timeout=18, accept="application/x-openvpn-profile,text/plain,*/*").decode("utf-8", errors="replace")
                if not looks_like_openvpn_config(text):
                    log_to_json("WARNING", "IPSpeed", f"下载到的配置不像 OpenVPN 文件: {row.get('url')}")
                    continue
                node = ipspeed_row_to_node(row, text)
                candidates.append(node)
                seen_keys.add(key)
            except Exception as exc:
                log_to_json("WARNING", "IPSpeed", f"下载 OpenVPN 配置失败 {ip}: {exc}")
        log_to_json("INFO", "IPSpeed", f"IPSpeed 地区过滤 {target_display}: 匹配 {matched} 行，跳过 {filtered} 行，成功 {len(candidates)} 个")
    except Exception as exc:
        log_to_json("ERROR", "IPSpeed", f"IPSpeed 节点拉取失败: {exc}")
    return candidates

def fdciabdul_row_to_node(row: dict[str, Any], config_text: str) -> dict[str, Any]:
    ip = str(row.get("ip") or "")
    country_long = str(row.get("country_long") or "Unknown")
    country_short = str(canonical_country_code(country_long) or "XX")
    country_short, country_zh = canonicalize_country_fields(country_short, country_long)
    text = sanitize_openvpn_config_for_eianun(config_text)
    remote_host, remote_port, proto = vpn_utils.parse_remote(text, ip)
    
    if not remote_host:
        remote_host = ip
    if not remote_port:
        remote_port = 443
        
    node_id = safe_name("_".join(["FDCIABDUL", country_short, ip or remote_host, str(remote_port), proto or "ovpn"]))
    config_path = CONFIG_DIR / f"{node_id}.ovpn"
    
    return {
        "id": node_id,
        "source": "fdciabdul",
        "country": country_zh,
        "country_short": country_short,
        "host_name": ip,
        "auth_user": OPENVPN_AUTH_USER,
        "auth_pass": OPENVPN_AUTH_PASS,
        "ip": ip,
        "score": 0,
        "ping": 0,
        "speed": 0,
        "sessions": 0,
        "owner": "",
        "asn": "",
        "as_name": "",
        "location": "",
        "ip_type": "",
        "quality": "",
        "fraud_score": 0,
        "clean_score": 0,
        "risk_level": "unknown",
        "fraud_flags": [],
        "risk_sources": [],
        "blacklist_hits": [],
        "blacklist_count": 0,
        "ip_clean": False,
        "latency_ms": 0,
        "config_file": str(config_path),
        "config_text": text,
        "proto": proto,
        "remote_host": remote_host,
        "remote_port": remote_port,
        "fetched_at": time.time(),
        "probe_status": "not_checked",
        "probe_message": "FDCIABDUL source; config fetched from CDN",
        "probed_at": 0,
    }

def fetch_fdciabdul_candidates(target_countries: list[str], seen_keys: set[str]) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    target_display = normalize_target_countries_input(target_countries) or "全部地区"
    cdn_mirror_url = "https://fastly.jsdelivr.net/gh/fdciabdul/Vpngate-Scraper-API@main/json/data.json"
    
    try:
        raw_data = http_get_bytes(cdn_mirror_url, timeout=20).decode('utf-8', errors='replace')
        data_list = json.loads(raw_data)
        
        matched = 0
        filtered = 0
        if isinstance(data_list, list):
            for item in data_list:
                ip = item.get("IP")
                config_b64 = item.get("OpenVPN_ConfigData_Base64")
                country_long = item.get("CountryLong", "Unknown")
                
                pseudo_row = {"CountryShort": "", "CountryLong": country_long}
                if not row_matches_target_countries(pseudo_row, target_countries):
                    filtered += 1
                    continue
                    
                matched += 1
                if matched > MAX_SCAN_ROWS:
                    break
                    
                if not ip or not config_b64:
                    continue
                    
                key = f"fdciabdul:{ip}"
                if key in seen_keys or ip in seen_keys:
                    continue
                    
                try:
                    config_text = decode_config(config_b64)
                    if not looks_like_openvpn_config(config_text):
                        continue
                        
                    node = fdciabdul_row_to_node({"country_long": country_long, "ip": ip}, config_text)
                    node["hostname"] = item.get("HostName", ip)
                    node["ping"] = int(item.get("Ping", 9999)) if item.get("Ping") else 9999
                    node["score"] = float(item.get("Score", 0)) if item.get("Score") else 0.0
                    
                    candidates.append(node)
                    seen_keys.add(key)
                    seen_keys.add(ip)
                except Exception as exc:
                    log_to_json("WARNING", "FDCIABDUL", f"解析 OpenVPN 配置失败 {ip}: {exc}")
                    
        log_to_json("INFO", "FDCIABDUL", f"FDCIABDUL 地区过滤 {target_display}: 匹配 {matched} 行，跳过 {filtered} 行，成功 {len(candidates)} 个")
    except Exception as exc:
        log_to_json("ERROR", "FDCIABDUL", f"FDCIABDUL 节点拉取失败: {exc}")
        
    return candidates
    
def fetch_candidates(target_override: list[str] | None = None) -> list[dict[str, Any]]:
    blacklist = load_blacklist()
    candidates: list[dict[str, Any]] = []
    seen_keys: set[str] = set()
    target_countries = target_override if target_override is not None else get_target_countries()
    target_display = normalize_target_countries_input(target_countries) or "全部地区"
    sources = get_node_sources()
    source_counts: dict[str, int] = {}
    for source in sources:
        before = len(candidates)
        try:
            if source == "vpngate":
                candidates.extend(fetch_vpngate_candidates(target_countries, seen_keys))
            elif source == "vpnbook":
                candidates.extend(fetch_vpnbook_candidates(target_countries, seen_keys))
            elif source == "ipspeed":
                candidates.extend(fetch_ipspeed_candidates(target_countries, seen_keys))
            elif source == "fdciabdul":
                candidates.extend(fetch_fdciabdul_candidates(target_countries, seen_keys))
        except Exception as exc:
            log_to_json("ERROR", "Main", f"节点来源 {source} 拉取失败: {exc}")
        source_counts[source] = len(candidates) - before
    set_state(
        last_fetch_at=time.time(),
        last_fetch_status="ok" if candidates else "empty",
        last_fetch_message=f"来源 {node_sources_display(','.join(sources))}，地区 {target_display}: fetched {len(candidates)} candidates. {source_counts}",
        blacklisted_nodes=len(blacklist),
        target_countries=normalize_target_countries_input(target_countries),
        target_countries_display=target_display,
        node_sources=normalize_node_sources_input(','.join(sources)),
        node_sources_display=node_sources_display(','.join(sources)),
    )
    log_to_json("INFO", "Main", f"成功获取候选节点 {len(candidates)} 个，来源 {source_counts}，地区 {target_display}")
    return candidates

def cached_nodes() -> list[dict[str, Any]]:
    return read_json(NODES_FILE, [])

_openvpn_version = None

def get_openvpn_version() -> float:
    global _openvpn_version
    if _openvpn_version is not None:
        return _openvpn_version
    try:
        cmd = shlex.split(OPENVPN_CMD, posix=False) or ["openvpn"]
        res = subprocess.run([cmd[0], "--version"], capture_output=True, text=True, timeout=2)
        match = re.search(r"OpenVPN\s+(\d+\.\d+)", res.stdout or res.stderr)
        if match:
            _openvpn_version = float(match.group(1))
            return _openvpn_version
    except Exception:
        pass
    _openvpn_version = 2.4
    return _openvpn_version

def auth_file_for_node(node: dict[str, Any] | None) -> Path:
    ensure_dirs()
    if not node:
        return AUTH_FILE
    user = str(node.get("auth_user")
