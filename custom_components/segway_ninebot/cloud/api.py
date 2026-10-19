"""Cliente de la API cloud de Segway-Ninebot (passport + business).

Port de ninebot-recon (MIT, (c) 2026 kxn), https://github.com/kxn/ninebot-recon
(ninebot_api.py). Se toma solo login/refresh/business/vehicles; viajes y CLI
quedan fuera. Ver NOTICE en la raiz.

Cadena: passport login (texto plano + Sign sha256) -> business login (capa
cifrada) -> vehicles (peticion cifrada / respuesta descifrada).

AVISO INTL: los hosts y versiones por defecto salen del backend CHINO
(九号出行, *-bj.ninebot.com). El usuario objetivo usa la app internacional
(com.ninebot.segway), cuyos hosts casi seguro difieren. Por eso toda funcion de
red acepta el host como parametro: los defaults son solo un punto de partida.
"""
import hashlib
import json
import os
import secrets
import time
import urllib.error
import urllib.request
from pathlib import Path

from . import crypto

# ---------------------------------------------------------------------------
# Hosts (backend chino; parametrizables en cada funcion)
# ---------------------------------------------------------------------------

PASSPORT_BASE = "https://api-passport-bj.ninebot.com"   # INTL: confirmar
BIZ_BASE = "https://api-jhcx-v6-bj.ninebot.com"         # INTL: confirmar
EBIKE_BASE = "https://ebike.ninebot.com"                # INTL: confirmar

CLIENT_VER = "610063322"          # Client-Ver / client_ver / current_version
APP_VERSION = "610063322"
OS_VERSION = "13"
OS_MODEL = "Xiaomi"
PLATFORM_VER = "13 Xiaomi"        # os_version + " " + os_model
RN_VERSION = "743"
CLIENT_KEY = "e177176a-3b3e-1513-e26e-d1123034cb66"     # clientKey del passport  # INTL: confirmar

PATH_PASSPORT_LOGIN = "/v6/user/login"
PATH_PASSPORT_REFRESH = "/v3/user/refresh"
PATH_BIZ_LOGIN = "/user/user/login"
PATH_VEHICLES = "/vehicle/binding/my-vehicle"

# Parametros comunes (los 11 primeros campos, identicos en login/vehicles segun captura)
COMMON_PARAMS = [
    ("sys_language", "zh-hans-cn"),
    ("client_ver", CLIENT_VER),
    ("device_id", None),          # se rellena con config
    ("regionx", "bj"),
    ("language", "zh"),
    ("ostype", "and"),
    ("lang", "zh"),
    ("platform_ver", PLATFORM_VER),
    ("platform", "android"),
    ("login_country", "CN"),
]


# ---------------------------------------------------------------------------
# Config / tokens (compatible con config.json / tokens.json de ninecli)
# ---------------------------------------------------------------------------

def default_config_dir():
    return os.environ.get("NINEBOT_CONFIG_DIR", str(Path.home() / ".config" / "ninebot"))


def load_json(path, default=None):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return default if default is not None else {}


def save_json(path, obj):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)


def load_config(config_dir):
    cfg = load_json(Path(config_dir) / "config.json")
    if not cfg.get("device_id"):
        cfg["device_id"] = secrets.token_hex(16)
        save_json(Path(config_dir) / "config.json", cfg)
    return cfg


def load_tokens(config_dir):
    return load_json(Path(config_dir) / "tokens.json")


def save_tokens(config_dir, tokens):
    tokens["saved_at"] = int(time.time())
    save_json(Path(config_dir) / "tokens.json", tokens)


# ---------------------------------------------------------------------------
# Passport (texto plano + Sign)
# ---------------------------------------------------------------------------

def passport_sign(url: str, params: dict) -> str:
    """PassportSign: sha256 del canonical ordenado k=v&k=v (anade clientKey)."""
    params = dict(params)
    params["clientKey"] = CLIENT_KEY
    params["url"] = url
    canonical = "&".join(f"{k}={v}" for k, v in sorted(params.items()))
    return hashlib.sha256(canonical.encode()).hexdigest()


def _passport_post(base, path, body: dict, extra_headers=None) -> dict:
    url = base.rstrip("/") + path
    headers = {
        "App_version": APP_VERSION,
        "Clientid": "vehicle_app_prod",
        "Content-Type": "application/json; charset=UTF-8",
        "Os": "Android",
        "Os_language": "zh-hans-cn",
        "Os_version": OS_VERSION,
        "Accept-Encoding": "gzip",
    }
    if extra_headers:
        headers.update(extra_headers)
    req = urllib.request.Request(url, data=json.dumps(body, separators=(",", ":")).encode(),
                                 headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode("utf-8"))


def passport_login(username: str, password: str, area_code="86",
                   device="ANDROID", base=PASSPORT_BASE) -> dict:
    """Login por contrasena -> {access_token, refresh_token, uuid, ...}."""
    ts = int(time.time() * 1000)
    body = {"areaCode": area_code, "device": device, "password": password, "username": username}
    sign_params = {
        "app_version": APP_VERSION, "areaCode": area_code, "device": device,
        "os": "Android", "os_language": "zh-hans-cn", "os_version": OS_VERSION,
        "password": password, "timestamp": str(ts), "url": PATH_PASSPORT_LOGIN,
        "username": username,
    }
    headers = {
        "Timestamp": str(ts),
        "Sign": passport_sign(PATH_PASSPORT_LOGIN, sign_params),
    }
    resp = _passport_post(base, PATH_PASSPORT_LOGIN, body, headers)
    if resp.get("code") != 0:
        raise RuntimeError(f"passport login failed: code={resp.get('code')} msg={resp.get('msg')}")
    data = resp.get("data") or {}
    if not data.get("access_token"):
        raise RuntimeError(f"passport login: missing access_token in response: {resp}")
    return {
        "uuid": data.get("uuid", ""),
        "username": username,
        "phone": data.get("phone", ""),
        "region": data.get("region", ""),
        "areaCode": area_code,
        "access_token": data["access_token"],
        "refresh_token": data.get("refresh_token", ""),
        "accessTokenValidity": str(data.get("accessTokenValidity", "")),
    }


def passport_refresh(tokens: dict, base=PASSPORT_BASE) -> dict:
    """Refresco de token (POST /v3/user/refresh)."""
    ts = int(time.time() * 1000)
    body = {"accessToken": tokens["access_token"], "device": "ANDROID",
            "refreshToken": tokens["refresh_token"]}
    sign_params = {
        "accessToken": body["accessToken"], "app_version": APP_VERSION, "device": "ANDROID",
        "os": "Android", "os_language": "zh-hans-cn", "os_version": OS_VERSION,
        "refreshToken": body["refreshToken"], "timestamp": str(ts), "url": PATH_PASSPORT_REFRESH,
    }
    headers = {
        "Timestamp": str(ts),
        "Sign": passport_sign(PATH_PASSPORT_REFRESH, sign_params),
    }
    resp = _passport_post(base, PATH_PASSPORT_REFRESH, body, headers)
    if resp.get("code") != 0:
        raise RuntimeError(f"passport refresh failed: code={resp.get('code')} desc={resp.get('desc')}")
    data = resp.get("data") or {}
    tokens = dict(tokens)
    tokens["access_token"] = data.get("access_token", tokens["access_token"])
    tokens["refresh_token"] = data.get("refresh_token", tokens["refresh_token"])
    if data.get("accessTokenValidity"):
        tokens["accessTokenValidity"] = str(data["accessTokenValidity"])
    return tokens


def tokens_valid(tokens: dict) -> bool:
    """accessTokenValidity es un timestamp absoluto en ms; margen de 60 s."""
    if not tokens or not tokens.get("access_token"):
        return False
    try:
        expiry = int(tokens.get("accessTokenValidity", 0))
    except ValueError:
        return False
    if not expiry:
        return False
    return expiry / 1000.0 > time.time() + 60


# ---------------------------------------------------------------------------
# Business (capa cifrada)
# ---------------------------------------------------------------------------

def _business_headers(access_token: str = None, business_type=0, extra=None) -> dict:
    h = {
        "User-Agent": "okhttp/4.9.1",
        "Accept-Encoding": "gzip",
        "Business-Type": str(business_type),
        "Cache-Control": "no-cache",
        "Client-Ver": CLIENT_VER,
        "Content-Type": "text/html;charset=UTF-8",
        "Debug": "0",
        "Device-Id": None,          # lo rellena el llamante con config.device_id
        "Language": "zh",
        "Login-Country": "CN",
        "Need_decrypt": "1",
        "Ninebot-Version": "2",
        "Platform": "Android",
        "Platform-Ver": OS_VERSION,
        "Regionx": "bj",
        "Request-Id": secrets.token_hex(16),
        "Service-Time": str(int(time.time() * 1000)),
        "Sys-Language": "zh-hans-cn",
    }
    if access_token:
        h["Access_token"] = access_token
        h["Accept"] = "application/json"
        h["Rn-Module"] = "Track"
        h["Rn-Ver"] = RN_VERSION
        h["Rn-Version"] = "0"
    if extra:
        h.update(extra)
    return h


def _common_params(device_id: str) -> dict:
    return dict((k, (v if v is not None else device_id)) for k, v in COMMON_PARAMS)


def _send_encrypted(host, path, inner_params: dict, device_id: str,
                    access_token=None, business_type=0, timeout=60) -> dict:
    """Cifra la peticion, la envia y descifra la respuesta -> JSON interno ({code, data, ...})."""
    inner = crypto.build_inner(inner_params)
    body, sec = crypto.build_request(inner.encode())
    headers = _business_headers(access_token, business_type)
    headers["Device-Id"] = device_id
    req = urllib.request.Request(host.rstrip("/") + path,
                                 data=json.dumps(body, separators=(",", ":")).encode(),
                                 headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"business {path}: HTTP {e.code}: {e.read()[:200]}")
    try:
        outer = json.loads(raw.decode("utf-8"))
    except ValueError:
        raise RuntimeError(f"business {path}: respuesta no JSON: {raw[:200]!r}")
    if not isinstance(outer, dict) or not isinstance(outer.get("r"), str) or not outer["r"]:
        raise RuntimeError(f"business {path}: respuesta sin campo r: {raw[:200]!r}")
    plain = crypto.decrypt_wire_response(outer, sec)
    try:
        return json.loads(plain.decode("utf-8"))
    except ValueError:
        raise RuntimeError(f"business {path}: descifrado no JSON: {plain[:200]!r}")


def business_login(tokens: dict, device_id: str, base=BIZ_BASE, region="bj") -> str:
    """Login business -> business_uid (lo escribe en tokens y lo devuelve)."""
    now_ms = int(time.time() * 1000)
    params = _common_params(device_id)
    params.update({
        "access_token": tokens["access_token"],
        "uuid": tokens.get("uuid", ""),
        "token": tokens["access_token"],
        "refresh_token": tokens.get("refresh_token", ""),
        "region": region,
        "serviceTime": now_ms,
        "nonce": crypto.gen_nonce(),
    })
    resp = _send_encrypted(base, PATH_BIZ_LOGIN, params, device_id, business_type=0)
    if resp.get("code") != 0:
        raise RuntimeError(f"business_login: server code={resp.get('code')} message={resp.get('message')!r}")
    data = resp.get("data")
    if not isinstance(data, dict):
        raise RuntimeError("business_login: missing data field in response")
    uid = data.get("uid")
    if not uid:
        raise RuntimeError("business_login: missing uid in response data")
    tokens["business_uid"] = str(uid)
    return str(uid)


def vehicles(tokens: dict, device_id: str, base=EBIKE_BASE,
             vehicle_type="64", timeout=60) -> list:
    """Lista de vehiculos (dicts con wnumber, etc.). vehicle_type=64 es el valor de captura."""
    now_ms = int(time.time() * 1000)
    params = _common_params(device_id)
    params.update({
        "access_token": tokens["access_token"],
        "uid": tokens.get("business_uid", ""),
        "vehicle_type": vehicle_type,
        "serviceTime": now_ms,
        "nonce": crypto.gen_nonce(),
    })
    resp = _send_encrypted(base, PATH_VEHICLES, params, device_id,
                           access_token=tokens["access_token"], business_type=2, timeout=timeout)
    if resp.get("code") != 0:
        raise RuntimeError(f"vehicles: server code={resp.get('code')} message={resp.get('message')!r}")
    data = resp.get("data")
    if isinstance(data, dict):
        return data.get("vehicles") or data.get("list") or []
    if isinstance(data, list):
        return data
    return []


# ---------------------------------------------------------------------------
# Orquestacion de login
# ---------------------------------------------------------------------------

def ensure_login(config_dir=None, username=None, password=None, **hosts) -> dict:
    """Asegura un token usable; hace passport + business login si hace falta.

    Devuelve tokens (con business_uid). hosts admite claves passport / biz.
    """
    config_dir = config_dir or default_config_dir()
    cfg = load_config(config_dir)
    tokens = load_tokens(config_dir)
    if tokens_valid(tokens) and tokens.get("business_uid"):
        return tokens
    if not tokens_valid(tokens) and username and password:
        tokens = passport_login(username, password, base=hosts.get("passport", PASSPORT_BASE))
        save_tokens(config_dir, tokens)
    if not tokens_valid(tokens):
        raise RuntimeError("token ausente o caducado: inicia sesion primero (usuario/contrasena)")
    if not tokens.get("business_uid"):
        business_login(tokens, cfg["device_id"], base=hosts.get("biz", BIZ_BASE))
        save_tokens(config_dir, tokens)
    return tokens
