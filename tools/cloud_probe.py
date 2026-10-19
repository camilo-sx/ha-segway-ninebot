#!/usr/bin/env python3
"""Sonda de la API cloud de Segway-Ninebot. Solo lectura HTTP.

Responde la pregunta que bloquea la fase cloud (ver STACK_PLAN.md): ¿la nube
devuelve la contrasena de sesion BLE (y el ident) de un vehiculo emparejado?

Hace login, lista vehiculos y para cada uno consulta endpoints candidatos de
credencial -- al menos /vehicle/vehicle/vehicle-basic-info {uid, wnumber} --,
vuelca TODOS los campos descifrados y marca los que parezcan ident/contrasena
(16 bytes / 32 hex, o nombres con ident/decrypt/secret/key/pwd...).

NUNCA toca BLE ni emite SET_PWD: es solo lectura por HTTP. No rota nada.

  --user / --pass          credenciales Segway (o usa tokens.json guardados)
  --*-host                 hosts (los defaults son del backend CHINO, confirmar)
  --extra-endpoint PATH    endpoint adicional a sondear (repetible), {uid,wnumber}

Ejemplo:
  cloud_probe.py --user 600000000 --pass secreta \
      --passport-host https://... --biz-host https://... --vehicle-host https://...
"""

from __future__ import annotations

import argparse
import base64
import json
import re
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "custom_components" / "segway_ninebot"))

from cloud import api  # noqa: E402
from cloud import crypto  # noqa: E402

# Nombres de campo que delatan una credencial.
SUSPECT_NAME = re.compile(r"ident|decrypt|secret|\bkey\b|pwd|password|cipher|token|aes", re.I)
HEX32 = re.compile(r"^[0-9a-fA-F]{32}$")

# Claves por las que un vehiculo expone su numero de serie / wnumber.
WNUMBER_KEYS = ("wnumber", "sn", "serial_no", "serial_number", "vehicle_no", "deviceSn")


def _looks_like_credential(name: str, value) -> str | None:
    """Devuelve el motivo si (name, value) huele a credencial; si no, None."""
    if isinstance(name, str) and SUSPECT_NAME.search(name):
        return f"nombre coincide con {SUSPECT_NAME.pattern!r}"
    if isinstance(value, str):
        if HEX32.match(value):
            return "valor 32 hex (posible clave de 16 bytes)"
        if len(value) == 16:
            return "valor de 16 caracteres (posible clave cruda)"
        try:
            if len(base64.b64decode(value, validate=True)) == 16:
                return "valor base64 de 16 bytes"
        except ValueError:  # binascii.Error es subclase de ValueError
            pass
    return None


def _walk(obj, path=""):
    """Recorre dict/list y produce (ruta_con_puntos, nombre_hoja, valor)."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            sub = f"{path}.{k}" if path else str(k)
            if isinstance(v, (dict, list)):
                yield from _walk(v, sub)
            else:
                yield sub, k, v
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            sub = f"{path}[{i}]"
            if isinstance(v, (dict, list)):
                yield from _walk(v, sub)
            else:
                yield sub, path.rsplit(".", 1)[-1], v


def _dump_and_flag(label: str, payload) -> list[str]:
    """Imprime el payload completo y devuelve la lista de hallazgos sospechosos."""
    print(f"\n----- {label} (todos los campos) -----")
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    hits = []
    for ruta, nombre, valor in _walk(payload):
        motivo = _looks_like_credential(nombre, valor)
        if motivo:
            hits.append(f"  [!] {ruta} = {valor!r}  <- {motivo}")
    return hits


def _vehicle_wnumber(v: dict) -> str | None:
    for k in WNUMBER_KEYS:
        if v.get(k):
            return str(v[k])
    return None


def _probe_endpoint(path: str, tokens: dict, device_id: str, host: str,
                    wnumber: str) -> list[str]:
    """Consulta un endpoint de credencial con {uid, wnumber} + params comunes."""
    params = api._common_params(device_id)
    params.update({
        "access_token": tokens["access_token"],
        "uid": tokens.get("business_uid", ""),
        "wnumber": wnumber,
        "serviceTime": int(time.time() * 1000),
        "nonce": crypto.gen_nonce(),
    })
    try:
        resp = api._send_encrypted(host, path, params, device_id,
                                   access_token=tokens["access_token"], business_type=2)
    except Exception as e:  # noqa: BLE001 - la sonda reporta y sigue con el resto
        print(f"\n----- {path} -----\n  error: {e}")
        return []
    return _dump_and_flag(f"{path}  (wnumber={wnumber})", resp)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--user")
    ap.add_argument("--password", "--pass", dest="password")
    ap.add_argument("--creds-file", help="JSON {\"user\":..,\"password\":..,\"area_code\":..} "
                    "fuera del repo; evita que la contrasena salga en la lista de procesos")
    ap.add_argument("--area-code", default="86")
    ap.add_argument("--config", default=api.default_config_dir())
    ap.add_argument("--passport-host", default=api.PASSPORT_BASE)
    ap.add_argument("--biz-host", default=api.BIZ_BASE)
    ap.add_argument("--ebike-host", default=api.EBIKE_BASE, help="host de la lista de vehiculos")
    ap.add_argument("--vehicle-host", default=api.EBIKE_BASE,
                    help="host de los endpoints de credencial (confirmar para INTL)")
    ap.add_argument("--extra-endpoint", action="append", default=[],
                    help="endpoint extra a sondear con {uid, wnumber} (repetible)")
    args = ap.parse_args()

    cfg = api.load_config(args.config)
    device_id = cfg["device_id"]

    # Credenciales: preferible un fichero fuera del repo (no sale en `ps`).
    user, password, area_code = args.user, args.password, args.area_code
    if args.creds_file:
        import json
        with open(args.creds_file, encoding="utf-8") as fh:
            c = json.load(fh)
        user = c.get("user", user)
        password = c.get("password", password)
        area_code = c.get("area_code", area_code)

    # Login: credenciales explicitas o tokens guardados.
    if user and password:
        tokens = api.passport_login(user, password, area_code=area_code,
                                    base=args.passport_host)
        api.save_tokens(args.config, tokens)
        print(f"[+] passport login ok  uuid={tokens.get('uuid')}")
        api.business_login(tokens, device_id, base=args.biz_host)
        api.save_tokens(args.config, tokens)
    else:
        tokens = api.load_tokens(args.config)
        if not tokens.get("access_token"):
            print("sin credenciales y sin tokens.json: pasa --user/--pass", file=sys.stderr)
            return 2
        if not tokens.get("business_uid"):
            api.business_login(tokens, device_id, base=args.biz_host)
            api.save_tokens(args.config, tokens)
    print(f"[+] business_uid={tokens.get('business_uid')}")

    # Vehiculos: ya es util volcar sus campos (puede traer ident/ipc_id).
    lst = api.vehicles(tokens, device_id, base=args.ebike_host)
    print(f"\n[+] {len(lst)} vehiculo(s)")
    all_hits: list[str] = []
    all_hits += _dump_and_flag("my-vehicle (lista)", lst)

    # Endpoints de credencial por vehiculo.
    endpoints = ["/vehicle/vehicle/vehicle-basic-info"] + list(args.extra_endpoint)
    for v in lst:
        wnumber = _vehicle_wnumber(v) if isinstance(v, dict) else None
        if not wnumber:
            print(f"\n[!] vehiculo sin wnumber reconocible, salto: {v}")
            continue
        for path in endpoints:
            all_hits += _probe_endpoint(path, tokens, device_id, args.vehicle_host, wnumber)

    print("\n========================================")
    if all_hits:
        print(f"CAMPOS SOSPECHOSOS DE CREDENCIAL ({len(all_hits)}):")
        print("\n".join(all_hits))
        print("\n-> Revisa si alguno es la contrasena de sesion BLE (16 bytes) o el ident.")
    else:
        print("Ningun campo con pinta de ident/contrasena en lo sondeado.")
        print("-> Probablemente la nube solo sirve para listar vehiculos (ver STACK_PLAN).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
