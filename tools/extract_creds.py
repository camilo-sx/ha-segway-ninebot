#!/usr/bin/env python3
"""Exporta la credencial que la app Segway Mobility ya tiene para tu patinete,
para que Home Assistant use LA MISMA y no haga falta reemparejar nada.

La app guarda, por numero de serie, dos secretos en sus UserDefaults:

    {serie}_decrypt   16 bytes  contrasena de sesion (AUTH y trafico posterior)
    {serie}_ident     32 hex    token de acciones del vehiculo (cmd 0x64)

Dos modos:

  --usb      lee el contenedor de la app por USB con house_arrest.
                 pip install pymobiledevice3
             OJO: iOS solo vende por AFC las apps con file sharing o firmadas
             para depuracion. Segway Mobility, al venir de la App Store, da
             InstallationLookupFailed en un iPhone sin jailbreak. Queda aqui
             por si una build futura lo permite, pero hoy usa --backup.

  --backup   lee una copia de seguridad LOCAL y SIN CIFRAR hecha desde Finder.
             Alternativa si house_arrest no vende el contenedor. En macOS
             necesita Acceso total al disco para el terminal.

Ejemplos:
    python3 tools/extract_creds.py --usb
    python3 tools/extract_creds.py --usb --sn 1EFGE2513C1181 --out creds.json
    python3 tools/extract_creds.py --backup
"""

from __future__ import annotations

import argparse
import base64
import json
import plistlib
import sys
from pathlib import Path

BUNDLE_ID = "com.ninebot.segway"
BACKUP_ROOT = Path.home() / "Library/Application Support/MobileSync/Backup"
# Id estable del fichero UserDefaults de com.ninebot.segway dentro de la copia.
SEGWAY_PLIST_ID = "7fff5a30d7d67fe00bf012e2dc3a61f63c8661bd"


# ---------------------------------------------------------------------------
# Interpretacion del plist
# ---------------------------------------------------------------------------

def creds_from_plist(data: dict) -> dict[str, str]:
    """Saca {clave: hex} de un UserDefaults de la app."""
    out: dict[str, str] = {}
    for key, value in data.items():
        if not isinstance(key, str) or not key.endswith(("_decrypt", "_ident")):
            continue
        if isinstance(value, str) and key.endswith("_decrypt"):
            # NSUserDefaults puede devolver el NSData ya en base64.
            try:
                value = base64.b64decode(value, validate=True)
            except Exception:  # noqa: BLE001 - entonces era texto de verdad
                pass
        out[key] = value.hex() if isinstance(value, (bytes, bytearray)) else str(value)
    return out


def looks_like_segway_prefs(blob: bytes) -> bool:
    try:
        data = plistlib.loads(blob)
    except Exception:  # noqa: BLE001 - no es un plist utilizable
        return False
    return isinstance(data, dict) and any(
        isinstance(k, str) and k.endswith("_decrypt") for k in data
    )


# ---------------------------------------------------------------------------
# Modo USB (house_arrest)
# ---------------------------------------------------------------------------

async def _read_container() -> dict[str, str]:
    from pymobiledevice3.lockdown import create_using_usbmux
    from pymobiledevice3.services.house_arrest import HouseArrestService

    lockdown = await create_using_usbmux()
    errors: list[str] = []
    # VendContainer da el contenedor entero; VendDocuments solo Documents y casi
    # nunca sirve aqui, pero se intenta por si el firmware restringe el primero.
    for documents_only in (False, True):
        label = "VendDocuments" if documents_only else "VendContainer"
        try:
            async with await HouseArrestService.create(
                lockdown, BUNDLE_ID, documents_only
            ) as afc:
                blob = await _find_prefs(afc)
                if blob is None:
                    errors.append(f"{label}: contenedor accesible, sin UserDefaults")
                    continue
                return creds_from_plist(plistlib.loads(blob))
        except Exception as err:  # noqa: BLE001 - se informa y se prueba el otro
            errors.append(f"{label}: {type(err).__name__}: {err}")
    raise SystemExit(
        "No pude leer el contenedor de la app por USB:\n  "
        + "\n  ".join(errors)
        + "\n\nComprueba que el iPhone este desbloqueado y haya confiado en este"
        "\nordenador, o usa --backup."
    )


async def _find_prefs(afc) -> bytes | None:
    """Ruta esperada primero; si no, recorre el contenedor buscando el plist."""
    direct = f"/Library/Preferences/{BUNDLE_ID}.plist"
    try:
        blob = await afc.get_file_contents(direct)
        if looks_like_segway_prefs(blob):
            return blob
    except Exception:  # noqa: BLE001 - seguimos con la busqueda amplia
        pass
    for root, _dirs, files in await _walk(afc):
        for name in files:
            if not name.endswith(".plist"):
                continue
            path = f"{root.rstrip('/')}/{name}"
            try:
                blob = await afc.get_file_contents(path)
            except Exception:  # noqa: BLE001 - fichero inaccesible
                continue
            if looks_like_segway_prefs(blob):
                print(f"  (encontrado en {path})", file=sys.stderr)
                return blob
    return None


async def _walk(afc) -> list[tuple[str, list[str], list[str]]]:
    """walk() acotado a las carpetas donde iOS guarda preferencias."""
    results = []
    pending = ["/Library", "/Documents"]
    seen = set()
    while pending:
        current = pending.pop()
        if current in seen or len(seen) > 400:  # ponytail: tope duro, no es un indexador
            continue
        seen.add(current)
        try:
            entries = await afc.listdir(current)
        except Exception:  # noqa: BLE001 - carpeta inaccesible
            continue
        dirs, files = [], []
        for entry in entries:
            if entry in (".", ".."):
                continue
            path = f"{current.rstrip('/')}/{entry}"
            try:
                (dirs if await afc.isdir(path) else files).append(entry)
            except Exception:  # noqa: BLE001
                files.append(entry)
        results.append((current, dirs, files))
        pending.extend(f"{current.rstrip('/')}/{d}" for d in dirs)
    return results


# ---------------------------------------------------------------------------
# Modo copia de seguridad
# ---------------------------------------------------------------------------

def _segway_plist_from_backup(backup: Path) -> bytes | None:
    """Localiza el plist de Segway via Manifest.db (indice SQLite del backup).

    El nombre del fichero es SHA1(dominio-rutaRelativa), distinto por app y
    version, asi que no se puede fijar. Manifest.db mapea dominio/ruta -> fileID.
    """
    import sqlite3

    mdb = backup / "Manifest.db"
    if not mdb.is_file():
        return None
    try:
        con = sqlite3.connect(f"file:{mdb}?mode=ro", uri=True)
    except sqlite3.Error:
        return None  # cifrado o ilegible
    try:
        rows = con.execute(
            "SELECT fileID, relativePath FROM Files "
            "WHERE domain LIKE 'AppDomain-com.ninebot.segway%' "
            "AND relativePath LIKE '%.plist'"
        ).fetchall()
    except sqlite3.DatabaseError:
        return None  # Manifest.db cifrado (backup encriptado)
    finally:
        con.close()
    for file_id, _rel in rows:
        blob_path = backup / file_id[:2] / file_id
        if blob_path.is_file():
            blob = blob_path.read_bytes()
            if looks_like_segway_prefs(blob):
                return blob
    return None


def _backup_domains(backup: Path) -> list[str]:
    """Dominios de app presentes en el backup (para diagnostico)."""
    import sqlite3

    mdb = backup / "Manifest.db"
    if not mdb.is_file():
        return []
    try:
        con = sqlite3.connect(f"file:{mdb}?mode=ro", uri=True)
        rows = con.execute(
            "SELECT DISTINCT domain FROM Files WHERE domain LIKE 'AppDomain-%'"
        ).fetchall()
        con.close()
    except sqlite3.Error:
        return []
    return sorted(d for (d,) in rows)


def read_from_backup(explicit: Path | None) -> dict[str, str]:
    if explicit:
        return creds_from_plist(plistlib.loads(explicit.read_bytes()))
    if not BACKUP_ROOT.is_dir():
        raise SystemExit(
            "No hay copias de iOS en este Mac. Hazla desde Finder > iPhone >\n"
            "Crear copia de seguridad ahora, con \"Encriptar copia local\" DESMARCADO."
        )
    try:
        backups = sorted(p for p in BACKUP_ROOT.iterdir() if p.is_dir())
    except PermissionError:
        raise SystemExit(
            f"macOS bloquea el acceso a {BACKUP_ROOT}.\nAjustes del Sistema > "
            "Privacidad y seguridad > Acceso total al disco > anade tu terminal."
        ) from None

    had_segway_domain = False
    for backup in backups:
        encrypted = False
        manifest = backup / "Manifest.plist"
        if manifest.is_file():
            try:
                encrypted = bool(plistlib.loads(manifest.read_bytes()).get("IsEncrypted"))
            except Exception:  # noqa: BLE001 - manifest ilegible
                pass
        blob = _segway_plist_from_backup(backup)
        if blob:
            return creds_from_plist(plistlib.loads(blob))
        domains = _backup_domains(backup)
        has_segway = any("com.ninebot.segway" in d for d in domains)
        had_segway_domain = had_segway_domain or has_segway
        state = "cifrada" if encrypted else "sin cifrar"
        print(f"  [{backup.name[:12]}…] {state}, {len(domains)} apps, "
              f"Segway {'SI' if has_segway else 'NO'} presente", file=sys.stderr)

    if had_segway_domain:
        raise SystemExit(
            "El backup contiene la app Segway pero su plist de preferencias no\n"
            "trae las credenciales. Abre la app una vez con el patinete cerca\n"
            "(que conecte), y rehaz el backup SIN cifrar."
        )
    raise SystemExit(
        "Ningun backup sin cifrar contiene datos de la app Segway.\n"
        "Si el backup salio cifrado, rehazlo con \"Encriptar copia local\" DESMARCADO.\n"
        "Si no, abre la app Segway una vez y vuelve a hacer el backup."
    )


# ---------------------------------------------------------------------------

def report(creds: dict[str, str], wanted_sn: str | None, out: Path | None) -> int:
    serials = sorted({k.rsplit("_", 1)[0] for k in creds})
    if not serials:
        print("La app no tiene credenciales de ningun vehiculo.", file=sys.stderr)
        return 1
    if wanted_sn and wanted_sn not in serials:
        print(f"No hay credencial para '{wanted_sn}'. Disponibles: {serials}",
              file=sys.stderr)
        return 1

    selected = [wanted_sn] if wanted_sn else serials
    for sn in selected:
        password = creds.get(f"{sn}_decrypt")
        ident = creds.get(f"{sn}_ident")
        print(f"\nserie : {sn}")
        if password and len(password) == 32:
            print(f"pwd   : {password}   <-- pegar en Home Assistant")
        else:
            print(f"pwd   : ausente o con formato raro ({password!r})")
        print(f"ident : {ident or '(ninguno; la integracion es de solo lectura igual)'}")

    if out:
        payload = {sn: {"password": creds.get(f"{sn}_decrypt"),
                        "ident": creds.get(f"{sn}_ident")} for sn in selected}
        out.write_text(json.dumps(payload, indent=2))
        out.chmod(0o600)
        print(f"\nGuardado en {out} (permisos 600). Es una llave de tu patinete:"
              "\nborralo cuando lo hayas pegado en Home Assistant.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--usb", action="store_true",
                        help="leer del iPhone conectado (recomendado)")
    source.add_argument("--backup", action="store_true",
                        help="leer de una copia local sin cifrar")
    parser.add_argument("--plist", type=Path, help="ruta directa a un plist ya extraido")
    parser.add_argument("--sn", help="numero de serie a exportar")
    parser.add_argument("--out", type=Path, help="volcar tambien a un JSON")
    args = parser.parse_args()

    if args.plist:
        creds = creds_from_plist(plistlib.loads(args.plist.read_bytes()))
    elif args.backup:
        creds = read_from_backup(None)
    else:
        import asyncio
        creds = asyncio.run(_read_container())
    return report(creds, args.sn, args.out)


if __name__ == "__main__":
    raise SystemExit(main())
