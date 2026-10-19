#!/usr/bin/env python3
"""Extrae de una copia de seguridad de iOS la credencial que la app de Segway
ya tiene para tu patinete, para que Home Assistant use LA MISMA y no haga
falta reemparejar nada.

La app guarda, por numero de serie, dos secretos en sus UserDefaults:

    {serie}_decrypt   16 bytes  contrasena de sesion (AUTH y trafico posterior)
    {serie}_ident     32 hex    token para acciones del vehiculo (cmd 0x64)

Requiere una copia de seguridad LOCAL y SIN CIFRAR hecha desde Finder
(Finder > iPhone > Gestionar copias > desmarcar "Encriptar copia local").

    python3 tools/extract_creds.py                 # busca sola la copia
    python3 tools/extract_creds.py --sn 1EFGE2513C1181
    python3 tools/extract_creds.py --plist ruta/com.ninebot.segway.plist
"""

from __future__ import annotations

import argparse
import plistlib
import sys
from pathlib import Path

BACKUP_ROOT = Path.home() / "Library/Application Support/MobileSync/Backup"
# Id estable del fichero UserDefaults de com.ninebot.segway dentro de la copia.
SEGWAY_PLIST_ID = "7fff5a30d7d67fe00bf012e2dc3a61f63c8661bd"


def find_plists() -> list[Path]:
    """Localiza el plist de Segway en las copias locales."""
    hits: list[Path] = []
    if not BACKUP_ROOT.is_dir():
        return hits
    for backup in sorted(BACKUP_ROOT.iterdir()):
        if not backup.is_dir():
            continue
        manifest = backup / "Manifest.plist"
        if manifest.is_file():
            try:
                if plistlib.loads(manifest.read_bytes()).get("IsEncrypted"):
                    print(f"  [saltada] {backup.name}: copia cifrada", file=sys.stderr)
                    continue
            except Exception:  # noqa: BLE001 - manifest ilegible, probamos igual
                pass
        candidate = backup / SEGWAY_PLIST_ID[:2] / SEGWAY_PLIST_ID
        if candidate.is_file():
            hits.append(candidate)
        else:
            # El id puede cambiar entre versiones: busca por contenido.
            hits.extend(
                p for p in backup.rglob("*")
                if p.is_file() and p.stat().st_size < 4_000_000
                and _looks_like_segway(p)
            )
    return hits


def _looks_like_segway(path: Path) -> bool:
    try:
        with path.open("rb") as fh:
            if fh.read(8) != b"bplist00":
                return False
        data = plistlib.loads(path.read_bytes())
    except Exception:  # noqa: BLE001 - no es un plist utilizable
        return False
    return isinstance(data, dict) and any(
        isinstance(k, str) and k.endswith("_decrypt") for k in data
    )


def dump(path: Path, wanted_sn: str | None) -> int:
    data = plistlib.loads(path.read_bytes())
    serials = sorted({k.rsplit("_", 1)[0] for k in data
                      if isinstance(k, str) and k.endswith(("_decrypt", "_ident"))})
    if not serials:
        print(f"{path}: sin credenciales de vehiculo", file=sys.stderr)
        return 1

    print(f"\n{path}")
    found = 0
    for sn in serials:
        if wanted_sn and sn != wanted_sn:
            continue
        password = data.get(f"{sn}_decrypt")
        ident = data.get(f"{sn}_ident")
        if isinstance(password, str):  # NSUserDefaults puede devolverlo en base64
            import base64
            password = base64.b64decode(password)
        print(f"\n  serie : {sn}")
        if isinstance(password, (bytes, bytearray)) and len(password) == 16:
            print(f"  pwd   : {bytes(password).hex()}   <-- esto va en Home Assistant")
            found += 1
        else:
            print(f"  pwd   : ausente o con formato raro ({password!r})")
        print(f"  ident : {ident if ident else '(ninguno; solo lectura)'}")
    if wanted_sn and not found:
        print(f"\nNo hay credencial para '{wanted_sn}'. Series disponibles: {serials}",
              file=sys.stderr)
        return 1
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--sn", help="numero de serie a extraer")
    parser.add_argument("--plist", type=Path, help="ruta directa al plist")
    args = parser.parse_args()

    paths = [args.plist] if args.plist else find_plists()
    if not paths:
        print("No encontre ninguna copia de iOS sin cifrar con datos de Segway.\n"
              "Haz una desde Finder > iPhone > Crear copia de seguridad ahora,\n"
              "con \"Encriptar copia local\" DESMARCADO.", file=sys.stderr)
        return 1
    return max(dump(p, args.sn) for p in paths)


if __name__ == "__main__":
    raise SystemExit(main())
