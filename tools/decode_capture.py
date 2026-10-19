#!/usr/bin/env python3
"""Recupera la contrasena de sesion BLE de una captura de un re-emparejamiento.

Idea: cuando la app empareja (o re-empareja) un patinete, envia el comando
SET_PWD (0x5C) con la contrasena de 16 bytes, cifrado en modo SN con una clave
que SI sabemos derivar: SHA-1(nombreBLE || auth_param), y el auth_param viaja en
claro-derivable en la respuesta PRE_COMM de la misma captura. Asi que de una
captura HCI del re-emparejamiento sacamos la contrasena SIN romper la app: la
contrasena la pone la app, nosotros solo la leemos.

No envia nada; solo lee un fichero de captura (pcapng/pklg/raw: da igual, se
escanean los bytes buscando las tramas Encryption2).

  python3 tools/decode_capture.py <captura> --name <numeroSerieBLE>

ponytail: escaneo de bytes por el sync 5AA5/5AB5 en vez de disecar HCI->L2CAP->
ATT. Con MTU alto cada trama del handshake cabe en un paquete, asi que no hace
falta reensamblar fragmentos. Si una trama viniera partida, subir a un parser
ATT (scapy) seria el siguiente paso.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "custom_components" / "segway_ninebot"))

from nb import protocol as proto
from nb.crypto import FW_DATA, NbCrypto

CMD_SET_PWD = 0x5C  # no lo emitimos; solo lo reconocemos en la captura


def _candidate_frames(blob: bytes) -> list[bytes]:
    """Todas las ventanas que empiezan por un sync valido y cuadran en longitud."""
    out, seen = [], set()
    for i in range(len(blob) - 2):
        if blob[i] != proto.SYNC1 or blob[i + 1] not in proto.VALID_SYNC2:
            continue
        total = blob[i + 2] + 13  # LEN + cabecera(3) + tag(4) + contador(2) ... = LEN+13
        if 13 <= total <= 43 and i + total <= len(blob):
            frame = blob[i : i + total]
            if frame not in seen:
                seen.add(frame)
                out.append(frame)
    return out


def _recover_auth(frames: list[bytes], name: str, gen: int) -> bytes | None:
    """Descifra la respuesta PRE_COMM (no-SN) y devuelve el auth_param."""
    crypto = NbCrypto(ecb_input=FW_DATA if gen == 2 else b"\x00" * 16)
    crypto.reset_sn()
    crypto.set_key(name.encode(), FW_DATA if gen == 2 else None)
    for frame in frames:
        try:
            plain, rc = crypto.decrypt(frame)
        except Exception:  # noqa: BLE001 - candidato que no era una trama
            continue
        f = proto.parse(plain)
        if rc == 0 and f and f.cmd == proto.CMD_PRE_COMM and len(f.data) >= 30:
            return bytes(f.data[0:16])
    return None


def _recover_password(frames: list[bytes], name: str, auth: bytes, gen: int) -> bytes | None:
    """Descifra el SET_PWD (modo SN, key=SHA1(name||auth)) -> 16 bytes."""
    for frame in frames:
        crypto = NbCrypto(ecb_input=FW_DATA if gen == 2 else b"\x00" * 16)
        crypto.set_auth_param(auth)
        crypto.start_sn()
        crypto.set_key(name.encode(), auth)
        try:
            plain, rc = crypto.decrypt(frame)
        except Exception:  # noqa: BLE001
            continue
        # SET_PWD es una PETICION (app->placa): [5A A5 LEN 3E target 5C idx pwd].
        # proto.parse() valida respuestas (byte[4]==0x3E), no peticiones, asi que
        # se lee el layout de peticion a mano.
        if (rc == 0 and len(plain) >= 23 and plain[3] == proto.BT_ID
                and plain[5] == CMD_SET_PWD and plain[2] >= 16):
            return bytes(plain[7:23])
    return None


def decode(blob: bytes, name: str) -> int:
    for gen in (2, 3):
        frames = _candidate_frames(blob)
        auth = _recover_auth(frames, name, gen)
        if auth is None:
            continue
        print(f"[+] gen{gen}: PRE_COMM descifrado, auth={auth.hex()}")
        pwd = _recover_password(frames, name, auth, gen)
        if pwd:
            print(f"\n[✓] CONTRASENA DE SESION = {pwd.hex()}")
            print("    Pegala en Home Assistant (campo 'Contrasena de sesion').")
            print("    La app sigue funcionando: es la misma que acaba de poner.")
            return 0
        print("[!] auth recuperado pero sin SET_PWD en la captura.")
        print("    Asegurate de capturar DURANTE el re-emparejamiento (borra el")
        print("    patinete en la app y vuelve a anadirlo mientras se graba).")
        return 1
    print("[!] No se encontro una respuesta PRE_COMM descifrable.", file=sys.stderr)
    print(f"    Verifica el --name (debe ser el serie/nombre BLE exacto: {name!r}).",
          file=sys.stderr)
    print(f"    Tramas candidatas halladas: {len(_candidate_frames(blob))}", file=sys.stderr)
    return 2


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("capture", type=Path, help="fichero de captura (pcapng/pklg/raw)")
    ap.add_argument("--name", required=True, help="numero de serie / nombre BLE del patinete")
    args = ap.parse_args()
    return decode(args.capture.read_bytes(), args.name)


if __name__ == "__main__":
    raise SystemExit(main())
