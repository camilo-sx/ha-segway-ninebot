"""Verifica que decode_capture recupera la contrasena de un SET_PWD capturado.

Usa el auth_param y la respuesta PRE_COMM REALES del patinete 1EFGE2513C1181
(captura del 2026-10-18) y sintetiza un SET_PWD con una contrasena conocida,
cifrado como lo haria la app. El decoder debe sacarla de entre bytes de ruido.
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "custom_components" / "segway_ninebot"))
sys.path.insert(0, str(ROOT / "tools"))

from nb import protocol as proto
from nb.crypto import FW_DATA, NbCrypto
import decode_capture as dc

NAME = "1EFGE2513C1181"
# Respuesta PRE_COMM real (no-SN); contiene auth=1a17...3771 + serie.
REAL_PRE_COMM = bytes.fromhex(
    "5aa51eab6a0d4a3612914dd27214177c119e558122613a1d409237ccdf5fae65729f9d97650000cef60000"
)
AUTH = bytes.fromhex("1a17453d5b9f7e882a2030f92e763771")
SECRET_PWD = bytes.fromhex("00112233445566778899aabbccddeeff")


def _build_set_pwd_wire(name: str, auth: bytes, pwd: bytes) -> bytes:
    """Cifra un SET_PWD como lo manda la app (modo SN, key=SHA1(name||auth))."""
    crypto = NbCrypto(ecb_input=FW_DATA)
    crypto.set_auth_param(auth)
    crypto.start_sn()
    crypto.set_key(name.encode(), auth)
    # Trama en claro app->BLE(0x04): 5A A5 LEN 3E 04 5C 00 + pwd(16)
    plain = bytes([proto.SYNC1, proto.SYNC2[2], len(pwd), proto.BT_ID,
                   proto.BOARD_BLE, dc.CMD_SET_PWD, 0x00]) + pwd
    return crypto.encrypt(plain)


def test_auth_recovered_from_real_precomm():
    frames = dc._candidate_frames(REAL_PRE_COMM)
    assert dc._recover_auth(frames, NAME, 2) == AUTH


def test_password_recovered_from_synthetic_setpwd():
    set_pwd_wire = _build_set_pwd_wire(NAME, AUTH, SECRET_PWD)
    # Captura simulada: ruido + PRE_COMM + ruido + SET_PWD + ruido.
    blob = (b"\xde\xad\xbe\xef" * 7 + REAL_PRE_COMM + b"\x00\x11" * 13
            + set_pwd_wire + b"\xff" * 9)
    frames = dc._candidate_frames(blob)
    auth = dc._recover_auth(frames, NAME, 2)
    assert auth == AUTH
    assert dc._recover_password(frames, NAME, auth, 2) == SECRET_PWD


def test_wrong_name_recovers_nothing():
    blob = REAL_PRE_COMM
    assert dc._recover_auth(dc._candidate_frames(blob), "NOMBREMALO1234", 2) is None


if __name__ == "__main__":
    failures = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"  ok    {name}")
            except AssertionError as err:
                failures += 1
                print(f"  FALLO {name}: {err}")
    print(f"\n{failures} fallos")
    raise SystemExit(1 if failures else 0)
