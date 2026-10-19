"""Comprobacion contra una captura real de un F3 Pro.

Se ejecuta sin framework:  python3 tests/test_protocol.py

La trama de abajo es la respuesta PRE_COMM real del patinete con serie
1EFGE2513C1181, capturada por BLE el 2026-10-18. Si el cifrado, el formato de
trama o el parser se rompen, este fichero falla.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "custom_components" / "ninebot_f3"))

from nb import protocol as proto
from nb.crypto import FW_DATA, NbCrypto, derive_key

SERIAL = "1EFGE2513C1181"
PRE_COMM_RESPONSE = bytes.fromhex(
    "5aa51eab6a0d4a3612914dd27214177c119e558122613a1d409237ccdf5fae65729f9d97650000cef60000"
)
EXPECTED_AUTH = bytes.fromhex("1a17453d5b9f7e882a2030f92e763771")


def _fresh_crypto() -> NbCrypto:
    crypto = NbCrypto(ecb_input=FW_DATA)
    crypto.reset_sn()
    crypto.set_key(SERIAL.encode(), FW_DATA)
    return crypto


def test_frame_length_matches_header():
    assert len(PRE_COMM_RESPONSE) == PRE_COMM_RESPONSE[2] + 13


def test_real_pre_comm_response_decrypts():
    plain, rc = _fresh_crypto().decrypt(PRE_COMM_RESPONSE)
    assert rc == 0, f"checksum invalido (rc={rc})"
    frame = proto.parse(plain)
    assert frame is not None
    assert frame.board == proto.BOARD_BLE
    assert frame.cmd == proto.CMD_PRE_COMM
    assert frame.index == 1, "el patinete deberia tener contrasena guardada"
    assert frame.data[0:16] == EXPECTED_AUTH
    assert proto.ascii_sn(frame.data[16:30]) == SERIAL


def test_wrong_key_is_rejected():
    """Con otra clave el checksum debe fallar: es lo que detecta un nombre malo."""
    crypto = NbCrypto(ecb_input=FW_DATA)
    crypto.reset_sn()
    crypto.set_key(b"OTRONOMBRE1234", FW_DATA)
    _plain, rc = crypto.decrypt(PRE_COMM_RESPONSE)
    assert rc != 0


def test_pre_comm_request_layout():
    assert proto.build_pre_comm(2) == bytes([0x5A, 0xA5, 0x00, 0x3E, 0x04, 0x5B, 0x00])
    assert proto.build_pre_comm(3) == bytes([0x5A, 0xB5, 0x00, 0x3E, 0x04, 0x5B, 0x00])


def test_read_request_layout():
    # Leer 14 bytes del registro rSN (0x10) en la VCU.
    assert proto.build_read(proto.BOARD_VCU, 0x10, 14, 2) == bytes(
        [0x5A, 0xA5, 0x01, 0x3E, 0x09, 0x01, 0x10, 0x0E]
    )


def test_sn_mode_roundtrip():
    """El trafico posterior al AUTH va en modo SN con contador creciente."""
    auth, password = EXPECTED_AUTH, bytes(range(16))
    tx, rx = NbCrypto(ecb_input=FW_DATA), NbCrypto(ecb_input=FW_DATA)
    for crypto in (tx, rx):
        crypto.set_auth_param(auth)
        crypto.start_sn()
        crypto.set_key(password, auth)
    frame = proto.build_read(proto.BOARD_VCU, 0x55, 2, 2)
    plain, rc = rx.decrypt(tx.encrypt(frame))
    assert rc == 0 and plain == frame


def test_key_derivation_is_sha1_truncated():
    import hashlib
    expected = hashlib.sha1(SERIAL.encode().ljust(16, b"\0") + FW_DATA).digest()[:16]
    assert derive_key(SERIAL.encode(), FW_DATA) == expected


def test_set_pwd_has_no_builder():
    """La garantia de convivencia con la app es estructural: el codigo no
    puede construir SET_PWD, que es lo unico que rotaria la contrasena."""
    assert not hasattr(proto, "build_set_pwd")
    assert proto.CMD_SET_PWD_FORBIDDEN not in proto.ALLOWED_CMDS


def test_allowlist_is_read_only():
    assert proto.ALLOWED_CMDS == frozenset(
        {proto.CMD_PRE_COMM, proto.CMD_AUTH, proto.CMD_READ}
    )
    for forbidden in (proto.CMD_WRITE, proto.CMD_WRITE_NR, 0x64, 0x80):
        assert forbidden not in proto.ALLOWED_CMDS


def test_client_blocks_forbidden_commands():
    """_send rechaza antes de cifrar cualquier trama que no sea de lectura."""
    import asyncio
    from nb.client import ForbiddenCommand, NinebotF3Client

    crypto = NbCrypto(ecb_input=FW_DATA)
    crypto.set_key(SERIAL.encode(), FW_DATA)

    class _Spy:
        sent = []
        async def send(self, data): self.sent.append(data)

    spy = _Spy()
    # Una escritura al registro de luces: bien formada, y aun asi bloqueada.
    write_frame = proto.build(proto.BOARD_VCU, proto.CMD_WRITE_NR, 0x5B, b"\x01\x00")
    try:
        asyncio.run(NinebotF3Client._send(spy, crypto, write_frame))
    except ForbiddenCommand:
        pass
    else:
        raise AssertionError("se dejo pasar una escritura")
    assert spy.sent == [], "no debe salir nada al patinete"

    # Una lectura legitima si pasa.
    asyncio.run(NinebotF3Client._send(
        spy, crypto, proto.build_read(proto.BOARD_VCU, 0x55, 2)))
    assert len(spy.sent) == 1


def test_decoders():
    assert proto.u16(b"\x34\x12") == 0x1234
    assert proto.s16(b"\xff\xff") == -1
    assert proto.u32(b"\x01\x00\x00\x00") == 1
    assert proto.bms_temps(b"\x2d\x2e\x00\x00") == 26.0  # 0x2E - 20
    assert proto.ascii_sn(b"ABC\x00\x00") == "ABC"


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
