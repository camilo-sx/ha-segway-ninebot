"""Prueba el camino de lectura del cliente contra un patinete simulado.

Verifica, sin BLE real, que: la allowlist deja pasar el READ, el cliente cifra
la peticion, descifra la respuesta del patinete, la parsea y aplica el decoder
y la escala correctos. Es el eslabon que convierte bytes del patinete en el
valor que ve Home Assistant.
"""

import asyncio
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "custom_components" / "segway_ninebot"))

from nb import protocol as proto
from nb.client import ForbiddenCommand, NinebotF3Client
from nb.crypto import FW_DATA, NbCrypto

NAME = "1EFGE2513C1181"
AUTH = bytes.fromhex("1a17453d5b9f7e882a2030f92e763771")
PASSWORD = bytes(range(16))


def _session_crypto() -> NbCrypto:
    c = NbCrypto(ecb_input=FW_DATA)
    c.set_auth_param(AUTH)
    c.start_sn()
    c.set_key(PASSWORD, AUTH)
    return c


class _FakeScooter:
    """Responde a un READ con la respuesta cifrada que daria el patinete."""

    def __init__(self, reg: proto.Reg, raw: bytes) -> None:
        self._reg, self._raw = reg, raw
        self._dev = _session_crypto()  # lado dispositivo
        self.sent: list[bytes] = []

    async def send(self, data: bytes) -> None:
        self.sent.append(data)

    async def recv(self, timeout: float = 3.0) -> bytes:
        board = 0x09 if self._reg.board == "vcu" else 0x02
        # Respuesta device->app: [5A A5 LEN board 3E READ_RESP index data]
        plain = bytes([proto.SYNC1, proto.SYNC2[2], len(self._raw), board,
                       proto.BT_ID, proto.CMD_READ_RESP, self._reg.index]) + self._raw
        return self._dev.encrypt(plain)


def _read(reg_key: str, raw: bytes):
    reg = proto.REGISTERS_BY_KEY[reg_key]
    client = NinebotF3Client(NAME, PASSWORD)
    scooter = _FakeScooter(reg, raw)
    return asyncio.run(client._read(scooter, _session_crypto(), reg))


def test_battery_percent():
    assert _read("battery", bytes([80, 0])) == 80


def test_speed_scaled_0_1():
    # 150 * 0.1 = 15.0 km/h
    assert _read("speed", bytes([150, 0])) == 15.0


def test_total_mileage_u32_meters_to_km():
    # 123456 m * 0.001 = 123.456 km
    assert _read("total_mileage", (123456).to_bytes(4, "little")) == 123.456


def test_bms_current_signed_negative():
    # -200 * 0.01 = -2.0 A (regen)
    raw = (-200 & 0xFFFF).to_bytes(2, "little")
    assert _read("bms1_current", raw) == -2.0


def test_serial_number_ascii():
    assert _read("serial_number", NAME.encode()) == NAME


def test_read_blocks_non_read_commands():
    # _send debe rechazar cualquier trama que no sea de lectura.
    client = NinebotF3Client(NAME, PASSWORD)
    bad = proto.build(proto.BOARD_VCU, proto.CMD_WRITE_NR, 0x5B, b"\x01\x00")

    class _Spy:
        sent = []
        async def send(self, d): self.sent.append(d)

    spy = _Spy()
    try:
        asyncio.run(NinebotF3Client._send(spy, _session_crypto(), bad))
    except ForbiddenCommand:
        pass
    else:
        raise AssertionError("dejo pasar una escritura")
    assert spy.sent == []


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
