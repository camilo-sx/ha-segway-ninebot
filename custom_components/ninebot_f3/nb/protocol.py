"""Tramas Encryption2 y mapa de registros del Ninebot KickScooter F3 / F3 Pro.

El mapa viene de la configuracion del propio modelo en la app Segway-Ninebot
(familia `eKickScooter F3`, hardware id 259, ble_protocol=2, encrypt=2), tal y
como la documenta el proyecto segway-ninebot-ble. A diferencia de los F-series
antiguos, el F3 no expone la placa `dis`: los datos de marcha viven en `vcu`.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

SYNC1 = 0x5A
SYNC2 = {2: 0xA5, 3: 0xB5}  # gen2 / gen3; el F3 declara ble_protocol=2
VALID_SYNC2 = set(SYNC2.values())
BT_ID = 0x3E  # origen: telefono por BLE

# Placas (sendId). `vcu` no esta confirmado contra hardware real: la app lo
# direcciona como ECU/VCU 0x09, pero algunos kickscooters responden en 0x20.
# ponytail: un solo candidato por defecto; probe_f3.py prueba los alternativos.
BOARD_MCU = 0x02
BOARD_BLE = 0x04
BOARD_BMS2 = 0x06
BOARD_BMS1 = 0x07
BOARD_VCU = 0x09
VCU_CANDIDATES = (0x09, 0x20, 0x01, 0x02)

CMD_READ = 0x01
CMD_WRITE = 0x02
CMD_WRITE_NR = 0x03
CMD_READ_RESP = 0x04
CMD_WRITE_RESP = 0x05

CMD_PRE_COMM = 0x5B
CMD_SET_PWD = 0x5C
CMD_AUTH = 0x5D


@dataclass(frozen=True)
class Frame:
    length: int
    board: int
    cmd: int
    index: int
    data: bytes


def build(target: int, cmd: int, index: int, data: bytes = b"", gen: int = 2) -> bytes:
    """Trama en claro App -> vehiculo, antes de cifrar."""
    if len(data) > 255:
        raise ValueError(f"payload demasiado largo: {len(data)}")
    return bytes([SYNC1, SYNC2[gen], len(data), BT_ID, target, cmd, index]) + data


def parse(decrypted: bytes) -> Frame | None:
    """Trama en claro vehiculo -> App, despues de descifrar."""
    if len(decrypted) < 7:
        return None
    if decrypted[0] != SYNC1 or decrypted[1] not in VALID_SYNC2 or decrypted[4] != BT_ID:
        return None
    length = decrypted[2]
    return Frame(length, decrypted[3], decrypted[5], decrypted[6], decrypted[7 : 7 + length])


def build_pre_comm(gen: int = 2) -> bytes:
    return build(BOARD_BLE, CMD_PRE_COMM, 0x00, b"", gen)


def build_set_pwd(password: bytes, gen: int = 2) -> bytes:
    return build(BOARD_BLE, CMD_SET_PWD, 0x00, password[:16], gen)


def build_auth(sn: bytes, gen: int = 2) -> bytes:
    return build(BOARD_BLE, CMD_AUTH, 0x00, sn[:14], gen)


def build_read(target: int, index: int, read_len: int = 2, gen: int = 2) -> bytes:
    return build(target, CMD_READ, index, bytes([read_len]), gen)


# --------------------------------------------------------------------------
# Decodificadores
# --------------------------------------------------------------------------

def u16(data: bytes) -> int:
    return struct.unpack("<H", data[:2])[0]


def s16(data: bytes) -> int:
    return struct.unpack("<h", data[:2])[0]


def u32(data: bytes) -> int:
    return struct.unpack("<I", data[:4])[0]


def ascii_sn(data: bytes) -> str:
    return data.split(b"\x00")[0].decode("ascii", "replace").strip()


def version(data: bytes) -> str:
    v = u16(data)
    return f"{v >> 8}.{(v >> 4) & 0x0F}.{v & 0x0F}"


def bms_temps(data: bytes) -> float:
    """rBmsTmp: bytes de temperatura con offset -20 C. Devuelve la mayor."""
    return float(max(data[0], data[1]) - 20)


# --------------------------------------------------------------------------
# Registros
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class Reg:
    key: str
    board: str  # "vcu" | "bms1" | "bms2" | "ble"
    index: int
    size: int
    decode: object
    scale: float = 1.0
    static: bool = False  # se lee una sola vez por sesion


# Escalas tomadas de la documentacion del protocolo. Las marcadas "verificar"
# no estan confirmadas contra un F3 real; tools/probe_f3.py imprime el valor
# crudo junto al escalado para poder ajustarlas sin tocar nada mas.
REGISTERS: tuple[Reg, ...] = (
    Reg("serial_number", "vcu", 0x10, 14, ascii_sn, static=True),
    Reg("firmware_ctrl", "vcu", 0x17, 2, version, static=True),
    Reg("firmware_mcu", "vcu", 0x18, 2, version, static=True),
    Reg("firmware_bms", "vcu", 0x19, 2, version, static=True),
    Reg("battery", "vcu", 0x55, 2, u16),
    Reg("speed", "vcu", 0x57, 2, u16, 0.1),
    Reg("error_code", "vcu", 0x58, 2, u16),
    Reg("warn_code", "vcu", 0x59, 2, u16),
    Reg("gear_mode", "vcu", 0x5A, 2, u16),
    Reg("precise_mileage", "vcu", 0x5E, 2, u16, 0.01),  # verificar
    Reg("left_mileage", "vcu", 0x5F, 2, u16, 0.01),  # verificar
    Reg("total_mileage", "vcu", 0x62, 4, u32, 0.001),
    Reg("runtime", "vcu", 0x64, 4, u32, 1 / 3600),
    Reg("ride_time", "vcu", 0x66, 4, u32, 1 / 3600),
    Reg("trip_mileage", "vcu", 0x68, 2, u16, 0.01),
    Reg("trip_time", "vcu", 0x6A, 2, u16),
    Reg("body_temp", "vcu", 0x6B, 2, s16, 0.1),
    Reg("bms1_voltage", "bms1", 0x8C, 2, u16, 0.01),
    Reg("bms1_current", "bms1", 0x8D, 2, s16, 0.01),
    Reg("bms1_soc", "bms1", 0x8F, 2, u16),
    Reg("bms1_temp", "bms1", 0x96, 4, bms_temps),
    Reg("bms2_voltage", "bms2", 0x8C, 2, u16, 0.01),
    Reg("bms2_current", "bms2", 0x8D, 2, s16, 0.01),
    Reg("bms2_soc", "bms2", 0x8F, 2, u16),
)

REGISTERS_BY_KEY = {r.key: r for r in REGISTERS}
