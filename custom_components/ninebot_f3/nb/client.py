"""Cliente BLE del Ninebot F3 / F3 Pro, pensado para convivir con la app oficial.

Dos reglas de convivencia, ambas deliberadas:

1. **Nunca se ejecuta SET_PWD.** La contrasena de sesion es un unico slot en el
   patinete: generar una nueva lo desemparejaria de la app de Segway. Este
   cliente solo hace PRE_COMM + AUTH reutilizando la contrasena que la app ya
   tiene (ver tools/extract_creds.py). Si el patinete no tiene contrasena
   guardada, falla y pide emparejar primero con la app oficial.

2. **Conexion efimera.** El modulo BLE del patinete acepta un unico central a
   la vez: si Home Assistant se queda conectado, la app no puede entrar. Cada
   sondeo conecta, lee y se desconecta.
"""

from __future__ import annotations

import asyncio
import logging

from bleak import BleakClient
from bleak.backends.device import BLEDevice
from bleak_retry_connector import establish_connection

from . import protocol as proto
from .crypto import FW_DATA, NbCrypto

_LOGGER = logging.getLogger(__name__)

# Un F3 Pro real (serie 1EFGE2513C1181) expone los dos perfiles, pero solo
# contesta por Nordic UART; el servicio Ninebot propietario acepta la escritura
# y no responde. Por eso Nordic va primero.
NORDIC_WRITE = "6e400002-b5a3-f393-e0a9-e50e24dcca9e"
NORDIC_NOTIFY = "6e400003-b5a3-f393-e0a9-e50e24dcca9e"
NB_WRITE = "6e400002-0000-0000-006e-696e65626f74"
NB_NOTIFY = "6e400004-0000-0000-006e-696e65626f74"
CHAR_PAIRS = ((NORDIC_WRITE, NORDIC_NOTIFY), (NB_WRITE, NB_NOTIFY))

# Ids de fabricante de Ninebot. Son pares ASCII ("NB"/"NC") y aparecen tambien
# con los bytes invertidos segun el firmware. 17230 (0x434E, "CN") es el que
# anuncia un F3 Pro real y no estaba en las listas publicadas.
NINEBOT_MFR_PRIMARY = (20034, 16974)    # 0x4E42 "NB", 0x424E "BN": version en offset 1
NINEBOT_MFR_SECONDARY = (20035, 16975, 17230, 20290)  # "NC"/"BO"/"CN": offset 2
NINEBOT_MFR_IDS = NINEBOT_MFR_PRIMARY + NINEBOT_MFR_SECONDARY

BOARD_IDS = {"ble": proto.BOARD_BLE, "mcu": proto.BOARD_MCU,
             "bms1": proto.BOARD_BMS1, "bms2": proto.BOARD_BMS2}


class ForbiddenCommand(Exception):
    """Se intento emitir un comando fuera de la allowlist de solo lectura."""


class NinebotError(Exception):
    """Fallo generico de protocolo."""


class AuthRejected(NinebotError):
    """El patinete rechazo el handshake (contrasena mala o authV3)."""


class NotPaired(NinebotError):
    """El patinete no tiene contrasena guardada: hay que emparejar con la app."""


def detect_auth_version(manufacturer_data: dict[int, bytes] | None) -> int | None:
    """2 = authV2 (soportado), 3 = authV3 (no soportado), None = desconocido."""
    for cid, payload in (manufacturer_data or {}).items():
        if cid in NINEBOT_MFR_PRIMARY and len(payload) >= 2 and payload[1] in (2, 3):
            return payload[1]
        if cid in NINEBOT_MFR_SECONDARY and len(payload) >= 3 and payload[2] in (2, 3):
            return payload[2]
    return None


class _Transport:
    """Reensambla tramas cifradas a partir de las notificaciones BLE."""

    def __init__(self, client: BleakClient, write_uuid: str, notify_uuid: str) -> None:
        self._client = client
        self._write_uuid = write_uuid
        self._notify_uuid = notify_uuid
        self._queue: asyncio.Queue[bytes] = asyncio.Queue()
        self._buf = bytearray()
        self._subscribed: list[str] = []

    async def start(self, extra_notify: list[str] | None = None) -> None:
        for uuid in dict.fromkeys([self._notify_uuid, *(extra_notify or [])]):
            try:
                await self._client.start_notify(uuid, self._on_notify)
                self._subscribed.append(uuid)
            except Exception as err:  # noqa: BLE001 - canal opcional
                _LOGGER.debug("sin notificaciones en %s: %s", uuid, err)
        if not self._subscribed:
            raise NinebotError("no se pudo suscribir a ninguna caracteristica notify")

    async def stop(self) -> None:
        for uuid in self._subscribed:
            try:
                await self._client.stop_notify(uuid)
            except Exception:  # noqa: BLE001 - la desconexion ya puede haber ocurrido
                pass

    def _on_notify(self, _sender, data: bytearray) -> None:
        self._buf.extend(data)
        while True:
            start = next(
                (i for i in range(len(self._buf) - 1)
                 if self._buf[i] == proto.SYNC1 and self._buf[i + 1] in proto.VALID_SYNC2),
                None,
            )
            if start is None:
                # Conserva un 0x5A final por si la trama viene partida.
                self._buf = self._buf[-1:] if self._buf[-1:] == b"\x5a" else bytearray()
                return
            del self._buf[:start]
            if len(self._buf) < 3:
                return
            total = self._buf[2] + 13  # LEN + cabecera + tag + contador
            if len(self._buf) < total:
                return
            self._queue.put_nowait(bytes(self._buf[:total]))
            del self._buf[:total]

    async def send(self, data: bytes) -> None:
        mtu = max(self._client.mtu_size - 3, 20)
        for off in range(0, len(data), mtu):
            await self._client.write_gatt_char(
                self._write_uuid, data[off : off + mtu], response=False
            )
            if off + mtu < len(data):
                await asyncio.sleep(0.01)  # el firmware pierde fragmentos sin pausa

    async def recv(self, timeout: float = 5.0) -> bytes:
        return await asyncio.wait_for(self._queue.get(), timeout=timeout)


class NinebotF3Client:
    """Una sesion de lectura: conecta, autentica, lee registros y se desconecta."""

    def __init__(self, bt_name: str, password: bytes, gen: int = 2,
                 vcu_board: int = proto.BOARD_VCU) -> None:
        self._bt_name = bt_name
        self._password = password
        self._gen = gen
        self._vcu = vcu_board
        self.serial: str | None = None

    def _board_id(self, board: str) -> int:
        return self._vcu if board == "vcu" else BOARD_IDS[board]

    async def async_read_all(self, device: BLEDevice, keys: list[str]) -> dict[str, object]:
        """Conecta, autentica y devuelve {key: valor} para los registros pedidos."""
        # max_attempts bajo a proposito: reintentar roba radio a la app de
        # Segway. Si el patinete no esta, se espera al siguiente sondeo.
        client = await establish_connection(
            BleakClient, device, self._bt_name, max_attempts=2
        )
        try:
            write_uuid, notify_uuid = self._pick_characteristics(client)
            transport = _Transport(client, write_uuid, notify_uuid)
            await transport.start(extra_notify=self._all_notify_uuids(client))
            crypto = await self._handshake(transport)
            values: dict[str, object] = {}
            for key in keys:
                reg = proto.REGISTERS_BY_KEY[key]
                try:
                    values[key] = await self._read(transport, crypto, reg)
                except (TimeoutError, asyncio.TimeoutError, NinebotError) as err:
                    # Un registro ausente en esta variante no invalida el resto.
                    _LOGGER.debug("registro %s no disponible: %s", key, err)
            await transport.stop()
            return values
        finally:
            await client.disconnect()  # libera el radio para la app de Segway

    @staticmethod
    def _pick_characteristics(client: BleakClient) -> tuple[str, str]:
        uuids = {c.uuid.lower() for s in client.services for c in s.characteristics}
        for write, notify in CHAR_PAIRS:
            if write in uuids and notify in uuids:
                return write, notify
        raise NinebotError(f"sin caracteristicas Ninebot ni Nordic UART: {sorted(uuids)}")

    @staticmethod
    def _all_notify_uuids(client: BleakClient) -> list[str]:
        """Todas las notify 6e4000xx: nos suscribimos a todas por si el firmware
        contesta por un canal distinto al que esperamos."""
        return [c.uuid.lower() for s in client.services for c in s.characteristics
                if "notify" in c.properties and "6e4000" in c.uuid.lower()]

    @staticmethod
    async def _send(transport: _Transport, crypto: NbCrypto, frame: bytes) -> None:
        """Unica salida al patinete. Bloquea cualquier comando que no sea de
        lectura antes de cifrarlo: ni SET_PWD, ni escrituras, ni clearAllKeys,
        ni unbondFindMy pueden salir de aqui aunque alguien los construya."""
        cmd = frame[5]
        if cmd not in proto.ALLOWED_CMDS:
            raise ForbiddenCommand(
                f"comando 0x{cmd:02X} bloqueado: esta integracion es de solo "
                "lectura y no puede alterar el emparejamiento del patinete"
            )
        await transport.send(crypto.encrypt(frame))

    async def _handshake(self, transport: _Transport) -> NbCrypto:
        crypto = NbCrypto(ecb_input=FW_DATA if self._gen == 2 else b"\x00" * 16)
        crypto.reset_sn()
        crypto.set_key(self._bt_name.encode(), FW_DATA if self._gen == 2 else None)

        request = proto.build_pre_comm(self._gen)
        await self._send(transport, crypto, request)
        plain, _rc = crypto.decrypt(await transport.recv())
        if plain == request:
            # El patinete devuelve la trama tal cual cuando la rechaza.
            raise AuthRejected(
                f"PRE_COMM rechazado. El nombre BLE '{self._bt_name}' debe ser el "
                "numero de serie exacto que se anuncia, o el patinete usa authV3, "
                "que no esta soportado."
            )
        frame = proto.parse(plain)
        if frame is None or frame.cmd != proto.CMD_PRE_COMM or len(frame.data) < 30:
            raise NinebotError(f"respuesta PRE_COMM invalida: {plain.hex()}")

        auth, sn = frame.data[0:16], frame.data[16:30]
        self.serial = proto.ascii_sn(sn)
        if frame.index == 0:
            raise NotPaired(
                "El patinete no tiene contrasena guardada. Emparejalo primero con "
                "la app oficial de Segway y vuelve a importar la credencial; esta "
                "integracion nunca ejecuta SET_PWD para no desemparejar la app."
            )

        crypto.set_auth_param(auth)
        crypto.start_sn()
        crypto.set_key(self._password, auth)
        await self._send(transport, crypto, proto.build_auth(sn, self._gen))
        plain, _rc = crypto.decrypt(await transport.recv())
        frame = proto.parse(plain)
        if frame is None or frame.cmd != proto.CMD_AUTH:
            raise NinebotError(f"respuesta AUTH invalida: {plain.hex()}")
        if frame.index != 1:
            raise AuthRejected(
                "AUTH rechazado: la contrasena no coincide con la que guarda el "
                "patinete. Vuelve a exportarla de la app (puede haber cambiado si "
                "la app se re-emparejo)."
            )
        return crypto

    async def _read(self, transport: _Transport, crypto: NbCrypto, reg: proto.Reg):
        request = proto.build_read(self._board_id(reg.board), reg.index, reg.size, self._gen)
        await self._send(transport, crypto, request)
        plain, rc = crypto.decrypt(await transport.recv(timeout=3.0))
        if rc != 0:
            raise NinebotError(f"MAC invalido leyendo {reg.key}")
        frame = proto.parse(plain)
        if frame is None or frame.index != reg.index or len(frame.data) < reg.size:
            raise NinebotError(f"respuesta inesperada para {reg.key}: {plain.hex()}")
        value = reg.decode(frame.data[: reg.size])
        if isinstance(value, (int, float)) and reg.scale != 1.0:
            return round(value * reg.scale, 3)
        return value
