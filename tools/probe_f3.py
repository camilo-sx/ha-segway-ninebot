#!/usr/bin/env python3
"""Reconocimiento del Ninebot F3 / F3 Pro por BLE. Solo lectura.

Nunca ejecuta SET_PWD, asi que no toca el emparejamiento de la app de Segway.

  scan                      lista patinetes Segway/Ninebot cercanos
  probe  -a MAC -n NOMBRE   handshake PRE_COMM: serie, authV2/V3, si hay pwd
  dump   -a MAC -n NOMBRE -p HEX32
                            autentica y vuelca los registros crudos + escalados,
                            probando las placas candidatas para la VCU
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "custom_components" / "ninebot_f3"))

from bleak import BleakClient, BleakScanner  # noqa: E402

from nb import protocol as proto  # noqa: E402
from nb.client import (  # noqa: E402
    NINEBOT_MFR_IDS,
    NinebotF3Client,
    _Transport,
    detect_auth_version,
)
from nb.crypto import FW_DATA, NbCrypto  # noqa: E402

AUTH_TAG = {2: "authV2 (soportado)", 3: "authV3 (NO soportado)"}


async def cmd_scan(_args) -> int:
    print("Escaneando 10 s...")
    found = await BleakScanner.discover(timeout=10.0, return_adv=True)
    hits = []
    for dev, adv in found.values():
        name = dev.name or adv.local_name or ""
        mfr = adv.manufacturer_data or {}
        if any(t in name.upper() for t in ("NB", "S1D", "NINEBOT", "SEGWAY")) or any(
            cid in NINEBOT_MFR_IDS for cid in mfr
        ):
            hits.append((adv.rssi, dev.address, name, detect_auth_version(mfr), dict(mfr)))
    if not hits:
        print("\nNingun Segway/Ninebot visible. Los 15 dispositivos mas cercanos:")
        for dev, adv in sorted(found.values(), key=lambda d: d[1].rssi, reverse=True)[:15]:
            print(f"  [{adv.rssi:>4} dBm] {dev.address}  {dev.name or adv.local_name or '(sin nombre)'}")
        print("\nEnciende el patinete y cierra la app de Segway (ocupa el radio).")
        return 1
    print()
    for rssi, addr, name, ver, mfr in sorted(hits, reverse=True):
        print(f"  [{rssi:>4} dBm] {addr}  {name or '(sin nombre)'}  "
              f"{AUTH_TAG.get(ver, 'auth=? (desconocido)')}")
        for cid, payload in mfr.items():
            print(f"       mfr {cid}: {payload.hex()}")
    print("\nEl NOMBRE anunciado es la clave de cifrado: usalo tal cual en -n.")
    return 0


async def _connect(address: str, bt_name: str):
    device = await BleakScanner.find_device_by_address(address, timeout=15.0)
    if device is None:
        raise SystemExit(f"{address} no encontrado. Enciende el patinete.")
    client = BleakClient(device)
    await client.connect()
    uuids = {c.uuid.lower() for s in client.services for c in s.characteristics}
    print(f"Conectado. MTU={client.mtu_size}")
    print("Caracteristicas 6e4000xx:", sorted(u for u in uuids if "6e4000" in u) or "ninguna")
    write, notify = NinebotF3Client._pick_characteristics(client)
    transport = _Transport(client, write, notify)
    await transport.start()
    return client, transport


async def _pre_comm(transport, bt_name: str, gen: int):
    crypto = NbCrypto(ecb_input=FW_DATA if gen == 2 else b"\x00" * 16)
    crypto.reset_sn()
    crypto.set_key(bt_name.encode(), FW_DATA if gen == 2 else None)
    request = proto.build_pre_comm(gen)
    await transport.send(crypto.encrypt(request))
    plain, rc = crypto.decrypt(await transport.recv(timeout=6.0))
    return crypto, request, plain, rc


async def cmd_probe(args) -> int:
    client, transport = await _connect(args.address, args.name)
    try:
        for gen in (2, 3):
            print(f"\n--- PRE_COMM gen{gen} (sync 0x5A{proto.SYNC2[gen]:02X}) ---")
            try:
                crypto, request, plain, rc = await _pre_comm(transport, args.name, gen)
            except (TimeoutError, asyncio.TimeoutError):
                print("  sin respuesta")
                continue
            print(f"  rc={rc} claro={plain.hex()}")
            if plain == request:
                print("  ECO -> rechazado (nombre incorrecto o authV3)")
                continue
            frame = proto.parse(plain)
            if frame is None or len(frame.data) < 30:
                print("  trama no reconocida")
                continue
            print(f"  OK  gen{gen} es el correcto")
            print(f"  auth  = {frame.data[0:16].hex()}")
            print(f"  serie = {proto.ascii_sn(frame.data[16:30])}")
            print(f"  contrasena guardada en el patinete: "
                  f"{'si' if frame.index else 'NO (empareja antes con la app)'}")
            return 0
        return 1
    finally:
        await client.disconnect()


async def cmd_dump(args) -> int:
    client, transport = await _connect(args.address, args.name)
    try:
        gen = args.gen
        crypto, request, plain, rc = await _pre_comm(transport, args.name, gen)
        frame = proto.parse(plain)
        if plain == request or frame is None or len(frame.data) < 30:
            raise SystemExit("PRE_COMM rechazado; ejecuta primero 'probe'")
        auth, sn = frame.data[0:16], frame.data[16:30]
        print(f"serie={proto.ascii_sn(sn)}  pwd_guardada={bool(frame.index)}")
        crypto.set_auth_param(auth)
        crypto.start_sn()
        crypto.set_key(bytes.fromhex(args.password), auth)
        await transport.send(crypto.encrypt(proto.build_auth(sn, gen)))
        plain, rc = crypto.decrypt(await transport.recv(timeout=6.0))
        frame = proto.parse(plain)
        if frame is None or frame.index != 1:
            raise SystemExit(f"AUTH rechazado: {plain.hex()}")
        print("AUTH OK\n")

        # Averigua que byte de placa responde a rSN antes de volcar nada mas.
        vcu = None
        for candidate in proto.VCU_CANDIDATES:
            try:
                await transport.send(crypto.encrypt(
                    proto.build_read(candidate, 0x10, 14, gen)))
                resp = proto.parse(crypto.decrypt(await transport.recv(timeout=2.5))[0])
            except (TimeoutError, asyncio.TimeoutError):
                print(f"  placa 0x{candidate:02X}: sin respuesta")
                continue
            if resp and resp.index == 0x10:
                print(f"  placa 0x{candidate:02X}: responde -> VCU")
                vcu = candidate
                break
        if vcu is None:
            raise SystemExit("ninguna placa candidata respondio a rSN")

        print(f"\nVCU = 0x{vcu:02X}\n")
        print(f"{'registro':<18}{'placa':<7}{'idx':<6}{'crudo':<14}{'escalado'}")
        for reg in proto.REGISTERS:
            board = vcu if reg.board == "vcu" else {
                "bms1": proto.BOARD_BMS1, "bms2": proto.BOARD_BMS2,
                "mcu": proto.BOARD_MCU, "ble": proto.BOARD_BLE}[reg.board]
            try:
                await transport.send(crypto.encrypt(
                    proto.build_read(board, reg.index, reg.size, gen)))
                resp = proto.parse(crypto.decrypt(await transport.recv(timeout=2.5))[0])
            except (TimeoutError, asyncio.TimeoutError):
                print(f"{reg.key:<18}{reg.board:<7}0x{reg.index:02X}  {'timeout'}")
                continue
            if resp is None or resp.index != reg.index:
                print(f"{reg.key:<18}{reg.board:<7}0x{reg.index:02X}  sin dato")
                continue
            raw = resp.data[: reg.size]
            try:
                value = reg.decode(raw)
                scaled = round(value * reg.scale, 3) if isinstance(value, (int, float)) else value
            except Exception as err:  # noqa: BLE001 - volcado de diagnostico
                scaled = f"<{err}>"
            print(f"{reg.key:<18}{reg.board:<7}0x{reg.index:02X}  {raw.hex():<14}{scaled}")
        return 0
    finally:
        await client.disconnect()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("scan").set_defaults(func=cmd_scan)
    for name in ("probe", "dump"):
        p = sub.add_parser(name)
        p.add_argument("-a", "--address", required=True)
        p.add_argument("-n", "--name", required=True, help="nombre BLE anunciado (= clave)")
        if name == "dump":
            p.add_argument("-p", "--password", required=True, help="32 hex de la app")
            p.add_argument("--gen", type=int, default=2, choices=(2, 3))
        p.set_defaults(func=cmd_probe if name == "probe" else cmd_dump)
    args = parser.parse_args()
    return asyncio.run(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
