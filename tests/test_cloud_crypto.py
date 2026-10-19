"""Autotest de la capa de cifrado cloud (sin red).

Se ejecuta sin framework:  python3 tests/test_cloud_crypto.py

Porta el round-trip de self_test() de ninebot-recon: firma passport de vector
fijo, vectores fijos de derive_key / android_b64, y el ciclo completo
cifra-peticion / descifra-respuesta simulando el servidor.
"""

import base64
import hashlib
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "custom_components" / "segway_ninebot"))

from cloud import api
from cloud import crypto


def test_passport_sign_vector_fijo():
    """sha256 del canonical ordenado, con clientKey inyectado (captura GDB)."""
    params = {"app_version": "610063322", "areaCode": "86", "device": "ANDROID",
              "os": "Android", "os_language": "zh-hans-cn", "os_version": "13",
              "password": "endtoendpw1", "timestamp": "1786095783403",
              "url": "/v6/user/login", "username": "e2etest"}
    expect_canonical = ("app_version=610063322&areaCode=86&clientKey=e177176a-3b3e-1513-"
                        "e26e-d1123034cb66&device=ANDROID&os=Android&os_language=zh-hans-cn"
                        "&os_version=13&password=endtoendpw1&timestamp=1786095783403"
                        "&url=/v6/user/login&username=e2etest")
    sig = api.passport_sign("/v6/user/login", params)
    assert sig == hashlib.sha256(expect_canonical.encode()).hexdigest(), sig


def test_derive_key_vector_fijo():
    tv = crypto.derive_key(b"abcdefghijklm", b"0123456789ab", b"XYZ", b"ninebot!")
    assert tv.hex() == "82ffe6a8cbb9a4ffdbf791a74e37176e", tv.hex()


def test_android_b64_vector_fijo():
    assert crypto.android_b64(b"hello") == "aGVsbG8=\n"
    assert crypto.android_b64(b"") == ""
    largo = crypto.android_b64(b"x" * 58)   # 78 chars b64 -> un salto a los 76
    assert largo.count("\n") == 2 and len(largo) == 82


def test_gen_nonce_formato():
    for _ in range(20):
        n = crypto.gen_nonce()
        assert len(n) == 32 and n[0:2] == n[0:2].lower() and n[2:] == n[2:].upper(), n


def test_build_inner_checkcode():
    """checkcode = MD5(hex mayuscula) del JSON sin checkcode."""
    params = {"a": "1", "nonce": crypto.gen_nonce()}
    sin_cc = crypto._go_json_dumps(params)
    inner = json.loads(crypto.build_inner(params))
    assert inner["checkcode"] == hashlib.md5(sin_cc.encode()).hexdigest().upper()


def test_request_roundtrip():
    """Vision servidor: RSA->AES key, AES->wrapper; h = MD5(wrapper); campos ok."""
    data = json.dumps({"sn": "NB1234567890", "month": "202608"}).encode()
    body, sec = crypto.build_request(data)
    assert set(body) == {"d", "h", "k", "p", "t"}
    assert body["p"] == "101" and body["t"] == "0" and len(body["h"]) == 32

    wrapper_plain = crypto._aes_cbc_decrypt(sec["aes_key"], base64.b64decode(body["d"]))
    assert hashlib.md5(wrapper_plain).hexdigest() == body["h"]
    wrapper = json.loads(wrapper_plain.decode())
    assert wrapper["data"] == crypto.android_b64(data)
    assert wrapper["keyDataOne"] == sec["kd1"] and wrapper["keyDataFour"] == sec["kd4"]
    assert wrapper["platform"] == 2 and wrapper["timeStamp"] < 2 ** 31  # segundos


def test_response_roundtrip():
    """Vision cliente: el servidor cifra con DeriveKey(kd), nosotros desciframos."""
    data = json.dumps({"code": 0, "data": {"vehicles": [{"wnumber": "NB1"}]}}).encode()
    _body, sec = crypto.build_request(b"{}")
    resp_key = crypto.derive_key(sec["kd1"].encode(), sec["kd2"].encode(),
                                 sec["kd3"].encode(), sec["kd4"].encode())
    resp_wrapper = json.dumps({"data": crypto.android_b64(data), "platform": 2,
                               "timeStamp": int(time.time())}).encode()
    fake = {"r": base64.b64encode(crypto._aes_cbc_encrypt(resp_key, resp_wrapper)).decode()}
    descifrado = crypto.decrypt_wire_response(fake, sec)
    assert descifrado == data
    assert json.loads(descifrado)["data"]["vehicles"][0]["wnumber"] == "NB1"


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
