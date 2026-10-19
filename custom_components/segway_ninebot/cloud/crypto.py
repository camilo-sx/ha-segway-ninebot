"""
crypto.py -- port de ninebot-recon (MIT, (c) 2026 kxn).
Fuente: https://github.com/kxn/ninebot-recon (ninebot_crypto.py).
AES/RSA via `cryptography` (ya la trae Home Assistant). Ver NOTICE en la raiz.

Capa de cifrado "NetEase" de la SDK de Ninebot. La misma SDK la usan el backend
chino y el internacional, asi que esta capa es agnostica al host.

Enlace (wire):
  peticion: {"d": b64(AES-CBC(wrapper)), "h": md5hex(wrapper),
             "k": b64(RSA(AESkey)), "p": "101", "t": "0"}
  wrapper:  {"data": AndroidB64(JSON de negocio), "keyDataOne..Four": kd1..4,
             "platform": 2, "timeStamp": <seg>}
  respuesta: {"r": b64} -> AES-CBC con DeriveKey(kd1..4), IV=0 -> wrapper -> data

Las formulas de DeriveKey y AndroidB64 estan verificadas en la fuente contra la
ejecucion del binario original (unicorn). Se portan tal cual.
"""
import base64
import hashlib
import json
import secrets
import struct
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# ---------------------------------------------------------------------------
# Constantes (extraidas del binario en la fuente)
# ---------------------------------------------------------------------------

# GenKReq: 94 ASCII imprimibles (0x21-0x7e)
CHARSET_KREQ = "!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~"
# GenKeyData 4o componente: 69 caracteres
CHARSET_KEYDATA4 = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789;-_.,+/"
CHARSET_HEX = "0123456789abcdef"

# Clave publica RSA-1024 embebida (N1, la que usa EncryptRequest; N2 era codigo muerto)
RSA_PUBLIC_KEY_PEM = """-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDT3m0c/8y9c13PzaFbATEg+Zwd
kpPcCy0V21VKBBSx16ckVtLERAQ7EH8d6DqgEbyzayAwlQd1gDhUmx27hDWafXr9
/evUZkkBegcsNnKrIlh93lPKccjk+LDXS1TnDIIFiTlSbNnaYwehI/9pUbKCI3h7
yE0pum6hJh/9QtGPlwIDAQAB
-----END PUBLIC KEY-----"""

WIRE_P = "101"
WIRE_T = "0"
# Dominio business (login/vehicles): platform=2, timeStamp en segundos.
PLATFORM = 2


# ---------------------------------------------------------------------------
# Utilidades base
# ---------------------------------------------------------------------------

def _rol32(v: int, n: int) -> int:
    n %= 32
    return ((v << n) | (v >> (32 - n))) & 0xFFFFFFFF


def _rol8acc(s: bytes) -> int:
    """v = 0; for b in s: v = rol32(v,8) ^ b."""
    v = 0
    for b in s:
        v = _rol32(v, 8) ^ b
    return v & 0xFFFFFFFF


def _rand_int(bound: int) -> int:
    return secrets.randbelow(bound)


# ---------------------------------------------------------------------------
# Generacion de material de clave
# ---------------------------------------------------------------------------

def rand_hex(n: int) -> str:
    return "".join(CHARSET_HEX[_rand_int(16)] for _ in range(n))


def rand_charset(n: int, charset: str) -> str:
    return "".join(charset[_rand_int(len(charset))] for _ in range(n))


def gen_kreq() -> bytes:
    """Material de clave AES-128: 16 bytes del charset de 94."""
    return rand_charset(16, CHARSET_KREQ).encode()


def gen_key_data() -> tuple[str, str, str, str]:
    """4 componentes para descifrar la respuesta: hex(11), hex(11), hex(10), charset(8)."""
    return (rand_hex(11), rand_hex(11), rand_hex(10), rand_charset(8, CHARSET_KEYDATA4))


def gen_nonce() -> str:
    """16 bytes aleatorios -> 32 hex, primer byte en minuscula y el resto en mayuscula."""
    raw = bytes(_rand_int(256) for _ in range(16))
    h = raw.hex()
    return h[0:2].lower() + h[2:].upper()


# ---------------------------------------------------------------------------
# DeriveKey (formula verificada contra el binario en la fuente)
# ---------------------------------------------------------------------------

def derive_key(a: bytes, b: bytes, c: bytes, d: bytes) -> bytes:
    """DeriveKey(A,B,C,D) -> 16 bytes de clave AES.

    Cada entrada se acumula con ROL8 a un u32; luego mezcla fija (ver fuente) y
    empaquetado little-endian de los 4 u32 resultantes.
    """
    A = _rol8acc(a); B = _rol8acc(b); C = _rol8acc(c); D = _rol8acc(d)
    x = A ^ C
    y = B ^ D
    fx = _rol32(x, 8) ^ x ^ _rol32(x, 24)
    gy = _rol32(y, 8) ^ y ^ _rol32(y, 24)
    a1 = A ^ gy
    b1 = B ^ fx
    c1 = C ^ gy
    d1 = D ^ fx
    out3 = (c1 & b1) ^ a1
    tmp = (~(c1 ^ d1 ^ ((c1 | d1) ^ b1))) & 0xFFFFFFFF
    out2 = out3 ^ tmp
    out1 = ((tmp | out3) ^ ((c1 | d1) ^ b1)) & 0xFFFFFFFF
    out0 = ((~((c1 | d1) ^ b1) & out2) ^ d1) & 0xFFFFFFFF
    return struct.pack("<IIII", out0, out1, out2, out3)


# ---------------------------------------------------------------------------
# AndroidB64: base64 estandar, salto cada 76 chars y un salto final si no esta vacio
# ---------------------------------------------------------------------------

def android_b64(data: bytes) -> str:
    b = base64.b64encode(data)
    if not b:
        return ""
    lines = [b[i:i + 76] for i in range(0, len(b), 76)]
    return b"\n".join(lines).decode() + "\n"


# ---------------------------------------------------------------------------
# JSON: el binario serializa con escape minimo (5 caracteres) y orden de campos fijo
# ---------------------------------------------------------------------------

def _json_escape(s: str) -> str:
    """Devuelve el string entrecomillado con escape de solo \\ " \\n \\r \\t."""
    out = ['"']
    for ch in s:
        if ch == '"':
            out.append('\\"')
        elif ch == '\\':
            out.append('\\\\')
        elif ch == '\n':
            out.append('\\n')
        elif ch == '\r':
            out.append('\\r')
        elif ch == '\t':
            out.append('\\t')
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def build_wrapper(data: bytes, kd1: str, kd2: str, kd3: str, kd4: str,
                  platform: int = PLATFORM, timestamp: int | None = None,
                  timestamp_seconds: bool = True) -> str:
    """Wrapper de negocio: orden de campos exacto del binario (no es orden de map)."""
    if timestamp is None:
        ts = int(time.time()) if timestamp_seconds else int(time.time() * 1000)
    else:
        ts = timestamp
    parts = [
        "{\n",
        '\t"data" : ', _json_escape(android_b64(data)), ",\n",
        '\t"keyDataFour" : "', kd4, '",\n',
        '\t"keyDataOne" : "', kd1, '",\n',
        '\t"keyDataThree" : "', kd3, '",\n',
        '\t"keyDataTwo" : "', kd2, '",\n',
        '\t"platform" : ', str(platform), ",\n",
        '\t"timeStamp" : ', str(ts), "\n}\n",
    ]
    return "".join(parts)


def _go_json_dumps(d: dict) -> str:
    """Serializa como el binario: orden de insercion, compacto, escape de 5 chars,
    el resto (<>&, no-ASCII, U+2028/2029) tal cual en UTF-8."""
    def _val(v):
        if isinstance(v, str):
            return _json_escape(v)
        if isinstance(v, bool):
            return "true" if v else "false"
        if isinstance(v, int):
            return str(v)
        if isinstance(v, float):
            return repr(v)
        if v is None:
            return "null"
        if isinstance(v, dict):
            return "{" + ",".join(_json_escape(str(k)) + ":" + _val(x) for k, x in v.items()) + "}"
        if isinstance(v, (list, tuple)):
            return "[" + ",".join(_val(x) for x in v) + "]"
        return _json_escape(str(v))
    return "{" + ",".join(_json_escape(str(k)) + ":" + _val(x) for k, x in d.items()) + "}"


def build_inner(params: dict) -> str:
    """JSON de negocio: calcula el MD5 (hex mayuscula) sin checkcode, lo anade como
    checkcode y reemite. params debe venir en el orden de campos del captura."""
    params = dict(params)
    inner_no_cc = _go_json_dumps(params)
    checkcode = hashlib.md5(inner_no_cc.encode()).hexdigest().upper()
    params["checkcode"] = checkcode
    return _go_json_dumps(params)


# ---------------------------------------------------------------------------
# AES-128-CBC (IV = 16 ceros, PKCS7) y RSA PKCS1v15
# ---------------------------------------------------------------------------

def _pkcs7_pad(data: bytes, block: int = 16) -> bytes:
    pad = block - (len(data) % block)
    return data + bytes([pad]) * pad


def _pkcs7_unpad(data: bytes, block: int = 16) -> bytes:
    if not data:
        raise ValueError("empty data")
    pad = data[-1]
    if pad < 1 or pad > block or data[-pad:] != bytes([pad]) * pad:
        raise ValueError("bad PKCS7 padding")
    return data[:-pad]


def _aes_cbc_encrypt(key: bytes, plaintext: bytes) -> bytes:
    iv = b"\x00" * 16
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return enc.update(_pkcs7_pad(plaintext)) + enc.finalize()


def _aes_cbc_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    iv = b"\x00" * 16
    dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    padded = dec.update(ciphertext) + dec.finalize()
    return _pkcs7_unpad(padded)


def _rsa_encrypt(pub_pem: str, data: bytes) -> bytes:
    pub = serialization.load_pem_public_key(pub_pem.encode())
    return pub.encrypt(data, asym_padding.PKCS1v15())


# ---------------------------------------------------------------------------
# Peticion / respuesta
# ---------------------------------------------------------------------------

def encrypt_request(data: bytes, aes_key: bytes, kd1: str, kd2: str, kd3: str, kd4: str,
                    platform: int = PLATFORM, timestamp: int | None = None,
                    timestamp_seconds: bool = True) -> dict:
    """Cuerpo wire {"d","h","k","p","t"}."""
    wrapper = build_wrapper(data, kd1, kd2, kd3, kd4, platform, timestamp,
                            timestamp_seconds).encode()
    d_raw = _aes_cbc_encrypt(aes_key, wrapper)
    h = hashlib.md5(wrapper).hexdigest()
    k_raw = _rsa_encrypt(RSA_PUBLIC_KEY_PEM, aes_key)
    return {
        "d": base64.b64encode(d_raw).decode(),
        "h": h,
        "k": base64.b64encode(k_raw).decode(),
        "p": WIRE_P,
        "t": WIRE_T,
    }


def decrypt_response(r_b64: str, kd1: str, kd2: str, kd3: str, kd4: str) -> bytes:
    """{"r": b64} -> wrapper en claro. key = DeriveKey(kd1..kd4), IV=0.

    El claro es el wrapper (el JSON de negocio va dentro, en data/AndroidB64).
    """
    r = base64.b64decode(r_b64)
    key = derive_key(kd1.encode(), kd2.encode(), kd3.encode(), kd4.encode())
    return _aes_cbc_decrypt(key, r)


def unwrap_response(plain: bytes) -> bytes:
    """Del wrapper de respuesta saca data (AndroidB64) -> JSON de negocio en bytes."""
    w = json.loads(plain.decode("utf-8"))
    if not isinstance(w, dict) or not isinstance(w.get("data"), str):
        raise ValueError("missing 'data' field in wrapper")
    return base64.b64decode(w["data"].strip())


# ---------------------------------------------------------------------------
# Alto nivel
# ---------------------------------------------------------------------------

def build_request(data: bytes, platform: int = PLATFORM,
                  timestamp: int | None = None, timestamp_seconds: bool = True
                  ) -> tuple[dict, dict]:
    """Peticion completa + material de clave (para descifrar la respuesta).

    Devuelve (wire_body, secrets) con aes_key y kd1..4.
    """
    aes_key = gen_kreq()
    kd1, kd2, kd3, kd4 = gen_key_data()
    body = encrypt_request(data, aes_key, kd1, kd2, kd3, kd4, platform,
                           timestamp, timestamp_seconds)
    return body, {"aes_key": aes_key, "kd1": kd1, "kd2": kd2, "kd3": kd3, "kd4": kd4}


def decrypt_wire_response(resp_body: dict, secrets_: dict) -> bytes:
    """resp_body {"r": b64} + secrets -> JSON de negocio en bytes."""
    plain = decrypt_response(resp_body["r"], secrets_["kd1"], secrets_["kd2"],
                             secrets_["kd3"], secrets_["kd4"])
    return unwrap_response(plain)
