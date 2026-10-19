# Fase cloud — hacia una integración autónoma

**Objetivo:** que un usuario configure la integración con solo su cuenta Segway,
sin extraer nada del teléfono ni copias de seguridad, conviviendo con la app.

## La pregunta que decide toda la fase

El handshake BLE necesita la **contraseña de sesión** (`{serie}_decrypt`, 16 B).
Hoy sale de los UserDefaults de la app. "Autónomo" significa obtenerla de otra
parte. Solo hay un sitio posible: la nube de Segway. Por tanto todo depende de:

> **¿La API cloud internacional devuelve la contraseña de sesión BLE (y el
> `ident`) de un vehículo ya emparejado?**

Tres desenlaces y lo que implica cada uno:

| La nube devuelve… | Config flow resultante | Convive con la app |
|---|---|---|
| contraseña **y** `ident` | login Segway → listo, 100% autónomo | sí (misma credencial) |
| solo `ident` | login da `ident`; la contraseña aún necesita BLE/backup | sí |
| ninguno | la nube solo sirve para listar vehículos | — |

**Hasta no confirmar esto, no se escribe el cliente cloud.** Construir la capa
de login (RSA+AES+DeriveKey+sign, ~450 líneas) antes de saber si el dato está
ahí es trabajo que se puede tirar entero. Es el paso 2, no el 1.

## Lo que ya está resuelto (fundaciones disponibles)

- **Protocolo BLE** (fase 1): verificado contra la unidad real `1EFGE2513C1181`.
  gen2, authV2, Nordic UART, solo-lectura estructural. Ver README.
- **Capa de cifrado cloud**: `kxn/ninebot-recon` (MIT) la tiene reimplementada en
  Python puro y **su autotest de round-trip pasa offline** aquí. Es agnóstica al
  backend (misma SDK "capa de cifrado NetEase" en China e internacional). Se
  vendoriza en el paso 2, no antes.
- **Endpoints conocidos** (backend **China**, `*-bj.ninebot.com`):
  - Passport login `POST /v6/user/login` → access/refresh token
  - Business login `POST /user/user/login` → `business_uid`
  - Vehículos `POST /vehicle/binding/my-vehicle` (host `ebike.ninebot.com`)
  - *(viajes: fuera de alcance para control)*

## Incógnitas a cerrar, en orden

1. **Hosts internacionales.** Camilo usa `com.ninebot.segway` (Segway Mobility),
   no el 九号出行 chino. Los hosts `*-bj` casi seguro cambian (otra región,
   probablemente AWS). No se puede adivinar a fuerza bruta contra servidores de
   auth en producción: bloquearía la cuenta. Vías limpias:
   - extraer los hosts de strings del APK internacional (RE con REA, sin tocar
     la cuenta);
   - capturar el tráfico de la app con mitmproxy + desanclado de certificado
     (la comunidad de HA ya lo hizo; requiere el teléfono de Camilo).
2. **El endpoint de credencial BLE.** `segway-ninebot-ble` documentó para la app
   `POST /vehicle/vehicle/vehicle-basic-info {uid, wnumber}` → `ident`. No dice
   que devuelva la contraseña. Confirmar empíricamente volcando **todos** los
   campos de los endpoints de vehículo con una cuenta real.
3. **Diseño del config flow** según el desenlace de la tabla de arriba.

## Riesgo documentado

La doc `authentication.md` dice que la contraseña se genera en el cliente por
`SET_PWD` (Java Random); `credentials-qr.md` dice que "ambos valores los emite la
nube en el primer emparejamiento". Contradicción real sin resolver. Si la
contraseña NO vive en la nube, el objetivo "autónomo + convivencia" es imposible
para un vehículo ya emparejado: habría que elegir entre reemparejar (rompe la
app) o seguir con el backup. El paso 2 lo resuelve con un hecho, no con teoría.

## Qué necesito de Camilo para arrancar el paso 2

Una de estas dos (deciden la rama):
- **Login de su cuenta Segway** (correo/teléfono + contraseña) → con hosts
  confirmados, corro la sonda y en una llamada sabemos si la contraseña está ahí.
- **El teléfono para capturar tráfico** (mitmproxy): más trabajo pero da los
  hosts y el endpoint exacto de una vez.

Independiente de eso: puedo intentar extraer los hosts del APK con REA sin tocar
la cuenta. Es el siguiente movimiento que no depende de nadie.

## Decisión tomada (2026-10-18): captura BLE del re-emparejamiento

La contraseña no vive en la nube (RE del APK lo confirma: deriva en el
dispositivo). Vía elegida para obtenerla sin romper la app: **capturar el HCI
Bluetooth del iPhone durante un re-emparejamiento** y descifrar el `SET_PWD`,
cuya clave SÍ sabemos derivar (`SHA-1(nombre‖auth)`, con el `auth` del PRE_COMM
de la misma captura). La contraseña la pone la app, nosotros solo la leemos →
convivencia garantizada.

Herramientas (en el repo): `tools/bt_capture.sh` (túnel nativo sin root +
`btlogger` por USB) y `tools/decode_capture.py` (saca la contraseña de la
captura). Test: `tests/test_capture_decode.py` (recupera una contraseña
sintética con el `auth` real del patinete). Único requisito manual: Modo
Desarrollador activo en el iPhone.

La fase cloud queda aparcada para el `ident` (acciones de control), fase futura.
