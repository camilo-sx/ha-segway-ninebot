# Segway Ninebot F3 / F3 Pro para Home Assistant

Integración personalizada (HACS) que lee por BLE el patinete **Segway-Ninebot
KickScooter F3 / F3 Pro** y **convive con la app oficial de Segway**: ninguna de
las dos desempareja a la otra.

Verificada contra una unidad real (serie `1EFGE2513C1181`, gen2, authV2).

## Por qué la convivencia necesita diseño

El handshake del protocolo tiene tres fases: `PRE_COMM` → `SET_PWD` → `AUTH`. La
contraseña de sesión es **un único slot** en el patinete: si un segundo cliente
ejecuta `SET_PWD`, genera una contraseña nueva y la app oficial deja de
autenticar hasta que la vuelvas a emparejar a mano.

Por eso esta integración **nunca ejecuta `SET_PWD`**. Reutiliza la contraseña que
la app ya tiene, exportada con `tools/extract_creds.py`. Las dos comparten
credencial y ninguna pisa a la otra.

El segundo límite es físico: el módulo BLE acepta **un solo central a la vez**.
Mientras Home Assistant lee, la app no puede conectarse. Mitigaciones:

- cada sondeo conecta, lee y **se desconecta** (no mantiene el radio ocupado);
- intervalo configurable, 5 minutos por defecto;
- un interruptor **Sondeo BLE** para dejar el patinete libre mientras conduces.

## Instalación

1. HACS → Repositorios personalizados → `https://github.com/camilo-sx/ha-segway-ninebot`, tipo *Integration*.
2. Instalar y reiniciar Home Assistant.
3. Ajustes → Dispositivos y servicios → Añadir integración → *Segway Ninebot F3*.

Instalación manual: copia `custom_components/ninebot_f3/` a tu `config/custom_components/`.

El host de Home Assistant necesita un adaptador Bluetooth **a menos de unos
metros del patinete** (un Raspberry Pi o un ESPHome Bluetooth Proxy en el garaje).

## Obtener la contraseña de sesión

La app guarda por número de serie dos secretos en sus UserDefaults:

| Clave | Contenido |
|---|---|
| `{serie}_decrypt` | 16 bytes: contraseña de sesión (la que pide la integración) |
| `{serie}_ident` | 32 hex: token de acciones del vehículo (`cmd 0x64`), opcional |

Ambos los emite la nube de Segway en el primer emparejamiento. **No son
derivables**: hay que copiarlos de una instalación que ya los tenga.

```bash
# 1. Finder > iPhone > Crear copia de seguridad ahora,
#    con "Encriptar copia local" DESMARCADO.
# 2. Da Acceso total al disco a tu terminal:
#    Ajustes del Sistema > Privacidad y seguridad > Acceso total al disco
python3 tools/extract_creds.py --sn 1EFGE2513C1181
```

Imprime `pwd : <32 hex>`. Eso es lo que se pega en el formulario de alta.

> Esa contraseña abre tu patinete por BLE. Trátala como una llave.

## Herramientas de diagnóstico

```bash
pip install bleak bleak-retry-connector cryptography

python3 tools/probe_f3.py scan                       # patinetes cercanos + authV2/V3
python3 tools/probe_f3.py probe -a <MAC> -n <SERIE>  # handshake PRE_COMM, solo lectura
python3 tools/probe_f3.py dump  -a <MAC> -n <SERIE> -p <PWD32>
```

`dump` autentica, detecta qué byte de placa responde como VCU y vuelca cada
registro **en crudo y escalado**. Es lo que hay que usar para confirmar las
escalas marcadas `# verificar` en `nb/protocol.py`.

Ninguno de los tres ejecuta `SET_PWD`.

## Lo que se expone

Sensores de la placa VCU: batería, velocidad, kilometraje total y del trayecto,
autonomía restante, temperatura, tiempo de conducción y de encendido, modo de
conducción, códigos de error y aviso. De las BMS 1 y 2: tensión, corriente,
carga y temperatura. Más el interruptor *Sondeo BLE*.

Solo lectura. Las escrituras documentadas (luces, velocidad máxima, `openAcc`)
no están implementadas: `openAcc` además necesita el `ident`.

## Detalles del protocolo

| | |
|---|---|
| Familia | `eKickScooter F3`, hardware id 259 (0x103) |
| Trama | Proto2, sync `0x5A 0xA5` |
| Cifrado | Encryption2: AES-128 CTR no estándar + CBC-MAC de 4 bytes |
| Clave | `SHA-1(key1‖key2)[:16]`; en `PRE_COMM`, key1 = nombre BLE, key2 = `FW_DATA` |
| Transporte | Nordic UART: write `6e400002-b5a3-…`, notify `6e400003-b5a3-…` |
| Fabricante | **17230 (0x434E, "CN")**, id secundario; versión de auth en el offset 2 |
| Registros | placa `vcu`; el F3 no expone `dis`, a diferencia de los F-series antiguos |

El F3 publica además el servicio propietario `6e400001-0000-0000-006e-696e65626f74`,
pero la unidad probada **solo responde por Nordic UART**.

```bash
python3 tests/test_protocol.py   # 8 comprobaciones contra una trama real capturada
```

## Créditos y aviso legal

`nb/crypto.py` deriva de [segway-ninebot-ble-cli](https://codeberg.org/NootNooot/segway-ninebot-ble-cli)
(Apache-2.0); el mapa de registros, de [segway-ninebot-ble](https://codeberg.org/NootNooot/segway-ninebot-ble).
Ver [NOTICE](NOTICE).

Proyecto no oficial, sin relación con Segway Inc. ni Ninebot. Ingeniería inversa
con fines de interoperabilidad. Úsalo solo con vehículos de tu propiedad.
