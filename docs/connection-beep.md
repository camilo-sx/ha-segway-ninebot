# El pitido de conexión — hallazgo de RE

El patinete pita cada vez que un central BLE se conecta y autentica (la app o
Home Assistant). Silenciar el volumen en la app NO lo apaga.

## Qué se investigó
- **APK (`com.ninebot.segway`) empacado con NetEase 易盾**: jadx solo recupera el
  envoltorio `com.netease.nis.wrapper.*`; el `classes.dex` real se descifra en
  runtime. La lógica de sonido-al-conectar no es legible estáticamente (haría
  falta volcado dinámico con frida en un dispositivo con jailbreak).
- **Mapa de protocolo del F3** (RE'd del firmware, proyecto segway-ninebot-ble):
  **no hay un flag documentado de "pitido de conexión"**. Registros de sonido:
  `rWarn` (volumen + efecto), `setVoiceVolume`, `setAlarmLevel` (antirrobo),
  `playSound`. Sin valor documentado: `setConnectMode` y `mediaEnable` (placa
  BLE, cmd `0x6F`, índices `0x0C` y `0x10`).

## Conclusión
El pitido es comportamiento del firmware al conectar/autenticar, no un ajuste de
usuario. Por eso el volumen no lo calla.

## Mitigación aplicada
Sondeo espaciado (15 min por defecto, configurable hasta 6 h). Mantener la
conexión abierta NO es opción: dejaría el BLE del patinete despierto y lo
drenaría. Menos conexiones = menos pitidos y menos consumo.

## A probar en la fase de escritura (con contraseña)
Candidatos a escribir para apagar el pitido, por confirmar en hardware:
`mediaEnable = 0` y valores de `setConnectMode` (BLE, cmd `0x6F`). Requiere la
contraseña de sesión y levantar el modo escritura (hoy la integración es
solo-lectura por diseño).
