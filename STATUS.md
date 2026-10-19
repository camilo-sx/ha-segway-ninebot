# Estado — para retomar

## Listo y verificado
- Integración HACS completa: config flow, coordinator, sensores, switch,
  traducciones ES/EN, icono propio (patineta genérica), manifest con 6 IDs de
  fabricante Ninebot para autodescubrimiento.
- Protocolo BLE Encryption2 + criptografía, portados y **verificados contra la
  unidad real** (serie 1EFGE2513C1181, gen2/authV2).
- **Solo lectura estructural**: sin constructor de SET_PWD + allowlist en
  `_send`. No puede desemparejar la app ni accionar el vehículo.
- 27 pruebas verdes (crypto, protocolo, camino de lectura extremo a extremo con
  patinete simulado, decoder de captura). `for t in tests/test_*.py; do python3 $t; done`
- Base cloud (login passport/business, cifrado) vendorizada y con round-trip
  verde; hosts internacionales (región `ore`) documentados en `docs/`.

## Lo ÚNICO pendiente para conectar en vivo: la contraseña de sesión
No está en la nube (lo confirma el RE del APK: deriva en el dispositivo). Vías,
por preferencia:

1. **Backup (recomendado, no re-empareja):** copia local del iPhone SIN cifrar
   (Finder → "este Mac", no iCloud) → `python3 tools/extract_creds.py --backup
   --sn 1EFGE2513C1181 --out /tmp/segway_pwd.json`. La herramienta ya localiza el
   plist por `Manifest.db`. Bloqueo de anoche: **no había copia local real** (la
   carpeta estaba vacía, Finder apuntaba a iCloud). Al rehacer la copia a "este
   Mac" debería salir.
2. **Captura USB:** `tools/bt_capture.sh` + `decode_capture.py`. Anoche `btlogger`
   no levantó el servicio en iOS 26 por la vía sin root; faltaba probar con
   `sudo remote tunneld`.

Con la contraseña: alta de la integración (dirección BLE + nombre/serie +
contraseña) y a funcionar. El camino de lectura ya está probado en simulación,
así que debería leer en el primer intento.

## Fase futura (opcional): control
`ident` desde la nube (acciones: bloqueo, baúl, `cmd 0x64`). Requiere adaptar el
login al backend internacional (firma distinta, `libnetseckit-4.3.1`). Ver
`STACK_PLAN.md` y `docs/cloud-hosts-intl.md`.

## Recordatorio
Cambiar la contraseña de la **cuenta Segway** (quedó visible en el chat de anoche).
