#!/usr/bin/env bash
# Captura el HCI Bluetooth del iPhone por USB mientras re-emparejas el patinete.
# Requiere: pip install pymobiledevice3 ; Modo Desarrollador activo en el iPhone.
#
#   PY=/ruta/al/python tools/bt_capture.sh salida.pcapng
#
# Luego, con la captura:
#   PY=... python3 tools/decode_capture.py salida.pcapng --name <serieBLE>
set -euo pipefail
OUT="${1:-captura_bt.pcapng}"
PY="${PY:-python3}"

cleanup() { [[ -n "${TPID:-}" ]] && kill "$TPID" 2>/dev/null || true; }
trap cleanup EXIT

echo "[1/4] Montando imagen de desarrollo (si hace falta)..."
"$PY" -m pymobiledevice3 mounter auto-mount 2>/dev/null || true

echo "[2/4] Levantando tunel nativo (sin root)..."
TUN=$(mktemp)
"$PY" -m pymobiledevice3 remote start-tunnel --native --script-mode >"$TUN" 2>&1 &
TPID=$!
for _ in $(seq 1 20); do
  RSD=$(grep -Eo '^[0-9a-f:]+ [0-9]+$' "$TUN" | tail -1 || true)
  [[ -n "$RSD" ]] && break
  sleep 0.5
done
[[ -z "${RSD:-}" ]] && { echo "No se pudo abrir el tunel:"; cat "$TUN"; exit 1; }
HOST=$(echo "$RSD" | cut -d' ' -f1); PORT=$(echo "$RSD" | cut -d' ' -f2)
echo "      RSD = $HOST $PORT"

echo "[3/4] Grabando HCI en $OUT"
echo "      >>> AHORA en la app Segway: borra el patinete y vuelve a anadirlo."
echo "      >>> Pulsa el boton del patinete si te lo pide (eso dispara SET_PWD)."
echo "      >>> Cuando termine el emparejamiento, pulsa Ctrl-C aqui."
"$PY" -m pymobiledevice3 btlogger --rsd "$HOST" "$PORT" -f pcapng "$OUT"

echo "[4/4] Captura guardada en $OUT"
