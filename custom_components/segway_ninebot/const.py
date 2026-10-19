"""Constantes de la integracion."""

DOMAIN = "segway_ninebot"

CONF_BT_NAME = "bt_name"
CONF_PASSWORD_HEX = "password_hex"
CONF_GEN = "gen"
CONF_VCU_BOARD = "vcu_board"
CONF_SCAN_INTERVAL_S = "scan_interval_s"

# Un sondeo ocupa el radio del patinete unos segundos y bloquea a la app de
# Segway mientras dura. 5 minutos es un compromiso razonable; es configurable.
# 15 min por defecto: cada sondeo conecta por BLE (el patinete pita y gasta algo
# de bateria al despertar el radio), asi que se espacia. Subelo mas si prefieres
# menos pitidos/consumo a cambio de datos menos frescos.
DEFAULT_SCAN_INTERVAL_S = 900
