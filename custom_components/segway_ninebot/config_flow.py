"""Alta de la integracion: descubrimiento BLE + credencial importada de la app."""

from __future__ import annotations

import logging
from typing import Any

import voluptuous as vol
from homeassistant.components.bluetooth import BluetoothServiceInfoBleak
from homeassistant.config_entries import ConfigFlow, ConfigFlowResult, OptionsFlow
from homeassistant.core import callback

from .const import (
    CONF_BT_NAME,
    CONF_GEN,
    CONF_PASSWORD_HEX,
    CONF_SCAN_INTERVAL_S,
    CONF_VCU_BOARD,
    DEFAULT_SCAN_INTERVAL_S,
    DOMAIN,
)
from .nb import protocol as proto
from .nb.client import detect_auth_version

_LOGGER = logging.getLogger(__name__)


def _normalise_password(raw: str) -> bytes:
    cleaned = raw.strip().lower().replace(" ", "").replace(":", "")
    if len(cleaned) != 32:
        raise ValueError("longitud")
    return bytes.fromhex(cleaned)  # ValueError si no es hex


class NinebotF3ConfigFlow(ConfigFlow, domain=DOMAIN):
    """Pide direccion, nombre BLE y la contrasena exportada de la app."""

    VERSION = 1

    def __init__(self) -> None:
        self._discovered: dict[str, str] = {}  # address -> nombre BLE

    async def async_step_bluetooth(
        self, discovery_info: BluetoothServiceInfoBleak
    ) -> ConfigFlowResult:
        await self.async_set_unique_id(discovery_info.address)
        self._abort_if_unique_id_configured()
        name = discovery_info.name or discovery_info.address
        self._discovered = {discovery_info.address: name}
        self.context["title_placeholders"] = {"name": name}
        if detect_auth_version(discovery_info.manufacturer_data) == 3:
            return self.async_abort(reason="auth_v3")
        return await self.async_step_user()

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        errors: dict[str, str] = {}

        if not self._discovered:
            from homeassistant.components import bluetooth

            for info in bluetooth.async_discovered_service_info(self.hass, False):
                if detect_auth_version(info.manufacturer_data) is not None:
                    self._discovered[info.address] = info.name or info.address

        if user_input is not None:
            try:
                password = _normalise_password(user_input[CONF_PASSWORD_HEX])
            except ValueError:
                errors[CONF_PASSWORD_HEX] = "invalid_password"
            else:
                address = user_input["address"]
                await self.async_set_unique_id(address, raise_on_progress=False)
                self._abort_if_unique_id_configured()
                bt_name = user_input[CONF_BT_NAME].strip()
                return self.async_create_entry(
                    title=bt_name or address,
                    data={
                        "address": address,
                        CONF_BT_NAME: bt_name,
                        CONF_PASSWORD_HEX: password.hex(),
                        CONF_GEN: user_input[CONF_GEN],
                        CONF_VCU_BOARD: proto.BOARD_VCU,
                    },
                )

        default_address = next(iter(self._discovered), "")
        schema = vol.Schema(
            {
                vol.Required("address", default=default_address): (
                    vol.In(self._discovered) if self._discovered else str
                ),
                vol.Required(
                    CONF_BT_NAME, default=self._discovered.get(default_address, "")
                ): str,
                vol.Required(CONF_PASSWORD_HEX): str,
                vol.Required(CONF_GEN, default=2): vol.In({2: "gen2 (0x5AA5)", 3: "gen3 (0x5AB5)"}),
            }
        )
        return self.async_show_form(step_id="user", data_schema=schema, errors=errors)

    async def async_step_reauth(self, _entry_data: dict[str, Any]) -> ConfigFlowResult:
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        entry = self._get_reauth_entry()
        errors: dict[str, str] = {}
        if user_input is not None:
            try:
                password = _normalise_password(user_input[CONF_PASSWORD_HEX])
            except ValueError:
                errors[CONF_PASSWORD_HEX] = "invalid_password"
            else:
                return self.async_update_reload_and_abort(
                    entry, data_updates={CONF_PASSWORD_HEX: password.hex()}
                )
        return self.async_show_form(
            step_id="reauth_confirm",
            data_schema=vol.Schema({vol.Required(CONF_PASSWORD_HEX): str}),
            errors=errors,
        )

    @staticmethod
    @callback
    def async_get_options_flow(config_entry) -> OptionsFlow:
        return NinebotF3OptionsFlow()


class NinebotF3OptionsFlow(OptionsFlow):
    """Intervalo de sondeo: cada lectura ocupa el radio unos segundos."""

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        if user_input is not None:
            return self.async_create_entry(data=user_input)
        current = self.config_entry.options.get(
            CONF_SCAN_INTERVAL_S, DEFAULT_SCAN_INTERVAL_S
        )
        return self.async_show_form(
            step_id="init",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_SCAN_INTERVAL_S, default=current): vol.All(
                        vol.Coerce(int), vol.Range(min=60, max=21600)
                    )
                }
            ),
        )
