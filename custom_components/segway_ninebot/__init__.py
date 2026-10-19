"""Integracion Segway Ninebot F3 / F3 Pro por BLE."""

from __future__ import annotations

import logging
from datetime import timedelta

from homeassistant.components import bluetooth
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

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
from .nb.client import AuthRejected, NinebotError, NinebotF3Client, NotPaired

_LOGGER = logging.getLogger(__name__)
PLATFORMS = [Platform.SENSOR, Platform.SWITCH]

type NinebotConfigEntry = ConfigEntry[NinebotCoordinator]


class NinebotCoordinator(DataUpdateCoordinator[dict[str, object]]):
    """Sondea el patinete liberando el radio entre lecturas."""

    def __init__(self, hass: HomeAssistant, entry: NinebotConfigEntry) -> None:
        self.address: str = entry.data["address"]
        self._client = NinebotF3Client(
            bt_name=entry.data[CONF_BT_NAME],
            password=bytes.fromhex(entry.data[CONF_PASSWORD_HEX]),
            gen=entry.data.get(CONF_GEN, 2),
            vcu_board=entry.data.get(CONF_VCU_BOARD, proto.BOARD_VCU),
        )
        self.polling_enabled = True
        self._static_done = False
        super().__init__(
            hass,
            _LOGGER,
            name=f"{DOMAIN} {self.address}",
            update_interval=timedelta(
                seconds=entry.options.get(CONF_SCAN_INTERVAL_S, DEFAULT_SCAN_INTERVAL_S)
            ),
        )

    @property
    def serial(self) -> str | None:
        return self._client.serial

    async def _async_update_data(self) -> dict[str, object]:
        if not self.polling_enabled:
            # Pausa manual: el usuario esta usando la app oficial.
            return self.data or {}

        device = bluetooth.async_ble_device_from_address(self.hass, self.address, True)
        if device is None:
            raise UpdateFailed(f"{self.address} fuera de alcance o apagado")

        keys = [r.key for r in proto.REGISTERS if not r.static or not self._static_done]
        try:
            values = await self._client.async_read_all(device, keys)
        except (AuthRejected, NotPaired) as err:
            raise ConfigEntryAuthFailed(str(err)) from err
        except (NinebotError, TimeoutError, OSError) as err:
            raise UpdateFailed(str(err)) from err

        if any(proto.REGISTERS_BY_KEY[k].static for k in values):
            self._static_done = True
        # Los estaticos solo se leen una vez: conserva los de la pasada anterior.
        return {**(self.data or {}), **values}


async def async_setup_entry(hass: HomeAssistant, entry: NinebotConfigEntry) -> bool:
    coordinator = NinebotCoordinator(hass, entry)
    await coordinator.async_config_entry_first_refresh()
    entry.runtime_data = coordinator
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    entry.async_on_unload(entry.add_update_listener(_async_reload))
    return True


async def async_unload_entry(hass: HomeAssistant, entry: NinebotConfigEntry) -> bool:
    return await hass.config_entries.async_unload_platforms(entry, PLATFORMS)


async def _async_reload(hass: HomeAssistant, entry: NinebotConfigEntry) -> None:
    await hass.config_entries.async_reload(entry.entry_id)
