"""Interruptor para ceder el radio BLE a la app oficial."""

from __future__ import annotations

from typing import Any

from homeassistant.components.switch import SwitchEntity, SwitchEntityDescription
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from . import NinebotConfigEntry
from .entity import NinebotEntity

DESCRIPTION = SwitchEntityDescription(
    key="polling",
    translation_key="polling",
    entity_category=EntityCategory.CONFIG,
)


async def async_setup_entry(
    hass: HomeAssistant, entry: NinebotConfigEntry, async_add_entities: AddEntitiesCallback
) -> None:
    async_add_entities([NinebotPollingSwitch(entry.runtime_data)])


class NinebotPollingSwitch(NinebotEntity, SwitchEntity):
    """Apagado, Home Assistant no conecta: el patinete queda libre para la app.

    El modulo BLE acepta un unico central a la vez, asi que durante un sondeo
    la app de Segway no puede conectarse. Apaga esto mientras conduces.
    """

    entity_description = DESCRIPTION

    def __init__(self, coordinator) -> None:
        super().__init__(coordinator, DESCRIPTION.key)

    @property
    def available(self) -> bool:
        return True  # debe poder apagarse aunque el patinete este fuera de alcance

    @property
    def is_on(self) -> bool:
        return self.coordinator.polling_enabled

    async def async_turn_on(self, **kwargs: Any) -> None:
        self.coordinator.polling_enabled = True
        self.async_write_ha_state()
        await self.coordinator.async_request_refresh()

    async def async_turn_off(self, **kwargs: Any) -> None:
        self.coordinator.polling_enabled = False
        self.async_write_ha_state()
