"""Base comun de las entidades."""

from __future__ import annotations

from homeassistant.helpers.device_registry import CONNECTION_BLUETOOTH, DeviceInfo
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from . import NinebotCoordinator
from .const import DOMAIN


class NinebotEntity(CoordinatorEntity[NinebotCoordinator]):
    """Entidad ligada al patinete."""

    _attr_has_entity_name = True

    def __init__(self, coordinator: NinebotCoordinator, key: str) -> None:
        super().__init__(coordinator)
        self._attr_unique_id = f"{coordinator.address}_{key}"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, coordinator.address)},
            connections={(CONNECTION_BLUETOOTH, coordinator.address)},
            manufacturer="Segway-Ninebot",
            model="KickScooter F3 / F3 Pro",
            name=coordinator.name,
            serial_number=coordinator.serial,
            sw_version=str((coordinator.data or {}).get("firmware_ctrl") or ""),
        )
