"""Sensores leidos de las placas VCU y BMS."""

from __future__ import annotations

from dataclasses import dataclass

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorEntityDescription,
    SensorStateClass,
)
from homeassistant.const import (
    PERCENTAGE,
    EntityCategory,
    UnitOfElectricCurrent,
    UnitOfElectricPotential,
    UnitOfLength,
    UnitOfSpeed,
    UnitOfTemperature,
    UnitOfTime,
)
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from . import NinebotConfigEntry
from .entity import NinebotEntity

_TOTAL = SensorStateClass.TOTAL_INCREASING
_MEAS = SensorStateClass.MEASUREMENT

GEAR_MODES = {0: "normal", 1: "eco", 2: "sport", 3: "custom"}


@dataclass(frozen=True, kw_only=True)
class NinebotSensorDescription(SensorEntityDescription):
    """Descripcion con el mapa opcional de enumerados."""

    options_map: dict[int, str] | None = None


SENSORS: tuple[NinebotSensorDescription, ...] = (
    NinebotSensorDescription(
        key="battery", translation_key="battery", native_unit_of_measurement=PERCENTAGE,
        device_class=SensorDeviceClass.BATTERY, state_class=_MEAS),
    NinebotSensorDescription(
        key="speed", translation_key="speed",
        native_unit_of_measurement=UnitOfSpeed.KILOMETERS_PER_HOUR,
        device_class=SensorDeviceClass.SPEED, state_class=_MEAS),
    NinebotSensorDescription(
        key="total_mileage", translation_key="total_mileage",
        native_unit_of_measurement=UnitOfLength.KILOMETERS,
        device_class=SensorDeviceClass.DISTANCE, state_class=_TOTAL),
    NinebotSensorDescription(
        key="trip_mileage", translation_key="trip_mileage",
        native_unit_of_measurement=UnitOfLength.KILOMETERS,
        device_class=SensorDeviceClass.DISTANCE, state_class=_MEAS),
    NinebotSensorDescription(
        key="left_mileage", translation_key="left_mileage",
        native_unit_of_measurement=UnitOfLength.KILOMETERS,
        device_class=SensorDeviceClass.DISTANCE, state_class=_MEAS),
    NinebotSensorDescription(
        key="precise_mileage", translation_key="precise_mileage",
        native_unit_of_measurement=UnitOfLength.KILOMETERS,
        device_class=SensorDeviceClass.DISTANCE, state_class=_MEAS,
        entity_registry_enabled_default=False),
    NinebotSensorDescription(
        key="body_temp", translation_key="body_temp",
        native_unit_of_measurement=UnitOfTemperature.CELSIUS,
        device_class=SensorDeviceClass.TEMPERATURE, state_class=_MEAS),
    NinebotSensorDescription(
        key="ride_time", translation_key="ride_time",
        native_unit_of_measurement=UnitOfTime.HOURS,
        device_class=SensorDeviceClass.DURATION, state_class=_TOTAL),
    NinebotSensorDescription(
        key="runtime", translation_key="runtime",
        native_unit_of_measurement=UnitOfTime.HOURS,
        device_class=SensorDeviceClass.DURATION, state_class=_TOTAL,
        entity_category=EntityCategory.DIAGNOSTIC),
    NinebotSensorDescription(
        key="trip_time", translation_key="trip_time",
        native_unit_of_measurement=UnitOfTime.SECONDS,
        device_class=SensorDeviceClass.DURATION, state_class=_MEAS,
        entity_registry_enabled_default=False),
    NinebotSensorDescription(
        key="gear_mode", translation_key="gear_mode",
        device_class=SensorDeviceClass.ENUM,
        options=sorted(set(GEAR_MODES.values()) | {"unknown"}),
        options_map=GEAR_MODES),
    NinebotSensorDescription(
        key="error_code", translation_key="error_code",
        entity_category=EntityCategory.DIAGNOSTIC),
    NinebotSensorDescription(
        key="warn_code", translation_key="warn_code",
        entity_category=EntityCategory.DIAGNOSTIC),
    NinebotSensorDescription(
        key="serial_number", translation_key="serial_number",
        entity_category=EntityCategory.DIAGNOSTIC,
        entity_registry_enabled_default=False),
)

for _board in ("bms1", "bms2"):
    SENSORS += (
        NinebotSensorDescription(
            key=f"{_board}_voltage", translation_key=f"{_board}_voltage",
            native_unit_of_measurement=UnitOfElectricPotential.VOLT,
            device_class=SensorDeviceClass.VOLTAGE, state_class=_MEAS,
            entity_category=EntityCategory.DIAGNOSTIC),
        NinebotSensorDescription(
            key=f"{_board}_current", translation_key=f"{_board}_current",
            native_unit_of_measurement=UnitOfElectricCurrent.AMPERE,
            device_class=SensorDeviceClass.CURRENT, state_class=_MEAS,
            entity_category=EntityCategory.DIAGNOSTIC),
        NinebotSensorDescription(
            key=f"{_board}_soc", translation_key=f"{_board}_soc",
            native_unit_of_measurement=PERCENTAGE,
            device_class=SensorDeviceClass.BATTERY, state_class=_MEAS,
            entity_category=EntityCategory.DIAGNOSTIC),
    )
SENSORS += (
    NinebotSensorDescription(
        key="bms1_temp", translation_key="bms1_temp",
        native_unit_of_measurement=UnitOfTemperature.CELSIUS,
        device_class=SensorDeviceClass.TEMPERATURE, state_class=_MEAS,
        entity_category=EntityCategory.DIAGNOSTIC),
)


async def async_setup_entry(
    hass: HomeAssistant, entry: NinebotConfigEntry, async_add_entities: AddEntitiesCallback
) -> None:
    coordinator = entry.runtime_data
    async_add_entities(NinebotSensor(coordinator, d) for d in SENSORS)


class NinebotSensor(NinebotEntity, SensorEntity):
    """Un registro del patinete expuesto como sensor."""

    entity_description: NinebotSensorDescription

    def __init__(self, coordinator, description: NinebotSensorDescription) -> None:
        super().__init__(coordinator, description.key)
        self.entity_description = description

    @property
    def available(self) -> bool:
        return super().available and self.entity_description.key in (self.coordinator.data or {})

    @property
    def native_value(self):
        value = (self.coordinator.data or {}).get(self.entity_description.key)
        if value is None:
            return None
        if self.entity_description.options_map is not None:
            return self.entity_description.options_map.get(int(value), "unknown")
        return value
