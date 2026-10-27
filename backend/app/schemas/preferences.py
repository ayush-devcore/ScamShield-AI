from typing import Literal

from pydantic import BaseModel


AppearanceMode = Literal["dark", "light", "system"]


class AppearancePreference(BaseModel):
    appearance: AppearanceMode


class NotificationPreferences(BaseModel):
    high_risk: bool
    critical_risk: bool
    security_events: bool


class PrivacyPreferences(BaseModel):
    store_scan_history: bool
