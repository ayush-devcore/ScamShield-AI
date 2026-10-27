import asyncio
import os
import unittest
from types import SimpleNamespace
from uuid import uuid4

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost/test")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")
os.environ.setdefault("JWT_SECRET_KEY", "test-only-secret")

from pydantic import ValidationError

from app.db.models import User, UserPreference
from app.routes.preferences import get_appearance, update_appearance, update_notification_preferences, update_privacy_preferences
from app.schemas.preferences import AppearancePreference, NotificationPreferences, PrivacyPreferences


class PreferenceFakeDB:
    def __init__(self, preference=None):
        self.preference = preference
        self.statements = []
        self.commits = 0

    async def execute(self, statement):
        self.statements.append(statement)
        if isinstance(statement, type(UserPreference.__table__.insert())):
            return SimpleNamespace()
        return SimpleNamespace(scalar_one_or_none=lambda: self.preference)

    async def commit(self):
        self.commits += 1


class AppearancePreferenceTests(unittest.TestCase):
    def setUp(self):
        self.user = User(id=uuid4(), name="Test", email="test@example.com", password_hash="unused", is_active=True)

    def test_missing_preference_defaults_to_dark(self):
        async def scenario():
            result = await get_appearance(self.user, PreferenceFakeDB())
            self.assertEqual(result.appearance, "dark")
        asyncio.run(scenario())

    def test_preference_updates_are_scoped_to_authenticated_user(self):
        async def scenario():
            db = PreferenceFakeDB()
            result = await update_appearance(AppearancePreference(appearance="light"), self.user, db)
            self.assertEqual(result.appearance, "light")
            self.assertEqual(db.commits, 1)
            self.assertEqual(db.statements[0].compile().params["user_id"], self.user.id)
        asyncio.run(scenario())

    def test_only_supported_appearance_modes_are_accepted(self):
        for mode in ("dark", "light", "system"):
            self.assertEqual(AppearancePreference(appearance=mode).appearance, mode)
        with self.assertRaises(ValidationError):
            AppearancePreference(appearance="solarized")

    def test_notification_and_history_preferences_are_user_scoped_upserts(self):
        async def scenario():
            notification_db = PreferenceFakeDB()
            notification = NotificationPreferences(high_risk=False, critical_risk=True, security_events=False)
            await update_notification_preferences(notification, self.user, notification_db)
            params = notification_db.statements[0].compile().params
            self.assertEqual(params["user_id"], self.user.id)
            self.assertEqual(params["notify_high_risk"], False)
            self.assertEqual(params["notify_critical_risk"], True)

            privacy_db = PreferenceFakeDB()
            await update_privacy_preferences(PrivacyPreferences(store_scan_history=False), self.user, privacy_db)
            privacy_params = privacy_db.statements[0].compile().params
            self.assertEqual(privacy_params["user_id"], self.user.id)
            self.assertIs(privacy_params["store_scan_history"], False)
        asyncio.run(scenario())


if __name__ == "__main__":
    unittest.main()
