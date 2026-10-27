import asyncio
import os
import unittest
from types import SimpleNamespace
from uuid import uuid4

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost/test")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")
os.environ.setdefault("JWT_SECRET_KEY", "test-only-secret")

from app.db.models import User, UserNotification
from app.routes.notifications import list_notifications, mark_all_notifications_read, mark_notification_read
from app.services.notifications import create_scan_risk_notification


class NotificationFakeDB:
    def __init__(self, preference=None, rows=None, unread=0):
        self.preference = preference
        self.rows = rows or []
        self.unread = unread
        self.statements = []
        self.added = []
        self.commits = 0

    def add(self, value):
        self.added.append(value)

    async def execute(self, statement):
        self.statements.append(statement)
        sql = str(statement).lower()
        if sql.startswith("update"):
            return SimpleNamespace(rowcount=1)
        if "user_preferences" in sql:
            return SimpleNamespace(scalar_one_or_none=lambda: self.preference)
        if "count(" in sql:
            return SimpleNamespace(scalar_one=lambda: self.unread)
        return SimpleNamespace(scalars=lambda: SimpleNamespace(all=lambda: self.rows))

    async def commit(self):
        self.commits += 1


class NotificationTests(unittest.TestCase):
    def setUp(self):
        self.user = User(id=uuid4(), name="Test", email="test@example.com", password_hash="unused", is_active=True)

    def test_only_enabled_genuine_high_or_critical_events_create_notifications(self):
        async def scenario():
            db = NotificationFakeDB(preference=SimpleNamespace(notify_high_risk=True, notify_critical_risk=False))
            self.assertTrue(await create_scan_risk_notification(db, self.user.id, "high", uuid4()))
            self.assertFalse(await create_scan_risk_notification(db, self.user.id, "critical", uuid4()))
            self.assertFalse(await create_scan_risk_notification(db, self.user.id, "safe", None))
            self.assertEqual(len(db.added), 1)
            self.assertIsInstance(db.added[0], UserNotification)
            self.assertEqual(db.added[0].message, "A completed scan was classified as high risk.")
            self.assertIsNotNone(db.added[0].link_path)
        asyncio.run(scenario())

    def test_list_and_read_mutations_are_scoped_to_the_signed_in_user(self):
        async def scenario():
            notification = UserNotification(id=uuid4(), user_id=self.user.id, event_type="scan_high_risk", title="High-risk scan result", message="A completed scan was classified as high risk.", created_at=__import__("datetime").datetime.now(__import__("datetime").timezone.utc))
            db = NotificationFakeDB(rows=[notification], unread=3)
            response = await list_notifications(self.user, db)
            self.assertEqual(response.unread_count, 3)
            self.assertEqual(response.items[0].id, notification.id)
            self.assertTrue(all(self.user.id in statement.compile().params.values() for statement in db.statements))

            db.statements.clear()
            await mark_notification_read(notification.id, self.user, db)
            self.assertIn(self.user.id, db.statements[0].compile().params.values())
            db.statements.clear()
            await mark_all_notifications_read(self.user, db)
            self.assertIn(self.user.id, db.statements[0].compile().params.values())
            self.assertEqual(db.commits, 2)
        asyncio.run(scenario())


if __name__ == "__main__":
    unittest.main()
