"""Small, controlled audit-event helpers for user-visible security activity."""

from app.db.models import AuditLog


def record_activity(db, user_id, event_type: str, metadata: dict | None = None) -> None:
    """Persist only controlled event metadata; never pass user input to this helper."""
    db.add(AuditLog(user_id=user_id, event_type=event_type, metadata_json=metadata or None))
