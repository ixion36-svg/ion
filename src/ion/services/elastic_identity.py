"""Which Elastic user profile belongs to which ION user.

Kibana case assignees are Elastic profile UIDs, and ION maps a UID back to an
ION user through ``users.elastic_uid``. A user can set their own
``elastic_username`` (PUT /auth/profile), so the name looked up is chosen by
the person it is looked up for. Two rules keep that from binding someone
else's profile:

- a profile whose email differs from the ION user's email is not theirs;
- a UID another ION user already holds is never stored a second time.

Known limit: an Elastic profile with no email, not yet bound to anyone, can
still be claimed by a user who names it. An administrator sets
``elastic_uid`` directly where that matters.
"""

from __future__ import annotations

from typing import Any, Optional


def profile_email(profile: Any) -> str:
    user = profile.get("user") if isinstance(profile, dict) else None
    email = user.get("email") if isinstance(user, dict) else None
    return str(email or "").strip().lower()


def email_conflicts(profile: Any, email: Optional[str]) -> bool:
    """True when both sides have an email and they differ."""
    theirs = profile_email(profile)
    ours = str(email or "").strip().lower()
    return bool(theirs and ours and theirs != ours)


def uid_held_by_another(session: Any, uid: str, user_id: Optional[int]) -> bool:
    """True when a different ION user already holds this Elastic UID."""
    from ion.models.user import User

    q = session.query(User.id).filter(User.elastic_uid == uid)
    if user_id is not None:
        q = q.filter(User.id != user_id)
    return q.first() is not None
