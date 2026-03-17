"""Seed role-based group chat rooms on startup.

Creates system-managed chat rooms for each role group and auto-adds members
based on their roles.  Idempotent -- skips rooms that already exist and
reconciles memberships on every run.
"""

import logging
from sqlalchemy import select

logger = logging.getLogger(__name__)

# Role name -> room config
ROLE_ROOMS = [
    {
        "name": "SOC Analysts",
        "roles": ["analyst", "senior_analyst", "principal_analyst"],
    },
    {
        "name": "Engineering",
        "roles": ["engineering"],
    },
    {
        "name": "SOC Leads",
        "roles": ["lead"],
    },
    {
        "name": "Forensics",
        "roles": ["forensic"],
    },
    {
        "name": "All Hands",
        "roles": ["analyst", "senior_analyst", "principal_analyst", "lead", "forensic", "engineering", "admin"],
    },
]


def seed_chat_rooms():
    """Create role-based group chat rooms and reconcile memberships. Idempotent."""
    from ion.storage.database import get_engine, get_session_factory
    from ion.core.config import get_config
    from ion.models.chat import ChatRoom, ChatRoomMember
    from ion.models.user import User, Role, user_roles

    config = get_config()
    engine = get_engine(config.db_path)
    factory = get_session_factory(engine)
    session = factory()

    try:
        # Need an admin user as the creator
        admin = session.execute(
            select(User).where(User.username == "admin")
        ).scalar_one_or_none()
        if not admin:
            logger.debug("No admin user yet, skipping chat room seeding")
            return

        created = 0
        members_added = 0

        for room_cfg in ROLE_ROOMS:
            # Find or create the room
            room = session.execute(
                select(ChatRoom).where(
                    ChatRoom.name == room_cfg["name"],
                    ChatRoom.is_system == True,
                )
            ).scalar_one_or_none()

            if not room:
                room = ChatRoom(
                    name=room_cfg["name"],
                    room_type="group",
                    created_by_id=admin.id,
                    is_system=True,
                )
                session.add(room)
                session.flush()  # get room.id
                created += 1

            # Gather users who have any of the specified roles
            role_names = room_cfg["roles"]
            users_with_roles = session.execute(
                select(User).join(user_roles).join(Role).where(
                    Role.name.in_(role_names),
                    User.is_active == True,
                )
            ).scalars().all()

            # Deduplicate (a user may have multiple matching roles)
            user_ids = {u.id for u in users_with_roles}

            # Get existing member IDs for this room
            existing_member_ids = {
                row[0] for row in session.execute(
                    select(ChatRoomMember.user_id).where(
                        ChatRoomMember.room_id == room.id
                    )
                ).all()
            }

            # Add missing members
            for uid in user_ids:
                if uid not in existing_member_ids:
                    session.add(ChatRoomMember(room_id=room.id, user_id=uid))
                    members_added += 1

        session.commit()
        if created or members_added:
            logger.info(
                "Chat rooms: %d created, %d members added across %d rooms",
                created, members_added, len(ROLE_ROOMS),
            )
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
