"""Seed built-in meme pack for team chat.

Registers bundled meme images (in static/memes/) into the database.
Images are shipped with the application — no network downloads needed.
Idempotent.
"""

import logging
from pathlib import Path

logger = logging.getLogger(__name__)

MEME_DIR = Path(__file__).parent.parent / "web" / "static" / "memes"

# name -> filename (files already exist in static/memes/)
BUILTIN_MEMES = {
    "this_is_fine":      "this_is_fine.gif",
    "this_is_fine_fire": "this_is_fine_fire.gif",
    "lgtm":              "lgtm.png",
    "ship_it":           "ship_it.png",
    "facepalm":          "facepalm.png",
    "panic":             "panic.gif",
    "mild_panic":        "mild_panic.gif",
    "coffee":            "coffee.gif",
    "incident":          "incident.png",
    "escalate":          "escalate.png",
    "nice_catch":        "nice_catch.png",
    "nailed_it":         "nailed_it.gif",
    "thinking":          "thinking.gif",
    "mind_blown":        "mind_blown.gif",
    "friday_deploy":     "friday_deploy.gif",
    "suspicious":        "suspicious.gif",
    "no_sleep":          "no_sleep.jpg",
    "threat_hunting":    "threat_hunting.gif",
    "partyparrot":       "partyparrot.gif",
    "dumpster_fire":     "dumpster_fire.gif",
    "deal_with_it":      "deal_with_it.png",
    "alert_fatigue":     "alert_fatigue.gif",
    "all_the_things":    "all_the_things.jpg",
    "doge":              "doge.png",
    "blinkingguy":       "blinkingguy.gif",
    "false_positive":    "false_positive.png",
    "gg":                "gg.png",
    "patched":           "patched.png",
}


def seed_memes():
    """Seed built-in meme images and register in database. Idempotent."""
    from ion.storage.database import get_engine, get_session_factory
    from ion.core.config import get_config
    from ion.models.chat import ChatMeme
    from ion.models.user import User
    from sqlalchemy import select

    config = get_config()
    engine = get_engine(config.db_path)
    factory = get_session_factory(engine)
    session = factory()

    try:
        admin = session.execute(
            select(User).where(User.username == "admin")
        ).scalar_one_or_none()
        if not admin:
            logger.debug("No admin user yet, skipping meme seeding")
            return

        created = 0

        for name, filename in BUILTIN_MEMES.items():
            existing = session.execute(
                select(ChatMeme).where(ChatMeme.name == name)
            ).scalar_one_or_none()
            if existing:
                continue

            filepath = MEME_DIR / filename
            if not filepath.exists():
                logger.warning("Meme file missing: %s", filepath)
                continue

            meme = ChatMeme(name=name, filename=filename, uploaded_by_id=admin.id)
            session.add(meme)
            created += 1

        session.commit()
        if created:
            logger.info("Seeded %d built-in memes (%d total)", created, len(BUILTIN_MEMES))
    except Exception as e:
        session.rollback()
        raise
    finally:
        session.close()
