"""Seed built-in meme pack for team chat.

Creates SVG-based memes in static/memes/ and registers them in the database.
Idempotent — skips memes that already exist by name.
"""

import logging
from pathlib import Path

logger = logging.getLogger(__name__)

# Directory where meme files live
MEME_DIR = Path(__file__).parent.parent / "web" / "static" / "memes"

# Built-in meme definitions: (name, svg_content)
BUILTIN_MEMES = {
    "this_is_fine": (
        "This Is Fine",
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="64" height="64">'
        '<rect width="64" height="64" rx="8" fill="#ff6b35"/>'
        '<text x="32" y="20" text-anchor="middle" font-size="24">🔥</text>'
        '<text x="32" y="42" text-anchor="middle" font-family="sans-serif" font-size="8" '
        'fill="white" font-weight="bold">THIS IS</text>'
        '<text x="32" y="54" text-anchor="middle" font-family="sans-serif" font-size="8" '
        'fill="white" font-weight="bold">FINE</text></svg>'
    ),
    "lgtm": (
        "Looks Good To Me",
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="64" height="64">'
        '<rect width="64" height="64" rx="8" fill="#3fb950"/>'
        '<text x="32" y="28" text-anchor="middle" font-size="20">✅</text>'
        '<text x="32" y="48" text-anchor="middle" font-family="sans-serif" font-size="11" '
        'fill="white" font-weight="bold">LGTM</text></svg>'
    ),
    "ship_it": (
        "Ship It",
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="64" height="64">'
        '<rect width="64" height="64" rx="8" fill="#58a6ff"/>'
        '<text x="32" y="28" text-anchor="middle" font-size="22">🚀</text>'
        '<text x="32" y="50" text-anchor="middle" font-family="sans-serif" font-size="9" '
        'fill="white" font-weight="bold">SHIP IT</text></svg>'
    ),
    "facepalm": (
        "Facepalm",
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="64" height="64">'
        '<rect width="64" height="64" rx="8" fill="#484f58"/>'
        '<text x="32" y="38" text-anchor="middle" font-size="36">🤦</text></svg>'
    ),
    "alert_fatigue": (
        "Alert Fatigue",
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="64" height="64">'
        '<rect width="64" height="64" rx="8" fill="#da3633"/>'
        '<text x="32" y="20" text-anchor="middle" font-size="16">🔔🔔🔔</text>'
        '<text x="32" y="40" text-anchor="middle" font-family="sans-serif" font-size="7" '
        'fill="white" font-weight="bold">ALERT</text>'
        '<text x="32" y="52" text-anchor="middle" font-family="sans-serif" font-size="7" '
        'fill="white" font-weight="bold">FATIGUE</text></svg>'
    ),
    "false_positive": (
        "False Positive",
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="64" height="64">'
        '<rect width="64" height="64" rx="8" fill="#d29922"/>'
        '<text x="32" y="26" text-anchor="middle" font-size="20">🙄</text>'
        '<text x="32" y="44" text-anchor="middle" font-family="sans-serif" font-size="7" '
        'fill="white" font-weight="bold">FALSE</text>'
        '<text x="32" y="56" text-anchor="middle" font-family="sans-serif" font-size="7" '
        'fill="white" font-weight="bold">POSITIVE</text></svg>'
    ),
    "suspicious": (
        "Suspicious",
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="64" height="64">'
        '<rect width="64" height="64" rx="8" fill="#6e40c9"/>'
        '<text x="32" y="38" text-anchor="middle" font-size="34">🤨</text></svg>'
    ),
    "coffee": (
        "Coffee Time",
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="64" height="64">'
        '<rect width="64" height="64" rx="8" fill="#8b6914"/>'
        '<text x="32" y="38" text-anchor="middle" font-size="34">☕</text></svg>'
    ),
    "panic": (
        "Panic",
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="64" height="64">'
        '<rect width="64" height="64" rx="8" fill="#f85149"/>'
        '<text x="32" y="26" text-anchor="middle" font-size="22">😱</text>'
        '<text x="32" y="50" text-anchor="middle" font-family="sans-serif" font-size="9" '
        'fill="white" font-weight="bold">PANIC</text></svg>'
    ),
    "nailed_it": (
        "Nailed It",
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="64" height="64">'
        '<rect width="64" height="64" rx="8" fill="#238636"/>'
        '<text x="32" y="26" text-anchor="middle" font-size="22">💪</text>'
        '<text x="32" y="50" text-anchor="middle" font-family="sans-serif" font-size="8" '
        'fill="white" font-weight="bold">NAILED IT</text></svg>'
    ),
    "thinking": (
        "Thinking",
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="64" height="64">'
        '<rect width="64" height="64" rx="8" fill="#1f6feb"/>'
        '<text x="32" y="38" text-anchor="middle" font-size="34">🤔</text></svg>'
    ),
    "mind_blown": (
        "Mind Blown",
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="64" height="64">'
        '<rect width="64" height="64" rx="8" fill="#8957e5"/>'
        '<text x="32" y="38" text-anchor="middle" font-size="34">🤯</text></svg>'
    ),
    "friday_deploy": (
        "Friday Deploy",
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="64" height="64">'
        '<rect width="64" height="64" rx="8" fill="#b62324"/>'
        '<text x="32" y="20" text-anchor="middle" font-size="16">💀</text>'
        '<text x="32" y="38" text-anchor="middle" font-family="sans-serif" font-size="7" '
        'fill="white" font-weight="bold">FRIDAY</text>'
        '<text x="32" y="50" text-anchor="middle" font-family="sans-serif" font-size="7" '
        'fill="white" font-weight="bold">DEPLOY</text></svg>'
    ),
    "escalate": (
        "Escalate",
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="64" height="64">'
        '<rect width="64" height="64" rx="8" fill="#f0883e"/>'
        '<text x="32" y="26" text-anchor="middle" font-size="22">⬆️</text>'
        '<text x="32" y="50" text-anchor="middle" font-family="sans-serif" font-size="7" '
        'fill="white" font-weight="bold">ESCALATE</text></svg>'
    ),
    "incident": (
        "Incident",
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="64" height="64">'
        '<rect width="64" height="64" rx="8" fill="#da3633"/>'
        '<text x="32" y="26" text-anchor="middle" font-size="22">🚨</text>'
        '<text x="32" y="50" text-anchor="middle" font-family="sans-serif" font-size="7" '
        'fill="white" font-weight="bold">INCIDENT</text></svg>'
    ),
    "nice_catch": (
        "Nice Catch",
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="64" height="64">'
        '<rect width="64" height="64" rx="8" fill="#1a7f37"/>'
        '<text x="32" y="24" text-anchor="middle" font-size="18">🎯</text>'
        '<text x="32" y="44" text-anchor="middle" font-family="sans-serif" font-size="7" '
        'fill="white" font-weight="bold">NICE</text>'
        '<text x="32" y="56" text-anchor="middle" font-family="sans-serif" font-size="7" '
        'fill="white" font-weight="bold">CATCH</text></svg>'
    ),
    "no_sleep": (
        "No Sleep",
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="64" height="64">'
        '<rect width="64" height="64" rx="8" fill="#30363d"/>'
        '<text x="32" y="26" text-anchor="middle" font-size="22">😴</text>'
        '<text x="32" y="50" text-anchor="middle" font-family="sans-serif" font-size="8" '
        'fill="#8b949e" font-weight="bold">NO SLEEP</text></svg>'
    ),
    "patched": (
        "Patched",
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="64" height="64">'
        '<rect width="64" height="64" rx="8" fill="#238636"/>'
        '<text x="32" y="26" text-anchor="middle" font-size="20">🩹</text>'
        '<text x="32" y="50" text-anchor="middle" font-family="sans-serif" font-size="8" '
        'fill="white" font-weight="bold">PATCHED</text></svg>'
    ),
    "threat_hunting": (
        "Threat Hunting",
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="64" height="64">'
        '<rect width="64" height="64" rx="8" fill="#0d1117"/>'
        '<text x="32" y="26" text-anchor="middle" font-size="20">🔍</text>'
        '<text x="32" y="44" text-anchor="middle" font-family="sans-serif" font-size="6" '
        'fill="#00e5ff" font-weight="bold">THREAT</text>'
        '<text x="32" y="56" text-anchor="middle" font-family="sans-serif" font-size="6" '
        'fill="#00e5ff" font-weight="bold">HUNTING</text></svg>'
    ),
    "gg": (
        "Good Game",
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="64" height="64">'
        '<rect width="64" height="64" rx="8" fill="#58a6ff"/>'
        '<text x="32" y="26" text-anchor="middle" font-size="20">🎮</text>'
        '<text x="32" y="50" text-anchor="middle" font-family="sans-serif" font-size="14" '
        'fill="white" font-weight="bold">GG</text></svg>'
    ),
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
        # Get admin user for uploaded_by
        admin = session.execute(
            select(User).where(User.username == "admin")
        ).scalar_one_or_none()
        if not admin:
            logger.debug("No admin user found, skipping meme seeding")
            return

        # Ensure meme directory exists
        MEME_DIR.mkdir(parents=True, exist_ok=True)

        created = 0
        for name, (desc, svg_content) in BUILTIN_MEMES.items():
            # Check if already registered
            existing = session.execute(
                select(ChatMeme).where(ChatMeme.name == name)
            ).scalar_one_or_none()
            if existing:
                continue

            # Write SVG file
            filename = f"{name}.svg"
            filepath = MEME_DIR / filename
            if not filepath.exists():
                filepath.write_text(svg_content, encoding="utf-8")

            # Register in DB
            meme = ChatMeme(
                name=name,
                filename=filename,
                uploaded_by_id=admin.id,
            )
            session.add(meme)
            created += 1

        session.commit()
        if created:
            logger.info("Seeded %d built-in memes (%d total available)", created, len(BUILTIN_MEMES))
        else:
            logger.debug("Built-in memes already seeded")

    except Exception as e:
        session.rollback()
        raise
    finally:
        session.close()
