"""Dashboard widget layout customization service.

Manages per-user dashboard widget positions, visibility, and sizing.
Each user can customize which widgets appear and in what order;
widgets are filtered by the user's active roles.
"""

import json
import logging
from datetime import datetime, timezone

from sqlalchemy import select, func, and_
from sqlalchemy.orm import Session

from ion.models.sla import DashboardLayout

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Available widgets — master list
# ---------------------------------------------------------------------------
AVAILABLE_WIDGETS = [
    {"id": "alert_stats", "name": "Alert Statistics", "default_position": 0, "default_visible": True, "roles": ["analyst", "senior_analyst", "lead", "admin"]},
    {"id": "my_cases", "name": "My Cases", "default_position": 1, "default_visible": True, "roles": ["analyst", "senior_analyst", "lead"]},
    {"id": "recent_alerts", "name": "Recent Alerts", "default_position": 2, "default_visible": True, "roles": ["analyst", "senior_analyst", "lead", "admin"]},
    {"id": "oncall_status", "name": "On-Call Status", "default_position": 3, "default_visible": True, "roles": ["analyst", "senior_analyst", "lead", "admin"]},
    {"id": "sla_compliance", "name": "SLA Compliance", "default_position": 4, "default_visible": True, "roles": ["lead", "admin"]},
    {"id": "team_workload", "name": "Team Workload", "default_position": 5, "default_visible": True, "roles": ["lead", "admin"]},
    {"id": "threat_watches", "name": "Active Threat Watches", "default_position": 6, "default_visible": False, "roles": ["analyst", "senior_analyst", "lead"]},
    {"id": "attack_stories", "name": "Attack Stories", "default_position": 7, "default_visible": False, "roles": ["analyst", "senior_analyst", "lead"]},
    {"id": "soc_health", "name": "SOC Health Score", "default_position": 8, "default_visible": True, "roles": ["lead", "admin", "engineering"]},
    {"id": "integration_status", "name": "Integration Status", "default_position": 9, "default_visible": True, "roles": ["engineering", "admin"]},
    {"id": "active_hunts", "name": "Active Threat Hunts", "default_position": 10, "default_visible": False, "roles": ["senior_analyst", "lead"]},
    {"id": "quick_actions", "name": "Quick Actions", "default_position": 11, "default_visible": True, "roles": ["analyst", "senior_analyst"]},
]

# Lookup by widget id for quick access
_WIDGET_MAP = {w["id"]: w for w in AVAILABLE_WIDGETS}


def get_available_widgets(user_roles: list[str] = None) -> list[dict]:
    """Return available widgets, optionally filtered by user roles.

    Args:
        user_roles: List of role names the user holds.  If ``None`` or
            empty, all widgets are returned.

    Returns:
        List of widget definition dicts with keys:
        id, name, default_position, default_visible, roles.
    """
    if not user_roles:
        return [dict(w) for w in AVAILABLE_WIDGETS]

    return [
        dict(w)
        for w in AVAILABLE_WIDGETS
        if any(role in w["roles"] for role in user_roles)
    ]


def _default_widgets_for_roles(user_roles: list[str] = None) -> list[dict]:
    """Build the default widget list for a set of roles.

    Each widget dict has: id, name, position, visible, size.
    """
    filtered = get_available_widgets(user_roles)
    return [
        {
            "id": w["id"],
            "name": w["name"],
            "position": w["default_position"],
            "visible": w["default_visible"],
            "size": "1x1",
        }
        for w in filtered
    ]


def get_layout(
    session: Session,
    user_id: int,
    user_roles: list[str] = None,
) -> dict:
    """Return the user's dashboard layout.

    If the user has a saved custom layout it is returned (with widget
    metadata merged).  Otherwise the default layout filtered by the
    user's roles is returned.

    Args:
        session: SQLAlchemy database session.
        user_id: ID of the user.
        user_roles: Roles the user holds (used for default filtering).

    Returns:
        Dict with ``user_id``, ``widgets`` list, ``is_custom`` flag,
        and optional ``theme_overrides``.
    """
    layout = session.execute(
        select(DashboardLayout).where(DashboardLayout.user_id == user_id)
    ).scalar_one_or_none()

    if layout is not None:
        try:
            widgets = json.loads(layout.widgets)
        except (json.JSONDecodeError, TypeError):
            logger.warning("Corrupt widget JSON for user %s, returning defaults", user_id)
            widgets = _default_widgets_for_roles(user_roles)

        # Enrich stored widgets with canonical names from master list
        enriched = []
        for w in widgets:
            master = _WIDGET_MAP.get(w.get("id"))
            enriched.append({
                "id": w.get("id"),
                "name": master["name"] if master else w.get("name", "Unknown"),
                "position": w.get("position", 0),
                "visible": w.get("visible", True),
                "size": w.get("size", "1x1"),
            })

        theme_overrides = None
        if layout.theme_overrides:
            try:
                theme_overrides = json.loads(layout.theme_overrides)
            except (json.JSONDecodeError, TypeError):
                theme_overrides = None

        return {
            "user_id": user_id,
            "widgets": enriched,
            "is_custom": True,
            "theme_overrides": theme_overrides,
        }

    # No saved layout — return role-filtered defaults
    return {
        "user_id": user_id,
        "widgets": _default_widgets_for_roles(user_roles),
        "is_custom": False,
        "theme_overrides": None,
    }


def save_layout(
    session: Session,
    user_id: int,
    widgets: list[dict],
) -> dict:
    """Save a user's custom widget layout.

    Args:
        session: SQLAlchemy database session.
        user_id: ID of the user.
        widgets: List of widget dicts (id, position, visible, size).

    Returns:
        The saved layout dict.
    """
    # Normalise each widget entry
    cleaned = []
    for w in widgets:
        master = _WIDGET_MAP.get(w.get("id"))
        cleaned.append({
            "id": w.get("id"),
            "name": master["name"] if master else w.get("name", "Unknown"),
            "position": w.get("position", 0),
            "visible": w.get("visible", True),
            "size": w.get("size", "1x1"),
        })

    layout = session.execute(
        select(DashboardLayout).where(DashboardLayout.user_id == user_id)
    ).scalar_one_or_none()

    if layout is None:
        layout = DashboardLayout(user_id=user_id, widgets=json.dumps(cleaned))
        session.add(layout)
    else:
        layout.widgets = json.dumps(cleaned)

    session.commit()
    session.refresh(layout)

    return {
        "user_id": user_id,
        "widgets": cleaned,
        "is_custom": True,
        "theme_overrides": None,
    }


def reset_layout(
    session: Session,
    user_id: int,
) -> dict:
    """Delete a user's custom layout and return defaults.

    Args:
        session: SQLAlchemy database session.
        user_id: ID of the user.

    Returns:
        The default layout dict (``is_custom`` will be ``False``).
    """
    layout = session.execute(
        select(DashboardLayout).where(DashboardLayout.user_id == user_id)
    ).scalar_one_or_none()

    if layout is not None:
        session.delete(layout)
        session.commit()

    return {
        "user_id": user_id,
        "widgets": _default_widgets_for_roles(),
        "is_custom": False,
        "theme_overrides": None,
    }
