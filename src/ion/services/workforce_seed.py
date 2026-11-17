"""A fresh install starts with an induction and starter roles.

Workforce reads everything from role profiles, and nothing created any, so
a new deployment opened on three empty tabs with no hint of what to build
first. This gives it the one profile the Me tab is organised around, the
mandatory induction, and the roles that match ION's own access roles.

The seed runs only while no role profile exists at all. Once a deployment
has one, of its own or from here, its profiles are its own and a restart
never adds to them.

Each starter role is linked to the access role it corresponds to. That link
is what lets Workforce follow the Users page: an account holding ``analyst``
is put on SOC Analyst (L1). Accounts that already hold a role keep it; only
somebody onboarded into a role they do not yet hold has it held back.
"""

import logging

from sqlalchemy.orm import Session

from ion.models.user import Role, User
from ion.models.workforce import (
    KIND_COURSE,
    KIND_DOCUMENT,
    KIND_VETTING,
    PHASE_GATE,
    RoleProfile,
)
from ion.services import workforce_service as wf

logger = logging.getLogger(__name__)

INDUCTION_NAME = "Mandatory Induction"

INDUCTION_ITEMS = (
    ("Right to work and identity check", KIND_VETTING, None),
    ("Acceptable use and monitoring agreement", KIND_DOCUMENT, 12),
    ("Security awareness induction", KIND_COURSE, 12),
    ("Data handling and classification", KIND_COURSE, 12),
)

#: Catalogue role id to the built-in access role it corresponds to. The
#: rest of the catalogue stays one click away in Setup.
STARTER_ROLES = {
    "l1_soc_analyst": "analyst",
    "l2_soc_analyst": "senior_analyst",
    "l3_soc_analyst": "principal_analyst",
    "soc_lead": "lead",
    "detection_engineer": "senior_engineer",
    "soc_engineer": "platform_engineer",
    "dfir_analyst": "forensic",
    "grc_analyst": "grc",
}


def seed_workforce_defaults(session: Session) -> bool:
    """Create the induction and starter roles on an empty deployment.

    Returns whether anything was created. With nobody able to manage
    Workforce there is no one to publish as, so it waits for the next start.
    """
    if session.query(RoleProfile.id).first() is not None:
        return False
    publisher = wf.a_workforce_manager(session)
    if publisher is None:
        logger.info("Workforce defaults not seeded: no account can manage Workforce yet")
        return False

    induction = wf.create_profile(
        session, name=INDUCTION_NAME, is_baseline=True,
        description=(
            "Everyone gets this automatically when their account is created. "
            "Nothing here is role-specific. Edit the items to match your own "
            "vetting and agreements."
        ),
    )
    version = wf.draft_version(session, induction)
    for ordering, (name, kind, validity) in enumerate(INDUCTION_ITEMS):
        wf.add_requirement(session, version, name=name, kind=kind,
                           phase=PHASE_GATE, validity_months=validity,
                           ordering=ordering)
    session.commit()
    wf.publish_version(session, version, publisher)

    for role_id, access_role in STARTER_ROLES.items():
        profile = wf.adopt_catalogue_role(session, role_id, adopter=publisher)
        draft = wf.draft_version(session, profile)
        granted = session.query(Role).filter(Role.name == access_role).one_or_none()
        if granted is not None:
            profile.grants_role_id = granted.id
            # A profile that grants a role must carry a gate. The person's
            # verified induction items are carried across by name, so this
            # asks nobody for the same thing twice.
            for name, kind, validity in INDUCTION_ITEMS:
                wf.add_requirement(session, draft, name=name, kind=kind,
                                   phase=PHASE_GATE, validity_months=validity)
        session.commit()
        wf.publish_version(session, draft, publisher)

    # Posts for those roles, so the order of battle has seats for the
    # accounts map_existing_accounts is about to put on it.
    wf.establish_from_catalogue(session, actor=publisher)

    logger.info("Seeded the Workforce induction and %d starter roles",
                len(STARTER_ROLES))
    return True


def map_existing_accounts(session: Session) -> int:
    """Put every active account on the profiles of the roles it holds.

    Run on each start, so accounts given their roles before Workforce had
    any profiles are picked up once the profiles exist. Returns how many
    journeys were opened.
    """
    assigner = wf.a_workforce_manager(session)
    if assigner is None:
        return 0
    opened = 0
    for user in session.query(User).filter(User.is_active.is_(True)).order_by(User.id):
        opened += len(wf.follow_held_roles(session, user, assigner=assigner))
    if opened:
        logger.info("Opened %d Workforce journeys from roles accounts already hold", opened)
    return opened
