"""Coverage of the day-to-day pillars, from three kinds of evidence.

"Are we covered for forensics tomorrow" is three questions that get added
up and should not be:

* somebody whose job it is -- in post, training finished, and the pillar
  is what their role is accountable for;
* somebody who has rated themselves capable in it but does something
  else -- real secondary cover, and self-rated;
* somebody holding a current certificate in it -- examined on it once,
  which is not the same as doing it here every day.

One number hides all of that. Three analysts who each ticked 4 out of 5
on a form is not three forensics analysts, and a dashboard that renders
both as "3" will be believed. So every count stays next to the weighted
total, every person carries the basis they were counted on, and a pillar
resting only on self-rating says so in the headline.

The weights are a judgement and they are deliberately blunt:

* 1.0 for whoever owns the pillar,
* 0.5 for assessed proficiency outside your role,
* 0.25 for a current certificate,

capped at 1.0 per person, because no evidence makes somebody two bodies
on a shift. They are not a measurement. They are a way of saying "half a
person" out loud instead of implying it by putting two kinds of cover in
the same column.

What this cannot tell you: whether a self-rating is accurate, whether
somebody is on leave tomorrow, or whether the one person who owns a
pillar is about to leave. It answers "who could", not "who is rostered".
"""

from __future__ import annotations

import logging
from datetime import date
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from ion.data import skills_matrix as sm
from ion.models.skills import (
    CapabilityThreshold,
    SkillAssessment,
    TeamCertification,
)
from ion.models.user import User
from ion.models.workforce import (
    STAGE_CLOSED,
    STAGE_OPERATIONAL,
    STAGE_SUSPENDED,
    STAGE_WITHDRAWN,
    RoleProfile,
    RoleProfileVersion,
    UserJourney,
)

logger = logging.getLogger(__name__)

#: Whoever owns the pillar. One person doing the job.
PRIMARY_WEIGHT = 1.0
#: Assessed proficiency in a pillar that is not your role's.
SECONDARY_WEIGHT = 0.5
#: A current certificate in the pillar.
CERT_WEIGHT = 0.25
#: The self-rating at which somebody counts as secondary cover.
#: Intermediate. Rating yourself aware of memory forensics is not cover
#: for it, and counting it would make every pillar look staffed.
SECONDARY_MIN_RATING = 3
#: With no threshold set, one person who owns the pillar is cover. Not a
#: recommendation -- a SOC running 24/7 needs more than one of most of
#: these, and the point of CapabilityThreshold is to say so.
DEFAULT_MIN_STAFF = 1

#: Stages that put somebody on the floor.
_LIVE = (STAGE_OPERATIONAL, STAGE_SUSPENDED)
_DEAD = (STAGE_CLOSED, STAGE_WITHDRAWN)


def _catalogue_role(profile: Optional[RoleProfile]) -> Optional[str]:
    """Which catalogue role a profile is, by the most reliable link first.

    ``catalogue_id`` is set on adoption. ``skills_role_id`` uses the same
    vocabulary and covers profiles adopted before that column existed. The
    name is last and only matches an unrenamed one.
    """
    if profile is None:
        return None
    for candidate in (profile.catalogue_id, profile.skills_role_id):
        if candidate and candidate in sm.CATALOGUE_TO_SKILLS_ROLE:
            return candidate
    from ion.data.soc_role_catalogue import SOC_ROLE_CATALOGUE

    for entry in SOC_ROLE_CATALOGUE:
        if entry["name"] == profile.name:
            return entry["id"]
    return None


def _roster(session: Session) -> Dict[int, dict]:
    """Everybody with a live journey, and the matrix role it maps to.

    Baseline journeys are skipped: a baseline is the induction everybody
    does, not a role, so counting it would place every joiner against
    whatever pillars the baseline's name happened to match.
    """
    rows = (
        session.query(UserJourney, RoleProfile)
        .join(RoleProfileVersion,
              RoleProfileVersion.id == UserJourney.version_id)
        .join(RoleProfile, RoleProfile.id == RoleProfileVersion.profile_id)
        .filter(~UserJourney.stage.in_(_DEAD))
        .all()
    )
    user_ids = {j.user_id for j, _ in rows}
    names = {
        u.id: (u.display_name or u.username)
        for u in session.query(User).filter(User.id.in_(user_ids or [0])).all()
    }

    roster: Dict[int, dict] = {}
    for journey, profile in rows:
        if profile.is_baseline:
            continue
        catalogue_id = _catalogue_role(profile)
        skills_role = sm.skills_role_for(catalogue_id) if catalogue_id else None
        entry = roster.setdefault(journey.user_id, {
            "user_id": journey.user_id,
            "name": names.get(journey.user_id, f"user {journey.user_id}"),
            "roles": [],          # every matrix role this person holds
            "profiles": [],
            "operational": False,
            "stages": [],
        })
        entry["profiles"].append(profile.name)
        entry["stages"].append(journey.stage)
        if skills_role:
            # A cover journey counts the same as a primary one here: if
            # somebody is cleared to work a second role, that role's
            # pillars are ones they can actually take.
            if journey.stage == STAGE_OPERATIONAL:
                entry["roles"].append(skills_role)
            entry.setdefault("training_roles", []).append(
                (skills_role, journey.stage))
        else:
            entry["unmapped_profile"] = profile.name
        if journey.stage == STAGE_OPERATIONAL:
            entry["operational"] = True
    return roster


def _ratings(session: Session) -> Dict[int, Dict[str, int]]:
    out: Dict[int, Dict[str, int]] = {}
    for row in session.query(SkillAssessment).all():
        out.setdefault(row.user_id, {})[row.skill_key] = int(row.rating or 0)
    return out


def _certs(session: Session, today: date) -> Dict[int, Dict[str, list]]:
    """Per user: the pillars they hold a current certificate for, and the
    ones where the only certificate has expired.

    The expired list exists because an expired certificate is not nothing.
    It is a renewal somebody has to book, and dropping it silently turns a
    lapsed qualification into an absence nobody can explain.
    """
    out: Dict[int, Dict[str, list]] = {}
    for row in session.query(TeamCertification).all():
        pillars = sm.pillars_for_cert(row.cert_name)
        if not pillars:
            # None means ION has not been taught this certificate, () means
            # it is deliberately not pillar-specific. Neither is coverage,
            # but the first is worth logging -- it is a mapping to add.
            if pillars is None:
                logger.debug("No pillar mapping for certificate %r",
                             row.cert_name)
            continue
        bucket = out.setdefault(row.user_id, {"current": [], "expired": []})
        expired = (row.status or "").lower() == "expired" or (
            row.expiry_date is not None and row.expiry_date < today)
        if (row.status or "").lower() == "planned":
            # A course nobody has sat yet. A development item, not cover.
            continue
        key = "expired" if expired else "current"
        for pillar in pillars:
            if pillar not in bucket[key]:
                bucket[key].append(pillar)
    return out


def _pillar_mean_rating(ratings: Dict[str, int], pillar: str) -> Optional[float]:
    """Somebody's mean self-rating across a pillar, or None if unrated.

    Averaged over the skills they actually rated. Averaging over all of
    them would read an unanswered question as a zero, which turns a
    half-finished form into a declaration of incompetence.
    """
    rated = [ratings[k] for k in sm.skill_keys(pillar) if k in ratings]
    if not rated:
        return None
    return sum(rated) / len(rated)


def pillar_coverage(session: Session, *,
                    today: Optional[date] = None) -> Dict[str, Any]:
    """Who could cover each day-to-day pillar, and on what evidence."""
    today = today or date.today()
    roster = _roster(session)
    ratings = _ratings(session)
    certs = _certs(session, today)
    thresholds = {
        t.capability_key: t
        for t in session.query(CapabilityThreshold).all()
    }

    # "Nobody has recorded anything" and "nobody is capable" look the same
    # on a dashboard and lead somewhere completely different: one sends a
    # lead to chase the team for an afternoon, the other to recruit.
    measured = bool(roster) or bool(ratings) or bool(certs)

    unplaced = [
        {"user_id": r["user_id"], "name": r["name"],
         "profile": r["unmapped_profile"]}
        for r in roster.values()
        if r.get("unmapped_profile") and r["operational"]
    ]

    pillars: List[dict] = []
    for pillar in sm.pillars():
        owners = sm.owners_of(pillar)
        threshold = thresholds.get(pillar)
        min_staff = int(getattr(threshold, "min_staff", None) or
                        DEFAULT_MIN_STAFF)
        min_level = int(getattr(threshold, "min_level", None) or
                        SECONDARY_MIN_RATING)

        people: List[dict] = []
        in_training = 0
        suspended = 0
        expired_certs = 0

        for entry in roster.values():
            owns = any(r in owners for r in entry["roles"])
            if not owns:
                # Somebody partway through training for a role that owns
                # this pillar is the most important number on the page for
                # a lead planning next month, and the most dangerous one
                # to add to the cover.
                for role, stage in entry.get("training_roles", []):
                    if role in owners and stage != STAGE_OPERATIONAL:
                        if stage == STAGE_SUSPENDED:
                            suspended += 1
                        else:
                            in_training += 1
                        break

            user_certs = certs.get(entry["user_id"], {})
            if pillar in user_certs.get("expired", []) and \
                    pillar not in user_certs.get("current", []):
                expired_certs += 1

            if not entry["operational"]:
                # Not on the floor, so not cover whatever they hold.
                continue

            if owns:
                people.append({
                    "user_id": entry["user_id"], "name": entry["name"],
                    "basis": "primary", "weight": PRIMARY_WEIGHT,
                    "measured": True,
                    "evidence": ", ".join(entry["profiles"]),
                })
                continue

            weight = 0.0
            bases = []
            mean = _pillar_mean_rating(ratings.get(entry["user_id"], {}),
                                       pillar)
            if mean is not None and mean >= min_level:
                weight += SECONDARY_WEIGHT
                bases.append(f"self-rated {mean:.1f}/5")
            has_cert = pillar in user_certs.get("current", [])
            if has_cert:
                weight += CERT_WEIGHT
                bases.append("current certificate")
            if not weight:
                continue
            people.append({
                "user_id": entry["user_id"], "name": entry["name"],
                # A certificate is somebody else's examination; a rating is
                # the person's own opinion. Named by the stronger of the
                # two so the label never overstates the evidence.
                "basis": "certified" if has_cert and mean is None
                         else "secondary",
                # Capped: no amount of evidence makes one person two
                # bodies on a shift.
                "weight": min(weight, PRIMARY_WEIGHT),
                "measured": bool(has_cert),
                "evidence": " and ".join(bases),
            })

        primary = sum(1 for p in people if p["basis"] == "primary")
        secondary = sum(1 for p in people if p["basis"] == "secondary")
        certified = sum(
            1 for p in people
            if p["basis"] in ("secondary", "certified")
            and "certificate" in p["evidence"]
        )
        weighted = round(sum(p["weight"] for p in people), 2)
        self_rated_only = primary == 0 and secondary > 0 and certified == 0

        if not measured:
            state = "unmeasured"
        elif primary:
            state = "covered" if weighted >= min_staff else "thin"
        elif secondary or certified:
            state = "self_rated" if self_rated_only else "partial"
        else:
            state = "uncovered"

        pillars.append({
            "pillar": pillar,
            "owners": list(owners),
            "people": sorted(people, key=lambda p: (-p["weight"], p["name"])),
            "primary": primary,
            "secondary": secondary,
            "certified": certified,
            "in_training": in_training,
            "suspended": suspended,
            "expired_certs": expired_certs,
            "weighted": weighted,
            "min_staff": min_staff,
            "min_level": min_level,
            "state": state,
            "self_rated_only": self_rated_only,
            "headline": _headline(pillar, state, primary, secondary,
                                  certified, in_training, weighted,
                                  min_staff, self_rated_only),
        })

    return {
        "pillars": pillars,
        "measured": measured,
        "uncovered": sum(1 for p in pillars if p["state"] == "uncovered"),
        "self_rated_pillars": sum(1 for p in pillars if p["self_rated_only"]),
        "thin": sum(1 for p in pillars if p["state"] == "thin"),
        # Operational people the matrix cannot place. Not a fault of
        # theirs: it means the role they hold has no matrix equivalent, so
        # their work counts towards no pillar on this page.
        "unplaced": unplaced,
        "weights": {
            "primary": PRIMARY_WEIGHT,
            "secondary": SECONDARY_WEIGHT,
            "certificate": CERT_WEIGHT,
        },
    }


def _headline(pillar: str, state: str, primary: int, secondary: int,
              certified: int, in_training: int, weighted: float,
              min_staff: int, self_rated_only: bool) -> str:
    """One sentence a lead can read without the key.

    It has to carry the basis, not just the number. "2.5 people" with no
    statement of where that came from is the thing this module exists to
    stop.
    """
    if state == "unmeasured":
        return (
            "Nothing recorded yet, so this is unmeasured rather than "
            "uncovered -- nobody is in post, assessed or certified in ION."
        )
    if state == "uncovered":
        tail = ""
        if in_training:
            tail = (f" {in_training} in training for a role that would, "
                    f"which is not cover yet.")
        return f"Nobody in post owns {pillar}.{tail}"

    parts = []
    if primary:
        parts.append(f"{primary} whose job it is")
    if secondary:
        parts.append(f"{secondary} self-rated capable")
    if certified:
        parts.append(f"{certified} holding a current certificate")
    body = ", ".join(parts)

    if self_rated_only:
        return (
            f"{body}, and nobody in post owns {pillar}. That is "
            f"self-rated cover, not a measured capability."
        )
    if state == "thin":
        return (
            f"{body}: {weighted} weighted against a target of {min_staff}."
        )
    return f"{body}: {weighted} weighted, target {min_staff}."
