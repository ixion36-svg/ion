"""Workforce lifecycle: role profiles, joining journeys and leaver records.

Two phases gate a person. **Gate** requirements are held by the PERSON and
satisfied once — clearance, agreements, induction. They decide whether an
account exists at all, so a lapse withdraws every role at once. **Readiness**
requirements are held per ROLE, so a lapse withdraws that role and leaves the
others alone. A cover role therefore adds requirements rather than inheriting
its way out of them.

Requirements are COPIED onto a journey when a profile is assigned, never
referenced live. Editing a role tomorrow cannot retrospectively mark someone
non-compliant, and the record answers the question an assessor actually asks:
what was this person required to hold on the day they were granted access?
"""

from __future__ import annotations

from datetime import date, datetime
from enum import Enum
from typing import Optional

from sqlalchemy import (
    Boolean,
    Date,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy import (
    Enum as SQLEnum,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ion.models.base import Base, TimestampMixin

# --- vocabularies -----------------------------------------------------------
# Plain strings, not SQLEnum: a native_enum=False column stores the member NAME
# and raw SQL then has to match that casing. These are compared in raw SQL by
# the expiry sweep, so the stored value is the value.

PHASE_GATE = "gate"
PHASE_READINESS = "readiness"
PHASES = (PHASE_GATE, PHASE_READINESS)

KIND_DOCUMENT = "document"
KIND_VETTING = "vetting"
KIND_ACCESS = "access"
KIND_COURSE = "course"
KIND_CERT = "cert"
KIND_SIGNOFF = "signoff"
KINDS = (KIND_DOCUMENT, KIND_VETTING, KIND_ACCESS, KIND_COURSE, KIND_CERT, KIND_SIGNOFF)

STATUS_PENDING = "pending"
STATUS_SUBMITTED = "submitted"
STATUS_VERIFIED = "verified"
STATUS_EXPIRED = "expired"
STATUS_WAIVED = "waived"
#: Met by assessed proficiency rather than by the named certificate.
#:
#: Distinct from both neighbours on purpose. Recording it as VERIFIED would
#: be a lie -- an assessor asking "does your L2 hold GCIA" would be told
#: yes. Recording it as WAIVED is also wrong: waived means the requirement
#: was set aside, not met. The record has to say which happened.
STATUS_EQUIVALENT = "equivalent"
STATUSES = (STATUS_PENDING, STATUS_SUBMITTED, STATUS_VERIFIED, STATUS_EXPIRED,
            STATUS_WAIVED, STATUS_EQUIVALENT)

STAGE_PRE_ACCESS = "pre_access"
STAGE_TRAINING = "role_training"
STAGE_OPERATIONAL = "operational"
STAGE_SUSPENDED = "suspended"
STAGE_WITHDRAWN = "withdrawn"
STAGE_CLOSED = "closed"


class RoleProfile(Base, TimestampMixin):
    """A role a SOC defines for itself, e.g. "L1 SOC Analyst"."""

    __tablename__ = "role_profiles"
    __table_args__ = (UniqueConstraint("name", name="uq_role_profile_name"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(150), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    # Optional NICE work role, so custom roles still report against a standard.
    nice_work_role: Mapped[Optional[str]] = mapped_column(String(150), nullable=True)
    # A baseline applies to every role and cannot be edited away in a child.
    is_baseline: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    # The ION role this profile grants. Membership is withheld until the gate
    # is verified and removed again when it lapses, so the mandatory list is
    # what actually holds the permissions back -- not a separate manual step.
    grants_role_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("roles.id", ondelete="SET NULL"), nullable=True
    )

    versions: Mapped[list["RoleProfileVersion"]] = relationship(
        "RoleProfileVersion", back_populates="profile", cascade="all, delete-orphan",
        order_by="RoleProfileVersion.version",
    )


class RoleProfileVersion(Base, TimestampMixin):
    """A published, immutable set of requirements for a profile.

    A draft is editable; once published it never changes, because journeys
    reference the version they were assigned under.
    """

    __tablename__ = "role_profile_versions"
    __table_args__ = (
        UniqueConstraint("profile_id", "version", name="uq_profile_version"),
        Index("ix_role_profile_versions_profile", "profile_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    profile_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("role_profiles.id", ondelete="CASCADE"), nullable=False
    )
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    published_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    published_by_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    profile: Mapped["RoleProfile"] = relationship("RoleProfile", back_populates="versions")
    requirements: Mapped[list["ProfileRequirement"]] = relationship(
        "ProfileRequirement", back_populates="version", cascade="all, delete-orphan",
        order_by="ProfileRequirement.ordering",
    )

    @property
    def is_published(self) -> bool:
        return self.published_at is not None


class ProfileRequirement(Base, TimestampMixin):
    """One requirement in a profile version."""

    __tablename__ = "profile_requirements"
    __table_args__ = (Index("ix_profile_requirements_version", "version_id"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    version_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("role_profile_versions.id", ondelete="CASCADE"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    kind: Mapped[str] = mapped_column(String(20), nullable=False, default=KIND_DOCUMENT)
    phase: Mapped[str] = mapped_column(String(20), nullable=False, default=PHASE_GATE)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    # None = never expires. Drives the reminder sweep once satisfied.
    validity_months: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    # COURSE requirements resolve from course_enrolments rather than a manual tick.
    course_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("courses.id", ondelete="SET NULL"), nullable=True
    )
    cost: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    funding_type: Mapped[str] = mapped_column(String(20), nullable=False, default="company")
    ordering: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    version: Mapped["RoleProfileVersion"] = relationship(
        "RoleProfileVersion", back_populates="requirements"
    )


class UserJourney(Base, TimestampMixin):
    """One person against one role profile version.

    ``is_cover`` marks a secondary role taken on for cover. A person has at
    most one non-cover journey open at a time; cover journeys are additional.
    """

    __tablename__ = "user_journeys"
    __table_args__ = (
        Index("ix_user_journeys_user", "user_id"),
        Index("ix_user_journeys_stage", "stage"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    version_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("role_profile_versions.id"), nullable=False
    )
    is_cover: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    stage: Mapped[str] = mapped_column(String(20), nullable=False, default=STAGE_PRE_ACCESS)
    sponsor_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    started_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)
    gate_cleared_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    operational_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    closed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    target_days: Mapped[int] = mapped_column(Integer, nullable=False, default=30)
    # A lapse suspends immediately but permissions survive until this moment,
    # so an expiry ticking over at midnight cannot pull access from someone
    # mid-incident. Null once the grace has been served or was never started.
    grace_until: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    version: Mapped["RoleProfileVersion"] = relationship("RoleProfileVersion")
    requirements: Mapped[list["JourneyRequirement"]] = relationship(
        "JourneyRequirement", back_populates="journey", cascade="all, delete-orphan",
        order_by="JourneyRequirement.ordering",
    )


class JourneyRequirement(Base, TimestampMixin):
    """A requirement as it stood when the profile was assigned.

    A copy, deliberately: the profile it came from may change afterwards, and
    this row is the audit record of what was actually required.
    """

    __tablename__ = "journey_requirements"
    __table_args__ = (
        Index("ix_journey_requirements_journey", "journey_id"),
        Index("ix_journey_requirements_expiry", "expires_on"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    journey_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("user_journeys.id", ondelete="CASCADE"), nullable=False
    )
    # Kept for traceability; the copied fields below are what is enforced.
    source_requirement_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)

    name: Mapped[str] = mapped_column(String(200), nullable=False)
    kind: Mapped[str] = mapped_column(String(20), nullable=False, default=KIND_DOCUMENT)
    phase: Mapped[str] = mapped_column(String(20), nullable=False, default=PHASE_GATE)
    validity_months: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    course_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    cost: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    ordering: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    status: Mapped[str] = mapped_column(String(20), nullable=False, default=STATUS_PENDING)
    evidence_ref: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    # What the person themselves claims: the date they completed it and when
    # they put it forward. Never sets the status past SUBMITTED -- only a
    # verifier moves it to VERIFIED.
    completed_on: Mapped[Optional[date]] = mapped_column(Date, nullable=True)
    submitted_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    verified_by_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    verified_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    expires_on: Mapped[Optional[date]] = mapped_column(Date, nullable=True)
    # Highest reminder threshold already sent, so a sweep does not resend.
    last_reminder_days: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    journey: Mapped["UserJourney"] = relationship("UserJourney", back_populates="requirements")

    @property
    def satisfied(self) -> bool:
        return self.status in (STATUS_VERIFIED, STATUS_WAIVED, STATUS_EQUIVALENT)


class LeaverRecord(Base, TimestampMixin):
    """The offboarding mirror.

    Revocation is scheduled from the last working day, not from completion of
    the checklist: outstanding items become a record to chase, never a reason
    to leave an account enabled.
    """

    __tablename__ = "leaver_records"
    __table_args__ = (Index("ix_leaver_records_user", "user_id"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    last_working_day: Mapped[date] = mapped_column(Date, nullable=False)
    reason: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    revoke_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    revoked_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    raised_by_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    # JSON list of {name, done, owner}. Not compared in SQL.
    checklist: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)


class OrgUnit(Base, TimestampMixin):
    """A node in the SOC's own structure: SOC > team or function > posts.

    The tree is the SOC's to draw. Nothing here is seeded, and the ORBAT is
    empty (not wrong) until someone builds it.
    """

    __tablename__ = "org_units"
    __table_args__ = (
        UniqueConstraint("parent_id", "name", name="uq_org_unit_sibling_name"),
        Index("ix_org_units_parent", "parent_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    parent_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("org_units.id", ondelete="CASCADE"), nullable=True
    )
    name: Mapped[str] = mapped_column(String(150), nullable=False)
    ordering: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    posts: Mapped[list["OrgPost"]] = relationship(
        "OrgPost", back_populates="unit", cascade="all, delete-orphan",
        order_by="OrgPost.ordering",
    )
    children: Mapped[list["OrgUnit"]] = relationship(
        "OrgUnit", cascade="all, delete-orphan", order_by="OrgUnit.ordering",
    )


class OrgPost(Base, TimestampMixin):
    """An established post within a unit.

    A post exists whether or not anyone fills it -- an empty post IS the gap
    the ORBAT is for. It is filled by a journey, not a bare user, so occupancy
    carries the stage (operational, still training, suspended) with it.
    """

    __tablename__ = "org_posts"
    __table_args__ = (Index("ix_org_posts_unit", "unit_id"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    unit_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("org_units.id", ondelete="CASCADE"), nullable=False
    )
    title: Mapped[str] = mapped_column(String(150), nullable=False)
    profile_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("role_profiles.id", ondelete="SET NULL"), nullable=True
    )
    filled_by_journey_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("user_journeys.id", ondelete="SET NULL"), nullable=True
    )
    ordering: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    unit: Mapped["OrgUnit"] = relationship("OrgUnit", back_populates="posts")
    filled_by: Mapped[Optional["UserJourney"]] = relationship("UserJourney")
    profile: Mapped[Optional["RoleProfile"]] = relationship("RoleProfile")


# --- training record --------------------------------------------------------
# Course, CourseLevel and UserEnrolment moved here when the courseware cluster
# was archived (see archive/courseware/). The product that authored and
# delivered courses is gone; the record of what training a person holds is a
# workforce concern. JourneyRequirement.course_id is a foreign key to
# courses.id, and sync_course_requirements resolves COURSE requirements from
# course_enrolments rather than a manual tick.
#
# Table names are unchanged, so existing databases need no migration. Columns
# the courseware wrote but nothing now reads (badge_image_path, pass_threshold,
# description_md and the rest) are kept deliberately: dropping them would
# rewrite tables holding real completion history, for no benefit.


class CourseLevel(str, Enum):
    """Training tier — maps to SOC career ladder."""
    L1 = "L1"
    L2 = "L2"
    L3 = "L3"
    L4 = "L4"


class Course(Base):
    """A training course at a specific tier (L1/L2/L3/L4)."""

    __tablename__ = "courses"
    __table_args__ = (
        Index("ix_courses_level", "level"),
        Index("ix_courses_published", "published"),
        Index("ix_courses_slug", "slug", unique=True),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    slug: Mapped[str] = mapped_column(String(255), nullable=False)  # URL-safe, unique
    level: Mapped[str] = mapped_column(
        SQLEnum(CourseLevel, native_enum=False), nullable=False
    )
    description_md: Mapped[str] = mapped_column(Text, nullable=False, default="")
    estimated_hours: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    badge_image_path: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    # Optional prerequisite — UI can lock the course until the prereq is
    # completed. Self-referential FK so existing v0 courses stay valid.
    prerequisite_course_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("courses.id", ondelete="SET NULL"), nullable=True
    )
    order_in_level: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    pass_threshold: Mapped[int] = mapped_column(
        Integer, nullable=False, default=70
    )  # percent — quiz lessons need ≥ this to be marked completed
    published: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    skill_keys: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True
    )  # JSON array — skills bumped on course completion (links to SkillAssessment.skill_key)
    author_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("users.id"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=func.now(), onupdate=func.now(), nullable=False
    )

    def __repr__(self) -> str:
        return f"<Course(id={self.id}, level={self.level}, title='{self.title}')>"


class UserEnrolment(Base):
    """A user's enrolment in a Course."""

    __tablename__ = "course_enrolments"
    __table_args__ = (
        UniqueConstraint("user_id", "course_id", name="uq_course_enrolment_user_course"),
        Index("ix_course_enrolments_user", "user_id"),
        Index("ix_course_enrolments_course", "course_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    course_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("courses.id", ondelete="CASCADE"), nullable=False
    )
    started_at: Mapped[datetime] = mapped_column(
        DateTime, default=func.now(), nullable=False
    )
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    badge_earned: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    # URL of generated PDF certificate (v0.11.7+). Nullable until then.
    certificate_url: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    # Aggregate score across all quiz lessons (percent). Caches expensive
    # rollup so the catalog can sort by score without touching UserAnswer.
    score_pct: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)

    def __repr__(self) -> str:
        return f"<UserEnrolment(user={self.user_id}, course={self.course_id}, completed={self.completed_at is not None})>"
