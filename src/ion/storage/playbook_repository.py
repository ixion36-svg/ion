"""Repository for Playbook operations."""

from datetime import datetime
from typing import Optional, List
from sqlalchemy import select, or_, and_, func
from sqlalchemy.orm import Session, joinedload, selectinload

from ion.models.playbook import (
    Playbook,
    PlaybookStep,
    PlaybookExecution,
    ExecutionStatus,
    StepType,
)


class PlaybookRepository:
    """Repository for Playbook CRUD operations."""

    def __init__(self, session: Session):
        self.session = session

    # =========================================================================
    # Playbook CRUD
    # =========================================================================

    def create_playbook(
        self,
        name: str,
        trigger_conditions: dict,
        created_by_id: int,
        description: str | None = None,
        is_active: bool = True,
        priority: int = 0,
    ) -> Playbook:
        """Create a new playbook."""
        playbook = Playbook(
            name=name,
            description=description,
            is_active=is_active,
            trigger_conditions=trigger_conditions,
            priority=priority,
            created_by_id=created_by_id,
        )
        self.session.add(playbook)
        self.session.flush()
        return playbook

    def get_playbook_by_id(self, playbook_id: int) -> Optional[Playbook]:
        """Get a playbook by ID with its steps."""
        stmt = (
            select(Playbook)
            .options(
                joinedload(Playbook.created_by),
                selectinload(Playbook.steps),
            )
            .where(Playbook.id == playbook_id)
        )
        return self.session.execute(stmt).unique().scalar_one_or_none()

    def get_playbook_by_name(self, name: str) -> Optional[Playbook]:
        """Get a playbook by name."""
        stmt = (
            select(Playbook)
            .options(selectinload(Playbook.steps))
            .where(Playbook.name == name)
        )
        return self.session.execute(stmt).unique().scalar_one_or_none()

    def list_playbooks(
        self,
        active_only: bool = False,
        include_steps: bool = True,
    ) -> List[Playbook]:
        """List all playbooks."""
        stmt = select(Playbook).options(joinedload(Playbook.created_by))

        if include_steps:
            stmt = stmt.options(selectinload(Playbook.steps))

        if active_only:
            stmt = stmt.where(Playbook.is_active == True)

        stmt = stmt.order_by(Playbook.priority.desc(), Playbook.name)
        return list(self.session.execute(stmt).unique().scalars().all())

    def update_playbook(
        self,
        playbook: Playbook,
        name: str | None = None,
        description: str | None = None,
        is_active: bool | None = None,
        trigger_conditions: dict | None = None,
        priority: int | None = None,
    ) -> Playbook:
        """Update a playbook."""
        if name is not None:
            playbook.name = name
        if description is not None:
            playbook.description = description
        if is_active is not None:
            playbook.is_active = is_active
        if trigger_conditions is not None:
            playbook.trigger_conditions = trigger_conditions
        if priority is not None:
            playbook.priority = priority
        self.session.flush()
        return playbook

    def delete_playbook(self, playbook: Playbook) -> None:
        """Delete a playbook and all its steps/executions (cascade)."""
        self.session.delete(playbook)
        self.session.flush()

    # =========================================================================
    # Step Management
    # =========================================================================

    def add_step(
        self,
        playbook: Playbook,
        step_type: str,
        title: str,
        step_order: int | None = None,
        description: str | None = None,
        step_params: dict | None = None,
        is_required: bool = False,
    ) -> PlaybookStep:
        """Add a step to a playbook."""
        if step_order is None:
            # Get max order and add 1
            max_order = 0
            for step in playbook.steps:
                if step.step_order > max_order:
                    max_order = step.step_order
            step_order = max_order + 1

        step = PlaybookStep(
            playbook_id=playbook.id,
            step_order=step_order,
            step_type=step_type,
            title=title,
            description=description,
            step_params=step_params,
            is_required=is_required,
        )
        self.session.add(step)
        self.session.flush()
        return step

    def get_step_by_id(self, step_id: int) -> Optional[PlaybookStep]:
        """Get a step by ID."""
        stmt = (
            select(PlaybookStep)
            .options(joinedload(PlaybookStep.playbook))
            .where(PlaybookStep.id == step_id)
        )
        return self.session.execute(stmt).unique().scalar_one_or_none()

    def update_step(
        self,
        step: PlaybookStep,
        step_type: str | None = None,
        title: str | None = None,
        description: str | None = None,
        step_params: dict | None = None,
        is_required: bool | None = None,
    ) -> PlaybookStep:
        """Update a step."""
        if step_type is not None:
            step.step_type = step_type
        if title is not None:
            step.title = title
        if description is not None:
            step.description = description
        if step_params is not None:
            step.step_params = step_params
        if is_required is not None:
            step.is_required = is_required
        self.session.flush()
        return step

    def delete_step(self, step: PlaybookStep) -> None:
        """Delete a step from a playbook."""
        self.session.delete(step)
        self.session.flush()

    def reorder_steps(self, playbook: Playbook, step_order: List[int]) -> List[PlaybookStep]:
        """
        Reorder steps in a playbook.
        step_order is a list of step IDs in the desired order.
        """
        step_map = {step.id: step for step in playbook.steps}

        for order, step_id in enumerate(step_order, start=1):
            if step_id in step_map:
                step_map[step_id].step_order = order

        self.session.flush()
        return sorted(playbook.steps, key=lambda s: s.step_order)

    def replace_steps(
        self,
        playbook: Playbook,
        steps_data: List[dict],
    ) -> List[PlaybookStep]:
        """Replace all steps in a playbook with new steps."""
        # Delete existing steps
        for step in playbook.steps[:]:
            self.session.delete(step)
        self.session.flush()

        # Create new steps
        new_steps = []
        for order, step_data in enumerate(steps_data, start=1):
            step = PlaybookStep(
                playbook_id=playbook.id,
                step_order=order,
                step_type=step_data.get("step_type", StepType.MANUAL_CHECKLIST.value),
                title=step_data.get("title", ""),
                description=step_data.get("description"),
                step_params=step_data.get("step_params"),
                is_required=step_data.get("is_required", False),
            )
            self.session.add(step)
            new_steps.append(step)

        self.session.flush()
        return new_steps

    # =========================================================================
    # Matching
    # =========================================================================

    def find_playbook_for_pattern(self, pattern_id: str) -> Optional[Playbook]:
        """Find the best active playbook associated with a pattern ID.

        Returns the highest-priority active playbook whose trigger_conditions
        contain the given pattern_id (via ``pattern_id`` or ``pattern_ids``).
        """
        playbooks = self.list_playbooks(active_only=True, include_steps=True)
        matching = [pb for pb in playbooks if pb.matches_pattern(pattern_id)]
        if not matching:
            return None
        # list_playbooks already sorted by priority desc
        return matching[0]

    def find_matching_playbooks(
        self,
        rule_name: str | None = None,
        severity: str | None = None,
        mitre_techniques: List[str] | None = None,
        mitre_tactics: List[str] | None = None,
    ) -> List[Playbook]:
        """
        Find active playbooks that match the given alert characteristics.
        Returns playbooks ordered by priority (highest first).
        """
        # Get all active playbooks
        playbooks = self.list_playbooks(active_only=True, include_steps=True)

        # Filter by matching
        matching = []
        for playbook in playbooks:
            if playbook.matches_alert(
                rule_name=rule_name,
                severity=severity,
                mitre_techniques=mitre_techniques,
                mitre_tactics=mitre_tactics,
            ):
                matching.append(playbook)

        # Already sorted by priority from list_playbooks
        return matching

    def find_suggested_playbooks(
        self,
        rule_name: str | None = None,
        severity: str | None = None,
        mitre_techniques: List[str] | None = None,
        mitre_tactics: List[str] | None = None,
    ) -> List[Playbook]:
        """
        Find ALL playbooks (active + inactive) that match alert characteristics.
        Returns active playbooks first, then inactive, both sorted by priority.
        """
        playbooks = self.list_playbooks(active_only=False, include_steps=True)

        matching = [
            p for p in playbooks
            if p.matches_alert_relaxed(
                rule_name=rule_name,
                severity=severity,
                mitre_techniques=mitre_techniques,
                mitre_tactics=mitre_tactics,
            )
        ]

        # Sort: active first, then by priority descending
        return sorted(matching, key=lambda p: (-int(p.is_active), -p.priority))

    # =========================================================================
    # Execution
    # =========================================================================

    def start_execution(
        self,
        playbook: Playbook,
        es_alert_id: str,
        executed_by_id: int,
        case_id: int | None = None,
    ) -> PlaybookExecution:
        """Start a new playbook execution for an alert."""
        execution = PlaybookExecution(
            playbook_id=playbook.id,
            es_alert_id=es_alert_id,
            status=ExecutionStatus.IN_PROGRESS.value,
            started_at=datetime.utcnow(),
            step_statuses={},
            executed_by_id=executed_by_id,
            case_id=case_id,
        )
        self.session.add(execution)
        self.session.flush()
        return execution

    def get_execution(self, execution_id: int) -> Optional[PlaybookExecution]:
        """Get an execution by ID."""
        stmt = (
            select(PlaybookExecution)
            .options(
                joinedload(PlaybookExecution.playbook).selectinload(Playbook.steps),
                joinedload(PlaybookExecution.executed_by),
                joinedload(PlaybookExecution.case),
            )
            .where(PlaybookExecution.id == execution_id)
        )
        return self.session.execute(stmt).unique().scalar_one_or_none()

    def get_executions_for_alert(self, es_alert_id: str) -> List[PlaybookExecution]:
        """Get all executions for a specific alert."""
        stmt = (
            select(PlaybookExecution)
            .options(
                joinedload(PlaybookExecution.playbook).selectinload(Playbook.steps),
                joinedload(PlaybookExecution.executed_by),
                joinedload(PlaybookExecution.case),
            )
            .where(PlaybookExecution.es_alert_id == es_alert_id)
            .order_by(PlaybookExecution.created_at.desc())
        )
        return list(self.session.execute(stmt).unique().scalars().all())

    def get_active_execution_for_alert(
        self,
        es_alert_id: str,
        playbook_id: int | None = None,
    ) -> Optional[PlaybookExecution]:
        """Get the active (in_progress) execution for an alert."""
        stmt = (
            select(PlaybookExecution)
            .options(
                joinedload(PlaybookExecution.playbook).selectinload(Playbook.steps),
                joinedload(PlaybookExecution.executed_by),
            )
            .where(
                PlaybookExecution.es_alert_id == es_alert_id,
                PlaybookExecution.status == ExecutionStatus.IN_PROGRESS.value,
            )
        )

        if playbook_id:
            stmt = stmt.where(PlaybookExecution.playbook_id == playbook_id)

        stmt = stmt.order_by(PlaybookExecution.created_at.desc())
        return self.session.execute(stmt).unique().scalars().first()

    def update_step_status(
        self,
        execution: PlaybookExecution,
        step_id: int,
        status: str,
        completed_by_id: int | None = None,
        completed_by_username: str | None = None,
        notes: str | None = None,
        action_data: dict | None = None,
    ) -> PlaybookExecution:
        """Update the status of a step in an execution."""
        execution.update_step_status(
            step_id=step_id,
            status=status,
            completed_by_id=completed_by_id,
            completed_by_username=completed_by_username,
            notes=notes,
            action_data=action_data,
        )

        # Check if all required steps are done
        execution.check_completion()

        self.session.flush()
        return execution

    def fail_execution(
        self,
        execution: PlaybookExecution,
        reason: str | None = None,
    ) -> PlaybookExecution:
        """Mark an execution as failed."""
        execution.status = ExecutionStatus.FAILED.value
        execution.completed_at = datetime.utcnow()
        if reason:
            if execution.step_statuses is None:
                execution.step_statuses = {}
            execution.step_statuses["_failure_reason"] = reason
        self.session.flush()
        return execution

    def complete_execution(
        self,
        execution: PlaybookExecution,
        outcome: str | None = None,
        outcome_notes: str | None = None,
    ) -> PlaybookExecution:
        """Mark an execution as completed."""
        execution.status = ExecutionStatus.COMPLETED.value
        execution.completed_at = datetime.utcnow()
        if outcome:
            execution.outcome = outcome
        if outcome_notes:
            execution.outcome_notes = outcome_notes
        self.session.flush()
        return execution

    def set_report_document(
        self,
        execution: PlaybookExecution,
        document_id: int,
    ) -> PlaybookExecution:
        """Link a report document to an execution."""
        execution.report_document_id = document_id
        self.session.flush()
        return execution

    def list_executions(
        self,
        playbook_id: int | None = None,
        status: str | None = None,
        limit: int = 100,
    ) -> List[PlaybookExecution]:
        """List executions with optional filters."""
        stmt = (
            select(PlaybookExecution)
            .options(
                joinedload(PlaybookExecution.playbook),
                joinedload(PlaybookExecution.executed_by),
            )
        )

        if playbook_id:
            stmt = stmt.where(PlaybookExecution.playbook_id == playbook_id)

        if status:
            stmt = stmt.where(PlaybookExecution.status == status)

        stmt = stmt.order_by(PlaybookExecution.created_at.desc()).limit(limit)
        return list(self.session.execute(stmt).unique().scalars().all())

    def get_executions_for_case(self, case_id: int) -> List[PlaybookExecution]:
        """Get all executions linked to a specific case."""
        stmt = (
            select(PlaybookExecution)
            .options(
                joinedload(PlaybookExecution.playbook).selectinload(Playbook.steps),
                joinedload(PlaybookExecution.executed_by),
                joinedload(PlaybookExecution.case),
            )
            .where(PlaybookExecution.case_id == case_id)
            .order_by(PlaybookExecution.created_at.desc())
        )
        return list(self.session.execute(stmt).unique().scalars().all())

    def get_executions_dashboard(
        self,
        status: str | None = None,
        limit: int = 50,
    ) -> List[PlaybookExecution]:
        """Get executions for the dashboard with full relationships."""
        stmt = (
            select(PlaybookExecution)
            .options(
                joinedload(PlaybookExecution.playbook).selectinload(Playbook.steps),
                joinedload(PlaybookExecution.executed_by),
                joinedload(PlaybookExecution.case),
            )
        )

        if status:
            stmt = stmt.where(PlaybookExecution.status == status)

        stmt = stmt.order_by(PlaybookExecution.created_at.desc()).limit(limit)
        return list(self.session.execute(stmt).unique().scalars().all())

    def get_execution_counts_by_status(self) -> dict:
        """Get counts of executions grouped by status."""
        stmt = (
            select(PlaybookExecution.status, func.count(PlaybookExecution.id))
            .group_by(PlaybookExecution.status)
        )
        rows = self.session.execute(stmt).all()
        counts = {row[0]: row[1] for row in rows}
        return counts
