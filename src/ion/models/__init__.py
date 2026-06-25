"""SQLAlchemy models for ION."""

from ion.models.ai_chat import (
    AIChatMessage,
    AIChatSession,
    AIContextType,
)
from ion.models.ai_feedback import AIFeedback  # noqa: F401
from ion.models.ai_preferences import (
    AIResponseFeedback,
    AIUserPreference,
)

# v0.10.3: alert_prompt, ticker, tuning proposals, AI feedback ledger.
# Imported eagerly here so Base.metadata registers the tables at startup;
# otherwise create_all() misses them because callers lazy-import.
# Order matters: alert_prompt MUST come before tuning_proposal and
# ai_feedback because they FK to alert_prompt_templates.
from ion.models.alert_prompt import AlertPromptTemplate  # noqa: F401
from ion.models.alert_triage import (
    AlertCase,
    AlertCaseAnnotation,  # noqa: F401
    AlertCaseStatus,
    AlertComment,  # Backward compatibility alias for Note
    AlertTriage,
    AlertTriageStatus,
    CaseNote,  # Backward compatibility alias for Note
    Note,
    NoteEntityType,
)
from ion.models.analyst_note import AnalystNote
from ion.models.analytics import (
    AnalyticsJob,
    AnalyticsJobType,
    AnalyticsSnapshot,
)
from ion.models.base import Base

# v0.21.0: Bob Prompt Evaluation Harness — per-template P/R/F1 runs.
from ion.models.bob_eval import BobEvalRun, BobEvalRunSample  # noqa: F401
from ion.models.canary import Canary, CanaryHit, CanaryStatus, CanaryType

# v0.10.4: case-similarity embeddings (pgvector-backed).
from ion.models.case_embedding import CaseEmbedding  # noqa: F401

# v0.20.0: Workbench — pinned evidence + tamper-evident ledger.
from ion.models.case_evidence import (  # noqa: F401
    CaseEvidenceLedger,
    CaseEvidencePin,
    FindingStatus,
    PinSeverity,
    PinSourceType,
)

# v0.11.2: L1/L2/L3/L4 SOC analyst training course subsystem.
from ion.models.course import (  # noqa: F401
    Course,
    CourseLevel,
    CourseModule,
    Lesson,
    LessonProgressStatus,
    LessonType,
    Question,
    QuestionKind,
    UserAnswer,
    UserEnrolment,
    UserLessonProgress,
)
from ion.models.cyab import CyabDataSource, CyabSnapshot, CyabSystem
from ion.models.cyab_doc_checklist import CyabDocChecklistItem
from ion.models.cyab_subprofile import CyabPillar, CyabSubProfile
from ion.models.cyab_wizard import CyabWizardSession  # noqa: F401
from ion.models.document import Document, DocumentVersion
from ion.models.emulation import EmulationPlan, EmulationPlanStatus, EmulationStep, StepResult

# v0.20.1: ForensicCase Workbench — parallel ledger + pins for forensic cases.
from ion.models.forensic_workbench import (  # noqa: F401
    ForensicCaseLedger,
    ForensicCasePin,
)
from ion.models.forensics import (
    CustodyAction,
    CustodyLogEntry,
    EvidenceItem,
    EvidenceStatus,
    EvidenceType,
    ForensicCase,
    ForensicCaseAnnotation,  # noqa: F401
    ForensicCasePriority,
    ForensicCaseStatus,
    ForensicCaseStep,
    ForensicPlaybook,
    ForensicPlaybookStep,
    ForensicTimelineEntry,
    InvestigationType,
)
from ion.models.integration import (
    IntegrationEvent,
    IntegrationEventType,
    IntegrationHealthCheck,  # Backward compatibility alias for IntegrationEvent
    IntegrationLog,  # Backward compatibility alias for IntegrationEvent
    IntegrationStatus,
    IntegrationType,
    LogLevel,
    Webhook,
    WebhookLog,  # Backward compatibility alias for IntegrationEvent
    WebhookStatus,
)
from ion.models.investigation import Investigation  # noqa: F401

# v0.10.6: KB article embeddings for Bob's RAG grounding.
from ion.models.kb_document_embedding import KBDocumentEmbedding  # noqa: F401
from ion.models.log_source import LogSource, LogSourceCategory
from ion.models.maturity import MaturityAssessment
from ion.models.note_folder import NoteFolder
from ion.models.observable import (
    Observable,
    ObservableAlertLink,  # Backward compatibility alias for ObservableLink
    ObservableCaseLink,  # Backward compatibility alias for ObservableLink
    ObservableEnrichment,
    ObservableLink,
    ObservableLinkType,
    ObservableSighting,  # Backward compatibility alias for ObservableLink
    ObservableType,
    ThreatLevel,
    WatchlistAlert,
    WatchlistAlertType,
)
from ion.models.oncall import (
    ChangeLogEntry,
    CommTemplate,
    ServiceAccount,
    UserBookmark,
)
from ion.models.playbook import (
    ExecutionStatus,
    Playbook,
    PlaybookExecution,
    PlaybookStep,
    StepType,
)
from ion.models.saved_search import (
    SavedSearch,
    SearchType,
)
from ion.models.security import (
    BlockedIP,
    SecurityAlertRule,
    SecurityEvent,
    SecurityEventSeverity,
    SecurityEventStatus,
    SecurityEventType,
)
from ion.models.skills import (
    AssessmentReviewCycle,
    AssessmentSnapshot,
    KnowledgeArticle,
    RoleAssessment,
    SkillAssessment,
    SOCCMMAssessment,
    TeamCertification,
    TeamScheduleEntry,
    TrainingPlan,
    TrainingPlanItem,
    UserCareerGoal,
)
from ion.models.sla import (
    DashboardLayout,
    PlaybookAction,
    PlaybookActionLog,
    ScheduledReport,
    SLABreachLog,
    SLAPolicy,
    # ThreatHunt removed v0.27.0; see ion/models/sla.py for the removal note.
)
from ion.models.social import (
    SocialComment,
    SocialPost,
    SocialReaction,
)

# v0.11.0: JSON-DAG playbook automation (Tines-inspired).
from ion.models.story import Story, StoryRun  # noqa: F401
from ion.models.template import Collection, Tag, Template, Variable, template_tags
from ion.models.threat_intel import ThreatIntelWatch
from ion.models.ticker import (  # noqa: F401
    Ticker,
    TickerDismissal,
    TickerKind,
    TickerSeverity,
    TickerSourceType,
)
from ion.models.tide_snapshot import TideSnapshot
from ion.models.traffic_exclusion import TrafficExclusion  # noqa: F401
from ion.models.tuning_proposal import TuningProposal, TuningProposalStatus  # noqa: F401
from ion.models.user import (
    AuditLog,
    Permission,
    Role,
    User,
    UserSession,
    role_permissions,
    user_roles,
)
from ion.models.version import TemplateVersion
from ion.models.vulnerability import Vulnerability, VulnerabilityAsset, VulnSeverity, VulnStatus

# v0.43.0: daily-work tracking — manual work-log entries + admin task taxonomy.
from ion.models.worklog import (  # noqa: F401
    DEFAULT_TASK_TYPES,
    WorkLogEntry,
    WorkTaskType,
    seed_default_task_types,
)

__all__ = [
    "Base",
    "WorkTaskType",
    "WorkLogEntry",
    "Template",
    "Tag",
    "Variable",
    "Collection",
    "template_tags",
    "TemplateVersion",
    "Document",
    "DocumentVersion",
    "User",
    "Role",
    "Permission",
    "UserSession",
    "AuditLog",
    "user_roles",
    "role_permissions",
    "SecurityEvent",
    "SecurityEventType",
    "SecurityEventSeverity",
    "SecurityEventStatus",
    "SecurityAlertRule",
    "BlockedIP",
    "AlertTriage",
    "AlertTriageStatus",
    "AlertCase",
    "AlertCaseStatus",
    "Note",
    "NoteEntityType",
    "AlertComment",  # Alias for Note
    "CaseNote",  # Alias for Note
    # Integration models
    "IntegrationType",
    "IntegrationStatus",
    "LogLevel",
    "WebhookStatus",
    "IntegrationEventType",
    "Webhook",
    "IntegrationEvent",
    "WebhookLog",  # Alias for IntegrationEvent
    "IntegrationLog",  # Alias for IntegrationEvent
    "IntegrationHealthCheck",  # Alias for IntegrationEvent
    # Observable models
    "Observable",
    "ObservableType",
    "ThreatLevel",
    "ObservableEnrichment",
    "ObservableLink",
    "ObservableLinkType",
    "ObservableAlertLink",  # Alias for ObservableLink
    "ObservableCaseLink",  # Alias for ObservableLink
    "ObservableSighting",  # Alias for ObservableLink
    "WatchlistAlert",
    "WatchlistAlertType",
    # AI Chat models
    "AIChatSession",
    "AIChatMessage",
    "AIContextType",
    # AI Preferences models
    "AIUserPreference",
    "AIResponseFeedback",
    # Saved Search models
    "SavedSearch",
    "SearchType",
    # Playbook models
    "Playbook",
    "PlaybookStep",
    "PlaybookExecution",
    "StepType",
    "ExecutionStatus",
    # Skills assessment models
    "AssessmentReviewCycle",
    "SkillAssessment",
    "UserCareerGoal",
    "AssessmentSnapshot",
    "TeamScheduleEntry",
    # SOC-CMM alignment models
    "TeamCertification",
    "SOCCMMAssessment",
    "KnowledgeArticle",
    # Training plan models
    "TrainingPlan",
    "TrainingPlanItem",
    "RoleAssessment",
    # Analyst notepad
    "AnalystNote",
    "NoteFolder",
    # Analytics Engine models
    "AnalyticsJob",
    "AnalyticsJobType",
    "AnalyticsSnapshot",
    # Forensic investigation models
    "ForensicCase",
    "ForensicCaseStatus",
    "ForensicCasePriority",
    "InvestigationType",
    "EvidenceItem",
    "EvidenceType",
    "EvidenceStatus",
    "CustodyLogEntry",
    "CustodyAction",
    "ForensicPlaybook",
    "ForensicPlaybookStep",
    "ForensicCaseStep",
    "ForensicTimelineEntry",
    # v0.20.1: ForensicCase Workbench
    "ForensicCasePin",
    "ForensicCaseLedger",
    # CyAB models
    "CyabSystem",
    "CyabDataSource",
    "CyabSnapshot",
    "CyabPillar",
    "CyabSubProfile",
    "CyabWizardSession",
    # Canary / deception
    "Canary",
    "CanaryHit",
    "CanaryType",
    "CanaryStatus",
    # Log source health
    "LogSource",
    "LogSourceCategory",
    # Adversary emulation
    "EmulationPlan",
    "EmulationStep",
    "EmulationPlanStatus",
    "StepResult",
    # Vulnerability tracking
    "Vulnerability",
    "VulnerabilityAsset",
    "VulnSeverity",
    "VulnStatus",
    # Threat Intel watch model
    "ThreatIntelWatch",
    # Social Hub models
    "SocialPost",
    "SocialComment",
    "SocialReaction",
]
