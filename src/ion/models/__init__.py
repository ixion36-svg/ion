"""SQLAlchemy models for ION."""

from ion.models.base import Base
from ion.models.template import Template, Tag, Variable, Collection, template_tags
from ion.models.version import TemplateVersion
from ion.models.document import Document, DocumentVersion
from ion.models.user import (
    User,
    Role,
    Permission,
    UserSession,
    AuditLog,
    user_roles,
    role_permissions,
)
from ion.models.security import (
    SecurityEvent,
    SecurityEventType,
    SecurityEventSeverity,
    SecurityEventStatus,
    SecurityAlertRule,
    BlockedIP,
)
from ion.models.alert_triage import (
    AlertTriage,
    AlertTriageStatus,
    AlertCase,
    AlertCaseStatus,
    Note,
    NoteEntityType,
    AlertComment,  # Backward compatibility alias for Note
    CaseNote,  # Backward compatibility alias for Note
)
from ion.models.integration import (
    IntegrationType,
    IntegrationStatus,
    LogLevel,
    WebhookStatus,
    IntegrationEventType,
    Webhook,
    IntegrationEvent,
    WebhookLog,  # Backward compatibility alias for IntegrationEvent
    IntegrationLog,  # Backward compatibility alias for IntegrationEvent
    IntegrationHealthCheck,  # Backward compatibility alias for IntegrationEvent
)
from ion.models.observable import (
    Observable,
    ObservableType,
    ThreatLevel,
    ObservableEnrichment,
    ObservableLink,
    ObservableLinkType,
    ObservableAlertLink,  # Backward compatibility alias for ObservableLink
    ObservableCaseLink,  # Backward compatibility alias for ObservableLink
    ObservableSighting,  # Backward compatibility alias for ObservableLink
    WatchlistAlert,
    WatchlistAlertType,
)
from ion.models.ai_chat import (
    AIChatSession,
    AIChatMessage,
    AIContextType,
)
from ion.models.ai_preferences import (
    AIUserPreference,
    AIResponseFeedback,
)
from ion.models.saved_search import (
    SavedSearch,
    SearchType,
)
from ion.models.playbook import (
    Playbook,
    PlaybookStep,
    PlaybookExecution,
    StepType,
    ExecutionStatus,
)
from ion.models.skills import (
    AssessmentReviewCycle,
    SkillAssessment,
    UserCareerGoal,
    AssessmentSnapshot,
    TeamScheduleEntry,
    TeamCertification,
    SOCCMMAssessment,
    KnowledgeArticle,
    TrainingPlan,
    TrainingPlanItem,
    RoleAssessment,
)
from ion.models.analyst_note import AnalystNote
from ion.models.note_folder import NoteFolder
from ion.models.social import (
    SocialPost,
    SocialComment,
    SocialReaction,
)
from ion.models.analytics import (
    AnalyticsJob,
    AnalyticsJobType,
    AnalyticsSnapshot,
)
from ion.models.cyab import CyabSystem, CyabDataSource, CyabSnapshot
from ion.models.canary import Canary, CanaryHit, CanaryType, CanaryStatus
from ion.models.log_source import LogSource, LogSourceCategory
from ion.models.emulation import EmulationPlan, EmulationStep, EmulationPlanStatus, StepResult
from ion.models.vulnerability import Vulnerability, VulnerabilityAsset, VulnSeverity, VulnStatus
from ion.models.tide_snapshot import TideSnapshot
from ion.models.maturity import MaturityAssessment
from ion.models.threat_intel import ThreatIntelWatch
from ion.models.forensics import (
    ForensicCase,
    ForensicCaseStatus,
    ForensicCasePriority,
    InvestigationType,
    EvidenceItem,
    EvidenceType,
    EvidenceStatus,
    CustodyLogEntry,
    CustodyAction,
    ForensicPlaybook,
    ForensicPlaybookStep,
    ForensicCaseStep,
    ForensicTimelineEntry,
)
from ion.models.oncall import (
    ServiceAccount,
    UserBookmark,
    CommTemplate,
    ChangeLogEntry,
)

from ion.models.sla import (
    SLAPolicy,
    SLABreachLog,
    ThreatHunt,
    DashboardLayout,
    ScheduledReport,
    PlaybookAction,
    PlaybookActionLog,
)

# v0.10.3: alert_prompt, ticker, tuning proposals, AI feedback ledger.
# Imported eagerly here so Base.metadata registers the tables at startup;
# otherwise create_all() misses them because callers lazy-import.
# Order matters: alert_prompt MUST come before tuning_proposal and
# ai_feedback because they FK to alert_prompt_templates.
from ion.models.alert_prompt import AlertPromptTemplate  # noqa: F401
from ion.models.investigation import Investigation  # noqa: F401
from ion.models.ticker import Ticker, TickerDismissal, TickerKind, TickerSeverity, TickerSourceType  # noqa: F401
from ion.models.tuning_proposal import TuningProposal, TuningProposalStatus  # noqa: F401
from ion.models.ai_feedback import AIFeedback  # noqa: F401

# v0.10.4: case-similarity embeddings (pgvector-backed).
from ion.models.case_embedding import CaseEmbedding  # noqa: F401

# v0.10.6: KB article embeddings for Bob's RAG grounding.
from ion.models.kb_document_embedding import KBDocumentEmbedding  # noqa: F401

# v0.11.0: JSON-DAG playbook automation (Tines-inspired).
from ion.models.story import Story, StoryRun  # noqa: F401

__all__ = [
    "Base",
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
    # CyAB models
    "CyabSystem",
    "CyabDataSource",
    "CyabSnapshot",
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
