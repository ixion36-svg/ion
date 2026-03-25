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
from ion.models.chat import (
    ChatRoom,
    ChatRoomMember,
    ChatMessage,
    MessageReaction,
    ChatMeme,
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
)
from ion.models.analyst_note import AnalystNote
from ion.models.note_folder import NoteFolder
from ion.models.notification import Notification
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
    "ChatRoom",
    "ChatRoomMember",
    "ChatMessage",
    "MessageReaction",
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
    # Threat Intel watch model
    "ThreatIntelWatch",
    # Notification model
    "Notification",
    # Social Hub models
    "SocialPost",
    "SocialComment",
    "SocialReaction",
]
