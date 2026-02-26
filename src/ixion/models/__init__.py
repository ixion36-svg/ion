"""SQLAlchemy models for IXION."""

from ixion.models.base import Base
from ixion.models.template import Template, Tag, Variable, Collection, template_tags
from ixion.models.version import TemplateVersion
from ixion.models.document import Document, DocumentVersion
from ixion.models.user import (
    User,
    Role,
    Permission,
    UserSession,
    AuditLog,
    user_roles,
    role_permissions,
)
from ixion.models.security import (
    SecurityEvent,
    SecurityEventType,
    SecurityEventSeverity,
    SecurityEventStatus,
    SecurityAlertRule,
    BlockedIP,
)
from ixion.models.alert_triage import (
    AlertTriage,
    AlertTriageStatus,
    AlertCase,
    AlertCaseStatus,
    Note,
    NoteEntityType,
    AlertComment,  # Backward compatibility alias for Note
    CaseNote,  # Backward compatibility alias for Note
)
from ixion.models.chat import (
    ChatRoom,
    ChatRoomMember,
    ChatMessage,
    MessageReaction,
)
from ixion.models.integration import (
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
from ixion.models.observable import (
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
from ixion.models.ai_chat import (
    AIChatSession,
    AIChatMessage,
    AIContextType,
)
from ixion.models.saved_search import (
    SavedSearch,
    SearchType,
)
from ixion.models.playbook import (
    Playbook,
    PlaybookStep,
    PlaybookExecution,
    StepType,
    ExecutionStatus,
)
from ixion.models.skills import (
    SkillAssessment,
    UserCareerGoal,
    AssessmentSnapshot,
    TeamScheduleEntry,
    TeamCertification,
    SOCCMMAssessment,
    KnowledgeArticle,
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
    "SkillAssessment",
    "UserCareerGoal",
    "AssessmentSnapshot",
    "TeamScheduleEntry",
    # SOC-CMM alignment models
    "TeamCertification",
    "SOCCMMAssessment",
    "KnowledgeArticle",
]
