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
    AlertComment,
    AlertCase,
    AlertCaseStatus,
    CaseNote,
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
    Webhook,
    WebhookLog,
    IntegrationLog,
    IntegrationHealthCheck,
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
    "AlertComment",
    "AlertCase",
    "AlertCaseStatus",
    "CaseNote",
    "ChatRoom",
    "ChatRoomMember",
    "ChatMessage",
    "MessageReaction",
    # Integration models
    "IntegrationType",
    "IntegrationStatus",
    "LogLevel",
    "WebhookStatus",
    "Webhook",
    "WebhookLog",
    "IntegrationLog",
    "IntegrationHealthCheck",
]
