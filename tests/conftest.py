"""Pytest configuration and fixtures."""

import pytest
from pathlib import Path
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from ion.models.document import Base
from ion.storage.database import reset_engine


@pytest.fixture
def temp_db(tmp_path: Path):
    """Create a temporary SQLite database."""
    db_path = tmp_path / "test.db"
    engine = create_engine(f"sqlite:///{db_path}")
    Base.metadata.create_all(engine)
    return engine


@pytest.fixture
def session(temp_db):
    """Create a database session."""
    Session = sessionmaker(bind=temp_db)
    session = Session()
    yield session
    session.close()
    reset_engine()


@pytest.fixture
def sample_template_content():
    """Sample template content with variables."""
    return """# Welcome, {{ name }}!

Hello {{ name }}, welcome to {{ company }}.

Your email is {{ email }}.

{% if department %}
You work in the {{ department }} department.
{% endif %}

{% for item in items %}
- {{ item }}
{% endfor %}
"""


@pytest.fixture
def sample_data():
    """Sample data for rendering."""
    return {
        "name": "John Doe",
        "company": "Acme Corp",
        "email": "john@example.com",
        "department": "Engineering",
        "items": ["Task 1", "Task 2", "Task 3"],
    }


@pytest.fixture
def sample_document_content():
    """Sample document content for extraction testing."""
    return """
Dear Mr. John Smith,

Thank you for your order placed on 2024-01-15.

Your order confirmation number is #12345.

Please contact us at support@example.com or call 555-123-4567 if you have questions.

Order Total: $149.99

Best regards,
Acme Corporation
123 Main Street
New York, NY 10001
"""
