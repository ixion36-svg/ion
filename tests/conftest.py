"""Pytest configuration and fixtures."""

import os
from pathlib import Path

import pytest

# v0.94.0 makes a weak or unset ION_ADMIN_PASSWORD fatal in _validate_startup_config,
# so any test booting the app through TestClient dies in startup instead of running.
# Set a strong value rather than ION_DEV_MODE, so tests exercise the enforcing path.
os.environ.setdefault("ION_ADMIN_PASSWORD", "Tst-C0nftest-N0t-A-Real-Pw-9f3a")

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


# ── WeasyPrint's native libraries ──
#
# PDF rendering needs Pango, Cairo and GDK-Pixbuf, which are present on the
# ubuntu-latest CI runner but not on a bare Windows host. ION's own error says
# as much: "Install them or use the Docker image."
#
# Without this, nine tests fail locally for a reason that has nothing to do
# with the code, and real regressions hide in the noise. Tests that genuinely
# render carry @pytest.mark.requires_weasyprint and skip when the libraries
# cannot be loaded. They still run in CI, so coverage is unchanged there.
try:
    from weasyprint import HTML as _WeasyHTML  # noqa: F401

    WEASYPRINT_AVAILABLE = True
except Exception:  # ImportError, OSError, and whatever else the loader raises
    WEASYPRINT_AVAILABLE = False


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "requires_weasyprint: needs WeasyPrint's native libraries (Pango, "
        "Cairo, GDK-Pixbuf); skipped where they are not installed",
    )


def pytest_collection_modifyitems(config, items):
    if WEASYPRINT_AVAILABLE:
        return
    skip = pytest.mark.skip(
        reason="WeasyPrint's native libraries (Pango, Cairo, GDK-Pixbuf) are "
        "not available on this host; these run in CI and in the Docker image"
    )
    for item in items:
        if "requires_weasyprint" in item.keywords:
            item.add_marker(skip)
