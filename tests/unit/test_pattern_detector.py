"""Tests for pattern detection."""

import pytest

from ion.extraction.pattern_detector import PatternDetector


class TestPatternDetector:
    """Tests for PatternDetector."""

    @pytest.fixture
    def detector(self):
        return PatternDetector()

    def test_detect_email(self, detector):
        """Test detecting email addresses."""
        text = "Contact us at support@example.com for help."
        matches = detector.detect(text)

        email_matches = [m for m in matches if m.pattern_type == "email"]
        assert len(email_matches) == 1
        assert email_matches[0].value == "support@example.com"
        assert email_matches[0].suggested_name == "email"

    def test_detect_date_iso(self, detector):
        """Test detecting ISO dates."""
        text = "The meeting is on 2024-01-15."
        matches = detector.detect(text)

        date_matches = [m for m in matches if "date" in m.pattern_type]
        assert len(date_matches) == 1
        assert date_matches[0].value == "2024-01-15"

    def test_detect_date_us(self, detector):
        """Test detecting US dates."""
        text = "Due date: 01/15/2024"
        matches = detector.detect(text)

        date_matches = [m for m in matches if "date" in m.pattern_type]
        assert len(date_matches) == 1
        assert date_matches[0].value == "01/15/2024"

    def test_detect_phone_us(self, detector):
        """Test detecting US phone numbers."""
        text = "Call us at (555) 123-4567"
        matches = detector.detect(text)

        phone_matches = [m for m in matches if "phone" in m.pattern_type]
        assert len(phone_matches) == 1
        assert "555" in phone_matches[0].value

    def test_detect_url(self, detector):
        """Test detecting URLs."""
        text = "Visit https://www.example.com/page for more info."
        matches = detector.detect(text)

        url_matches = [m for m in matches if m.pattern_type == "url"]
        assert len(url_matches) == 1
        assert url_matches[0].value == "https://www.example.com/page"

    def test_detect_currency_usd(self, detector):
        """Test detecting USD currency."""
        text = "Total: $1,234.56"
        matches = detector.detect(text)

        currency_matches = [m for m in matches if "currency" in m.pattern_type]
        assert len(currency_matches) == 1
        assert currency_matches[0].value == "$1,234.56"

    def test_detect_placeholder_bracket(self, detector):
        """Test detecting bracket placeholders."""
        text = "Dear [CUSTOMER NAME], your order [ORDER ID] is ready."
        matches = detector.detect(text)

        placeholder_matches = [m for m in matches if "placeholder" in m.pattern_type]
        assert len(placeholder_matches) == 2

    def test_detect_percentage(self, detector):
        """Test detecting percentages."""
        text = "Discount: 15%"
        matches = detector.detect(text)

        pct_matches = [m for m in matches if m.pattern_type == "percentage"]
        assert len(pct_matches) == 1
        assert pct_matches[0].value == "15%"

    def test_minimum_confidence_filter(self, detector):
        """Test filtering by minimum confidence."""
        text = "Contact: test@example.com on 2024-01-15"

        # Low threshold - should get all
        low_matches = detector.detect(text, min_confidence=0.1)

        # High threshold - should get fewer
        high_matches = detector.detect(text, min_confidence=0.95)

        assert len(low_matches) >= len(high_matches)

    def test_detect_multiple_patterns(self, detector, sample_document_content):
        """Test detecting multiple patterns in a document."""
        matches = detector.detect(sample_document_content)

        # Should find email
        assert any(m.pattern_type == "email" for m in matches)

        # Should find date
        assert any("date" in m.pattern_type for m in matches)

        # Should find phone
        assert any("phone" in m.pattern_type for m in matches)

        # Should find currency
        assert any("currency" in m.pattern_type for m in matches)

    def test_detect_by_type(self, detector):
        """Test detecting specific types only."""
        text = "Email: test@example.com, Date: 2024-01-15"

        email_only = detector.detect_by_type(text, ["email"])
        assert all(m.pattern_type == "email" for m in email_only)

        date_only = detector.detect_by_type(text, ["date_iso"])
        assert all("date" in m.pattern_type for m in date_only)
