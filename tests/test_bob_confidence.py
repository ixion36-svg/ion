"""Unit tests for Bob confidence scoring (_compute_confidence).

Pure Python — no mocks, no DB, no network. Tests the scoring logic in
isolation by constructing the parsed dict that _parse_llm_json would return.
"""
from ion.services.investigation_service import _compute_confidence


class TestComputeConfidence:
    """Tests for _compute_confidence helper."""

    def _base(self, **overrides) -> dict:
        """Build a minimal valid parsed dict for testing."""
        base = {
            "confidence": 90,
            "verdict": "true_positive",
            "suggested_closure_reason": "true_positive",
            "key_observations": [
                {"field": "process.name", "value": "cmd.exe", "significance": "suspicious"},
            ],
            "analyst_explanation": "Confirmed malicious activity.",
        }
        base.update(overrides)
        return base

    # ----------------------------------------------------------------------- #
    # Happy path

    def test_valid_inputs_90_returns_90(self):
        parsed = self._base()
        assert _compute_confidence(parsed) == 90

    # ----------------------------------------------------------------------- #
    # Invalid verdict deduction (-20)

    def test_invalid_verdict_deducts_20(self):
        parsed = self._base(verdict="banana")
        # 90 - 20 (invalid verdict) - 15 (closure != verdict: "true_positive" != "banana")
        # closure="true_positive", verdict="banana" -> mismatch -> -15
        # key_observations present -> no deduction
        assert _compute_confidence(parsed) == 55

    def test_invalid_verdict_no_closure_mismatch(self):
        # closure matches nothing valid either, but since verdict is invalid
        # and closure IS set and differs, both penalties apply.
        parsed = self._base(verdict="unknown_bad", suggested_closure_reason="")
        # verdict invalid -> -20; closure="" so closure mismatch check: closure is falsy -> skip
        # key_observations present -> ok
        assert _compute_confidence(parsed) == 70

    # ----------------------------------------------------------------------- #
    # No key_observations deduction (-10)

    def test_no_key_observations_deducts_10(self):
        parsed = self._base(key_observations=[])
        assert _compute_confidence(parsed) == 80

    def test_none_key_observations_deducts_10(self):
        parsed = self._base(key_observations=None)
        assert _compute_confidence(parsed) == 80

    # ----------------------------------------------------------------------- #
    # Closure/verdict mismatch deduction (-15)

    def test_closure_verdict_mismatch_deducts_15(self):
        parsed = self._base(
            verdict="true_positive",
            suggested_closure_reason="false_positive",
        )
        # verdict valid; closure present and != verdict -> -15; observations ok
        assert _compute_confidence(parsed) == 75

    def test_closure_matches_verdict_no_deduction(self):
        parsed = self._base(
            verdict="false_positive",
            suggested_closure_reason="false_positive",
        )
        assert _compute_confidence(parsed) == 90

    # ----------------------------------------------------------------------- #
    # Clamping

    def test_clamped_at_100(self):
        parsed = self._base(confidence=200)
        assert _compute_confidence(parsed) == 100  # input clamped to 100; no deductions on valid base

    def test_clamped_at_zero(self):
        # confidence=10, invalid verdict (-20), closure mismatch (-15), no obs (-10)
        parsed = self._base(
            confidence=10,
            verdict="bad_verdict",
            suggested_closure_reason="true_positive",
            key_observations=[],
        )
        # 10 - 20 - 15 - 10 = -35 -> clamped to 0
        assert _compute_confidence(parsed) == 0

    def test_raw_zero_confidence(self):
        parsed = self._base(confidence=0, key_observations=[])
        # 0 - 10 = -10 -> clamp to 0
        assert _compute_confidence(parsed) == 0

    # ----------------------------------------------------------------------- #
    # Benign true positive (valid verdict)

    def test_benign_true_positive_is_valid(self):
        parsed = self._base(
            verdict="benign_true_positive",
            suggested_closure_reason="benign_true_positive",
        )
        assert _compute_confidence(parsed) == 90

    # ----------------------------------------------------------------------- #
    # Missing confidence key falls back to 0

    def test_missing_confidence_key_is_zero(self):
        parsed = self._base()
        del parsed["confidence"]
        # 0 - no further deductions because verdict/closure/observations still valid
        assert _compute_confidence(parsed) == 0
