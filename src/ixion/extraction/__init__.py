"""Template extraction from documents."""

from ixion.extraction.pattern_detector import PatternDetector
from ixion.extraction.variable_inferrer import VariableInferrer
from ixion.extraction.template_generator import TemplateGenerator
from ixion.extraction.enhanced_detector import EnhancedPatternDetector
from ixion.extraction.nlp_service import NLPService, get_nlp_service

__all__ = [
    "PatternDetector",
    "VariableInferrer",
    "TemplateGenerator",
    "EnhancedPatternDetector",
    "NLPService",
    "get_nlp_service",
]
