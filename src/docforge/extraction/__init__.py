"""Template extraction from documents."""

from docforge.extraction.pattern_detector import PatternDetector
from docforge.extraction.variable_inferrer import VariableInferrer
from docforge.extraction.template_generator import TemplateGenerator
from docforge.extraction.enhanced_detector import EnhancedPatternDetector
from docforge.extraction.nlp_service import NLPService, get_nlp_service

__all__ = [
    "PatternDetector",
    "VariableInferrer",
    "TemplateGenerator",
    "EnhancedPatternDetector",
    "NLPService",
    "get_nlp_service",
]
