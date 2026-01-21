"""Template extraction from documents."""

from docforge.extraction.pattern_detector import PatternDetector
from docforge.extraction.variable_inferrer import VariableInferrer
from docforge.extraction.template_generator import TemplateGenerator

__all__ = [
    "PatternDetector",
    "VariableInferrer",
    "TemplateGenerator",
]
