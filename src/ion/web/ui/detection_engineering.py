"""Ungated detection engineering panel fragments."""
from fastapi import APIRouter

from ion.web.ui._detection_engineering_core import router as core_router
from ion.web.ui._detection_engineering_rules import router as rules_router

router = APIRouter()
router.include_router(core_router)
router.include_router(rules_router)
