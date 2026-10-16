"""Ungated detection engineering panels, sharing the existing alert read permission."""
from fastapi import APIRouter

from ion.web.ui._detection_engineering_catalogue import router as catalogue_router
from ion.web.ui._detection_engineering_core import router as core_router
from ion.web.ui._detection_engineering_execution import router as execution_router
from ion.web.ui._detection_engineering_rules import router as rules_router

router = APIRouter()
router.include_router(core_router)
router.include_router(rules_router)
router.include_router(execution_router)
router.include_router(catalogue_router)
