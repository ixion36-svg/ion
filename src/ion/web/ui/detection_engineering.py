"""Ungated detection engineering panels, sharing the existing alert read permission."""
from fastapi import APIRouter

from ion.web.ui._detection_engineering_bob import router as bob_router
from ion.web.ui._detection_engineering_catalogue import router as catalogue_router
from ion.web.ui._detection_engineering_core import router as core_router
from ion.web.ui._detection_engineering_readiness import router as readiness_router
from ion.web.ui._detection_engineering_health import router as health_router
from ion.web.ui._detection_engineering_overview import router as overview_router
from ion.web.ui._detection_engineering_rules import router as rules_router
from ion.web.ui._detection_engineering_systems import router as systems_router
from ion.web.ui._detection_engineering_work import router as work_router

router = APIRouter()
router.include_router(core_router)
router.include_router(overview_router)
router.include_router(rules_router)
router.include_router(systems_router)
router.include_router(readiness_router)
router.include_router(health_router)
router.include_router(catalogue_router)
router.include_router(work_router)
router.include_router(bob_router)
