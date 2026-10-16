"""Observable fragment router, split by the page's panel ownership."""
from fastapi import APIRouter

from ion.web.ui._observables_analysis import router as analysis_router
from ion.web.ui._observables_core import router as core_router

router = APIRouter()
router.include_router(core_router)
router.include_router(analysis_router)
