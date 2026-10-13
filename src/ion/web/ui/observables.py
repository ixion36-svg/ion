"""Server-rendered observables panels."""
from fastapi import APIRouter
from ion.web.ui._observables_core import router as core_router
router=APIRouter()
router.include_router(core_router)
