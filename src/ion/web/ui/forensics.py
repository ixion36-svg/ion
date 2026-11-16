"""Server-rendered forensic panels."""
from fastapi import APIRouter

from ion.web.ui._forensics_detail import router as detail_router
from ion.web.ui._forensics_overview import router as overview_router

router=APIRouter()
router.include_router(detail_router)
router.include_router(overview_router)
