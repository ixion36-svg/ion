"""Server-rendered forensics panels."""
from fastapi import APIRouter
from ion.web.ui._forensics_overview import router as overview_router
router=APIRouter()
router.include_router(overview_router)
