"""Authenticated integration dashboard fragments."""
from fastapi import APIRouter

from ion.web.ui._integrations_operations import router as operations_router

router = APIRouter()
router.include_router(operations_router)
