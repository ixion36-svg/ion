"""Authenticated integration dashboard fragments."""

from fastapi import APIRouter

from ion.web.ui._integrations_metrics import router as metrics_router
from ion.web.ui._integrations_operations import router as operations_router
from ion.web.ui._integrations_topology import router as topology_router

router = APIRouter()
router.include_router(operations_router)
router.include_router(metrics_router)
router.include_router(topology_router)
