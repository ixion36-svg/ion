"""Training page fragments; browser-owned calculations remain in the shell."""
from fastapi import APIRouter

from ion.web.ui._training_plans import router as plans_router

router = APIRouter()
router.include_router(plans_router)
