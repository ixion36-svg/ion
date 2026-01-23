#!/usr/bin/env python
"""Test script to verify all new modules import correctly."""

import sys
sys.path.insert(0, 'src')

print("Testing imports...")

try:
    # Test models
    from docforge.models.template import Collection, Template
    print("  [OK] Models: Collection, Template")

    # Test repository
    from docforge.storage.collection_repository import CollectionRepository
    print("  [OK] Repository: CollectionRepository")

    # Test services
    from docforge.services.template_service import (
        TemplateService,
        CollectionNotFoundError
    )
    print("  [OK] Service: TemplateService, CollectionNotFoundError")

    from docforge.services.render_service import (
        RenderService,
        ValidationResult,
        ValidationError,
        BatchRenderResult,
        BatchRenderSummary,
    )
    print("  [OK] Service: RenderService, ValidationResult, BatchRenderSummary")

    # Test CLI
    from docforge.cli.collection_commands import collection_app
    print("  [OK] CLI: collection_commands")

    from docforge.cli.main import app
    print("  [OK] CLI: main app")

    # Test config with env var support
    from docforge.core.config import get_config, _get_env_bool
    print("  [OK] Config: get_config, _get_env_bool")

    # Test API models
    from docforge.web.api import (
        CollectionCreate,
        CollectionUpdate,
        ValidateRequest,
        BatchRenderRequest,
    )
    print("  [OK] API: Pydantic models")

    print("\n" + "="*50)
    print("ALL IMPORTS SUCCESSFUL!")
    print("="*50)

except Exception as e:
    print(f"\n[FAIL] Import error: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
