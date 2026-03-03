#!/usr/bin/env python
"""Test script to verify all new modules import correctly."""

import sys
sys.path.insert(0, 'src')

print("Testing imports...")

try:
    # Test models
    from ion.models.template import Collection, Template
    print("  [OK] Models: Collection, Template")

    # Test repository
    from ion.storage.collection_repository import CollectionRepository
    print("  [OK] Repository: CollectionRepository")

    # Test services
    from ion.services.template_service import (
        TemplateService,
        CollectionNotFoundError
    )
    print("  [OK] Service: TemplateService, CollectionNotFoundError")

    from ion.services.render_service import (
        RenderService,
        ValidationResult,
        ValidationError,
        BatchRenderResult,
        BatchRenderSummary,
    )
    print("  [OK] Service: RenderService, ValidationResult, BatchRenderSummary")

    # Test CLI
    from ion.cli.collection_commands import collection_app
    print("  [OK] CLI: collection_commands")

    from ion.cli.main import app
    print("  [OK] CLI: main app")

    # Test config with env var support
    from ion.core.config import get_config, _get_env_bool
    print("  [OK] Config: get_config, _get_env_bool")

    # Test API models
    from ion.web.api import (
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
