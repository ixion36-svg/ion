"""v0.49.3 live-boot finding: every model module must be imported by
ion.models.__init__.

The docker entrypoint initialises the schema single-process via
`import ion.models` + create_all. A model module missing from the registry
(network_asset, scheduler) left its tables uncreated there — the 4 uvicorn
workers then raced to create them in their own lifespans, and 3 of 4 crashed
on a pg_type UniqueViolation on the first boot of a fresh Postgres.
"""

from __future__ import annotations

import ast
import pathlib

_MODELS_DIR = pathlib.Path("src/ion/models")


def _modules_on_disk() -> set:
    return {
        p.stem for p in _MODELS_DIR.glob("*.py")
        if p.stem != "__init__"
    }


def _modules_imported_by_registry() -> set:
    tree = ast.parse((_MODELS_DIR / "__init__.py").read_text(encoding="utf-8"))
    found = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            parts = node.module.split(".")
            if parts[:2] == ["ion", "models"] and len(parts) > 2:
                found.add(parts[2])
            elif node.module == "ion.models":
                found.update(a.name for a in node.names)
        elif isinstance(node, ast.Import):
            for a in node.names:
                parts = a.name.split(".")
                if parts[:2] == ["ion", "models"] and len(parts) > 2:
                    found.add(parts[2])
    return found


def test_every_model_module_is_registered():
    missing = _modules_on_disk() - _modules_imported_by_registry()
    assert not missing, (
        f"model modules not imported by ion.models.__init__: {sorted(missing)} — "
        f"their tables won't exist after the entrypoint's create_all, and the "
        f"N web workers will race (and crash) creating them on first boot"
    )


def test_registry_covers_all_declared_tables():
    """Importing ion.models alone must register every table that importing
    the web app would register — the entrypoint relies on it."""
    import importlib

    import ion.models  # noqa: F401
    from ion.models.base import Base

    registered = set(Base.metadata.tables)
    for stem in _modules_on_disk():
        importlib.import_module(f"ion.models.{stem}")
    after_all = set(Base.metadata.tables)
    assert registered == after_all, (
        f"tables only registered by direct module import: {sorted(after_all - registered)}"
    )
