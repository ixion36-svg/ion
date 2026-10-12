"""The one Jinja environment every /ui fragment renders through.

make_templates() builds a fresh Jinja2Templates on each call, so a module
per page calling it would stand up one environment, and one bytecode cache
handle, per page. There are 35 pages left to convert. This is the single
instance they share.

Importing server.templates instead would loop: server imports this router.
"""
from __future__ import annotations

from ion.web.templating import make_templates

templates = make_templates()
