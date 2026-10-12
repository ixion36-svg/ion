"""The one Jinja environment every /ui fragment renders through.

make_templates() builds a fresh Jinja2Templates on each call, so a module
per page calling it would stand up one environment, and one bytecode cache
handle, per page. There are 35 pages left to convert. This is the single
instance they share.

Importing server.templates instead would loop: server imports this router.
"""
from __future__ import annotations

from enum import Enum

from ion.web.templating import make_templates

templates = make_templates()


def plain(value: object) -> object:
    """An enum member's value, or the value unchanged.

    ION's status, severity and risk columns are `SQLEnum`, so a row read
    through the ORM carries the enum member rather than its string. The JSON
    endpoints got the string for free, because FastAPI serialises a
    str-mixin enum by value. A template does not: on Python 3.12
    `str(ChangeRequestStatus.SUBMITTED)` is "ChangeRequestStatus.SUBMITTED",
    which is what a pill renders.

    Value equality still holds, so a colour map keyed by the string keeps
    working and only the visible text is wrong. That is why it survives a
    glance and why it is worth one shared definition: two conversions in the
    same batch hit it independently and each wrote this function.

    None passes through, because a missing status is not the string "None".
    """
    if isinstance(value, Enum):
        return value.value
    return value
