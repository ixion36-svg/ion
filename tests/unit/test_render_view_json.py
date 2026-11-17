from dataclasses import dataclass
from datetime import datetime, timezone

from starlette.requests import Request

from ion.web.ui._shared import render_view


@dataclass
class _Panel:
    name: str
    seen_at: datetime


def _json_request():
    return Request({"type": "http", "method": "GET", "path": "/",
                    "headers": [(b"accept", b"application/json")]})


def test_a_view_model_holding_a_dataclass_and_a_datetime_renders_as_json():
    seen = datetime(2026, 11, 17, 8, 30, tzinfo=timezone.utc)
    response = render_view(_json_request(), "unused.html", {"panel": _Panel("DC", seen), "count": 3})
    assert response.status_code == 200
    assert response.body == b'{"panel":{"name":"DC","seen_at":"2026-11-17T08:30:00+00:00"},"count":3}'
