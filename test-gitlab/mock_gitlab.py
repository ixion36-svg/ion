"""Minimal mock GitLab REST v4 — just enough for ION's tuning-request mirror.

Full GitLab CE (docker-compose.yml here) needs ~4 GB and minutes to boot, which
is not viable on the dev box, so this stands in for the handful of endpoints
`gitlab_service` actually calls: project GET (connection test), issue create,
issue update (close), and issue notes (comments). It keeps issues in memory and
exposes GET /__debug/state so a test can assert what ION mirrored.

Run:  PORT=8930 python test-gitlab/mock_gitlab.py
Point ION at it: ION_GITLAB_URL=http://host.docker.internal:8930,
ION_GITLAB_TOKEN=<any>, ION_GITLAB_PROJECT_ID=42 (numeric → no %2F path quirk).
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any, Dict, List

from fastapi import FastAPI

app = FastAPI()

_ISSUES: Dict[int, Dict[str, Any]] = {}
_NOTES: Dict[int, List[Dict[str, Any]]] = {}
_SEQ = {"iid": 0, "note": 1000}


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _issue(iid: int) -> Dict[str, Any]:
    return _ISSUES[iid]


@app.get("/api/v4/projects/{project}")
async def get_project(project: str):
    # test_connection() just needs a 200 with an object.
    return {"id": 42, "path_with_namespace": "ion/detections", "name": "detections"}


@app.post("/api/v4/projects/{project}/issues")
async def create_issue(project: str, body: Dict[str, Any]):
    _SEQ["iid"] += 1
    iid = _SEQ["iid"]
    now = _now()
    labels = body.get("labels")
    if isinstance(labels, str):
        labels = [x for x in labels.split(",") if x]
    issue = {
        "id": 10000 + iid, "iid": iid,
        "title": body.get("title", ""), "description": body.get("description", "") or "",
        "state": "opened", "labels": labels or [],
        "assignees": [], "author": {"username": "ion-bot"},
        "created_at": now, "updated_at": now, "closed_at": None,
        "web_url": f"http://gitlab.local/ion/detections/-/issues/{iid}",
        "milestone": None, "due_date": None,
    }
    _ISSUES[iid] = issue
    _NOTES[iid] = []
    return issue


@app.get("/api/v4/projects/{project}/issues/{iid}")
async def get_issue(project: str, iid: int):
    return _issue(iid)


@app.put("/api/v4/projects/{project}/issues/{iid}")
async def update_issue(project: str, iid: int, body: Dict[str, Any]):
    issue = _issue(iid)
    if body.get("state_event") == "close":
        issue["state"] = "closed"
        issue["closed_at"] = _now()
    elif body.get("state_event") == "reopen":
        issue["state"] = "opened"
        issue["closed_at"] = None
    for k in ("title", "description", "labels"):
        if k in body:
            issue[k] = body[k]
    issue["updated_at"] = _now()
    return issue


@app.post("/api/v4/projects/{project}/issues/{iid}/notes")
async def add_note(project: str, iid: int, body: Dict[str, Any]):
    _SEQ["note"] += 1
    note = {
        "id": _SEQ["note"], "body": body.get("body", ""),
        "author": {"username": "ion-bot"}, "system": False,
        "created_at": _now(), "updated_at": _now(),
    }
    _NOTES.setdefault(iid, []).append(note)
    return note


@app.get("/api/v4/projects/{project}/issues/{iid}/notes")
async def list_notes(project: str, iid: int):
    return _NOTES.get(iid, [])


@app.get("/__debug/state")
async def debug_state():
    return {"issues": list(_ISSUES.values()),
            "notes": {str(k): v for k, v in _NOTES.items()}}


if __name__ == "__main__":
    import uvicorn

    port = int(os.environ.get("PORT", "8930"))
    print(f"[mock-gitlab] listening on 0.0.0.0:{port}")
    uvicorn.run(app, host="0.0.0.0", port=port)
