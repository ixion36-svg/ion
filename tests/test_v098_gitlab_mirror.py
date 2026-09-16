"""v0.98.0 — tuning-request → GitLab issue mirroring (PROD-verify, pinned in CI).

Verified live against test-gitlab/mock_gitlab.py; this pins the contract:
- raising a request creates a GitLab issue and stores its iid/url on the row,
- closing a request comments on and closes the mirrored issue,
- the mirror is best-effort: a GitLab failure never blocks the request.
"""

import asyncio
from types import SimpleNamespace
from unittest.mock import patch

from ion.services import de_tuning_request_service as svc


class _FakeIssue:
    iid = 7
    web_url = "http://gitlab.local/ion/detections/-/issues/7"


class _FakeGitLab:
    def __init__(self):
        self.is_configured = True
        self.comments = []
        self.closed = []
        self.created = None

    async def create_issue(self, *, title, description, labels):
        self.created = {"title": title, "description": description, "labels": labels}
        return _FakeIssue()

    async def add_issue_comment(self, iid, body):
        self.comments.append((iid, body))

    async def close_issue(self, iid):
        self.closed.append(iid)


def _user():
    return SimpleNamespace(id=1, username="admin")


def test_raise_mirrors_issue_and_stores_iid(session):
    fake = _FakeGitLab()
    with patch("ion.services.gitlab_service.get_gitlab_service", return_value=fake):
        req = asyncio.run(svc.create_request(
            session, _user(), rule_name="Brute Force Login Attempt Detected",
            reason="false_positive", details="verify",
        ))
    assert req.gitlab_issue_iid == 7
    assert req.gitlab_issue_url.endswith("/issues/7")
    assert fake.created["labels"] == ["ion", "tuning-request", "false_positive"]
    assert fake.created["title"].startswith("[tuning] Brute Force")


def test_close_comments_and_closes_mirrored_issue(session):
    fake = _FakeGitLab()
    with patch("ion.services.gitlab_service.get_gitlab_service", return_value=fake):
        req = asyncio.run(svc.create_request(
            session, _user(), rule_name="Some Rule", reason="other",
        ))
        asyncio.run(svc.close_request(session, _user(), req, resolution="tuned away"))
    assert req.status == "closed"
    assert fake.closed == [7]
    assert fake.comments and "tuned away" in fake.comments[-1][1]


def test_mirror_failure_never_blocks_the_request(session):
    fake = _FakeGitLab()

    async def _boom(**kw):
        raise RuntimeError("gitlab down")

    fake.create_issue = _boom
    with patch("ion.services.gitlab_service.get_gitlab_service", return_value=fake):
        req = asyncio.run(svc.create_request(session, _user(), rule_name="R", reason="other"))
    # Request persisted; mirror simply left the issue fields empty.
    assert req.id is not None and req.status == "open"
    assert req.gitlab_issue_iid is None
