"""Chat uploads survive across workers.

These used to live in a module-level dict, so only the uvicorn worker that
served the upload could see the file. Measured on a 4-worker container, 10 of
20 reads on fresh connections could not find a file that had just uploaded
successfully; a browser's keep-alive pins the connection to one worker, which
is why it presented as intermittent rather than broken.

A second process is simulated here by using a separate Session against the same
database — which is exactly what another worker has.
"""

import json

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from ion.models.ai_chat import AIChatUpload
from ion.models.base import Base
from ion.models.user import User
from ion.services import chat_upload_service as svc


@pytest.fixture(scope="module")
def _engine(tmp_path_factory):
    """Built once: create_all raises ION's whole schema and costs ~5s a go."""
    path = tmp_path_factory.mktemp("uploads") / "uploads.db"
    engine = create_engine(f"sqlite:///{path}")
    Base.metadata.create_all(engine)
    return engine


@pytest.fixture
def factory(_engine):
    """Fresh rows per test; the schema is shared."""
    maker = sessionmaker(bind=_engine)
    s = maker()
    s.query(AIChatUpload).delete()
    s.query(User).delete()
    s.commit()
    s.close()
    return maker


@pytest.fixture
def user_id(factory):
    s = factory()
    u = User(username="analyst", email="a@x.y", password_hash="x", display_name="A")
    s.add(u)
    s.commit()
    uid = u.id
    s.close()
    return uid


def test_an_upload_is_visible_from_another_process(factory, user_id):
    """The regression this fix exists for."""
    writer = factory()
    stored = svc.store_upload(
        writer, user_id, name="evidence.log", content="line one\nline two\n", size_bytes=18
    )
    writer.close()

    reader = factory()  # stands in for a different uvicorn worker
    seen = svc.list_uploads(reader, user_id)
    assert [f["id"] for f in seen] == [stored["id"]]
    assert svc.get_upload(reader, user_id, stored["id"])["content"] == "line one\nline two\n"


def test_the_model_context_is_visible_from_another_process(factory, user_id):
    writer = factory()
    svc.store_upload(writer, user_id, name="e.log", content="payload text", size_bytes=12)
    writer.close()

    reader = factory()
    ctx = svc.files_context(reader, user_id)
    assert "UPLOADED FILES" in ctx
    assert "payload text" in ctx


def test_indicators_survive_the_round_trip_and_label_the_context(factory, user_id):
    writer = factory()
    svc.store_upload(
        writer, user_id, name="s.sh", content="some sample", size_bytes=11,
        sha256="deadbeef", indicators=["reverse-shell"],
    )
    writer.close()

    reader = factory()
    row = svc.list_uploads(reader, user_id)[0]
    assert row["indicators"] == ["reverse-shell"]
    assert row["sha256"] == "deadbeef"
    assert "hostile data" in svc.files_context(reader, user_id)


def test_no_indicators_means_no_label(factory, user_id):
    s = factory()
    svc.store_upload(s, user_id, name="ok.log", content="ordinary log line", size_bytes=17)
    assert "hostile data" not in svc.files_context(s, user_id)


def test_the_per_user_cap_evicts_the_oldest(factory, user_id):
    s = factory()
    ids = [
        svc.store_upload(s, user_id, name=f"f{i}.log", content=f"body {i}", size_bytes=6)["id"]
        for i in range(svc.MAX_FILES_PER_USER + 3)
    ]
    kept = [f["id"] for f in svc.list_uploads(s, user_id)]
    assert len(kept) == svc.MAX_FILES_PER_USER
    assert ids[-1] in kept, "the newest upload must survive"
    assert ids[0] not in kept, "the oldest must be evicted"


def test_one_user_cannot_read_or_delete_anothers_upload(factory, user_id):
    s = factory()
    other = User(username="intruder", email="i@x.y", password_hash="x", display_name="I")
    s.add(other)
    s.commit()

    stored = svc.store_upload(s, user_id, name="private.log", content="secret", size_bytes=6)

    assert svc.get_upload(s, other.id, stored["id"]) is None
    assert svc.delete_upload(s, other.id, stored["id"]) is False
    assert svc.get_upload(s, user_id, stored["id"]) is not None, "owner still sees it"


def test_delete_removes_it_everywhere(factory, user_id):
    writer = factory()
    stored = svc.store_upload(writer, user_id, name="f.log", content="x", size_bytes=1)
    assert svc.delete_upload(writer, user_id, stored["id"]) is True
    writer.close()

    reader = factory()
    assert svc.list_uploads(reader, user_id) == []
    assert svc.delete_upload(reader, user_id, stored["id"]) is False


def test_an_edit_is_visible_from_another_process(factory, user_id):
    writer = factory()
    stored = svc.store_upload(writer, user_id, name="f.log", content="before", size_bytes=6)
    svc.update_content(writer, user_id, stored["id"], "after\nsecond line")
    writer.close()

    reader = factory()
    row = svc.get_upload(reader, user_id, stored["id"])
    assert row["content"] == "after\nsecond line"
    assert row["lines"] == 2
    assert row["size"] == len("after\nsecond line".encode("utf-8"))


def test_long_files_are_truncated_for_the_prompt(factory, user_id):
    s = factory()
    svc.store_upload(s, user_id, name="big.log", content="z" * 40_000, size_bytes=40_000)
    ctx = svc.files_context(s, user_id)
    assert "truncated" in ctx
    assert len(ctx) < 20_000


def test_indicators_are_stored_as_json_not_a_python_repr(factory, user_id):
    """Read back by anything other than this service, the column must parse."""
    s = factory()
    svc.store_upload(
        s, user_id, name="f.log", content="x", size_bytes=1, indicators=["webshell", "obfuscation"]
    )
    raw = s.query(AIChatUpload).one().indicators
    assert json.loads(raw) == ["webshell", "obfuscation"]


def test_the_api_no_longer_keeps_uploads_in_process_memory():
    import re
    from pathlib import Path

    src = Path(__file__).resolve().parents[1] / "src" / "ion" / "web" / "ai_api.py"
    code = "\n".join(re.sub(r"#.*$", "", ln) for ln in src.read_text(encoding="utf-8").splitlines())
    # Anchor on the declaration and subscript, not the bare name: the endpoint
    # list_uploaded_files legitimately contains that substring.
    assert "_uploaded_files:" not in code
    assert "_uploaded_files[" not in code
    assert "def get_user_files" not in code
    # UPLOAD_DIR implied a filesystem that was never written to.
    assert "UPLOAD_DIR" not in code
