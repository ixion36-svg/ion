"""v0.43.0 — daily-work API (Wave 1.2/1.3).

Exercises the worklog endpoints through the app. The integration `client`
fixture injects a fake admin (id=1) for the require_permission gates; we seed a
matching User row so the AuditLog FK and the team view resolve.
"""

# Register the worklog tables on Base.metadata before the temp_db fixture's
# create_all() runs.
import ion.models.worklog  # noqa: F401


def _seed_admin(temp_db):
    from sqlalchemy.orm import sessionmaker

    from ion.models.user import User

    Session = sessionmaker(bind=temp_db)
    s = Session()
    try:
        if not s.query(User).filter_by(id=1).first():
            s.add(User(
                id=1, username="admin", email="admin@localhost",
                password_hash="x", display_name="Administrator", is_active=True,
            ))
            s.commit()
    finally:
        s.close()


def test_task_types_seeds_and_lists(client, temp_db):
    _seed_admin(temp_db)
    r = client.get("/api/worklog/task-types")
    assert r.status_code == 200
    types = r.json()["task_types"]
    assert len(types) == 10
    keys = {t["key"] for t in types}
    assert {"meeting", "ir", "training", "break"} <= keys


def test_log_entry_then_day(client, temp_db):
    _seed_admin(temp_db)
    r = client.post("/api/worklog/entry", json={"task_type": "meeting", "text": "daily standup"})
    assert r.status_code == 200
    assert r.json()["entry"]["task_type"] == "meeting"

    day = client.get("/api/worklog/day")
    assert day.status_code == 200
    data = day.json()
    assert data["summary"]["logged"] >= 1
    assert any(i["text"] == "daily standup" and i["source"] == "logged" for i in data["items"])
    assert data["user"]["id"] == 1


def test_entry_rejects_empty(client, temp_db):
    _seed_admin(temp_db)
    r = client.post("/api/worklog/entry", json={"task_type": "meeting", "text": ""})
    assert r.status_code == 422  # pydantic min_length


def test_team_endpoint_shape(client, temp_db):
    _seed_admin(temp_db)
    r = client.get("/api/worklog/team")
    assert r.status_code == 200
    body = r.json()
    assert "date" in body and isinstance(body["team"], list)
