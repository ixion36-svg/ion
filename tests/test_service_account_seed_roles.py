"""A seeded service account holds its one role and nothing else.

`ion seed-tide` and `ion seed-metis` mint a bearer token and promise it
carries only the account's own permissions. Seeding used to add the role to
whatever already held the username, so an existing `tide` admin kept admin,
and a human `tide` account was quietly turned into a token-bearing service
account.
"""

from ion.auth.service import AuthService
from ion.models.user import User


def _auth(session) -> AuthService:
    User.metadata.create_all(session.get_bind())
    svc = AuthService(session)
    svc.seed_permissions()
    svc.seed_roles()
    session.commit()
    return svc


def _role_names(user: User) -> set[str]:
    return {r.name for r in user.roles}


def test_reseeding_strips_roles_added_to_the_service_account(session):
    svc = _auth(session)
    tide = svc.seed_tide_user()
    svc.user_repo.add_role(tide, svc.role_repo.get_by_name("admin"))
    session.commit()

    reseeded = svc.seed_tide_user()

    assert reseeded.id == tide.id
    assert _role_names(reseeded) == {"tide"}
    assert not reseeded.has_permission("user:delete")


def test_a_human_account_holding_the_name_is_not_converted(session):
    svc = _auth(session)
    human = svc.user_repo.create(
        username="tide", email="tide@example.com", password_hash="x",
    )
    svc.user_repo.add_role(human, svc.role_repo.get_by_name("admin"))
    session.commit()

    assert svc.seed_tide_user() is None

    session.refresh(human)
    assert human.is_service_account is False
    assert _role_names(human) == {"admin"}


def test_metis_follows_the_same_rule(session):
    svc = _auth(session)
    metis = svc.seed_metis_user()
    svc.user_repo.add_role(metis, svc.role_repo.get_by_name("admin"))
    session.commit()

    assert _role_names(svc.seed_metis_user()) == {"metis"}
