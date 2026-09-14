"""User lifecycle, exercised with no database.

The tests that matter most here are the ones about `token_version` and about
per-tenant email uniqueness. The first is the only revocation mechanism this
design has; the second is the thing most likely to be quietly implemented as a
global constraint, which would break a real person's real situation.
"""

from __future__ import annotations

import uuid

import pytest

from app.core.errors import Conflict, NotFound, ValidationFailed
from app.schemas.user import UserCreate, UserInvite
from app.services.password_service import PasswordService
from app.services.user_service import UserService
from tests.fakes import (
    FakeAuditSink,
    FakeRoleRepository,
    FakeUserRepository,
    Store,
    make_tenant,
    make_user,
    seed_roles,
)

PASSWORD = "correct horse battery staple"
CHEAP = {
    "time_cost": 1,
    "memory_cost_kib": 8,
    "parallelism": 1,
    "max_concurrency": 8,
    "min_length": 12,
    "max_bytes": 1024,
}


@pytest.fixture
def passwords() -> PasswordService:
    return PasswordService(**CHEAP)  # type: ignore[arg-type]


async def build(
    passwords: PasswordService, store: Store | None = None, tenant_id: uuid.UUID | None = None
) -> tuple[UserService, Store, FakeAuditSink, uuid.UUID]:
    store = store or Store()
    if tenant_id is None:
        tenant = make_tenant()
        store.tenants[tenant.id] = tenant
        tenant_id = tenant.id
    await seed_roles(store, tenant_id)
    audit = FakeAuditSink()
    service = UserService(
        FakeUserRepository(store, tenant_id),
        FakeRoleRepository(store, tenant_id),
        passwords,
        audit,
        tenant_id,
    )
    return service, store, audit, tenant_id


def payload(**overrides: object) -> UserCreate:
    base: dict[str, object] = {
        "email": "ada@example.com",
        "password": PASSWORD,
        "full_name": "Ada Lovelace",
        "role_keys": ["teacher"],
    }
    base.update(overrides)
    return UserCreate(**base)  # type: ignore[arg-type]


# ── Construction ────────────────────────────────────────────────────────────


async def test_a_service_cannot_be_built_across_two_tenants(
    passwords: PasswordService,
) -> None:
    store = Store()
    a, b = uuid.uuid4(), uuid.uuid4()
    with pytest.raises(RuntimeError):
        UserService(
            FakeUserRepository(store, a),
            FakeRoleRepository(store, b),
            passwords,
            FakeAuditSink(),
            a,
        )


# ── Creation ────────────────────────────────────────────────────────────────


async def test_a_created_user_can_be_looked_up_and_carries_their_scopes(
    passwords: PasswordService,
) -> None:
    service, _, _, _ = await build(passwords)
    user = await service.create(payload())

    assert user.status == "active"
    assert user.password_hash is not None
    assert await service.scopes_for(user.id) == frozenset(
        {
            "students:read",
            "students:write",
            "courses:read",
            "courses:write",
            "enrolments:write",
            "materials:read",
            "materials:write",
            "chat:use",
            "proposals:approve",
        }
    )


async def test_the_email_is_normalised_but_the_typed_form_is_kept(
    passwords: PasswordService,
) -> None:
    service, _, _, _ = await build(passwords)
    user = await service.create(payload(email="Ada.Lovelace@Example.com"))
    assert user.email_normalized == "ada.lovelace@example.com"
    assert user.email == "Ada.Lovelace@example.com"


async def test_a_duplicate_email_is_caught_after_normalisation(
    passwords: PasswordService,
) -> None:
    service, _, _, _ = await build(passwords)
    await service.create(payload())
    with pytest.raises(Conflict) as excinfo:
        await service.create(payload(email="ADA@example.com"))
    assert excinfo.value.detail == {"field": "email"}


async def test_the_same_address_may_exist_in_two_institutions(
    passwords: PasswordService,
) -> None:
    """The reason the unique index is per tenant rather than global.

    A tutor genuinely works at two colleges with one address. A global
    constraint would make that unrepresentable — and this is the property most
    likely to be lost by someone "simplifying" the index.
    """
    store = Store()
    first, _, _, _ = await build(passwords, store)
    second, _, _, _ = await build(passwords, store)

    await first.create(payload())
    await second.create(payload())
    assert len(store.users) == 2


async def test_a_weak_password_is_refused_before_it_is_hashed(
    passwords: PasswordService,
) -> None:
    service, store, _, _ = await build(passwords)
    with pytest.raises(ValidationFailed):
        await service.create(payload(password="short"))
    assert store.users == {}


async def test_granting_an_unknown_role_is_a_404(passwords: PasswordService) -> None:
    service, _, _, _ = await build(passwords)
    with pytest.raises(NotFound, match="registrar"):
        await service.create(payload(role_keys=["registrar"]))


async def test_a_user_with_no_roles_has_no_scopes(passwords: PasswordService) -> None:
    # An account that exists but authorises nothing. Every gate 403s, which is
    # the correct default for someone invited but not yet given a role.
    service, _, _, _ = await build(passwords)
    user = await service.create(payload(role_keys=[]))
    assert await service.scopes_for(user.id) == frozenset()


async def test_two_roles_union_their_scopes_without_duplicates(
    passwords: PasswordService,
) -> None:
    service, _, _, _ = await build(passwords)
    user = await service.create(payload(role_keys=["teacher", "tutor"]))
    scopes = await service.scopes_for(user.id)
    # tutor's scopes are a subset of teacher's, so the union is teacher's.
    assert "students:read" in scopes
    assert len(scopes) == 9


# ── Invitation ──────────────────────────────────────────────────────────────


async def test_an_invited_user_has_no_password(passwords: PasswordService) -> None:
    """NULL `password_hash`, and login must treat it like a wrong password.

    An invited-but-never-activated account that failed *differently* would
    confirm the address is real.
    """
    service, _, _, _ = await build(passwords)
    user = await service.invite(UserInvite(email="grace@example.com", role_keys=["tutor"]))
    assert user.password_hash is None
    assert user.status == "invited"


async def test_activation_sets_the_first_password(passwords: PasswordService) -> None:
    service, _, _, _ = await build(passwords)
    user = await service.invite(UserInvite(email="grace@example.com"))
    activated = await service.activate(user.id, PASSWORD)
    assert activated.status == "active"
    assert await passwords.verify(activated.password_hash or "", PASSWORD)


async def test_activating_twice_is_refused(passwords: PasswordService) -> None:
    # Otherwise a leaked invite link is a password reset for an account that is
    # already in use.
    service, _, _, _ = await build(passwords)
    user = await service.invite(UserInvite(email="grace@example.com"))
    await service.activate(user.id, PASSWORD)
    with pytest.raises(Conflict, match="already has a password"):
        await service.activate(user.id, "a different long password")


# ── token_version: the only revocation this design has ──────────────────────


async def test_disabling_a_user_bumps_their_token_version(
    passwords: PasswordService,
) -> None:
    """The whole point of disabling.

    Access tokens are verified offline, so nothing here can cancel one that is
    already issued. `token_version` is the compensating control — without the
    bump, an offboarded person keeps working access until their token expires.
    """
    service, _, _, _ = await build(passwords)
    user = await service.create(payload())
    assert user.token_version == 0

    disabled = await service.disable(user.id)
    assert disabled.status == "disabled"
    assert disabled.token_version == 1


async def test_changing_a_password_bumps_the_token_version(
    passwords: PasswordService,
) -> None:
    # A password change is a revocation event: whoever knew the old one must not
    # keep a live session.
    service, _, _, _ = await build(passwords)
    user = await service.create(payload())
    changed = await service.set_password(user.id, "an entirely different passphrase")
    assert changed.token_version == 1


async def test_disabling_twice_does_not_bump_twice(passwords: PasswordService) -> None:
    # Idempotent. Bumping on a no-op would invalidate sessions for an account
    # that was already disabled, which is noise in the revocation feed.
    service, _, _, _ = await build(passwords)
    user = await service.create(payload())
    await service.disable(user.id)
    again = await service.disable(user.id)
    assert again.token_version == 1


async def test_changing_a_password_clears_a_lockout(passwords: PasswordService) -> None:
    # The person has proven control of the account; keeping them locked out
    # would be a denial of service against the legitimate owner.
    service, store, _, _ = await build(passwords)
    user = await service.create(payload())
    store.users[user.id].failed_login_count = 5
    store.users[user.id].locked_until = None

    changed = await service.set_password(user.id, "an entirely different passphrase")
    assert changed.failed_login_count == 0
    assert changed.locked_until is None


async def test_a_never_activated_account_cannot_be_enabled(
    passwords: PasswordService,
) -> None:
    # "Enabled" would mean an account that is active with no password, which
    # login has to treat as a failure anyway.
    service, _, _, _ = await build(passwords)
    user = await service.invite(UserInvite(email="grace@example.com"))
    await service.disable(user.id)
    with pytest.raises(Conflict, match="never been activated"):
        await service.enable(user.id)


# ── Tenancy ─────────────────────────────────────────────────────────────────


async def test_a_user_in_another_tenant_is_a_404(passwords: PasswordService) -> None:
    store = Store()
    other_tenant = make_tenant(slug="southgate")
    store.tenants[other_tenant.id] = other_tenant
    theirs = make_user(other_tenant.id)
    store.users[theirs.id] = theirs

    service, _, _, _ = await build(passwords, store)
    with pytest.raises(NotFound):
        await service.disable(theirs.id)
    assert store.users[theirs.id].status == "active"


async def test_scopes_do_not_leak_across_tenants(passwords: PasswordService) -> None:
    """A grant is scoped by the grant's tenant, not the role's.

    If `scopes_for_user` ignored the tenant, a user id that happened to hold a
    role elsewhere would authorise here.
    """
    store = Store()
    first, _, _, _ = await build(passwords, store)
    user = await first.create(payload())

    second, _, _, _ = await build(passwords, store)
    assert await second.scopes_for(user.id) == frozenset()


# ── Audit ───────────────────────────────────────────────────────────────────


async def test_every_lifecycle_change_leaves_a_trail(passwords: PasswordService) -> None:
    service, _, audit, _ = await build(passwords)
    user = await service.create(payload())
    await service.disable(user.id)
    await service.set_password(user.id, "an entirely different passphrase")

    assert audit.actions() == [
        "user.role_grant",
        "user.create",
        "user.disable",
        "user.password_change",
    ]
    assert all(record.outcome == "success" for record in audit.records)


async def test_the_audit_row_names_the_subject_and_the_tenant(
    passwords: PasswordService,
) -> None:
    service, _, audit, tenant_id = await build(passwords)
    user = await service.create(payload())
    created = next(r for r in audit.records if r.action == "user.create")
    assert created.subject_user_id == user.id
    assert created.tenant_id == tenant_id


async def test_a_refused_creation_leaves_no_trail(passwords: PasswordService) -> None:
    # A Conflict means nothing happened; an audit row claiming otherwise would
    # be a lie in the one table that must not contain any.
    service, _, audit, _ = await build(passwords)
    await service.create(payload())
    audit.records.clear()
    with pytest.raises(Conflict):
        await service.create(payload())
    assert audit.records == []


async def test_the_seeder_records_itself_as_the_system_not_a_user(
    passwords: PasswordService,
) -> None:
    # `actor_id` is None for CLI-driven work. Recording it as a user would
    # invent an actor that does not exist.
    service, _, audit, _ = await build(passwords)
    await service.create(payload())
    assert all(r.actor_type == "system" for r in audit.records)
    assert all(r.actor_id is None for r in audit.records)
