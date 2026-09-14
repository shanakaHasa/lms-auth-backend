"""The scope catalogue and the role templates, as testable constants.

These are duplicated in migration `0001`, deliberately and unavoidably: a
migration must never import application code, or a later refactor silently
rewrites what an old migration does to a database that has already run it. The
duplication is made safe by tests that diff the two — `tests/unit/test_scopes.py`
imports the migration *by path* and asserts it agrees with this module.

So the rule is: change both, and the suite tells you when you have not.

`audience` is the property that stops a scope crossing a service boundary. A
token minted for auth's own admin API carries `teachassist-auth` scopes, and
`backend` verifies `aud` — so it can never authorise anything in the LMS.
"""

from __future__ import annotations

from typing import Final

__all__ = [
    "API_AUDIENCE",
    "AUTH_AUDIENCE",
    "ROLE_TEMPLATE_SCOPES",
    "SCOPE_CATALOGUE",
    "SCOPE_KEYS",
    "SENSITIVE_SCOPES",
]

API_AUDIENCE: Final = "teachassist-api"
AUTH_AUDIENCE: Final = "teachassist-auth"


# key -> (description, audience, is_sensitive)
#
# `is_sensitive` marks every scope that reaches student personal information,
# so an access review can answer "who can read student PII" without reading
# every role definition in the system.
SCOPE_CATALOGUE: Final[dict[str, tuple[str, str, bool]]] = {
    "students:read": ("Read student records", API_AUDIENCE, True),
    "students:write": ("Create and update student records", API_AUDIENCE, True),
    "courses:read": ("Read courses", API_AUDIENCE, False),
    "courses:write": ("Create and update courses", API_AUDIENCE, False),
    "enrolments:write": ("Enrol and withdraw students", API_AUDIENCE, True),
    "materials:read": ("Read course materials and policies", API_AUDIENCE, False),
    "materials:write": ("Upload and delete course materials", API_AUDIENCE, False),
    "chat:use": ("Use the assistant", API_AUDIENCE, False),
    # Deliberately separate from students:write. A tutor may ask the assistant
    # to prepare a change; only a teacher may commit it.
    "proposals:approve": (
        "Approve a change the assistant proposed",
        API_AUDIENCE,
        True,
    ),
    "admin:users:read": ("List users in the institution", AUTH_AUDIENCE, False),
    "admin:users:write": ("Invite, disable and manage users", AUTH_AUDIENCE, False),
    "admin:roles": ("Manage roles and grants", AUTH_AUDIENCE, False),
    "admin:audit": ("Read the authentication audit log", AUTH_AUDIENCE, True),
    "admin:tenant": ("Manage institution settings", AUTH_AUDIENCE, False),
}

SCOPE_KEYS: Final[frozenset[str]] = frozenset(SCOPE_CATALOGUE)
SENSITIVE_SCOPES: Final[frozenset[str]] = frozenset(
    key for key, (_, _, sensitive) in SCOPE_CATALOGUE.items() if sensitive
)


# A teacher can create courses. This was an explicit decision: the alternative
# is that only an admin can, which means a teacher cannot set up their own
# class. Note `courses:write` therefore appears HERE and not in the admin
# extras below -- listing it twice would put it in admin's array twice, and
# provisioning inserts role_scopes from that array straight into a table with
# a primary key on (role_id, scope_key).
TEACHER_SCOPES: Final[tuple[str, ...]] = (
    "students:read",
    "students:write",
    "courses:read",
    "courses:write",
    "enrolments:write",
    "materials:read",
    "materials:write",
    "chat:use",
    "proposals:approve",
)

TUTOR_SCOPES: Final[tuple[str, ...]] = (
    "students:read",
    "courses:read",
    "materials:read",
    "chat:use",
)

ADMIN_EXTRA_SCOPES: Final[tuple[str, ...]] = (
    "admin:users:read",
    "admin:users:write",
    "admin:roles",
    "admin:audit",
    "admin:tenant",
)

ROLE_TEMPLATE_SCOPES: Final[dict[str, tuple[str, ...]]] = {
    "admin": (*TEACHER_SCOPES, *ADMIN_EXTRA_SCOPES),
    "teacher": TEACHER_SCOPES,
    "tutor": TUTOR_SCOPES,
}

ROLE_TEMPLATE_META: Final[dict[str, tuple[str, str]]] = {
    "admin": ("Administrator", "Full access within the institution."),
    "teacher": (
        "Teacher",
        "Manages their own courses, students and materials, and approves "
        "changes the assistant proposes.",
    ),
    "tutor": (
        "Tutor",
        "Read-only. May ask the assistant to prepare a change, but cannot approve one.",
    ),
}
