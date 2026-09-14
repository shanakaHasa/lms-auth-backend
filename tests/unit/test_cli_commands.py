"""The Makefile and the CLI must agree about which commands exist.

`make seed` was broken for the entire life of this repository: it invoked
`app.cli seed-dev`, which had never been written. Nothing caught it, because
nothing ever ran it — a Makefile is the one part of a Python project that no
test looks at.

This is three lines of scanning and it would have caught that on day one. The
same instinct as the route-coverage meta-test, pointed at build tooling.
"""

from __future__ import annotations

import re
from pathlib import Path

from app.cli import app

MAKEFILE = Path(__file__).resolve().parents[2] / "Makefile"
INVOCATION = re.compile(r"\$\(PY\) -m app\.cli ([a-z][a-z0-9-]*)")


def registered_commands() -> set[str]:
    names = set()
    for command in app.registered_commands:
        # Typer uses the explicit name when given, else the function name with
        # underscores turned into dashes.
        names.add(command.name or (command.callback.__name__.replace("_", "-")))
    return names


def test_every_makefile_target_invokes_a_command_that_exists() -> None:
    invoked = set(INVOCATION.findall(MAKEFILE.read_text(encoding="utf-8")))
    assert invoked, "no `app.cli` invocations found — has the Makefile moved?"

    missing = invoked - registered_commands()
    assert not missing, f"the Makefile invokes commands the CLI does not define: {sorted(missing)}"


def test_the_commands_the_readme_and_plan_promise_exist() -> None:
    # `seed-dev` is Step 3's stated "done when". The others land later, and are
    # deliberately absent from this list until they do.
    assert {"info", "db-check", "seed-dev"} <= registered_commands()
