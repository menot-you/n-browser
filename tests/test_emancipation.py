"""The judge for this member's emancipation (Lock 7).

Without it, «I tore everything out» is an opinion — which is the phrase
`tools/rail/donor.sh` writes about itself. But that judge is global and cannot
name the term: the term appears as test DATA in other members (`apps/memory/core`,
`apps/memory/evals`), in `docs/`'s historical record, and in the audit workflow
that exists to READ the donor. A global pattern would tear the product out along
with the cage, which is exactly the defect `tools/rail/donor.sh` documents about
`monorepo`.

So the judge belongs to the MEMBER, runs in the member's gate, and has no
opinion at all about the rest of the tree.
"""

from pathlib import Path

import pytest
from workspace_root import workspace_path

# The member in the workspace, never the directory this file happens to sit in:
# under mutmut that is the `mutants/` copy, and scanning it would judge a copy.
MEMBER = workspace_path("mcps/nbrowser")

# The BARE form, on purpose: outside this file the term does not appear once in
# the member, so the broad form costs nothing and catches what narrow forms
# would let through, including the suffix and the uppercase.
# It subsumes the three narrow forms that left for being redundant.
#
# `nbrowser` is NOT here: it is this port's name. Bare `monorepo` is not either,
# for the reason tools/rail/donor.sh measured — the owner has a LIVING monorepo, and a
# pattern catching both tears the product out along with the cage.
DONOR_TERMS = ("pith", "d8e0be5", "port_pin", "oracle_bin")


# This file NAMES the terms it looks for, so scanning itself is a guaranteed
# accusation — the judge could never pass. `tools/rail/donor.sh` solves the same
# thing with an allowlist whose first line is itself. Here the exemption is ONE
# file, and the test below proves it is only that one.
SELF = MEMBER / "tests" / "test_emancipation.py"


def _sources(root: Path) -> list[Path]:
    return [
        path
        for path in root.rglob("*.py")
        if not {".venv", "__pycache__"}.intersection(path.relative_to(root).parts)
        # mutmut's staging copy of the member, which holds a copy of this file.
        and path.relative_to(root).parts[0] != "mutants"
    ]


def _scanned(root: Path = MEMBER) -> list[Path]:
    return [path for path in _sources(root) if path != SELF]


def _offenders(root: Path) -> set[str]:
    return {
        f"{path.relative_to(root)}: {term}"
        for path in _scanned(root)
        for term in DONOR_TERMS
        if term in path.read_text(encoding="utf-8").lower()
    }


def test_no_source_file_in_this_member_names_the_donor() -> None:
    """M9 = 0, and it stays. The attribute the walker reads has been called
    `data-nbrowser` since wave 5 (the owner's order): renaming cost only the
    pages the owner annotated by hand, because the annotation package the
    donor's documentation promised was never published."""
    assert _offenders(MEMBER) == set()


def test_scan_ignores_only_virtual_environments_and_mutmut_staging_inside_its_root(
    tmp_path: Path,
) -> None:
    root = tmp_path / ".venv" / "disposable-member"
    root.mkdir(parents=True)
    source = root / "source.py"
    source.write_text("pass\n")
    dependency = root / ".venv" / "dependency.py"
    dependency.parent.mkdir()
    dependency.write_text("pass\n")
    staged = root / "mutants" / "tests" / "copy.py"
    staged.parent.mkdir(parents=True)
    staged.write_text("pass\n")
    nested = root / "pkg" / "mutants" / "module.py"
    nested.parent.mkdir(parents=True)
    nested.write_text("pass\n")
    assert sorted(_scanned(root)) == sorted([source, nested])


def test_the_only_file_the_judge_excuses_is_itself() -> None:
    """The exemption is ONE file and the size proves it: a judge that passes
    because it scans nothing is an ornament. Measured from both sides — the
    difference between what exists and what is scanned is exactly this file,
    and what remains is the member's whole production and tests."""
    assert set(_sources(MEMBER)) - set(_scanned()) == {SELF}
    assert len(_scanned()) > 30
    assert MEMBER / "nbrowser" / "mcp_server.py" in _scanned()


def test_the_judge_would_catch_a_real_offender(tmp_path: Path) -> None:
    """The mutation that proves it: a scanned file carrying a term must be
    accused. Without this, «zero offenders» can be an `in` that never matches.

    The offender is planted in a DISPOSABLE root, never in the member's tree.
    The first version planted in `nbrowser/`, and the two sibling tests scan
    that tree: under xdist — which the meter's coverage phase runs for this
    member — xdist distributes test by test, and the scanner saw the planter's
    file. Five runs in five reds, and the message read «the donor came back»,
    which is the exact confusion this judge exists to undo.

    Planting in `tmp_path` kills the race and one more thing: a SIGKILL between
    the write and the `finally` would leave the offender inside the published
    package."""
    (tmp_path / "offender.py").write_text("# data-pith\n", encoding="utf-8")
    assert _offenders(tmp_path) == {"offender.py: pith"}


@pytest.mark.parametrize(
    "shape", ["pith", "PITH", "Pith", "data-pith", "@pith", "npith"]
)
def test_the_judge_reads_the_donor_name_in_any_case(shape: str, tmp_path: Path) -> None:
    """The uppercase is the form the donor's audit uses — it is in the
    `apps/memory/*` files the global judge lists. The first version compared
    with plain case-SENSITIVE `in` and let it through while the comment beside
    it claimed it caught it. A false claim about a judge is worse than the hole,
    because reading finds the hole."""
    (tmp_path / "offender.py").write_text(f"# {shape}\n", encoding="utf-8")
    assert _offenders(tmp_path) == {"offender.py: pith"}


def test_the_scan_root_is_the_member_and_a_test_says_so(tmp_path: Path) -> None:
    """The root the judge scans is the MEMBER, and a test says which. The
    review round measured the hole: `_offenders` was born with its own default
    that no test pinned, and swapping it for `MEMBER / "providers"` left the
    headline judge scanning almost nothing — 3 passed, green for not looking.

    The cure was deleting that default, not pinning one more: ONE remains, that
    of `_scanned`, which the exemption test already proves with `len() > 30` and
    `pilot.py` inside it. This test guards the other side — that a narrower root
    gives a different answer, so the root is load-bearing and not decoration."""
    import inspect

    # The root is an ARGUMENT, never a default: a silent default can be pointed
    # at a subdirectory and the judge passes green for not looking. This reads
    # the signature because no CALL can prove the absence of a value the call
    # itself supplies — that is how the first test attempt failed to kill the
    # mutation.
    assert (
        inspect.signature(_offenders).parameters["root"].default
        is inspect.Parameter.empty
    )
    (tmp_path / "offender.py").write_text("# pith\n", encoding="utf-8")
    assert _offenders(tmp_path) != _offenders(MEMBER / "providers")
