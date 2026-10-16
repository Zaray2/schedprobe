"""Which evidence standard each test holds the code to.

A reviewer asked the question this module exists to answer (translated from the Chinese
they wrote it in):

    are the tests in this file verifying the correctness of the code, or verifying the
    correctness of what the author declared?

That is not a rhetorical question, and answering it with prose would be exactly the kind
of self-assessment it is asking me to distrust. So every test declares its tier, and
``test_every_test_declares_a_tier`` refuses to let a test go untagged.

The three tiers are defined by **what would have to change for the test to fail**:

``oracle``
    Something independent of this codebase disagrees. A real operating system socket
    behaves differently, a byte-exact file edit breaks a hash, a brute-force attack
    succeeds, a digest recomputed by a different path differs, or two independent
    implementations of the same quantity must agree. These tests can fail because reality
    differs from the code, which is the only way a test can tell you something you did
    not already believe.

``contract``
    A consumer's expectation is violated. Exit codes, JSON on stdout, CSV columns, config
    validation, scope refusal. These encode decisions the author made, but they encode
    them from the outside - the question is "would a script that trusts the documented
    interface break?" - so they are worth more than the third tier and less than the
    first.

``consistency``
    The code does what its own docstring says. These are the tests that made a wrong
    segment score look correct for two rounds of review: they asserted every invariant
    the author had stated, and every one of those assertions was true. What they cannot do
    is notice an invariant that was never stated.

Why this is worth the annotation effort: the tier is not decoration, it is the answer to
"how much would this test have told me if I had been wrong about the design?" - and the
distribution is uncomfortable enough that publishing it is the point.
"""

from __future__ import annotations

from typing import Any

__all__ = [
    "TIERS",
    "TIER_CONSISTENCY",
    "TIER_CONTRACT",
    "TIER_ORACLE",
    "resolve_tier",
    "tier",
]

TIER_ORACLE = "oracle"
TIER_CONTRACT = "contract"
TIER_CONSISTENCY = "consistency"

TIERS: tuple[str, ...] = (TIER_ORACLE, TIER_CONTRACT, TIER_CONSISTENCY)

_ATTRIBUTE = "__test_tier__"

TIER_MEANING: dict[str, str] = {
    TIER_ORACLE: "something independent of this codebase disagrees",
    TIER_CONTRACT: "a consumer's expectation of the documented interface is violated",
    TIER_CONSISTENCY: "the code does what its own documentation claims",
}


def tier(kind: str) -> Any:
    """Declare the evidence standard for a test class or a single test method.

    Applies to classes (setting a default for every method) or to individual methods
    (overriding the class default), because most classes are homogeneous and annotating
    332 methods individually would be noise rather than information.
    """
    if kind not in TIERS:
        raise ValueError(f"unknown tier {kind!r}; expected one of {TIERS}")

    def decorate(target: Any) -> Any:
        setattr(target, _ATTRIBUTE, kind)
        return target

    return decorate


def resolve_tier(obj: Any, owner: Any = None) -> str | None:
    """Return the declared tier for a test, or ``None`` if undeclared.

    Resolution order: the method's own declaration, then its owning class's, then any base
    class's. ``owner`` has to be passed explicitly for a plain function, because a function
    object carries no back-pointer to the class it was defined on - looking for one via
    ``__class__`` finds ``function`` itself, which is why an earlier version of this
    function returned ``None`` for every inherited method.
    """
    if obj is None:
        return None
    explicit = getattr(obj, "__test_tier__", None)
    if isinstance(explicit, str):
        return explicit
    if isinstance(obj, type):
        for klass in getattr(obj, "__mro__", ()):
            declared = klass.__dict__.get(_ATTRIBUTE)
            if isinstance(declared, str):
                return declared
        return None
    # A bound method can find its class; a plain function cannot.
    bound_owner = getattr(obj, "__self__", None)
    return resolve_tier(bound_owner) if bound_owner is not None else resolve_tier(owner)
