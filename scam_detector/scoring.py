"""Fixed Scam Shield scoring bands."""

from collections.abc import Iterable

from .flag_definitions import FLAG_DEFINITIONS


ALERT_SCORE = 25


def risk_score(flags: Iterable[str]) -> int:
    return min(100, sum(FLAG_DEFINITIONS[flag] for flag in set(flags)))


def verdict_for_score(score: int) -> str:
    if score >= 50:
        return "SCAM"
    if score >= ALERT_SCORE:
        return "SUSPICIOUS"
    return "SAFE"
