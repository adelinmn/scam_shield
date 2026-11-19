"""Combine model confidence with optional deterministic rule evidence."""

from collections.abc import Mapping

from .flag_profiles import resolve_thresholds
from .rules import RuleStatus


class FlagFusionEngine:
    def __init__(self, thresholds: Mapping[str, float] | None = None) -> None:
        self.thresholds = resolve_thresholds(thresholds)

    def select(
        self, model_scores: Mapping[str, float], rule_evidence: Mapping[str, RuleStatus]
    ) -> list[str]:
        active = []
        for flag, threshold in self.thresholds.items():
            status = rule_evidence.get(flag, RuleStatus.UNKNOWN)
            if status == RuleStatus.CONFIRMED or (
                status == RuleStatus.UNKNOWN and model_scores[flag] >= threshold
            ):
                active.append(flag)
        return active
