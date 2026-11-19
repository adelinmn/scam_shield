"""Combine model confidence with optional deterministic rule evidence."""

from collections.abc import Mapping

from .flag_definitions import load_flag_config, validate_threshold
from .rules import RuleStatus


class FlagFusionEngine:
    def __init__(self, thresholds: Mapping[str, float] | None = None) -> None:
        self.thresholds = {flag: config.threshold for flag, config in load_flag_config().items()}
        for flag, threshold in (thresholds or {}).items():
            if flag not in self.thresholds:
                raise ValueError(f"Unknown flag: {flag}")
            validate_threshold(flag, threshold)
            self.thresholds[flag] = threshold

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
