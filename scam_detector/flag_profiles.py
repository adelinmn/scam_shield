"""Load editable Romanian hypotheses and flag thresholds from JSON."""

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from .flag_definitions import FLAG_DEFINITIONS, THRESHOLDS


@dataclass(frozen=True)
class FlagProfile:
    hypotheses: dict[str, tuple[str, ...]]
    thresholds: dict[str, float]

    def to_json(self) -> dict:
        return {"hypotheses": self.hypotheses, "thresholds": self.thresholds}


def resolve_hypotheses(
    overrides: Mapping[str, Sequence[str]] | None = None,
) -> dict[str, tuple[str, ...]]:
    hypotheses = {code: (definition.description,) for code, definition in FLAG_DEFINITIONS.items()}
    for code, phrases in (overrides or {}).items():
        if code not in FLAG_DEFINITIONS:
            raise ValueError(f"Unknown flag: {code}")
        if isinstance(phrases, str) or not isinstance(phrases, Sequence) or not phrases or any(
            not isinstance(phrase, str) or not phrase.strip() for phrase in phrases
        ):
            raise ValueError(f"Hypotheses for {code} must be a non-empty list of sentences.")
        hypotheses[code] = tuple(dict.fromkeys(phrase.strip() for phrase in phrases))
    return hypotheses


def resolve_thresholds(overrides: Mapping[str, float] | None = None) -> dict[str, float]:
    thresholds = THRESHOLDS | dict(overrides or {})
    for code, threshold in thresholds.items():
        if code not in FLAG_DEFINITIONS:
            raise ValueError(f"Unknown flag: {code}")
        if (
            isinstance(threshold, bool)
            or not isinstance(threshold, (int, float))
            or not 0 <= threshold <= 1
        ):
            raise ValueError(f"Threshold for {code} must be between 0 and 1.")
    return thresholds


def load_flag_profile(path: str | Path | None = None) -> FlagProfile:
    if path is None:
        return FlagProfile(resolve_hypotheses(), resolve_thresholds())
    data = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(data, dict) or data.keys() - {"hypotheses", "thresholds"}:
        raise ValueError("A flag profile must contain only hypotheses and thresholds.")
    overrides = data.get("hypotheses", {})
    thresholds = data.get("thresholds", {})
    if not isinstance(overrides, dict) or not isinstance(thresholds, dict):
        raise ValueError("Profile hypotheses and thresholds must be JSON objects.")
    return FlagProfile(resolve_hypotheses(overrides), resolve_thresholds(thresholds))
