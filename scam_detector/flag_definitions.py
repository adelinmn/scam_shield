"""Official flag points and the detector's editable flag configuration."""

import json
from dataclasses import dataclass
from functools import cache
from pathlib import Path


FLAG_DEFINITIONS = {
    "RF_CODE_REQUEST": 35,
    "RF_REMOTE_ACCESS": 35,
    "RF_DATA_REQUEST": 30,
    "RF_PAYMENT_REQUEST": 25,
    "RF_SUSPICIOUS_CONTACT": 25,
    "RF_NEW_NUMBER": 20,
    "RF_SECRECY": 20,
    "RF_TOO_GOOD": 20,
    "RF_IMPERSONATION": 15,
    "RF_URGENCY": 15,
    "RF_THREAT": 15,
    "RF_EMOTIONAL_PRESSURE": 10,
    "RF_CHANNEL_SWITCH": 10,
}
FLAG_CONFIG_PATH = Path(__file__).with_name("flag_config.json")


@dataclass(frozen=True)
class FlagConfig:
    phrases: tuple[str, ...]
    threshold: float


def validate_threshold(flag: str, threshold: float) -> None:
    if (
        isinstance(threshold, bool)
        or not isinstance(threshold, (int, float))
        or not 0 <= threshold <= 1
    ):
        raise ValueError(f"Threshold for {flag} must be between 0 and 1.")


def read_config_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, ValueError) as exc:
        raise ValueError(f"Cannot read {path.name}: {exc}") from exc


def parse_phrases(code: str, phrases: object) -> tuple[str, ...]:
    if not isinstance(phrases, list) or not phrases or any(
        not isinstance(phrase, str) or not phrase.strip() for phrase in phrases
    ):
        raise ValueError(f"Phrases for {code} must be a non-empty list of sentences.")
    return tuple(dict.fromkeys(phrase.strip() for phrase in phrases))


@cache
def load_flag_config() -> dict[str, FlagConfig]:
    entries = read_config_json(FLAG_CONFIG_PATH)

    if not isinstance(entries, dict) or entries.keys() != FLAG_DEFINITIONS.keys():
        raise ValueError(f"{FLAG_CONFIG_PATH.name} must contain all 13 official flag codes.")

    config = {}
    for code in FLAG_DEFINITIONS:
        entry = entries[code]
        if not isinstance(entry, dict) or entry.keys() != {"phrases", "threshold"}:
            raise ValueError(f"{code} must have phrases and threshold in {FLAG_CONFIG_PATH.name}.")
        threshold = entry["threshold"]
        validate_threshold(code, threshold)
        config[code] = FlagConfig(parse_phrases(code, entry["phrases"]), threshold)
    return config
