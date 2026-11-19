"""Extension point for future deterministic rules."""

from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from .conversation import Message, Sender
from .flag_definitions import FLAG_DEFINITIONS
from .model_assets import PROJECT_ROOT


class RuleStatus(StrEnum):
    CONFIRMED = "CONFIRMED"
    REJECTED = "REJECTED"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class RuleContext:
    channel: str
    sender: Sender
    previous_messages: tuple[Message, ...]


class RuleEngine:
    def __init__(self, catalog_path: str | Path = PROJECT_ROOT / "official_catalog.json"):
        self.catalog_path = Path(catalog_path)

    def evaluate(
        self, message: Message, context: RuleContext | None = None
    ) -> dict[str, RuleStatus]:
        # TODO: Verify organization domains and phone numbers using the official catalog.
        # TODO: Distinguish OTP requests from genuine informational messages.
        # TODO: Check sensitive data, payment, transfer and remote access requests.
        # TODO: Check deadlines, urgency, secrecy and new-number claims using metadata.
        # TODO: Handle negations and other recurring false positives.
        return dict.fromkeys(FLAG_DEFINITIONS, RuleStatus.UNKNOWN)
