"""Extension point for future deterministic rules."""

import re
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from .conversation import Message, Sender
from .flag_definitions import FLAG_DEFINITIONS
from .model_assets import PROJECT_ROOT


_NEW_NUMBER_NOTICE = re.compile(
    r"\b(?:num[ăa]r(?:ul)?(?: de telefon)?(?: meu)? nou|noul(?: meu)? num[ăa]r"
    r"|(?:pe|de pe) (?:un )?alt num[ăa]r)\b",
    re.IGNORECASE,
)
_SECRECY_CUE = re.compile(
    r"\b(?:secret\w*|discre[țt]i\w*|confiden[țt]ial\w*|[îi]ntre noi)\b"
    r"|\bnu(?:\s+|-(?:i|l|le|mi|[țt]i)\s+)(?:(?:s[ăa]|[îi]i|[îi]l|le|o)\s+)*"
    r"(?:spun\w*|zi\w*|povest\w*|anun[țt]\w*|verific\w*|[îi]ntreb\w*|"
    r"[îi]ntreab\w*|sun\w*|contact\w*)\b",
    re.IGNORECASE,
)


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
        evidence = dict.fromkeys(FLAG_DEFINITIONS, RuleStatus.UNKNOWN)
        # A new-number introduction is separate evidence from a request for secrecy.
        if (
            context is not None
            and context.channel in {"whatsapp", "sms", "chat"}
            and not context.sender.known_contact
            and not _SECRECY_CUE.search(message.text)
            and any(
                turn.role == "sender" and _NEW_NUMBER_NOTICE.search(turn.text)
                for turn in (*context.previous_messages, message)
            )
        ):
            evidence["RF_SECRECY"] = RuleStatus.REJECTED
        return evidence
