"""Parse official scenarios and extract metadata for each speaker turn."""

import re
import unicodedata
from dataclasses import dataclass


_ROMANIAN_LEGACY = str.maketrans("şŞţŢ", "șȘțȚ")
_URL = re.compile(
    r"https?://[^\s<>\"“”]+|(?<![@\w./-])"
    r"(?:[\w](?:[\w-]*[\w])?\.)+[a-z]{2,63}\b"
    r"(?::\d{1,5})?(?:[/?#][^\s<>\"“”]*)?",
    re.IGNORECASE,
)
_PHONE = re.compile(
    r"(?<![\w.,])(?:\+\d{1,3}[ .-]?|00\d{1,3}[ .-]?|0)"
    r"(?:\(?[\dxX]{1,5}\)?[ .-]?){1,6}(?![\w.,]\d|\w)"
)


class ScenarioError(ValueError):
    """Input did not match the official scenario format."""


def normalize_text(text: str) -> str:
    try:
        text.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ScenarioError("Text contains an invalid Unicode character.") from exc
    return " ".join(unicodedata.normalize("NFC", text).translate(_ROMANIAN_LEGACY).split())


def extract_urls(text: str) -> tuple[str, ...]:
    return tuple(dict.fromkeys(match.rstrip(".,;:!?)]}") for match in _URL.findall(text)))


def extract_phones(text: str) -> tuple[str, ...]:
    phones = (match.rstrip(" .-") for match in _PHONE.findall(text))
    return tuple(
        dict.fromkeys(phone for phone in phones if 9 <= len(re.findall(r"[\dxX]", phone)) <= 15)
    )


@dataclass(frozen=True)
class Sender:
    name: str | None
    address: str | None
    known_contact: bool
    urls: tuple[str, ...]
    phone_numbers: tuple[str, ...]


@dataclass(frozen=True)
class Message:
    number: int
    role: str
    original_text: str
    text: str
    urls: tuple[str, ...]
    phone_numbers: tuple[str, ...]


@dataclass(frozen=True)
class Conversation:
    id: str
    channel: str
    sender: Sender
    messages: tuple[Message, ...]


def parse_scenario(scenario: dict) -> Conversation:
    if not isinstance(scenario, dict):
        raise ScenarioError("Expected a scenario object.")
    scenario_id = scenario.get("id")
    channel = scenario.get("channel")
    if not isinstance(scenario_id, str) or not scenario_id.strip():
        raise ScenarioError("Scenario id must be a non-empty string.")
    if not isinstance(channel, str) or not channel.strip():
        raise ScenarioError("Scenario channel must be a non-empty string.")
    normalize_text(scenario_id)
    sender_data = scenario.get("sender")
    if not isinstance(sender_data, dict):
        raise ScenarioError("Scenario sender must be an object.")
    name = sender_data.get("name")
    address = sender_data.get("address")
    known_contact = sender_data.get("known_contact")
    if (name is not None and not isinstance(name, str)) or (
        address is not None and not isinstance(address, str)
    ):
        raise ScenarioError("Sender name and address must be strings or null.")
    if not isinstance(known_contact, bool):
        raise ScenarioError("Sender known_contact must be a boolean.")
    if name is not None:
        normalize_text(name)
    sender = Sender(
        name, address, known_contact, extract_urls(address or ""), extract_phones(address or "")
    )
    message_data = scenario.get("messages")
    if not isinstance(message_data, list) or not message_data:
        raise ScenarioError("Scenario messages must be a non-empty list.")

    messages: dict[int, Message] = {}
    for entry in message_data:
        if not isinstance(entry, dict):
            raise ScenarioError("Each message must be an object.")
        number, role, original_text = entry.get("n"), entry.get("from"), entry.get("text")
        if type(number) is not int or number < 1 or number in messages:
            raise ScenarioError("Message numbers must be unique positive integers.")
        if role not in ("sender", "reader") or not isinstance(original_text, str):
            raise ScenarioError("Each message needs a sender or reader role and text.")
        text = normalize_text(original_text)
        messages[number] = Message(
            number, role, original_text, text, extract_urls(text), extract_phones(text)
        )
    return Conversation(
        scenario_id, channel, sender, tuple(messages[number] for number in sorted(messages))
    )
