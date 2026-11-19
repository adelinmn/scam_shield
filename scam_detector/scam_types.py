"""Independent scam-type classification using the same local NLI model."""

from functools import cache
from pathlib import Path

from .conversation import Conversation, normalize_text
from .flag_definitions import parse_phrases, read_config_json
from .model import FlagClassifier
from .model_assets import PROJECT_ROOT


SCAM_TYPE_CONFIG_PATH = Path(__file__).with_name("scam_type_config.json")


@cache
def load_scam_type_hypotheses() -> dict[str, tuple[str, ...]]:
    entries = read_config_json(SCAM_TYPE_CONFIG_PATH)
    catalog = read_config_json(PROJECT_ROOT / "official_catalog.json")
    codes = [code for code in catalog["scam_types"] if code != "NONE"]
    if not isinstance(entries, dict) or entries.keys() != set(codes):
        raise ValueError(f"{SCAM_TYPE_CONFIG_PATH.name} must contain all official scam type codes except NONE.")

    hypotheses = {}
    for code in codes:
        entry = entries[code]
        if not isinstance(entry, dict) or entry.keys() != {"phrases"}:
            raise ValueError(f"{code} must have a phrases array in {SCAM_TYPE_CONFIG_PATH.name}.")
        hypotheses[code] = parse_phrases(code, entry["phrases"])
    return hypotheses


def classify_scam_type(
    classifier: FlagClassifier, conversation: Conversation, verdict: str
) -> tuple[str, dict[str, float]]:
    if verdict == "SAFE":
        return "NONE", {}

    lines = []
    if conversation.sender.name:
        lines.append(f"Numele afișat al expeditorului: {normalize_text(conversation.sender.name)}")
    if conversation.sender.known_contact:
        lines.append("Expeditorul apare în lista de contacte.")
    for message in conversation.messages:
        speaker = "Expeditor" if message.role == "sender" else "Destinatar"
        lines.append(f"{speaker}: {message.text}")
    scores = classifier.score_hypotheses(["\n".join(lines)], load_scam_type_hypotheses())[0]
    return max(scores, key=scores.__getitem__), scores
