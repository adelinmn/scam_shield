"""Independent scam-type classification using the same local NLI model."""

from collections.abc import Mapping
from functools import cache
from pathlib import Path

from .conversation import Conversation, normalize_text
from .flag_definitions import parse_phrases, read_config_json
from .model import FlagClassifier
from .model_assets import PROJECT_ROOT
from .rule_types import TypeEvidence, TypeStrength


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
        if isinstance(entry, dict) and entry.keys() == {"phrases"}:
            entry = entry["phrases"]
        hypotheses[code] = parse_phrases(code, entry)
    return hypotheses


def type_premise(conversation: Conversation) -> str:
    lines = []
    if conversation.sender.name:
        lines.append(f"Numele afișat al expeditorului: {normalize_text(conversation.sender.name)}")
    if conversation.sender.known_contact:
        lines.append("Expeditorul apare în lista de contacte.")
    for message in conversation.messages:
        speaker = "Expeditor" if message.role == "sender" else "Destinatar"
        lines.append(f"{speaker}: {message.text}")
    return "\n".join(lines)


def classify_scam_type(
    classifier: FlagClassifier | None,
    conversation: Conversation,
    verdict: str,
    rule_evidence: Mapping[str, TypeEvidence] | None = None,
    *,
    strong_bonus: float = 0.15,
    weak_bonus: float = 0.025,
    diagnostics: dict | None = None,
) -> tuple[str, dict[str, float]]:
    if verdict == "SAFE":
        if diagnostics is not None:
            diagnostics.update(reason="safe_verdict", candidates={})
        return "NONE", {}

    scores = (
        classifier.score_hypotheses([type_premise(conversation)], load_scam_type_hypotheses())[0]
        if classifier is not None else {}
    )
    if rule_evidence is None:
        specific = {code: score for code, score in scores.items() if code != "OTHER" and score >= 0.75}
        if diagnostics is not None:
            diagnostics.update(reason="model_score" if specific else "fallback", candidates=specific)
        return max(specific, key=specific.__getitem__, default="OTHER"), scores

    eligible = {
        code: evidence for code, evidence in rule_evidence.items()
        if code != "OTHER" and not evidence.contradicted
    }
    strong = {
        code: scores.get(code, 0.0) + strong_bonus
        for code, evidence in eligible.items()
        if evidence.strength == TypeStrength.STRONG
    }
    specific = strong or {
        code: scores[code] + (weak_bonus if evidence.supported else 0.0)
        for code, evidence in eligible.items()
        if scores.get(code, 0.0) >= 0.75
    }
    if diagnostics is not None:
        diagnostics.update(
            reason="strong_rule_evidence" if strong else "model_score" if specific else "fallback",
            candidates=specific,
        )
    return max(specific, key=specific.__getitem__, default="OTHER"), scores
