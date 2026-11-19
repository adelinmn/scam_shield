"""Public detection API and chronological analysis."""

from collections.abc import Mapping
from threading import Lock

from .conversation import Conversation, parse_scenario
from .flag_definitions import FLAG_DEFINITIONS
from .fusion import FlagFusionEngine
from .model import FlagClassifier
from .rules import RuleContext, RuleEngine
from .scam_types import classify_scam_type
from .scoring import ALERT_SCORE, risk_score, verdict_for_score


class ScamDetector:
    def __init__(
        self,
        classifier: FlagClassifier,
        *,
        thresholds: Mapping[str, float] | None = None,
        rules: RuleEngine | None = None,
    ) -> None:
        self.classifier = classifier
        self.fusion = FlagFusionEngine(thresholds)
        self.rules = rules if rules is not None else RuleEngine()

    def analyze_scenario(self, scenario: dict) -> dict:
        return self.analyze_conversation(parse_scenario(scenario))

    def analyze_conversation(self, conversation: Conversation) -> dict:
        flag_messages: dict[str, int] = {}
        model_scores = dict.fromkeys(FLAG_DEFINITIONS, 0.0)
        message_results = []
        rule_evidence = {}
        first_alert = None
        score = 0

        for index, message in enumerate(conversation.messages):
            if message.role == "reader":
                continue
            scores = self.classifier.classify(message.text)
            context = RuleContext(
                conversation.channel, conversation.sender, conversation.messages[:index]
            )
            evidence = self.rules.evaluate(message, context)
            detected = self.fusion.select(scores, evidence)
            for flag in detected:
                flag_messages.setdefault(flag, message.number)
            for flag, confidence in scores.items():
                model_scores[flag] = max(model_scores[flag], confidence)
            score = risk_score(flag_messages)
            if first_alert is None and score >= ALERT_SCORE:
                first_alert = message.number
            rule_evidence[message.number] = evidence
            message_results.append(
                {
                    "n": message.number,
                    "model_scores": scores,
                    "red_flags": detected,
                    "risk_score": score,
                }
            )

        verdict = verdict_for_score(score)
        scam_type, type_scores = classify_scam_type(self.classifier, conversation, verdict)
        return {
            "id": conversation.id,
            "verdict": verdict,
            "risk_score": score,
            "scam_type": scam_type,
            "first_alert": first_alert,
            "red_flags": list(flag_messages),
            "flag_messages": flag_messages,
            "model_scores": model_scores,
            "thresholds": dict(self.fusion.thresholds),
            "rule_evidence": rule_evidence,
            "message_results": message_results,
            "scam_type_scores": type_scores,
        }


_default_detector: ScamDetector | None = None
_detector_lock = Lock()


def analyze_scenario(scenario: dict) -> dict:
    """Analyze an official scenario with the process-wide offline detector."""
    global _default_detector

    conversation = parse_scenario(scenario)
    with _detector_lock:
        if _default_detector is None:
            _default_detector = ScamDetector(FlagClassifier())
        detector = _default_detector
    return detector.analyze_conversation(conversation)
