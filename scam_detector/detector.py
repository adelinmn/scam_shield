"""Public detection API and chronological analysis."""

from collections.abc import Mapping
from dataclasses import asdict
from enum import StrEnum
from threading import Lock

from .conversation import Conversation, parse_scenario
from .flag_definitions import FLAG_DEFINITIONS
from .fusion import FlagFusionEngine
from .model import FlagClassifier
from .rules import RuleContext, RuleEngine, RuleStatus
from .scam_types import classify_scam_type
from .scoring import ALERT_SCORE, risk_score, verdict_for_score


class DetectionMode(StrEnum):
    HYBRID = "hybrid"
    MODEL_ONLY = "model-only"
    RULES_ONLY = "rules-only"


class ScamDetector:
    def __init__(
        self,
        classifier: FlagClassifier | None,
        *,
        thresholds: Mapping[str, float] | None = None,
        rules: RuleEngine | None = None,
        mode: DetectionMode | str = DetectionMode.HYBRID,
    ) -> None:
        self.mode = DetectionMode(mode)
        if classifier is None and self.mode != DetectionMode.RULES_ONLY:
            raise ValueError("A classifier is required for hybrid and model-only detection.")
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
        context_flags = {}
        first_alert = None
        score = 0

        for index, message in enumerate(conversation.messages):
            if message.role == "reader":
                continue
            scores = self.classifier.classify(message.text) if self.mode != DetectionMode.RULES_ONLY else None
            context = RuleContext(
                conversation.channel, conversation.sender, conversation.messages[:index]
            )
            if self.mode == DetectionMode.MODEL_ONLY:
                evidence = dict.fromkeys(FLAG_DEFINITIONS, RuleStatus.UNKNOWN)
            else:
                evidence = self.rules.evaluate(message, context)
                for flag in self.rules.context_flags(message, context):
                    context_flags.setdefault(flag, []).append(message.number)
            detected = self.fusion.select(scores, evidence)
            for flag in detected:
                flag_messages.setdefault(flag, message.number)
            for flag, confidence in (scores or {}).items():
                model_scores[flag] = max(model_scores[flag], confidence)
            score = risk_score(flag_messages)
            if first_alert is None and score >= ALERT_SCORE:
                first_alert = message.number
            rule_evidence[message.number] = evidence
            message_results.append(
                {
                    "n": message.number,
                    "model_scores": scores if scores is not None else dict.fromkeys(FLAG_DEFINITIONS, 0.0),
                    "red_flags": detected,
                    "risk_score": score,
                }
            )

        verdict = verdict_for_score(score)
        type_evidence = None
        if self.mode != DetectionMode.MODEL_ONLY:
            message = conversation.messages[-1]
            type_context = RuleContext(conversation.channel, conversation.sender, conversation.messages[:-1])
            type_evidence = self.rules.evaluate_types(message, type_context)
        type_classifier = self.classifier if self.mode != DetectionMode.RULES_ONLY else None
        scam_type, type_scores = classify_scam_type(type_classifier, conversation, verdict, type_evidence)
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
            "context_flags": list(context_flags),
            "context_flag_messages": context_flags,
            "scam_type_rule_evidence": {code: asdict(item) for code, item in (type_evidence or {}).items()},
            "message_results": message_results,
            "scam_type_scores": type_scores,
        }


_default_detector: ScamDetector | None = None
_mode_detectors: dict[DetectionMode, ScamDetector] = {}
_detector_lock = Lock()


def analyze_scenario(scenario: dict, *, mode: DetectionMode | str = DetectionMode.HYBRID) -> dict:
    """Analyze an official scenario with the process-wide offline detector."""
    global _default_detector

    conversation = parse_scenario(scenario)
    mode = DetectionMode(mode)
    with _detector_lock:
        if mode == DetectionMode.HYBRID:
            if _default_detector is None:
                _default_detector = ScamDetector(FlagClassifier())
            detector = _default_detector
        else:
            if mode not in _mode_detectors:
                classifier = None if mode == DetectionMode.RULES_ONLY else FlagClassifier()
                _mode_detectors[mode] = ScamDetector(classifier, mode=mode)
            detector = _mode_detectors[mode]
    return detector.analyze_conversation(conversation)
