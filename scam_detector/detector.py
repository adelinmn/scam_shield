"""Public detection API and chronological analysis."""

from collections.abc import Mapping
from dataclasses import asdict
from enum import StrEnum
from threading import Lock

from .conversation import Conversation, parse_scenario
from .flag_definitions import FLAG_DEFINITIONS, load_flag_config
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
        debug: bool = False,
    ) -> None:
        self.mode = DetectionMode(mode)
        if classifier is None and self.mode != DetectionMode.RULES_ONLY:
            raise ValueError("A classifier is required for hybrid and model-only detection.")
        self.classifier = classifier
        self.fusion = FlagFusionEngine(thresholds)
        self.rules = rules if rules is not None else RuleEngine()
        self.debug = debug

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
        flag_diagnostics = {}
        type_diagnostics = {} if self.debug else None
        detailed_classifier = (
            getattr(self.classifier, "classify_detailed", None)
            if self.debug and self.mode != DetectionMode.RULES_ONLY else None
        )

        for index, message in enumerate(conversation.messages):
            if message.role == "reader":
                continue
            phrase_scores = {}
            if detailed_classifier is not None:
                scores, phrase_scores = detailed_classifier(message.text)
            else:
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
            if self.debug:
                assessment = self.rules.evaluate_detailed(message, context) if self.mode != DetectionMode.MODEL_ONLY else None
                flag_diagnostics[message.number] = self._explain_flags(scores, phrase_scores, evidence, detected, assessment)
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
        scam_type, type_scores = classify_scam_type(
            type_classifier, conversation, verdict, type_evidence, diagnostics=type_diagnostics,
        )
        result = {
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
        if self.debug:
            result["debug"] = {
                "flags": flag_diagnostics,
                "hypotheses": {code: item.phrases for code, item in load_flag_config().items()}
                if detailed_classifier is not None else {},
                "type_selection": type_diagnostics,
            }
        return result

    def _explain_flags(self, scores, phrase_scores, statuses, detected, assessment) -> dict:
        decisions = {}
        config = load_flag_config()
        for code, threshold in self.fusion.thresholds.items():
            score = scores.get(code) if scores is not None else None
            status = statuses.get(code, RuleStatus.UNKNOWN)
            decision = code in detected
            decisions[code] = {
                "model_score": score,
                "threshold": threshold,
                "rule_status": status,
                "rule_reason": assessment.reasons.get(code) if assessment and assessment.flags[code] == status else None,
                "final_decision": decision,
                "rule_changed_decision": status != RuleStatus.UNKNOWN and decision != (score is not None and score >= threshold),
            }
            if code in phrase_scores:
                decisions[code].update(aggregation=config[code].aggregation, hypothesis_scores=phrase_scores[code])
        return decisions


_default_detector: ScamDetector | None = None
_mode_detectors: dict[tuple[DetectionMode, bool], ScamDetector] = {}
_detector_lock = Lock()


def analyze_scenario(scenario: dict, *, mode: DetectionMode | str = DetectionMode.HYBRID, debug: bool = False) -> dict:
    """Analyze an official scenario with the process-wide offline detector."""
    global _default_detector

    conversation = parse_scenario(scenario)
    mode = DetectionMode(mode)
    with _detector_lock:
        if mode == DetectionMode.HYBRID and not debug:
            if _default_detector is None:
                _default_detector = ScamDetector(FlagClassifier())
            detector = _default_detector
        else:
            key = (mode, debug)
            if key not in _mode_detectors:
                classifier = None if mode == DetectionMode.RULES_ONLY else FlagClassifier()
                _mode_detectors[key] = ScamDetector(classifier, mode=mode, debug=debug)
            detector = _mode_detectors[key]
    return detector.analyze_conversation(conversation)
