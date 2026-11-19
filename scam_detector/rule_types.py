"""Combine lexical, behavioral and chronological evidence for scam types."""

from dataclasses import dataclass
from enum import StrEnum

from .rule_patterns import matches


class TypeStrength(StrEnum):
    NONE = "NONE"
    WEAK = "WEAK"
    STRONG = "STRONG"


@dataclass(frozen=True)
class TypeEvidence:
    supported: bool = False
    strength: TypeStrength = TypeStrength.NONE
    reasons: tuple[str, ...] = ()
    matched_terms: tuple[str, ...] = ()
    contradicted: bool = False


def assess_types(
    sender_text: str,
    reader_text: str,
    flags: set[str],
    *,
    targeted: bool,
) -> dict[str, TypeEvidence]:
    terms = {name: matches(name, sender_text) for name in (
        "bank", "courier", "authority", "family", "friend", "new_number", "emergency",
        "tech", "remote", "market", "payout", "account", "code", "investment", "returns",
        "romance", "job", "tasks", "prize", "winner", "benefit", "conditional_benefit", "risk_other",
    )}
    payment = "RF_PAYMENT_REQUEST" in flags
    data = "RF_DATA_REQUEST" in flags
    code = "RF_CODE_REQUEST" in flags
    remote = "RF_REMOTE_ACCESS" in flags
    threat = "RF_THREAT" in flags
    impersonation = "RF_IMPERSONATION" in flags
    contact = "RF_SUSPICIOUS_CONTACT" in flags
    urgent = "RF_URGENCY" in flags
    too_good = "RF_TOO_GOOD" in flags
    family_relation = bool(terms["family"] or matches("family", reader_text))
    named_family = family_relation or bool(terms["friend"] and terms["new_number"])
    market_payout = bool(terms["market"] and terms["payout"] and (data or contact))
    bank_story = bool(terms["bank"] and impersonation and (contact or threat or data or code or payment or remote))
    authority_story = bool(terms["authority"] and impersonation and (data or code or payment or threat or too_good))
    tech_story = bool((terms["tech"] and (remote or (impersonation and threat))) or remote)
    investment_offer = bool(terms["investment"] and (
        (terms["returns"] and (payment or targeted)) or (payment and (urgent or terms["benefit"]))
    ))
    prize_claim = bool(terms["prize"] and terms["winner"] and (targeted or payment or data or too_good))
    combinations = {
        "BANK_IMPERSONATION": (("bank",), bank_story and not (authority_story or tech_story), "bank_identity_with_risky_action"),
        "COURIER_FEE": (("courier",), bool(terms["courier"] and (payment or data) and not market_payout), "delivery_fee_or_card_request"),
        "AUTHORITY_IMPERSONATION": (("authority", "benefit"), authority_story, "authority_identity_with_risky_action"),
        "FAMILY_EMERGENCY": (("family", "friend", "new_number", "emergency"),
                             named_family and payment and bool(terms["new_number"] or terms["emergency"] or "RF_SECRECY" in flags),
                             "family_or_friend_identity_with_financial_request"),
        "TECH_SUPPORT": (("tech", "remote"), tech_story, "support_threat_or_remote_access_request"),
        "MARKETPLACE": (("market", "payout"),
                        market_payout or bool(terms["market"] and (data or (payment and contact)) and not terms["courier"]),
                        "marketplace_transaction_with_payment_or_data_request"),
        "ACCOUNT_TAKEOVER": (("account", "code"),
                             (code or bool(terms["account"] and data))
                             and not (bank_story or authority_story or tech_story or market_payout),
                             "request_for_access_code_or_account_credentials"),
        "INVESTMENT": (("investment", "returns"), investment_offer, "investment_offer_with_returns_or_deposit"),
        "ROMANCE": (("romance",), bool(terms["romance"] and payment and not family_relation),
                    "romantic_context_with_financial_request"),
        "JOB_OFFER": (("job", "tasks"), bool(terms["job"] and (payment or (terms["tasks"] and too_good))),
                      "job_offer_with_upfront_payment_or_promised_task_earnings"),
        "PRIZE_LOTTERY": (("prize", "winner"), prize_claim and not authority_story, "prize_claim_with_requested_action"),
    }
    conflicts = {
        "ROMANCE": (family_relation, "family_context"),
        "COURIER_FEE": (market_payout, "marketplace_payout_context"),
        "ACCOUNT_TAKEOVER": (bank_story or authority_story or tech_story or market_payout, "specific_organization_or_marketplace_context"),
        "PRIZE_LOTTERY": (authority_story, "authority_refund_context"),
    }
    evidence = {}
    for scam_type, (groups, strong, reason) in combinations.items():
        found = tuple(dict.fromkeys(term for group in groups for term in terms[group]))
        blocked, conflict_reason = conflicts.get(scam_type, (False, ""))
        if blocked:
            evidence[scam_type] = TypeEvidence(reasons=(conflict_reason,), matched_terms=found, contradicted=True)
        elif strong:
            evidence[scam_type] = TypeEvidence(True, TypeStrength.STRONG, (reason,), found)
        elif found:
            evidence[scam_type] = TypeEvidence(True, TypeStrength.WEAK, ("topic_mention",), found)
        else:
            evidence[scam_type] = TypeEvidence()

    fallback = bool(flags) and not any(item.strength == TypeStrength.STRONG for item in evidence.values())
    evidence["OTHER"] = (
        TypeEvidence(True, TypeStrength.WEAK, ("risky_behavior_without_specific_type",), terms["risk_other"])
        if fallback else TypeEvidence()
    )
    return evidence
