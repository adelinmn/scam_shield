"""Deterministic red flags and contextual evidence for Scam Shield."""

import re
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from .conversation import Message, Sender
from .flag_definitions import FLAG_DEFINITIONS
from .model_assets import PROJECT_ROOT
from .rule_contacts import AFFILIATION_CLAIM, MARKET_ACCOUNT, check_contacts, known_catalog_sender, load_contacts
from .rule_patterns import (
    DELIVERY_NOTICE, NO_PAYMENT, OTP_NOTICE, PAYMENT_ACTION, SOCIAL,
    fold, investment_return, isolation, matches, pattern, positive_action, request,
)
from .rule_types import TypeEvidence, assess_types


class RuleStatus(StrEnum):
    CONFIRMED = "CONFIRMED"
    REJECTED = "REJECTED"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class RuleContext:
    channel: str
    sender: Sender
    previous_messages: tuple[Message, ...]


@dataclass(frozen=True)
class RuleAssessment:
    flags: dict[str, RuleStatus]
    reasons: dict[str, str]
    targeted: bool


_CALL = pattern(r"suna(?:ti)?|apeleaz[a-z]*|telefon oficial|numar oficial|contactea[zz][a-z]*")
_PHONE_LABEL = re.compile(
    r"\b(?:telefon(?:ul)?(?: oficial)?|tel\.?|(?:numar(?:ul)?|nr\.?) (?:de contact|oficial))"
    r"\s*(?:[:=]\s*|(?=\+?\d))"
)
_ADMIN_NOTICE = pattern(r"actualizare a dosar[a-z]*|informare administrativa|dosar[a-z]* pentru indexare")
_INTRO_REPLY = re.compile(r"^(?:eu|sunt|eu sunt)[ ,]+[a-z]+(?:[, ]+(?:cine sa fie|cine altcineva))?[\W]*$")
_REPLY_PRIZE = pattern(r"raspunde(?:ti)?(?: cu)?|revendic[a-z]*|scrie(?:ti)?[ -]ne")
_OPT_IN_PRIZE = pattern(r"raspunde(?:ti)? cu (?:da|ok)|scrie(?:ti)?[ -]ne pentru detalii")
_MISDELIVERED_CODE = pattern(r"din greseala|trimis gresit|trimis din eroare")
_SENSITIVE_CODE = pattern(r"cod(?:ul)? (?:postal|de reducere|de reducerea|de produs|de bare)")
_AUTHORITY_PROMISE = pattern(r"pensi[a-z]*.{0,55}(?:creste cu|majorar[a-z]*)|(?:diferenta|majorarea).{0,30}pensi[a-z]*")
_JOBS_WINDFALL = pattern(r"(?:castig[a-z]*|lei|euro|comisio[a-z]*|plata).{0,45}(?:zilnic|pe zi|pentru (?:like|sarcin|recenzi)|garantat)")
_IMPLICIT_FIELDS = pattern(r"numele complet|ce date|lista de date|numar[a-z]* card[a-z]*")
_COERCION = pattern(r"daca nu|altfel|ca sa nu pier[zdt][a-z]*")
_PUBLIC_ROLE = pattern(
    r"(?:vorbesc|vorbim|action[a-z]*|va (?:scriu|inform[a-z]*|contactez)) in numele|"
    r"aici (?:este|e) (?:biroul|serviciul|departamentul)"
)
_HELP_REQUEST = pattern(
    r"(?:te|va) (?:rog|implor)(?: sa)? (?:ma ajut[a-z]*|ajuta[ -]ma)|"
    r"ajuta[ -]ma|trebuie sa ma ajuti|numai tu ma poti salva"
)
_PRIVATE_CREDENTIAL = pattern(r"cvv|cvc|pin[a-z]*|parol[a-z]*|date[a-z]* (?:ale cardului|cardului|de autentificare)")
_SELF_MANAGED_SECURITY = pattern(
    r"mi[ -]am (?:schimbat|resetat) (?:singur[a-z]* )?(?:parola|pinul)|"
    r"am (?:ignorat|raportat) (?:mesajul|notificarea|codul)"
)
_REQUIRED_ACTION = pattern(r"trebuie|obligatoriu|numai daca|altfel|termen[a-z]*")
_AMOUNT_ONLY = re.compile(r"\d[\d., ]*\s*(?:lei|ron|eur|euro)(?:[.!])?")
_UNREALISTIC_RETURN = pattern(
    r"(?:castig[a-z]*|venit[a-z]*|profit[a-z]*|randament[a-z]*) (?:zilnic[a-z]* )?(?:este |e )?garantat[a-z]*|"
    r"fara (?:niciun )?(?:efort|risc(?:uri)?)"
)
_ROUTINE_UPDATE = pattern(
    r"va informam despre|am si cateva informatii suplimentare|plata a fost deja inregistrata|"
    r"nu (?:este necesara|este nevoie de) (?:nicio actiune|o alta plata)|"
    r"reduceri la produse selectate"
)
_OFFICIAL_GUIDANCE = pattern(r"consultati informatiile generale|informatii generale in cont")
_DATA_SAFETY = pattern(
    r"nu (?:furnizati|comunicati|transmiteti|trimiteti|va cerem) date personale(?: prin mesaje)?"
)
_CONTACT_FLAGS_REQUIRING_EVIDENCE = frozenset({
    "RF_CODE_REQUEST", "RF_REMOTE_ACCESS", "RF_DATA_REQUEST", "RF_PAYMENT_REQUEST",
    "RF_NEW_NUMBER", "RF_SECRECY", "RF_IMPERSONATION",
})


class RuleEngine:
    def __init__(self, catalog_path: str | Path = PROJECT_ROOT / "official_catalog.json"):
        self.catalog_path = Path(catalog_path)
        self.catalog = load_contacts(self.catalog_path)

    def evaluate(
        self, message: Message | None, context: RuleContext | None = None
    ) -> dict[str, RuleStatus]:
        return self.evaluate_flags(message, context)

    def evaluate_flags(
        self, message: Message | None, context: RuleContext | None = None
    ) -> dict[str, RuleStatus]:
        return self.evaluate_detailed(message, context).flags

    def evaluate_detailed(
        self, message: Message | None, context: RuleContext | None = None
    ) -> RuleAssessment:
        flags = dict.fromkeys(FLAG_DEFINITIONS, RuleStatus.UNKNOWN)
        reasons = {}
        if message is None or message.role != "sender":
            return RuleAssessment(flags, reasons, False)
        text = fold(message.original_text)
        sender = context.sender if context else None
        history = tuple(item for item in context.previous_messages if item.number < message.number) if context else ()
        prior = " ".join(fold(item.text) for item in history if item.role == "sender")
        identity = fold(" ".join((sender.name or "", sender.address or ""))) if sender else ""
        current = {name: bool(matches(name, text)) for name in (
            "bank", "authority", "courier", "family", "friend", "new_number",
            "tech", "market", "emergency", "prize", "winner",
            "urgency", "threat", "emotion", "channel", "benefit",
            "conditional_benefit", "generic_data", "job", "tasks", "investment",
        )}
        code, no_code = request(text, "share", "code")
        remote, no_remote = request(text, "remote", "remote")
        data, no_data = request(text, "share", "data")
        payment, no_payment = request(text, "pay", "money")
        following = positive_action(text, "follow")
        if _SENSITIVE_CODE.search(text) and not matches("account", text) and "otp" not in text:
            code = False
        if NO_PAYMENT.search(text) and not payment:
            no_payment = True
        if _AMOUNT_ONLY.fullmatch(text) and not positive_action(prior, "pay"):
            no_payment = True

        support_context = current["tech"] or bool(matches("tech", prior) or matches("remote", prior))
        authority_context = current["authority"] or bool(matches("authority", prior))
        if following and PAYMENT_ACTION["login"].search(text) and support_context:
            data = True
        if (
            matches("data", text) and _IMPLICIT_FIELDS.search(text)
            and matches("generic_data", prior) and authority_context and not no_data
        ):
            data = True

        targeted = code or remote or data or payment or following
        contact = check_contacts(
            self.catalog, message, sender,
            directed=targeted or current["threat"],
            phone_requested=bool((_CALL.search(text) and following) or _PHONE_LABEL.search(text)),
            credential_request=code or (data and bool(_PRIVATE_CREDENTIAL.search(text))),
            previous=history,
        )
        catalog_contact = not contact.suspicious and known_catalog_sender(self.catalog, sender)
        family = current["family"] or current["friend"] or bool(matches("family", prior))
        new_number = bool(sender and not sender.known_contact and family and current["new_number"])
        otp_notice = bool(OTP_NOTICE.search(text))
        prize_claim = current["prize"] and current["winner"]
        prize_context = prize_claim or bool(matches("winner", prior) and matches("prize", prior))
        prize_action = prize_context and bool(_REPLY_PRIZE.search(text) or payment or data)
        pension_bait = bool(
            authority_context and _AUTHORITY_PROMISE.search(text)
            and current["conditional_benefit"] and current["generic_data"]
        )
        job_bait = current["job"] and current["tasks"] and bool(
            _JOBS_WINDFALL.search(text) or _UNREALISTIC_RETURN.search(text)
        )
        promised_return, no_return = investment_return(text)
        too_good = bool(
            prize_action or pension_bait or job_bait
            or (promised_return and (current["investment"] or targeted))
        )
        institution = (
            current["bank"] or authority_context or current["courier"] or current["tech"]
            or contact.claimed or support_context or bool(matches("bank", prior))
        )
        public_claim = bool(
            AFFILIATION_CLAIM.search(text) or AFFILIATION_CLAIM.search(prior)
            or _PUBLIC_ROLE.search(text) or _PUBLIC_ROLE.search(prior)
        )
        institutional_claim = (
            institution and (contact.affiliation_claim or not MARKET_ACCOUNT.search(identity))
            and (contact.affiliation_claim or public_claim or pension_bait
                 or any(matches(role, identity) for role in ("bank", "authority", "tech")))
        )
        suspicious_action = bool(
            code or remote or data or payment or current["threat"]
            or (contact.suspicious and contact.affiliation_claim)
        )
        impersonation = bool(
            (institutional_claim and (suspicious_action or pension_bait)) or (prize_action and contact.claimed)
        )
        urgent = current["urgency"] and (
            targeted or bool(prize_action or (current["threat"] and _REQUIRED_ACTION.search(text)))
            or (bool(PAYMENT_ACTION["deadline"].search(text)) and bool(
                message.urls or matches("threat", text) or positive_action(prior, "pay", "share", "follow")
            ))
            or bool(_REQUIRED_ACTION.search(text) and positive_action(prior, "pay", "share", "follow"))
        )
        threat = current["threat"] and (
            targeted or institutional_claim or bool(_COERCION.search(text))
        )
        protective_code = (otp_notice or no_code) and not code
        self_managed_security = bool(_SELF_MANAGED_SECURITY.search(text) and not targeted and not message.urls)
        secrecy, protective_advice = isolation(text)
        prior_pressure = bool(matches("emotion", prior)) and (
            family or bool(matches("romance", prior) or matches("emergency", prior))
        )
        emotion = bool(
            (current["emotion"] or prior_pressure)
            and (payment or code or data or remote or secrecy or _HELP_REQUEST.search(text))
        )
        confirmed = {
            "RF_CODE_REQUEST": (code, "explicit_code_request"),
            "RF_REMOTE_ACCESS": (remote, "requested_remote_control"),
            "RF_DATA_REQUEST": (data, "requested_sensitive_data_or_login"),
            "RF_PAYMENT_REQUEST": (payment, "requested_payment"),
            "RF_SUSPICIOUS_CONTACT": (contact.suspicious, contact.reason),
            "RF_NEW_NUMBER": (new_number, "unknown_sender_claims_familiar_identity_and_new_number"),
            "RF_SECRECY": (secrecy, "request_to_keep_secret_or_avoid_verification"),
            "RF_TOO_GOOD": (too_good, "prize_or_unusual_benefit_with_lure"),
            "RF_IMPERSONATION": (impersonation and not catalog_contact, "institutional_claim_with_risky_behavior"),
            "RF_URGENCY": (urgent, "pressure_to_act_or_explicit_deadline"),
            "RF_THREAT": (threat, "negative_consequence_used_as_pressure"),
            "RF_EMOTIONAL_PRESSURE": (emotion, "emotional_leverage_with_request"),
            "RF_CHANNEL_SWITCH": (current["channel"], "explicit_request_to_change_channel"),
        }
        for code_name, (found, reason) in confirmed.items():
            if found:
                flags[code_name] = RuleStatus.CONFIRMED
                reasons[code_name] = reason

        benign_notice = (
            (otp_notice and not code)
            or DELIVERY_NOTICE.search(text)
            or (authority_context and _ADMIN_NOTICE.search(text))
            or _ROUTINE_UPDATE.search(text)
            or (contact.official and _OFFICIAL_GUIDANCE.search(text) and _DATA_SAFETY.search(text))
            or ((no_code or no_remote or no_data) and not targeted)
        )
        ordinary = bool(
            (not text or not any(character.isalnum() for character in text))
            or SOCIAL.fullmatch(text)
            or (matches("new_number", prior) and _INTRO_REPLY.fullmatch(text))
        )
        only_intro = new_number and not any(
            found for key, (found, _) in confirmed.items() if key != "RF_NEW_NUMBER"
        )
        other_behavior = any(found for key, (found, _) in confirmed.items() if key != "RF_NEW_NUMBER")
        benign = bool(
            (benign_notice or ordinary or only_intro)
            and not other_behavior and not targeted
            and (not message.urls or (benign_notice and contact.official and not contact.suspicious))
        )
        prize_opt_in = prize_claim and _OPT_IN_PRIZE.search(text) and not message.urls and not matches("money", text)
        receiving_refund = data and current["benefit"] and current["conditional_benefit"] and not payment
        code_return = code and _MISDELIVERED_CODE.search(text) and not institutional_claim and not payment
        family_story = family and bool(current["new_number"] or matches("new_number", prior)) and not institutional_claim
        contradicted = {
            "RF_CODE_REQUEST": protective_code or self_managed_security,
            "RF_REMOTE_ACCESS": no_remote,
            "RF_DATA_REQUEST": no_data or self_managed_security,
            "RF_PAYMENT_REQUEST": no_payment or prize_opt_in or receiving_refund or code_return,
            "RF_SUSPICIOUS_CONTACT": contact.official and not contact.suspicious,
            "RF_NEW_NUMBER": institutional_claim and not family,
            "RF_SECRECY": protective_code or protective_advice or code_return,
            "RF_TOO_GOOD": no_return and not promised_return,
            "RF_IMPERSONATION": family_story or code_return,
            "RF_URGENCY": bool(DELIVERY_NOTICE.search(text) and not urgent),
        }
        for key in flags:
            catalog_requires_evidence = catalog_contact and key in _CONTACT_FLAGS_REQUIRING_EVIDENCE
            if flags[key] == RuleStatus.UNKNOWN and (
                benign or contradicted.get(key, False) or catalog_requires_evidence
            ):
                flags[key] = RuleStatus.REJECTED
                if key == "RF_PAYMENT_REQUEST" and no_payment:
                    reasons[key] = "negated_or_completed_payment"
                elif key == "RF_SECRECY" and protective_advice:
                    reasons[key] = "advice_to_protect_private_information"
                elif contradicted.get(key, False):
                    reasons[key] = "explicit_counterevidence"
                elif benign:
                    reasons[key] = "recognized_benign_context"
                else:
                    reasons[key] = "catalog_contact_without_flag_evidence"
        return RuleAssessment(flags, reasons, bool(targeted or prize_action))

    def context_flags(self, message: Message, context: RuleContext | None = None) -> tuple[str, ...]:
        if message.role != "sender":
            return ()
        text = fold(message.text)
        result = []
        if matches("bank", text):
            result.append("INFO_BANK_CONTEXT")
        if OTP_NOTICE.search(text) and not request(text, "share", "code")[0]:
            result.append("INFO_OTP_NOTICE")
        return tuple(result)

    def evaluate_types(
        self, message: Message, context: RuleContext | None = None
    ) -> dict[str, TypeEvidence]:
        preceding = tuple(item for item in context.previous_messages if item.number < message.number) if context else ()
        sender = context.sender if context else None
        channel = context.channel if context else ""
        messages = (*preceding, message)
        flags = set()
        targeted = False
        for index, turn in enumerate(messages):
            if turn.role != "sender":
                continue
            prefix = RuleContext(channel, sender, messages[:index]) if sender else None
            assessment = self.evaluate_detailed(turn, prefix)
            flags.update(flag for flag, status in assessment.flags.items() if status == RuleStatus.CONFIRMED)
            targeted |= assessment.targeted
        sender_text = " ".join(fold(turn.text) for turn in messages if turn.role == "sender")
        reader_text = " ".join(fold(turn.text) for turn in messages if turn.role == "reader")
        metadata = fold(sender.name or "") if sender else ""
        catalog_contact = "RF_SUSPICIOUS_CONTACT" not in flags and known_catalog_sender(self.catalog, sender)
        return assess_types(
            " ".join((metadata, sender_text)), reader_text, flags,
            targeted=targeted, catalog_contact=catalog_contact,
        )
