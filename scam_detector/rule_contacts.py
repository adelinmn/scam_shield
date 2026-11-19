"""Offline checks against the challenge's official contact catalog."""

import re
from dataclasses import dataclass
from difflib import SequenceMatcher
from pathlib import Path
from urllib.parse import urlsplit

from .conversation import Message, Sender
from .flag_definitions import read_config_json
from .rule_patterns import fold, pattern


_EMAIL_DOMAIN = re.compile(r"[\w.!#$%&'*+/=?^{}|~-]+@([\w.-]+\.[a-z]{2,63})", re.IGNORECASE)
_NON_WORD = re.compile(r"[^a-z0-9]+")
MARKET_ACCOUNT = pattern(r"cumparator[a-z]*|vanzator[a-z]*|buyer_[a-z0-9]+|seller_[a-z0-9]+")
_PERSONAL_LABEL = re.compile(r"^(?:client(?:ul|a)?|contribuabil(?:ul)?)\b")
_AFFILIATION_GRAMMAR = (
    r"(?:\b(?:sunt(?:em)?|lucrez|(?:va |te )?(?:sun|scriu))\s+"
    r"(?:(?!(?:client(?:ul|a)?|contribuabil(?:ul)?|cumparator(?:ul)?|vanzator(?:ul)?)\b)\w+\s+){0,5}"
    r"(?:de la|din partea|in numele)|\breprezint(?:am)?"
    r"|(?:^|\bsunt(?:em)?\s+)(?:in numele|din partea|"
    r"(?:reprezentant(?:ul)?|angajat(?:ul)?|operator(?:ul)?) (?:al|a)))"
)
_AFFILIATION = re.compile(_AFFILIATION_GRAMMAR + r"\s*$")
AFFILIATION_CLAIM = re.compile(_AFFILIATION_GRAMMAR + r"\b")


def hostname(address: str) -> str | None:
    address = address.strip()
    if not address:
        return None
    try:
        parsed = urlsplit(address if "://" in address else "//" + address)
        if parsed.scheme not in {"", "http", "https"} or parsed.username is not None or not parsed.hostname:
            return None
        host = parsed.hostname.rstrip(".").encode("idna").decode("ascii").lower()
        return host if "." in host else None
    except (ValueError, UnicodeError):
        return None


def phone_key(phone: str) -> str | None:
    phone = phone.strip().lower().removeprefix("tel:")
    if re.search(r"[a-z]", phone, re.IGNORECASE):
        return None
    digits = "".join(re.findall(r"[0-9]", phone))
    if digits.startswith("0040") and len(digits) == 13:
        digits = "0" + digits[4:]
    elif digits.startswith("40") and len(digits) == 11:
        digits = "0" + digits[2:]
    return digits if 9 <= len(digits) <= 15 else None


@dataclass(frozen=True)
class Organization:
    alias: re.Pattern
    domains: frozenset[str]
    phone: str | None

    def mentioned_in(self, text: str) -> bool:
        return bool(self.alias.search(fold(text)))

    def claimed_in(self, text: str) -> bool:
        normalized = fold(text)
        for name in self.alias.finditer(normalized):
            preceding = normalized[:name.start()]
            following = normalized[name.end():].lstrip()
            if (
                not preceding.strip(" [-") and following.startswith((":", "]"))
                or _AFFILIATION.search(preceding)
            ):
                return True
        return False

    def resembles_domain(self, host: str) -> bool:
        if self.mentioned_in(host):
            return True
        labels = [_NON_WORD.sub("", label) for label in host.split(".")[:-1]]
        official_labels = {domain.removeprefix("www.").split(".")[0] for domain in self.domains}
        return any(
            len(original) >= 6 and SequenceMatcher(None, original, label).ratio() >= 0.88
            for original in official_labels for label in labels
        )


def load_contacts(path: Path) -> tuple[Organization, ...]:
    if not path.is_file():
        return ()
    contacts = read_config_json(path).get("official_contacts", [])
    organizations = []
    for entry in contacts:
        domain = hostname(entry["website"])
        if domain:
            domains = {domain, "www." + domain}
            domains.update(filter(None, map(hostname, entry.get("subdomains", []))))
            words = _NON_WORD.split(fold(entry["organisation"]))
            alias = pattern(r"[\W_]*".join(map(re.escape, filter(None, words))))
            organizations.append(Organization(
                alias,
                frozenset(domains),
                phone_key(entry["phone"] or ""),
            ))
    return tuple(organizations)


def known_catalog_sender(catalog: tuple[Organization, ...], sender: Sender | None) -> bool:
    if sender is None or not sender.known_contact or not sender.name or not sender.address:
        return False
    number = phone_key(sender.address)
    name = fold(sender.name)
    return number is not None and any(
        org.phone == number and org.alias.fullmatch(name) for org in catalog
    )


@dataclass(frozen=True)
class ContactEvidence:
    claimed: bool
    official: bool
    suspicious: bool
    affiliation_claim: bool = False
    reason: str = ""


def check_contacts(
    catalog: tuple[Organization, ...],
    message: Message,
    sender: Sender | None,
    *,
    directed: bool,
    phone_requested: bool,
    credential_request: bool = False,
    previous: tuple[Message, ...] = (),
) -> ContactEvidence:
    if not catalog:
        return ContactEvidence(False, False, False)
    address = (sender.address or "") if sender else ""
    sender_name = (sender.name or "") if sender else ""
    sender_urls = sender.urls if sender else ()
    identity = " ".join((sender_name, address))
    sender_domains = set(filter(None, map(hostname, _EMAIL_DOMAIN.findall(address))))
    sender_domains.update(filter(None, map(hostname, sender_urls)))
    message_domains = set(filter(None, map(hostname, _EMAIL_DOMAIN.findall(message.text))))
    message_domains.update(filter(None, map(hostname, message.urls)))
    explicit = tuple(org for org in catalog if org.claimed_in(message.text))
    if not explicit and not (MARKET_ACCOUNT.search(fold(identity)) or _PERSONAL_LABEL.match(fold(sender_name))):
        explicit = tuple(org for org in catalog if org.mentioned_in(sender_name))
    if not explicit:
        for turn in reversed(previous):
            if turn.role == "sender" and turn.number < message.number:
                explicit = tuple(org for org in catalog if org.claimed_in(turn.text))
                if explicit:
                    break
    mentioned = tuple(
        org for org in catalog
        if org.mentioned_in(identity + " " + message.text)
        or any(org.resembles_domain(host) for host in sender_domains | message_domains)
    )
    sender_phone = phone_key(address)
    sender_matches = tuple(
        org for org in catalog if org.domains & sender_domains or (org.phone and org.phone == sender_phone)
    )
    # An explicit claim determines which catalog entry applies even if the URL names another brand.
    organizations = explicit or sender_matches or mentioned
    if not organizations:
        suspicious = credential_request and bool(message_domains)
        return ContactEvidence(
            False, False, suspicious, reason="credential_request_via_unverified_contact" if suspicious else ""
        )
    official_domains = frozenset().union(*(org.domains for org in organizations))
    official_phones = {org.phone for org in organizations if org.phone}
    presented_phones = set(filter(None, map(phone_key, message.phone_numbers)))
    if not phone_requested:
        presented_phones.clear()
    official = bool(
        (sender_domains | message_domains) & official_domains
        or sender_phone in official_phones
        or presented_phones & official_phones
    )
    branded_link = any(
        org.resembles_domain(host)
        for org in organizations for host in (sender_domains | message_domains) - official_domains
    )
    scoped = directed or bool(explicit) or branded_link
    mismatched_domains = scoped and bool(
        (sender_domains | message_domains) - official_domains
        or any("://" in url and hostname(url) is None for url in (*sender_urls, *message.urls))
    )
    mismatched_phones = bool(official_phones) and (
        bool(explicit and sender_phone and sender_phone not in official_phones)
        or bool(presented_phones - official_phones)
    )
    suspicious = mismatched_domains or mismatched_phones
    return ContactEvidence(bool(mentioned or explicit), official, suspicious, bool(explicit),
                           "contact_mismatch_with_official_catalog" if suspicious else "")
