"""
Option A: deterministic, context-aware warning generation for Scam Shield.

Pipeline (per conversation):
  detector(prefix) -> (red_flag_codes, scam_type)      <- YOUR MiniLM classifier plugs in here
  risk_score / verdict / first_alert                    <- official formula from the brief
  build_warning(...)                                    <- Romanian template + slots (no invented facts)

Everything that can appear in a warning (phones, sites, amounts, names) comes
from either the official catalog or the conversation itself, never from a model.
Every warning is checked against the catalog before it is returned: an official
phone may be offered, an unofficial one (email, number or site) is refused.
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field, replace
from typing import Callable, Iterable, Optional

# ----------------------------------------------------------------------------
# Official catalog (mirrors the brief; swap for official_catalog.json if you like)
# ----------------------------------------------------------------------------
POINTS = {
    "RF_CODE_REQUEST": 35, "RF_REMOTE_ACCESS": 35, "RF_DATA_REQUEST": 30,
    "RF_PAYMENT_REQUEST": 25, "RF_SUSPICIOUS_CONTACT": 25, "RF_NEW_NUMBER": 20,
    "RF_SECRECY": 20, "RF_TOO_GOOD": 20, "RF_IMPERSONATION": 15, "RF_URGENCY": 15,
    "RF_THREAT": 15, "RF_EMOTIONAL_PRESSURE": 10, "RF_CHANNEL_SWITCH": 10,
}

OFFICIAL = {
    "Banca Dunărea": {"site": "bancadunarea.ro", "phone": "0800 100 200", "aliases": ["banca dunarea", "bancadunarea"]},
    "CurierExpres": {"site": "curierexpres.ro", "phone": "0800 300 400", "aliases": ["curierexpres"]},
    "PiațaMea": {"site": "piatamea.ro", "phone": None, "aliases": ["piatamea"]},
    "MegaShop": {"site": "megashop.ro", "phone": "0800 500 600", "aliases": ["megashop"]},
    "ANAF": {"site": "anaf.ro", "phone": "031 403 91 60", "aliases": ["anaf"]},
}
OFFICIAL_DOMAINS = {v["site"] for v in OFFICIAL.values()}

# Authorities that are NOT in the catalog: we name them but never give a phone/site.
GENERIC_CLAIMS = [
    ("casa de pensii", "Casa de Pensii"),
    ("suport tehnic", "suportul tehnic"),
    ("politi", "Poliția"),
    ("parchet", "Parchetul"),
]

UI_LABEL = {
    "SAFE": "Pare în regulă",
    "SUSPICIOUS": "Atenție, verificați înainte să răspundeți",
    "SCAM": "Pare o țeapă! Nu răspundeți",
}
HEADLINE = {
    "SUSPICIOUS": "Atenție, verificați înainte să răspundeți!",
    "SCAM": "Atenție, pare o țeapă!",
}


def risk_score(flags: Iterable[str]) -> int:
    return min(100, sum(POINTS.get(f, 0) for f in set(flags)))


def verdict_for(score: int) -> str:
    return "SAFE" if score < 25 else "SUSPICIOUS" if score < 50 else "SCAM"


# ----------------------------------------------------------------------------
# Input model (adapt from_dict to the organisers' JSON format)
# ----------------------------------------------------------------------------
@dataclass
class Message:
    sender: str  # "other" | "reader"
    text: str


@dataclass
class Conversation:
    channel: str  # sms | whatsapp | email | chat | call
    messages: list[Message]
    sender_label: str = ""
    sender_known: bool = False     # saved contact (e.g. "Maria (vecina)")
    sender_official: bool = False  # sender ID is on the official list
    id: str = ""                   # scenario id from the JSON (e.g. "V04")


def norm(s: str) -> str:
    s = unicodedata.normalize("NFKD", s)
    return "".join(c for c in s if not unicodedata.combining(c)).lower()


# ----------------------------------------------------------------------------
# Loader for the organisers' JSON format (validation_set/Vxx.json, same for the test set)
# ----------------------------------------------------------------------------
CHANNEL_MAP = {"call_transcript": "call", "call": "call"}


def load_conversation(data) -> Conversation:
    """Accepts a dict, or a path to a JSON file, in the standard input format."""
    import json
    if isinstance(data, (str, bytes)) or hasattr(data, "__fspath__"):
        with open(data, encoding="utf-8") as fh:
            data = json.load(fh)
    snd = data.get("sender") or {}
    address = snd.get("address") or ""
    name = snd.get("name") or address
    official_ids = {a for v in OFFICIAL.values() for a in v["aliases"]}
    msgs = [Message("reader" if m.get("from") == "reader" else "other", m.get("text", ""))
            for m in sorted(data.get("messages", []), key=lambda m: m.get("n", 0))]
    ch = data.get("channel", "chat")
    return Conversation(
        channel=CHANNEL_MAP.get(ch, ch),
        messages=msgs,
        sender_label=name,
        sender_known=bool(snd.get("known_contact")),
        sender_official=norm(address).replace(" ", "") in official_ids,
        id=str(data.get("id", "")),
    )


def combine(*detectors):
    """Union the flags of several detectors (e.g. your MiniLM model + the rule layer).
    Scam type: first detector that returns something other than NONE/OTHER wins."""
    def _d(conv):
        flags, stype = set(), "NONE"
        for det in detectors:
            f, t = det(conv)
            flags |= set(f)
            if stype in ("NONE", "OTHER") and t not in ("NONE",):
                if stype == "NONE" or t != "OTHER":
                    stype = t
        return flags, stype
    return _d


# ----------------------------------------------------------------------------
# Slot extraction: facts taken from the conversation / catalog only
# ----------------------------------------------------------------------------
AMOUNT_RE = re.compile(r"\d{1,3}(?:[.\s]\d{3})*(?:,\d{1,2})?\s*(?:lei|ron|euro|eur|€)", re.I)
DOMAIN_RE = re.compile(r"(?<![@\w.-])((?:[a-z0-9-]+\.)+(?:ro|com|info|net|org|eu|xyz|top|online|site|click|ru|co))\b")
NAME_RE = re.compile(r"\b(?:Eu|Sunt),?\s+([A-ZĂÂÎȘȚ][a-zăâîșț]{2,})")


@dataclass
class Slots:
    subject: str = "Mesajul"
    org: Optional[str] = None
    org_phone: Optional[str] = None
    org_site: Optional[str] = None
    claim: Optional[str] = None
    amount: Optional[str] = None
    name: Optional[str] = None
    relation: Optional[str] = None
    contact: Optional[str] = None
    has_fake_link: bool = False
    mentions_card: bool = False


def extract_slots(conv: Conversation) -> Slots:
    other = [m.text for m in conv.messages if m.sender == "other"]
    raw = " ".join(other)
    n = norm(raw + " " + conv.sender_label)
    s = Slots()

    s.subject = "Apelul" if conv.channel == "call" else ("Conversația" if len(conv.messages) > 1 else "Mesajul")

    for org, info in OFFICIAL.items():
        if any(a in n for a in info["aliases"]):
            s.org, s.org_phone, s.org_site, s.claim = org, info["phone"], info["site"], org
            break
    if not s.claim:
        for key, display in GENERIC_CLAIMS:
            if key in n:
                s.claim = display
                break

    m = AMOUNT_RE.search(raw)
    s.amount = m.group(0).strip() if m else None

    s.has_fake_link = any(d not in OFFICIAL_DOMAINS for d in DOMAIN_RE.findall(norm(raw)))
    s.mentions_card = "card" in n

    nm = NAME_RE.search(raw)
    s.name = nm.group(1) if nm else None
    if re.search(r"\b(mami|mama|mamico|tati|tatico)\b[,!]", n) or re.search(r"\b(buna|salut|hei)\s+(mami|mama|tati|tata)\b", n):
        s.relation = "copilul dumneavoastră"
    elif re.search(r"\b(bunico|bunica|bunicule)\b", n):
        s.relation = "nepotul sau nepoata dumneavoastră"

    if conv.sender_known:
        s.contact = conv.sender_label
    return s


# ----------------------------------------------------------------------------
# Official-contact guard
# A warning may only offer a phone number, e-mail address or website that comes
# from the catalog above. Anything taken from the scam message, or invented by a
# model, is a hard failure: the scammer must never get his own channel repeated.
# ----------------------------------------------------------------------------
OFFICIAL_PHONE_DIGITS = {
    re.sub(r"\D", "", info["phone"]) for info in OFFICIAL.values() if info.get("phone")
}
# The catalog defines no official e-mail address. Extend this if one is ever added.
OFFICIAL_EMAILS: set[str] = set()

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
# A run that could be a phone number: optional +, digits with the usual separators.
PHONE_RE = re.compile(r"\+?\d[\d\s.\-/()xX]{4,}\d")


def _phone_digits(candidate: str) -> str:
    return re.sub(r"\D", "", candidate)


def _looks_like_phone(candidate: str) -> bool:
    """Keep sums ('10.000 lei'), dates and years from being read as phone numbers."""
    compact = re.sub(r"[\s.\-/()]", "", candidate)
    digits = _phone_digits(compact)
    if len(digits) < 5:
        return False
    return compact.startswith(("+", "00", "0")) or len(digits) >= 9


def contact_problems(text: str) -> list[str]:
    """Return every contact channel in `text` that is not in the official catalog."""
    problems = []
    for m in EMAIL_RE.finditer(text):
        if m.group(0).lower() not in OFFICIAL_EMAILS:
            problems.append(f"unofficial e-mail: {m.group(0)}")
    for m in PHONE_RE.finditer(text):
        candidate = m.group(0).strip()
        if _looks_like_phone(candidate) and _phone_digits(candidate) not in OFFICIAL_PHONE_DIGITS:
            problems.append(f"unofficial phone: {candidate}")
    for domain in DOMAIN_RE.findall(norm(text)):
        if domain not in OFFICIAL_DOMAINS:
            problems.append(f"unofficial site: {domain}")
    return problems


def assert_official_contacts(text: str) -> None:
    """Hard guarantee for template warnings: refuse to emit an unofficial contact.
    Raises explicitly (not via `assert`) so it also holds under `python -O`."""
    problems = contact_problems(text)
    if problems:
        raise AssertionError("warning names a contact channel outside the official catalog: "
                             + "; ".join(problems))


# ----------------------------------------------------------------------------
# Warning builder
# ----------------------------------------------------------------------------
@dataclass
class Warning:
    verdict: str
    scam_type: str
    headline: str
    why: str
    action: str
    ui_label: str
    keep: list[str] = field(default_factory=list)  # facts a rewrite must preserve

    @property
    def text(self) -> str:
        return f"{self.headline} {self.why} {self.action}"


def _join(items: list[str]) -> str:
    if len(items) <= 1:
        return "".join(items)
    return ", ".join(items[:-1]) + " și " + items[-1]


def _asks(f: set[str], s: Slots) -> list[str]:
    a = []
    if "RF_CODE_REQUEST" in f:
        a.append("un cod primit prin SMS")
    if "RF_DATA_REQUEST" in f:
        a.append("datele cardului" if s.mentions_card else "date personale")
    if "RF_PAYMENT_REQUEST" in f:
        a.append(f"o plată de {s.amount}" if s.amount else "o plată")
    if "RF_REMOTE_ACCESS" in f:
        a.append("să instalați un program de control de la distanță")
    return a


def _pressure(f: set[str]) -> Optional[str]:
    if "RF_URGENCY" in f:
        return "vă presează să acționați repede"
    if "RF_THREAT" in f:
        return "încearcă să vă sperie"
    return None


def _generic_why(f: set[str], s: Slots) -> str:
    clauses = []
    if "RF_TOO_GOOD" in f:
        clauses.append("vă promite bani sau un premiu")
    asks = _asks(f, s)
    if asks:
        clauses.append("vă cere " + _join(asks))
    if "RF_SUSPICIOUS_CONTACT" in f:
        clauses.append("folosește o adresă de internet falsă" if s.has_fake_link
                       else "nu vine de la un contact oficial")
    p = _pressure(f)
    if p:
        clauses.append(p)
    clauses = clauses[:3]
    if not clauses:
        return f"{s.subject} pare făcut ca să vă păcălească."
    body = _join(clauses)
    if s.claim:
        return f"{s.subject} se dă drept {s.claim}, dar {body}."
    return f"{s.subject} {body}."


def _generic_action(s: Slots, f: set[str], channel: str) -> str:
    if channel == "call":
        lead = ("Închideți apelul și nu dați niciun cod sau date personale"
                if f & {"RF_CODE_REQUEST", "RF_DATA_REQUEST"} else "Închideți apelul și nu dați nicio informație")
    elif "RF_PAYMENT_REQUEST" in f:
        lead = "Nu plătiți" + (" și nu apăsați pe adresă" if s.has_fake_link else "")
    elif s.has_fake_link:
        lead = "Nu apăsați pe adresă și nu completați nimic"
    else:
        lead = "Nu răspundeți și nu dați nicio informație"
    if s.org and s.org_phone:
        return f"{lead}; dacă vreți să verificați, sunați la {s.org_phone}, numărul oficial de la {s.org}."
    return (f"{lead}; dacă vreți să verificați, sunați dumneavoastră instituția "
            f"la un număr de pe documentele oficiale primite de la ea.")


def build_warning(conv: Conversation, scam_type: str, flags: set[str], verdict: str) -> Optional[Warning]:
    if verdict == "SAFE":
        return None
    s = extract_slots(conv)
    f = set(flags)
    headline = HEADLINE[verdict]
    why = action = None

    if scam_type == "BANK_IMPERSONATION":
        why = _generic_why(f, s)
        action = ("Nu apăsați pe adresă; sunați la numărul de pe spatele cardului." if s.has_fake_link
                  else "Nu răspundeți; sunați la numărul de pe spatele cardului.")

    elif scam_type == "FAMILY_EMERGENCY":
        who = s.name or s.relation or "o rudă"
        parts = []
        if "RF_NEW_NUMBER" in f:
            parts.append("vă scrie de pe un număr necunoscut")
        if "RF_PAYMENT_REQUEST" in f:
            parts.append(f"vă cere {s.amount}" if s.amount else "vă cere bani")
        if "RF_SECRECY" in f:
            parts.append("vă roagă să nu spuneți nimănui")
        if "RF_EMOTIONAL_PRESSURE" in f or "RF_URGENCY" in f:
            parts.append("vă grăbește")
        why = f"Cineva care spune că este {who} " + (_join(parts) if parts else "vă scrie de pe un număr necunoscut") + "."
        target = s.relation or "persoana respectivă"
        action = f"Nu trimiteți bani; sunați {target} la numărul pe care îl știți deja."

    elif scam_type == "ACCOUNT_TAKEOVER":
        subj = (f"Contul de WhatsApp al contactului „{s.contact}” pare preluat de altcineva"
                if s.contact else "Mesajul poate veni de la un cont piratat")
        extra = " și vă grăbește" if "RF_URGENCY" in f else ""
        why = f"{subj}, care vă cere un cod primit prin SMS{extra}."
        action = "Nu trimiteți codul; sunați persoana respectivă la numărul pe care îl aveți deja."

    elif scam_type == "TECH_SUPPORT":
        parts = []
        if "RF_THREAT" in f:
            parts.append("vă spune că aveți un virus")
        todo = []
        if "RF_REMOTE_ACCESS" in f:
            todo.append("să instalați un program de control de la distanță")
        if "RF_DATA_REQUEST" in f:
            todo.append("să intrați în contul de bancă")
        if todo:
            parts.append("vă cere " + " și ".join(todo))
        why = "Cineva care se dă drept suport tehnic " + (_join(parts) if parts else "vă sperie") + "."
        if "RF_REMOTE_ACCESS" in f and "RF_DATA_REQUEST" in f:
            action = "Închideți apelul și sunați acum la numărul de pe spatele cardului, ca să vă protejați contul."
        else:
            action = "Închideți apelul și nu instalați niciun program."

    elif scam_type == "MARKETPLACE":
        parts = []
        if "RF_DATA_REQUEST" in f:
            parts.append("vă cere datele cardului")
        if "RF_SUSPICIOUS_CONTACT" in f:
            parts.append("folosește o adresă de internet falsă")
        if "RF_URGENCY" in f:
            parts.append("vă grăbește")
        why = "Cumpărătorul spune că a plătit, dar " + (_join(parts) if parts else "cere ceva neobișnuit") + "."
        action = (f"Nu introduceți datele cardului; pentru plăți folosiți doar {s.org_site}." if s.org_site
                  else "Nu introduceți datele cardului pe adrese primite în conversație.")

    elif scam_type == "PRIZE_LOTTERY":
        who = f" de la {s.org}" if s.org else ""
        why = f"{s.subject} vă anunță că ați câștigat un premiu{who}, dar vine de la un număr necunoscut și nu pare oficial."
        tail = (f"; dacă vreți să verificați, sunați la {s.org_phone}, numărul oficial de la {s.org}."
                if s.org and s.org_phone else ".")
        action = "Nu răspundeți și nu dați date" + tail

    elif scam_type == "INVESTMENT":
        why = f"{s.subject} promite câștiguri sigure, dar câștigurile garantate nu există."
        action = "Nu trimiteți bani; vorbiți mai întâi cu o persoană de încredere din familie."

    elif scam_type == "ROMANCE":
        why = "O persoană cunoscută pe internet vă cere bani, deși nu v-ați întâlnit niciodată."
        action = "Nu trimiteți bani; povestiți unei persoane de încredere ce vi se cere."

    elif scam_type == "JOB_OFFER":
        why = f"{s.subject} promite bani ușori, dar vă cere o plată în avans."
        action = "Nu plătiți nimic în avans; un angajator real nu cere bani ca să vă angajeze."

    else:  # COURIER_FEE, AUTHORITY_IMPERSONATION, OTHER, ...
        why = _generic_why(f, s)
        action = _generic_action(s, f, conv.channel)

    keep = [x for x in (s.org_phone if s.org_phone and s.org_phone in action else None,
                        s.org_site if s.org_site and s.org_site in action else None,
                        s.amount if s.amount and s.amount in why else None,
                        s.name if s.name and s.name in why else None) if x]
    warning = Warning(verdict, scam_type, headline, why, action, UI_LABEL[verdict], keep)
    assert_official_contacts(warning.text)   # never ship an unofficial channel to the reader
    return warning


# ----------------------------------------------------------------------------
# Thread analysis: cumulative flags, first_alert, escalating warnings
# ----------------------------------------------------------------------------
Detector = Callable[[Conversation], tuple[set[str], str]]


def analyze(conv: Conversation, detector: Detector) -> dict:
    flags: set[str] = set()
    scam_type = "NONE"
    first_alert = None
    timeline = []
    prev_text = None

    for i in range(1, len(conv.messages) + 1):
        prefix = replace(conv, messages=conv.messages[:i])
        f, t = detector(prefix)
        flags |= set(f)
        if t != "NONE":
            scam_type = t
        score = risk_score(flags)
        v = verdict_for(score)
        if first_alert is None and score >= 25:
            first_alert = i
        if score >= 25:
            w = build_warning(prefix, scam_type, flags, v)
            if w and w.text != prev_text:
                timeline.append({"message": i, "risk_score": score, "verdict": v, "warning": w})
                prev_text = w.text

    score = risk_score(flags)
    v = verdict_for(score)
    return {
        "verdict": v,
        "scam_type": scam_type if v != "SAFE" else "NONE",
        "risk_score": score,
        "red_flags": sorted(flags),
        "first_alert": first_alert,
        "ui_label": UI_LABEL[v],
        "warning": timeline[-1]["warning"] if timeline else None,
        "timeline": timeline,
    }


# ----------------------------------------------------------------------------
# Style checks from the brief (used in tests, and by the LLM validator)
# ----------------------------------------------------------------------------
BANNED = re.compile(r"\b(phishing|url|link|malware|otp|credential\w*|token|spam|hack\w*|ransomware)\b", re.I)


def sentence_count(text: str) -> int:
    return len([x for x in re.split(r"(?<=[.!?])\s+", text.strip()) if x])


def style_problems(text: str) -> list[str]:
    p = []
    if sentence_count(text) > 3:
        p.append("more than 3 sentences")
    if BANNED.search(text):
        p.append("technical word")
    p.extend(contact_problems(text))   # unofficial phone / e-mail / site
    return p
