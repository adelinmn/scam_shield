"""Independent scam-type classification using the same local NLI model."""

from .conversation import Conversation, normalize_text
from .model import FlagClassifier


SCAM_TYPE_HYPOTHESES = {
    "BANK_IMPERSONATION": "Expeditorul se prezintă drept o bancă sau un angajat al băncii.",
    "COURIER_FEE": "Expeditorul cere plata unei taxe pentru livrarea unui colet.",
    "AUTHORITY_IMPERSONATION": "Expeditorul se prezintă drept reprezentantul unei autorități "
    "sau instituții publice.",
    "FAMILY_EMERGENCY": "Expeditorul pretinde că este o rudă sau un prieten aflat într-o urgență "
    "și cere ajutor.",
    "TECH_SUPPORT": "Expeditorul se prezintă drept suport tehnic și pretinde că dispozitivul "
    "destinatarului are o problemă.",
    "MARKETPLACE": "Expeditorul folosește pretextul unei tranzacții pe o platformă de vânzări "
    "online pentru a cere date sau bani.",
    "ACCOUNT_TAKEOVER": "Expeditorul încearcă să obțină un cod de verificare pentru a accesa "
    "contul altei persoane.",
    "INVESTMENT": "Expeditorul propune o investiție cu profit rapid sau garantat.",
    "ROMANCE": "Expeditorul pretinde că are o relație romantică cu destinatarul și îi cere bani.",
    "JOB_OFFER": "Expeditorul oferă un loc de muncă și solicită în schimb bani sau date personale.",
    "PRIZE_LOTTERY": "Expeditorul anunță că destinatarul a câștigat un premiu la o tombolă "
    "sau loterie.",
    "OTHER": "Expeditorul folosește un alt tip de înșelătorie.",
}


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
    scores = classifier.score_hypotheses(["\n".join(lines)], SCAM_TYPE_HYPOTHESES)[0]
    return max(scores, key=scores.__getitem__), scores
