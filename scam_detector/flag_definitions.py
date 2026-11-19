"""Official scoring weights and editable Romanian NLI hypotheses."""

from dataclasses import dataclass


@dataclass(frozen=True)
class FlagDefinition:
    points: int
    description: str


FLAG_DEFINITIONS = {
    "RF_CODE_REQUEST": FlagDefinition(
        35,
        "Expeditorul solicită destinatarului să dezvăluie sau să trimită un cod de "
        "autentificare, SMS, OTP sau din aplicație.",
    ),
    "RF_REMOTE_ACCESS": FlagDefinition(
        35,
        "Expeditorul cere instalarea sau utilizarea unui program pentru a controla "
        "de la distanță dispozitivul destinatarului.",
    ),
    "RF_DATA_REQUEST": FlagDefinition(
        30,
        "Expeditorul solicită date sensibile precum numărul cardului, PIN, parolă, "
        "CNP, fotografie de identitate sau autentificare bancară.",
    ),
    "RF_PAYMENT_REQUEST": FlagDefinition(
        25,
        "Expeditorul cere efectuarea unui transfer de bani, plata unei taxe, "
        "depunerea unui avans sau predarea unei sume.",
    ),
    "RF_SUSPICIOUS_CONTACT": FlagDefinition(
        25,
        "Mesajul utilizează o adresă de internet, o adresă de e-mail sau un număr "
        "de contact neoficial pentru organizația pretinsă.",
    ),
    "RF_NEW_NUMBER": FlagDefinition(
        20,
        "O persoană care contactează destinatarul de pe un număr necunoscut pretinde "
        "că este un membru al familiei sau un prieten cu număr nou.",
    ),
    "RF_SECRECY": FlagDefinition(
        20,
        "Expeditorul cere destinatarului să păstreze conversația secretă sau să nu "
        "verifice informațiile cu alte persoane.",
    ),
    "RF_TOO_GOOD": FlagDefinition(
        20,
        "Expeditorul promite un premiu, o rambursare, profit garantat sau câștiguri "
        "neobișnuit de avantajoase.",
    ),
    "RF_IMPERSONATION": FlagDefinition(
        15,
        "Expeditorul pretinde că reprezintă o bancă, o companie, poliția, o autoritate "
        "publică sau un serviciu de suport.",
    ),
    "RF_URGENCY": FlagDefinition(
        15,
        "Expeditorul pune presiune asupra destinatarului să acționeze imediat sau "
        "înaintea unui termen-limită scurt.",
    ),
    "RF_THREAT": FlagDefinition(
        15,
        "Expeditorul invocă blocarea unui cont, o amendă, consecințe legale, un virus "
        "sau un alt pericol pentru a provoca teamă.",
    ),
    "RF_EMOTIONAL_PRESSURE": FlagDefinition(
        10,
        "Expeditorul folosește frica, iubirea, mila, vinovăția sau panica pentru a "
        "influența decizia destinatarului.",
    ),
    "RF_CHANNEL_SWITCH": FlagDefinition(
        10,
        "Expeditorul solicită mutarea conversației către o altă aplicație sau un alt "
        "canal de comunicare.",
    ),
}

THRESHOLDS = dict.fromkeys(FLAG_DEFINITIONS, 0.75)
