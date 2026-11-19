import json
import unittest
from pathlib import Path

from scam_detector import ScamDetector
from scam_detector.conversation import parse_scenario
from scam_detector.flag_definitions import FLAG_DEFINITIONS
from scam_detector.rule_patterns import fold
from scam_detector.rule_types import TypeStrength
from scam_detector.rules import RuleContext, RuleEngine, RuleStatus
from scripts.validate import EXPECTED, compare, read_results


def scenario(*turns, sender_address=None, known_contact=False, sender_name=None):
    return {
        "id": "example",
        "channel": "sms",
        "sender": {"name": sender_name, "address": sender_address, "known_contact": known_contact},
        "messages": [
            {"n": index, "from": role, "text": text}
            for index, (role, text) in enumerate(turns, 1)
        ],
    }


def single(text, **sender):
    return scenario(("sender", text), **sender)


class DeterministicRulesTests(unittest.TestCase):
    def setUp(self):
        self.engine = RuleEngine()

    def inspect(self, data):
        parsed = parse_scenario(data)
        return self.engine.evaluate_flags(
            parsed.messages[-1], RuleContext(parsed.channel, parsed.sender, parsed.messages[:-1])
        )

    def evidence(self, data, scam_type):
        parsed = parse_scenario(data)
        return self.engine.evaluate_types(
            parsed.messages[-1], RuleContext(parsed.channel, parsed.sender, parsed.messages[:-1])
        )[scam_type]

    def test_every_flag_can_be_confirmed_by_behavior(self):
        cases = {
            "RF_CODE_REQUEST": "Spune-mi codul de verificare primit prin SMS.",
            "RF_REMOTE_ACCESS": "Instalați AnyDesk pentru a vă ajuta.",
            "RF_DATA_REQUEST": "Introdu numărul cardului în formular.",
            "RF_PAYMENT_REQUEST": "Achită taxa de procesare.",
            "RF_SUSPICIOUS_CONTACT": "CurierExpres: achită taxa pe curierexpres.ro.evil.com.",
            "RF_NEW_NUMBER": "Sunt fiul tău. Mi-am schimbat numărul.",
            "RF_SECRECY": "Nu-i spune lui tata despre transfer.",
            "RF_TOO_GOOD": "Investește și vei avea profit garantat fără risc.",
            "RF_IMPERSONATION": "Sunt de la BCR. Trimite-mi codul de verificare.",
            "RF_URGENCY": "Trimite banii chiar acum.",
            "RF_THREAT": "Contul va fi blocat dacă nu completați datele cardului.",
            "RF_EMOTIONAL_PRESSURE": "Dacă mă iubești, transferă banii astăzi.",
            "RF_CHANNEL_SWITCH": "Hai pe Telegram să discutăm.",
        }
        self.assertEqual(cases.keys(), FLAG_DEFINITIONS.keys())
        for code, text in cases.items():
            with self.subTest(code=code):
                self.assertEqual(self.inspect(single(text))[code], RuleStatus.CONFIRMED)

    def test_negation_is_local_and_an_explicit_request_wins(self):
        for text, flag in (
            ("Nu trimite nimănui codul.", "RF_CODE_REQUEST"),
            ("Nu-l instala: AnyDesk este pentru asistență.", "RF_REMOTE_ACCESS"),
            ("Nu comunicați PIN-ul.", "RF_DATA_REQUEST"),
        ):
            with self.subTest(text=text):
                self.assertEqual(self.inspect(single(text))[flag], RuleStatus.REJECTED)
        self.assertEqual(
            self.inspect(single("Nu trimite codul altora. Trimite-mi-l mie."))["RF_CODE_REQUEST"],
            RuleStatus.CONFIRMED,
        )

    def test_official_hostname_matching_and_phone_claims(self):
        for url, expected in (
            ("https://www.bancadunarea.ro/verifica", RuleStatus.REJECTED),
            ("https://bancadunarea.ro.evil.com/verifica", RuleStatus.CONFIRMED),
            ("https://bancadunarea.ro@evil.com/verifica", RuleStatus.CONFIRMED),
        ):
            with self.subTest(url=url):
                result = self.inspect(single(f"Banca Dunărea: accesează {url} pentru verificare."))
                self.assertEqual(result["RF_SUSPICIOUS_CONTACT"], expected)
        fraud = self.inspect(single("Banca Dunărea: sunați la numărul oficial 0800 999 100."))
        self.assertEqual(fraud["RF_SUSPICIOUS_CONTACT"], RuleStatus.CONFIRMED)
        warning = self.inspect(single("Banca Dunărea: sunați la 0800 100 200."))
        self.assertEqual(warning["RF_SUSPICIOUS_CONTACT"], RuleStatus.REJECTED)
        unknown = self.inspect(single("Hei, sunt aici.", sender_address="0712 345 678"))
        self.assertNotEqual(unknown["RF_SUSPICIOUS_CONTACT"], RuleStatus.CONFIRMED)

    def test_catalog_compares_the_claimed_organizations_sender_number(self):
        claim = "Vă scriu din partea ANAF. Bună ziua."
        for phone, expected in (
            ("+40 712 345 678", RuleStatus.CONFIRMED),
            ("0040 31 403 91 60", RuleStatus.REJECTED),
            ("tel:+40 31 403 91 60", RuleStatus.REJECTED),
        ):
            with self.subTest(phone=phone):
                verdict = self.inspect(single(claim, sender_address=phone, known_contact=True))
                self.assertEqual(verdict["RF_SUSPICIOUS_CONTACT"], expected)
        missing = self.inspect(single("Sunt de la PiațaMea. Telefon: 0712 345 678.", sender_address="0712 345 678"))
        self.assertEqual(missing["RF_SUSPICIOUS_CONTACT"], RuleStatus.UNKNOWN)
        customer = self.inspect(single("Sunt client de la ANAF.", sender_address="0712 345 678"))
        self.assertEqual(customer["RF_SUSPICIOUS_CONTACT"], RuleStatus.UNKNOWN)
        forwarded = self.inspect(single("Am primit un mesaj din partea ANAF.", sender_address="0712 345 678"))
        self.assertEqual(forwarded["RF_SUSPICIOUS_CONTACT"], RuleStatus.UNKNOWN)

    def test_catalog_checks_link_and_phone_against_the_attributed_brand(self):
        for text in (
            "ANAF: detalii pe portal-exemplu.test.",
            "ANAF: portalul nostru este www.megashop.ro.",
            "ANAF: Telefon de verificare. Telefon: 0712 345 678.",
        ):
            with self.subTest(text=text):
                status = self.inspect(single(text))["RF_SUSPICIOUS_CONTACT"]
                self.assertEqual(status, RuleStatus.CONFIRMED)
        neutral = self.inspect(single("Am fost la ANAF azi. Articolul este pe revista.test."))
        self.assertEqual(neutral["RF_SUSPICIOUS_CONTACT"], RuleStatus.UNKNOWN)
        bare_link = self.inspect(single("https://anaf-verificare-exemplu.test"))
        self.assertEqual(bare_link["RF_SUSPICIOUS_CONTACT"], RuleStatus.CONFIRMED)
        self.assertNotEqual(bare_link["RF_IMPERSONATION"], RuleStatus.CONFIRMED)

    def test_catalog_uses_earlier_sender_claim_but_ignores_reader_claim(self):
        text = "Acesta este site-ul nostru: portal-exemplu.test."
        accepted = self.inspect(scenario(("sender", "Sunt de la ANAF."), ("sender", text)))
        ignored = self.inspect(scenario(("reader", "Sunt de la ANAF."), ("sender", text)))
        self.assertEqual(accepted["RF_SUSPICIOUS_CONTACT"], RuleStatus.CONFIRMED)
        self.assertEqual(ignored["RF_SUSPICIOUS_CONTACT"], RuleStatus.UNKNOWN)

    def test_normalization_and_unrelated_words(self):
        self.assertEqual(fold("  BĂNCII, băncii!  ŞTIŢI 😊 "), "bancii, bancii! stiti 😊")
        self.assertEqual(self.inspect(single("Un continent îndepărtat."))["RF_CODE_REQUEST"], RuleStatus.UNKNOWN)
        evidence = self.evidence(single("Am fotografiat un continent îndepărtat."), "ACCOUNT_TAKEOVER")
        self.assertEqual(evidence.strength, TypeStrength.NONE)

    def test_reader_and_future_messages_do_not_supply_flags(self):
        parsed = parse_scenario(scenario(
            ("sender", "Salut!"),
            ("reader", "Transferă banii acum și trimite codul."),
            ("sender", "Mami, acesta e noul meu număr."),
        ))
        context = RuleContext(parsed.channel, parsed.sender, parsed.messages[1:])
        statuses = self.engine.evaluate(parsed.messages[0], context)
        self.assertNotIn(RuleStatus.CONFIRMED, statuses.values())
        self.assertNotIn(RuleStatus.CONFIRMED, self.engine.evaluate(parsed.messages[1]).values())

    def test_specific_types_have_strong_behavioral_evidence(self):
        examples = {
            "BANK_IMPERSONATION": single("Sunt de la BCR. Spune-mi codul de verificare pentru cont."),
            "COURIER_FEE": single("CurierExpres: Coletul este reținut. Achită taxa de livrare."),
            "AUTHORITY_IMPERSONATION": single("Vă sun de la ANAF. Completați CNP-ul pentru rambursare."),
            "FAMILY_EMERGENCY": scenario(
                ("sender", "Mami, am un număr nou."),
                ("reader", "Ești tu?"),
                ("sender", "Trimite-mi banii azi, am o problemă."),
            ),
            "TECH_SUPPORT": single("Sunt de la suportul tehnic. Instalați AnyDesk."),
            "MARKETPLACE": single("Sunt cumpărătorul de pe OLX. Am plătit. Introdu datele cardului pentru a încasa banii."),
            "ACCOUNT_TAKEOVER": single("Ți-am trimis din greșeală codul SMS. Trimite-mi-l înapoi."),
            "INVESTMENT": single("Depune 500 lei într-o investiție cu profit garantat."),
            "ROMANCE": scenario(
                ("sender", "Mi-e dor de tine, dragostea mea."),
                ("sender", "Trimite-mi bani pentru biletul de avion."),
            ),
            "JOB_OFFER": single("Pentru acest job de acasă achită taxa de activare."),
            "PRIZE_LOTTERY": single("Ai câștigat un voucher la tombolă. Răspunde cu DA."),
        }
        for category, data in examples.items():
            with self.subTest(category=category):
                evidence = self.evidence(data, category)
                self.assertEqual(evidence.strength, TypeStrength.STRONG)
                self.assertTrue(evidence.reasons)

    def test_weak_conflicting_and_fallback_evidence(self):
        bank = self.evidence(single("Am fost azi la bancă."), "BANK_IMPERSONATION")
        self.assertEqual(bank.strength, TypeStrength.WEAK)
        romance = self.evidence(single("Te iubesc, mama."), "ROMANCE")
        self.assertTrue(romance.contradicted)
        receipt = self.evidence(single("Coletul va fi livrat azi, ramburs: 0 lei."), "COURIER_FEE")
        self.assertNotEqual(receipt.strength, TypeStrength.STRONG)
        fallback = self.evidence(single("Trimite-mi bani pentru chirie."), "OTHER")
        self.assertTrue(fallback.supported)


class AccountAlarmClassifier:
    def classify(self, text):
        return dict.fromkeys(FLAG_DEFINITIONS, 0.0) | {
            "RF_CODE_REQUEST": 1.0,
            "RF_IMPERSONATION": 1.0,
            "RF_SECRECY": 1.0,
        }

    def score_hypotheses(self, texts, hypotheses):
        return [
            {"ACCOUNT_TAKEOVER": 0.99, "AUTHORITY_IMPERSONATION": 0.95, "BANK_IMPERSONATION": 0.95}
            for _ in texts
        ]


class HybridIntegrationTests(unittest.TestCase):
    def test_known_benign_evidence_blocks_even_maximal_neural_scores(self):
        class OverconfidentClassifier:
            def classify(self, text):
                return dict.fromkeys(FLAG_DEFINITIONS, 1.0)

        detector = ScamDetector(OverconfidentClassifier())
        otp = json.loads(Path("testing_set/input/R001.json").read_bytes())
        result = detector.analyze_scenario(otp)
        self.assertEqual((result["verdict"], result["risk_score"], result["red_flags"]), ("SAFE", 0, []))
        self.assertEqual(result["context_flags"], ["INFO_BANK_CONTEXT", "INFO_OTP_NOTICE"])
        for text in ("La ce oră ieși pe afară?", "La ce ora iesi pe afara", "🙂", ""):
            with self.subTest(text=text):
                result = detector.analyze_scenario(single(text))
                self.assertEqual((result["verdict"], result["red_flags"], result["context_flags"]), ("SAFE", [], []))

    def test_catalog_match_requires_known_contact_name_and_number(self):
        detector = ScamDetector(AccountAlarmClassifier())
        for name, address, known, matches_catalog in (
            ("ANAF", "0040 31 403 91 60", True, True),
            ("Banca Dunarea", "tel:+40 800 100 200", True, True),
            ("ANAF", "031 403 91 60", False, False),
            ("ANAF Suport", "031 403 91 60", True, False),
            (None, "031 403 91 60", True, False),
            ("ANAF", "0800 100 200", True, False),
        ):
            with self.subTest(name=name, address=address, known=known):
                result = detector.analyze_scenario(single(
                    "Documentul se regăsește în arhivă.",
                    sender_name=name, sender_address=address, known_contact=known,
                ))
                status = result["rule_evidence"][1]["RF_CODE_REQUEST"]
                if matches_catalog:
                    self.assertEqual(status, RuleStatus.REJECTED)
                    self.assertEqual((result["scam_type"], result["risk_score"], result["red_flags"]), ("NONE", 0, []))
                else:
                    self.assertEqual(status, RuleStatus.UNKNOWN)
                    self.assertIn("RF_CODE_REQUEST", result["red_flags"])

    def test_catalog_match_preserves_code_requests_and_mismatched_links(self):
        detector = ScamDetector(AccountAlarmClassifier())
        sender = {"sender_name": "ANAF", "sender_address": "031 403 91 60", "known_contact": True}
        result = detector.analyze_scenario(single("Trimite-mi codul primit prin SMS.", **sender))
        self.assertIn("RF_CODE_REQUEST", result["red_flags"])
        self.assertNotIn("RF_IMPERSONATION", result["red_flags"])
        self.assertEqual(result["scam_type"], "ACCOUNT_TAKEOVER")

        result = detector.analyze_scenario(single("Accesează portal-exemplu.test.", **sender))
        self.assertEqual(result["rule_evidence"][1]["RF_SUSPICIOUS_CONTACT"], RuleStatus.CONFIRMED)
        self.assertIn("RF_IMPERSONATION", result["red_flags"])

    def test_catalog_match_does_not_turn_a_payment_request_into_identity_fraud(self):
        detector = ScamDetector(AccountAlarmClassifier())
        result = detector.analyze_scenario(single(
            "Achitați taxa de procesare.", sender_name="ANAF",
            sender_address="031 403 91 60", known_contact=True,
        ))
        self.assertEqual(result["red_flags"], ["RF_PAYMENT_REQUEST"])
        self.assertEqual(result["scam_type"], "OTHER")
        for code in ("BANK_IMPERSONATION", "AUTHORITY_IMPERSONATION", "ACCOUNT_TAKEOVER"):
            with self.subTest(code=code):
                self.assertTrue(result["scam_type_rule_evidence"][code]["contradicted"])

    def test_all_official_cases_in_rules_only_mode(self):
        detector = ScamDetector(None, mode="rules-only")
        expected = read_results(EXPECTED)
        actual = {}
        for scenario_id in expected:
            path = EXPECTED.parent / "validation_set" / f"{scenario_id}.json"
            result = detector.analyze_scenario(json.loads(path.read_bytes()))
            result["red_flags"].sort()
            actual[scenario_id] = result
        comparison = compare(expected, actual)
        self.assertEqual(comparison["full_matches"], len(expected), comparison["scenarios"])
