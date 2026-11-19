"""
Tests for the official-contact guard (scam_warnings.contact_problems / assert_official_contacts).

Run from this folder:

    python -m unittest test_contact_guard -v
"""
import unittest

from scam_warnings import (contact_problems, assert_official_contacts, style_problems,
                           analyze, load_conversation, OFFICIAL)
from csv_detector import CsvDetector, default_validation_dir
from run_validation import stub_detector


class TestContactGuard(unittest.TestCase):
    def test_official_phone_allowed(self):
        for info in OFFICIAL.values():
            if info["phone"]:
                self.assertEqual(contact_problems(f"sunați la {info['phone']}."), [])

    def test_official_phone_reformatted_is_still_official(self):
        self.assertEqual(contact_problems("sunați la 0800-100-200."), [])

    def test_official_site_allowed(self):
        self.assertEqual(contact_problems("folosiți doar piatamea.ro."), [])

    def test_unofficial_phone_rejected(self):
        for bad in ("+40 722 555 552", "0722 555 552", "0740.123.456", "+40 7xx xxx 552"):
            self.assertTrue(contact_problems(f"Sunați la {bad}."), bad)

    def test_unofficial_phone_raises(self):
        with self.assertRaises(AssertionError):
            assert_official_contacts("Atenție, pare o țeapă! Sunați la 0722 555 552.")

    def test_unofficial_email_rejected(self):
        self.assertTrue(contact_problems("scrieți la notificari@anaf-rambursari.net."))
        self.assertTrue(contact_problems("scrieți la ajutor@banca-dunarea-securitate.com."))

    def test_unofficial_site_rejected(self):
        self.assertTrue(contact_problems("intrați pe bancadunarea-securitate.com."))

    def test_amounts_are_not_phones(self):
        for amount in ("1.850 lei", "10.000 lei", "125.000 lei", "2,99 lei", "3.500 lei"):
            self.assertEqual(contact_problems(f"vă cere {amount}."), [], amount)

    def test_style_problems_includes_contact_violations(self):
        self.assertTrue(style_problems("Atenție, pare o țeapă! Sunați la 0722 555 552."))
        self.assertFalse(style_problems("Atenție, pare o țeapă! Sunați la 0800 100 200."))

    def test_validation_warnings_stay_official(self):
        """The real guarantee: every template warning for V01-V11 passes the guard."""
        detector = CsvDetector()
        for path in sorted(default_validation_dir().glob("V*.json")):
            r = analyze(load_conversation(path), detector)
            for step in r["timeline"]:
                self.assertEqual(contact_problems(step["warning"].text), [], path.name)

    def test_stub_detector_warnings_stay_official(self):
        for path in sorted(default_validation_dir().glob("V*.json")):
            r = analyze(load_conversation(path), stub_detector)
            for step in r["timeline"]:
                self.assertEqual(contact_problems(step["warning"].text), [], path.name)


if __name__ == "__main__":
    unittest.main(verbosity=2)
