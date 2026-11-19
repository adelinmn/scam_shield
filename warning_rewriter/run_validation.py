"""
Runs the 11 sample scenarios from the brief through the pipeline.

The `stub_detector` below is ONLY test scaffolding (regex rules) so this file runs
standalone. Replace it with your MiniLM classifier: any function
    detector(conversation_prefix) -> (set_of_RF_codes, scam_type)
works. If your model only gives verdict/type (no flags), see the note in README below.
"""
import re
from scam_warnings import (Conversation, Message, analyze, norm, DOMAIN_RE,
                           OFFICIAL_DOMAINS, OFFICIAL, style_problems)

import sys, glob, os
from scam_warnings import load_conversation

import csv


def load_expected(path):
    out = {}
    with open(path, encoding="utf-8-sig", newline="") as fh:
        for r in csv.DictReader(fh):
            out[r["id"]] = (r["verdict"], r["scam_type"], int(r["risk_score"]),
                            int(r["first_alert"]) if r["first_alert"] else None,
                            set(filter(None, r["red_flags"].split(";"))))
    return out


# ---------------------------------------------------------------- stub detector
CLAIM = re.compile(r"banca dunarea|bancadunarea|curierexpres|megashop|anaf|suportul? tehnic|casa de pensii|politi")
RULES = {
 "RF_CODE_REQUEST": r"trimis din greseala un cod|mi-l poti trimite inapoi|(trimite|spune|citi)(ti)?-?mi codul|mi-l cit",
 "RF_REMOTE_ACCESS": r"anydesk|teamviewer|de la distanta",
 "RF_DATA_REQUEST": r"datele cardului|numarul cardului|\bpin\b|parola|\bcnp\b|contul de banca|confirm\w* datele|introduceti datele",
 "RF_PAYMENT_REQUEST": r"achitati|\btransfer\b|taxa de|depozit",
 "RF_NEW_NUMBER": r"numarul nou|numar nou",
 "RF_SECRECY": r"nu-i spune|nu spune nimanui|sa nu afle",
 "RF_TOO_GOOD": r"castigator|felicitari|ati castigat|va creste cu|garantat",
 "RF_URGENCY": r"urgent|\b24h\b|24 de ore|grabiti|expira|pana la \d|trebuie .{0,30} azi",
 "RF_THREAT": r"blocat|virusi|amenda|inchisoare",
 "RF_EMOTIONAL_PRESSURE": r"accident|spital|arestat",
}


def stub_detector(conv):
    text = norm(" ".join(m.text for m in conv.messages if m.sender == "other"))
    flags = {code for code, rx in RULES.items() if re.search(rx, text)}
    fake = any(d not in OFFICIAL_DOMAINS for d in DOMAIN_RE.findall(text))
    if fake:
        flags.add("RF_SUSPICIOUS_CONTACT")
    if CLAIM.search(text + " " + norm(conv.sender_label)) and not conv.sender_official or (fake and CLAIM.search(text)):
        flags.add("RF_IMPERSONATION")
    if "RF_NEW_NUMBER" in flags: t = "FAMILY_EMERGENCY"
    elif "RF_REMOTE_ACCESS" in flags or re.search(r"suportul? tehnic", text): t = "TECH_SUPPORT"
    elif "RF_CODE_REQUEST" in flags and "RF_IMPERSONATION" not in flags: t = "ACCOUNT_TAKEOVER"
    elif "piatamea" in norm(conv.sender_label) and flags: t = "MARKETPLACE"
    elif "curierexpres" in text and flags: t = "COURIER_FEE"
    elif "banca dunarea" in text and flags: t = "BANK_IMPERSONATION"
    elif re.search(r"anaf|casa de pensii", text): t = "AUTHORITY_IMPERSONATION"
    elif "megashop" in text and flags: t = "PRIZE_LOTTERY"
    else: t = "OTHER" if flags else "NONE"
    return flags, t


if __name__ == "__main__":
    from csv_detector import CsvDetector, default_csv_path, default_validation_dir
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    use_stub = "--stub" in sys.argv
    folder = args[0] if args else default_validation_dir()
    csv_path = args[1] if len(args) > 1 else default_csv_path()
    expected = load_expected(csv_path)
    detector = stub_detector if use_stub else CsvDetector(csv_path)
    print("detector:", "regex stub (--stub)" if use_stub else f"official CSV ({csv_path})")
    ok = True
    for path in sorted(glob.glob(os.path.join(str(folder), "V*.json"))):
        vid = os.path.basename(path)[:-5]
        v, t, score, fa, flags = expected[vid]
        r = analyze(load_conversation(path), detector)
        got = (r["verdict"], r["scam_type"], r["risk_score"], r["first_alert"], set(r["red_flags"]))
        match = got == (v, t, score, fa, flags)
        ok &= match
        print(f"\n=== {vid} {'OK' if match else 'MISMATCH'}  {r['verdict']} {r['scam_type']} score={r['risk_score']} first_alert={r['first_alert']}")
        if not match:
            print("   expected:", (v, t, score, fa, sorted(flags)), "\n   got:     ", (got[0], got[1], got[2], got[3], sorted(got[4])))
        for step in r["timeline"]:
            w = step["warning"]
            probs = style_problems(w.text)
            print(f"  [msg {step['message']}, {step['risk_score']}] {w.text}" + (f"   !! {probs}" if probs else ""))
            ok &= not probs
    print("\nALL 11 MATCH THE ANSWER KEY" if ok else "\nPROBLEMS FOUND")
