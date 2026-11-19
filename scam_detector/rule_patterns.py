"""Romanian text patterns shared by the deterministic rules."""

import re
import unicodedata


_DASHES = str.maketrans("‐‑‒–—", "-----")


def fold(text: str) -> str:
    decomposed = unicodedata.normalize("NFKD", text.casefold().translate(_DASHES))
    return " ".join("".join(c for c in decomposed if not unicodedata.combining(c)).split())


def pattern(body: str) -> re.Pattern:
    return re.compile(rf"(?<!\w)(?:{body})(?!\w)")


TERMS = {
    "bank": pattern(
        r"banca|bancii|banci|bancar[a-z]*|bcr|brd|bt|ing|raiffeisen|revolut|antifrauda"
        r"|tranzacti[ei] suspecte|plat[ai] neautorizat[ae]"
    ),
    "courier": pattern(r"curier[a-z]*|colet[a-z]*|awb|tracking|sameday|cargus|dpd|dhl|gls|ramburs|livrare"),
    "authority": pattern(
        r"anaf|fisc[a-z]*|casa de pensii|pensi[aei][a-z]*|politi[a-z]*|parchet|procuror|primari[a-z]*"
        r"|minister[a-z]*|guvern[a-z]*|autoritat[a-z]*|instituti[ae] public[a-z]*|amend[aei]"
    ),
    "family": pattern(
        r"mam[ai]|tat[ai]|taticule|fiul tau|fiica ta|fiule|fiu|fiica|copil[a-z]*|baiatul tau|fata ta"
        r"|bunic[a-z]*|nepot[a-z]*|nepoat[a-z]*|frat[a-z]*|sor[a-z]*|sot[a-z]*|rud[a-z]*|familie"
    ),
    "identity": pattern(r"sunt|lucrez|va sun|va scriu|vorbesc|suna[mti]*|reprezint|de la|in numele"),
    "friend": pattern(r"prieten[a-z]*|vecin[a-z]*|sunt eu"),
    "new_number": pattern(
        r"numar(?:ul)? (?:meu )?nou|alt numar|schimbat numarul|telefonul (?:s-a stricat|stricat)"
        r"|stricat telefonul|salveaza noul numar"
    ),
    "emergency": pattern(
        r"accident[a-z]*|spital[a-z]*|urgent[a-z]*|am o problema|operati[aei]|m-am lovit"
        r"|am ramas blocat"
    ),
    "tech": pattern(
        r"suport(?:ul)? (?:tehnic|it)|asistenta tehnica|helpdesk|microsoft|windows|apple|google"
        r"|antivirus|malware"
    ),
    "remote": pattern(
        r"anydesk|teamviewer|rustdesk|remote desktop|acces(?:ul)? (?:de )?la distanta"
        r"|control(?:ul)? la distanta|acces(?:ul)? la (?:calculator|dispozitiv|telefon)"
        r"|partaj[a-z]* ecranul"
    ),
    "market": pattern(
        r"olx|facebook marketplace|marketplace|piata\s*mea|cumparator[a-z]*|vanzator[a-z]*|anunt[a-z]*"
        r"|livrare sigura|protectia cumparatorului|biciclet[a-z]*"
    ),
    "payout": pattern(
        r"primit?i banii|primi(?:ti)? plata|incasa(?:ti)?|am platit|plata (?:a fost )?efectuata"
        r"|banii (?:sunt|vor fi) (?:trimisi|transferati)"
    ),
    "account": pattern(r"cont(?:ul|ului|uri)?|autentific[a-z]*|conect[a-z]*|login|parol[a-z]*|sesiun[a-z]*"),
    "code": pattern(
        r"cod(?:ul)?(?: [a-z]+){0,3} (?:de (?:verificare|confirmare|autentificare|acces|conectare|securitate|\d+ cifre|(?:sase|patru) cifre)|(?:prin )?sms)"
        r"|otp|cod(?:ul)?"
    ),
    "data": pattern(
        r"cvv|cvc|pin(?:ul)?|cnp(?:ul)?|parol[aei][a-z]*|(?:datele|numarul) (?:complete ale )?cardului"
        r"|(?:serie|numar)[a-z ]{0,12}buletin[a-z]*"
        r"|(?:fotografie|poza|copie)[a-z ]{0,20}(?:act[a-z]*|buletin[a-z]*)|date[a-z]* de autentificare"
        r"|date[a-z]* (?:bancare|sensibile)|(?:datele|numarul) card(?:ului|ului bancar)?"
    ),
    "money": pattern(
        r"bani[i]?|suma|lei|eur|euro|transfer[a-z]*|tax[a-z]*|avans[a-z]*|depozit[a-z]*|garanti[a-z]*"
        r"|plata|comision[a-z]*|numerar"
    ),
    "investment": pattern(
        r"invest[a-z]*|randament[a-z]*|crypto|criptomonede|bitcoin|ethereum|forex|trading|broker[a-z]*"
        r"|actiuni|portofel crypto|profit[a-z]*"
    ),
    "returns": pattern(
        r"profit(?:ul)? (?:rapid |sigur )?garantat|randament[a-z]* garantat"
        r"|castig[a-z]* (?:sigur[a-z]*|garantat[a-z]*)|fara risc(?:uri)?"
        r"|dubl[a-z]* (?:banii|investitia)|venit[a-z]* garantat|bani fara efort"
    ),
    "romance": pattern(
        r"iubir[a-z]*|te iubesc|dragostea mea|iubit[a-z]*|partener[a-z]* romantic[a-z]*|suflet pereche"
        r"|vreau sa fim impreuna|draga mea|dragul meu|scump[ao]|scumpule|dor de tine|indragostit[a-z]*"
    ),
    "job": pattern(
        r"job[a-z]*|angaj[a-z]*|recrut[a-z]*|salariu[a-z]*|munca de acasa|part[ -]time|task[a-z]*"
        r"|sarcin[a-z]*|like[ -]?uri|review[ -]?uri|comision[a-z]*"
    ),
    "tasks": pattern(
        r"task[a-z]*|sarcin[a-z]*|like[ -]?uri|review[ -]?uri|recenzi[a-z]*|rating|abon[ae][a-z]*"
        r"|vizualizari"
    ),
    "prize": pattern(r"premi[a-z]*|tombol[a-z]*|loteri[a-z]*|jackpot|voucher[a-z]*|concurs[a-z]*|recompens[a-z]*"),
    "winner": pattern(
        r"(?:ai|ati|a[st]i fost) (?:fost |ales )?castig[a-z]*|ales[a-z]* castigator[a-z]*"
        r"|esti castigator[a-z]*|revendic[a-z]* premi[a-z]*"
    ),
    "urgency": pattern(
        r"urgent[a-z]*|imediat|chiar acum|(?:plateste|platiti|achita(?:ti)?|trimite(?:ti)?) acum"
        r"|in (?:urmatoarea ora|\d+\s*(?:de )?(?:h|ore|min[utec]*))"
        r"|pana (?:la (?:\d+|[a-z]+)|azi|astazi|maine)|azi|astazi|grab[a-z]*va|grabeste te|inainte de"
        r"|expir[a-z]*|ultima sansa|altfel pierzi"
    ),
    "threat": pattern(
        r"(?:card[a-z]*|cont[a-z]*|acces[a-z]*) (?:a fost |este |va fi )?(?:blocat[a-z]*|suspendat[a-z]*)"
        r"|blocat temporar|deblocare|(?:vei|veti) (?:pierde|primi amenda|fi sanctionat[a-z]*)"
        r"|(?:amenda|sanctiuni) (?:daca|pentru neplata)|risc de inchisoare|consecinte legale"
        r"|(?:infect[a-z]* (?:cu )?|trimite |are |are un )viru[sz][a-z]*|dispozitiv compromis"
        r"|pierde[a-z]* accesul"
    ),
    "secrecy": pattern(
        r"nu(?:[ -]i)? (?:spune|spuneti|zice|ziceti) (?:nimanui|lui |mamei|tatalui|familiei)[a-z ]*"
        r"|tine(?:ti)? (?:asta )?intre noi|pastrea[zz][a-z]* (?:asta )?secret[a-z]*|sa nu afle"
        r"|ramane intre noi|nu (?:verifica|verificati) cu|nu suna(?:ti)? la (?:banca|politie)"
        r"|nu discuta(?:ti)? cu (?:politia|familia)"
    ),
    "emotion": pattern(
        r"am facut (?:un )?accident|sunt la spital|nu ma lasa singur[a-z]*|sunt disperat[a-z]*"
        r"|daca ma iubesti|numai tu ma poti salva|mi[ -]e frica|nu stiu ce sa fac"
        r"|am nevoie urgent[a-z]* de ajutor"
    ),
    "channel": pattern(
        r"(?:hai|scrie(?:ti)?[ -]mi|mutam discutia|continuam|vorbeste cu mine) (?:pe|in) (?:telegram|whatsapp|signal|messenger|alta aplicatie)"
        r"|contactea[zz][a-z]*[ -]ma pe alt numar|nu mai discutam aici|intr[a-z]* pe chatul privat"
    ),
    "benefit": pattern(
        r"rambursar[a-z]*|creste cu|majorar[a-z]*|crester[a-z]*|benefici[a-z]*|profit[a-z]*"
        r"|castig[a-z]*"
    ),
    "conditional_benefit": pattern(
        r"ca sa nu (?:pier[zdt][a-z]*|ratezi)|pentru a (?:primi|incasa|revendica)|in schimb"
        r"|conditionat[a-z]*"
    ),
    "generic_data": pattern(
        r"confirm[a-z]* (?:datele|identitatea)|datele (?:dumneavoastra|tale)"
        r"|actualiza[a-z]* dosar[a-z]*"
    ),
    "risk_other": pattern(
        r"donati[a-z]*|caritab[a-z]*|chiri[a-z]*|locuint[a-z]*|utilitat[a-z]*|datori[a-z]*"
        r"|public[a-z]* fotografi[a-z]*"
    ),
}

ACTIONS = {
    "share": pattern(
        r"(?:re)?trimite(?:ti)?|trimiti|spune(?:ti)?|comunic[a-z]*|citi(?:ti)?|citeste|"
        r"da(?:ti)?[ -]mi|introdu(?:c[a-z]*)?|completea[zz][a-z]*|completati|furni[sz][a-z]*|"
        r"transmit[a-z]*|redirection[a-z]*|scrie(?:ti)?|confirmati"
    ),
    "pay": pattern(
        r"achit[a-z]*|plateste|platiti|transfera(?:ti)?|depune(?:ti)?|vireaza|virati|preda(?:ti)?"
        r"|(?:fa|faceti|faci)(?:[ -]mi)? (?:tu )?un transfer|trimite(?:ti)?"
    ),
    "remote": pattern(
        r"instalea[zz][a-z]*|instala(?:ti)?|permite(?:ti)?|ofera|oferiti|partajea[zz][a-z]*|partajati"
        r"|da(?:ti)?[ -]mi acces|deschideti|deschide"
    ),
    "follow": pattern(
        r"accesea[zz][a-z]*|accesati|apas[a-z]*|deschide(?:ti)?|intra(?:ti)?|conectea[zz][a-z]*"
        r"|conectati|autentifica(?:ti)?|verifica(?:ti)?|foloseste|folositi|raspunde(?:ti)?"
        r"|revendic[a-z]*|suna(?:ti)?"
    ),
}

_CLAUSE = re.compile(r"[.!?;](?=\s|$)|(?:,\s*|\s+)(?:dar|insa|totusi)\s+")
_NEGATION = re.compile(
    r"\b(?:nu|niciodata|fara sa|evita(?:ti)? sa)[ -]+"
    r"(?:(?:i|il|le|l|mi|ni|te|va|mai|trebuie|sa|o sa|rog)\b[ -]*){0,6}$"
)
_PRONOUN = re.compile(r"\b(?:mi[ -](?:l|le)|ni[ -](?:l|le)|il|l[ -]mi|le|inapoi)\b")
OTP_NOTICE = pattern(r"cod(?:ul)?(?: [a-z]+){0,6} (?:este|e|pentru):?\s*\d{4,8}|(?:otp|cod de (?:verificare|confirmare)):?\s*\d{4,8}")
NO_PAYMENT = pattern(
    r"ramburs\s*:\s*0(?:[,.]0+)?\s*(?:lei|ron)|fara (?:ramburs|plata)|"
    r"am primit plata|am platit(?: deja)?|plata primita"
)
DELIVERY_NOTICE = pattern(
    r"(?:colet[a-z]*|pachet[a-z]*|livrare[a-z]*|awb).{0,70}"
    r"(?:va fi livrat|se livreaza|a fost livrat|ajunge|este in tranzit|interval|in procesare|a plecat din depozit)"
    r"|(?:va fi livrat|a fost livrat).{0,45}(?:azi|maine|intre)"
)
SOCIAL = re.compile(
    r"^(?:(?:hei|salut|buna(?: ziua)?|hello)[ ,!]+)?(?:la ce ora (?:iesi|vii|ajungi|pleci|ne vedem|mergem)|"
    r"cand (?:iesi|vii|ajungi|pleci|ne vedem)|(?:ne vedem|iesim|bem o cafea|"
    r"mai (?:este|e) (?:disponibil|valabil)[a-z]*|pot sa vin sa (?:o vad|il vad)|"
    r"ce mai faci|cum esti|ce faci|am (?:fost|trecut) azi (?:pe )?la banca|"
    r"te iubesc|mi[ -]e dor|multumesc|mersi|perfect|ok|bine|salut|buna|buna ziua)\b).{0,85}$"
)
PAYMENT_ACTION = {key: pattern(body) for key, body in {
    "login": r"(?:intra(?:ti)?|conect[a-z]*|autentific[a-z]*) (?:in |la )?(?:cont[a-z]*|aplicati[a-z]*)",
    "deadline": r"in \d+\s*(?:h|ore|min[utec]*)|pana la (?:\d+|maine|azi|astazi)|expir[a-z]*|ultima sansa|grab[a-z]*",
    "support": r"(?:verific[a-z]*|repar[a-z]*|ajut[a-z]*) (?:noi |de la distanta )?(?:calculatorul|dispozitivul|contul|sistemul)",
}.items()}


def matches(name: str, text: str) -> tuple[str, ...]:
    return tuple(dict.fromkeys(match[0] for match in TERMS[name].finditer(text)))


def request(text: str, action: str, target: str) -> tuple[bool, bool]:
    """Find an action with a nearby object and preserve local negation."""
    affirmative = denied = False
    previous_object = False
    clauses = _CLAUSE.split(text)
    for clause in clauses:
        objects = list(TERMS[target].finditer(clause))
        reference = previous_object and _PRONOUN.search(clause)
        for verb in ACTIONS[action].finditer(clause):
            if not reference and not any(
                max(obj.start() - verb.end(), verb.start() - obj.end()) <= 75 for obj in objects
            ):
                continue
            if _NEGATION.search(clause[:verb.start()]):
                denied = True
            else:
                affirmative = True
        previous_object = bool(objects) or bool(reference)
    return affirmative, denied


def positive_action(text: str, *kinds: str) -> bool:
    return any(
        not _NEGATION.search(clause[:verb.start()])
        for clause in _CLAUSE.split(text)
        for kind in kinds
        for verb in ACTIONS[kind].finditer(clause)
    )
