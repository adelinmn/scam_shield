const verdicts = {
  SAFE: { style: "safe", icon: "✓", label: "Pare în regulă", short: "Pare în regulă" },
  SUSPICIOUS: { style: "suspicious", icon: "?", label: "Atenție, verificați înainte să răspundeți", short: "De verificat" },
  SCAM: { style: "scam", icon: "!", label: "Pare o țeapă! Nu răspundeți", short: "Scam detectat" },
};

const pending = { style: "pending", icon: "…", label: "Analiză în așteptare" };

export function verdictBadge(verdict, mode = "full") {
  const status = verdicts[verdict] ?? pending;
  const badge = document.createElement("span");
  badge.className = `verdict ${status.style}`;
  const icon = document.createElement("span");
  icon.setAttribute("aria-hidden", "true");
  icon.textContent = status.icon;
  const label = mode === "technical" && verdict ? verdict : status.label;
  badge.append(icon, mode === "compact" ? status.short ?? label : label);
  return badge;
}

export function renderResult(container, { result, warning, warningError, loading, error }, { showExplanation = true } = {}) {
  container.replaceChildren();

  const banner = document.createElement("div");
  banner.className = `result-banner ${verdicts[result?.verdict]?.style ?? pending.style}`;
  banner.append(verdictBadge(result?.verdict));
  if (showExplanation && (warning || warningError || result?.verdict !== "SAFE")) {
    const explanation = document.createElement("p");
    explanation.textContent = warning || warningError || error || (loading ? "Se analizează scenariul…" : result
      ? "Textul de avertizare va fi afișat după integrarea modulului de avertismente."
      : "Scenariul a fost încărcat. Rezultatul va fi afișat după integrarea detectorului.");
    banner.append(explanation);
  }
  container.append(banner);

  if (result) {
    const meta = document.createElement("p");
    meta.className = "result-meta";
    meta.textContent = `Scor ${result.risk_score}/100`;
    if (result.first_alert !== null) {
      meta.append(` · Prima alertă la mesajul ${result.first_alert}`);
    }
    container.append(meta);
  }
}

export function renderConversation(container, entries, { layout, alertScenarioId } = {}) {
  const heading = document.createElement("h3");
  heading.className = "conversation-heading";
  const grouped = entries.length > 1;
  const hasMultipleMessages = grouped || entries[0].scenario.messages.length > 1;
  if (layout === "transcript") {
    heading.textContent = grouped ? "Transcrieri" : "Transcriere";
  } else if (layout === "mail") {
    heading.textContent = hasMultipleMessages ? "Mesaje" : "Mesajul";
  } else {
    heading.textContent = hasMultipleMessages ? "Conversația" : "Mesajul";
  }
  const messages = document.createElement("ol");
  messages.className = "conversation";
  if (layout) messages.classList.add(layout);
  let alertMessage;

  for (const { scenario, result, warning } of entries) {
    for (const message of scenario.messages) {
      const item = document.createElement("li");
      item.className = "message";
      const fromReader = message.from === "reader";
      item.classList.toggle("reader", fromReader);
      const firstAlert = message.n === result?.first_alert;
      item.classList.toggle("first-alert", firstAlert);

      const label = document.createElement("strong");
      const author = layout === "transcript" ? (fromReader ? "Destinatar" : "Apelant")
        : fromReader ? "Tu" : "Expeditor";
      label.textContent = layout === "mail" && !hasMultipleMessages ? author
        : `${author} · Mesajul ${message.n}`;
      if (grouped) label.prepend(`${scenario.id} · `);
      if (firstAlert) label.append(" · Prima alertă");
      item.append(label);

      if (layout && firstAlert) {
        const notice = document.createElement("div");
        notice.className = "message-warning";
        const action = document.createElement("p");
        action.textContent = warning || "Verificați cererea printr-un canal oficial pe care îl cunoașteți.";
        notice.append(verdictBadge(result.verdict), action);
        item.append(notice);
        if (scenario.id === alertScenarioId) {
          item.tabIndex = -1;
          alertMessage = item;
        }
      }

      const body = document.createElement("p");
      body.dir = "auto";
      body.textContent = message.text;
      item.append(body);

      const flags = [...new Set(result?.red_flags
        .filter((flag) => flag.message_number === message.n)
        .map((flag) => flag.code))];
      if (flags.length) {
        const flagLabel = document.createElement("p");
        flagLabel.className = "message-flags";
        flagLabel.textContent = flags.join(", ");
        item.append(flagLabel);
      }
      messages.append(item);
    }
  }

  container.append(heading, messages);
  return alertMessage;
}
