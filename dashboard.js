import { renderConversation, renderResult, verdictBadge } from "./result-view.js";

export function setupDashboard() {
  const rows = document.querySelector("#dashboard-rows");
  const table = document.querySelector("#dashboard-table");
  const empty = document.querySelector("#dashboard-empty");
  const dialog = document.querySelector("#details");
  const title = document.querySelector("#details-title");
  const content = document.querySelector("#details-content");
  const counters = {
    total: document.querySelector("#count-total"),
    SCAM: document.querySelector("#count-scam"),
    SUSPICIOUS: document.querySelector("#count-suspicious"),
    SAFE: document.querySelector("#count-safe"),
  };

  function showDetails(entry) {
    title.textContent = `Scenariul ${entry.scenario.id}`;
    renderResult(content, entry);
    renderConversation(content, [entry]);
    dialog.showModal();
  }

  return function renderRows(entries, counts) {
    const fragment = document.createDocumentFragment();
    for (const entry of entries) {
      const { scenario, result, error } = entry;
      const row = document.createElement("tr");
      const idCell = document.createElement("th");
      idCell.scope = "row";
      const button = document.createElement("button");
      button.className = "row-action";
      button.type = "button";
      button.textContent = scenario.id;
      button.setAttribute("aria-label", `Deschide scenariul ${scenario.id}`);
      button.addEventListener("click", () => showDetails(entry));
      idCell.append(button);
      row.append(idCell);
      row.addEventListener("click", (event) => {
        if (event.target !== button && !globalThis.getSelection()?.toString()) {
          button.focus();
          showDetails(entry);
        }
      });

      const codes = [...new Set(result?.red_flags.map((flag) => flag.code))];
      const cells = [
        error ?? verdictBadge(result?.verdict, "technical"),
        result?.scam_type ?? "—",
        result?.risk_score ?? "—",
        result ? result.first_alert ?? "" : "—",
        codes.join(", ") || "—",
      ];
      for (const value of cells) row.insertCell().append(value);
      fragment.append(row);
    }
    rows.replaceChildren(fragment);
    for (const [key, count] of Object.entries(counts)) {
      counters[key].textContent = count;
    }
    table.hidden = entries.length === 0;
    empty.hidden = entries.length !== 0;
  };
}
