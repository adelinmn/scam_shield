import { channels, entryUrl } from "./channels.js";
import { renderConversation, renderResult, verdictBadge } from "./result-view.js";

export function setupDashboard() {
  const rows = document.querySelector("#dashboard-rows");
  const table = document.querySelector("#dashboard-table");
  const empty = document.querySelector("#dashboard-empty");
  const resultsCount = document.querySelector("#results-count");
  const dialog = document.querySelector("#details");
  const title = document.querySelector("#details-title");
  const content = document.querySelector("#details-content");
  const scopeButtons = [...document.querySelectorAll("[data-scope]")];
  const verdictButtons = [...document.querySelectorAll("[data-verdict]")];
  const latestButton = document.querySelector('[data-scope="latest"]');
  const counters = {
    total: document.querySelector("#count-total"),
    SCAM: document.querySelector("#count-scam"),
    SUSPICIOUS: document.querySelector("#count-suspicious"),
    SAFE: document.querySelector("#count-safe"),
  };
  let allEntries = [];
  let latestEntries = [];
  let scope = "all";
  let verdict = "all";

  function showDetails(entry) {
    title.textContent = `Scenariul ${entry.scenario.id}`;
    renderResult(content, entry);
    renderConversation(content, [entry]);
    dialog.showModal();
  }

  function renderRows() {
    const entries = scope === "latest" ? latestEntries : allEntries;
    const counts = { total: entries.length, SCAM: 0, SUSPICIOUS: 0, SAFE: 0 };
    for (const { result } of entries) {
      if (result) counts[result.verdict] += 1;
    }
    for (const [key, count] of Object.entries(counts)) {
      counters[key].textContent = count;
    }

    const visibleEntries = entries
      .filter((entry) => verdict === "all" || entry.result?.verdict === verdict)
      .sort((a, b) => a.scenario.id.localeCompare(b.scenario.id, "ro"));

    const fragment = document.createDocumentFragment();
    for (const entry of visibleEntries) {
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
        if (!event.target.closest("button, a") && !globalThis.getSelection()?.toString()) {
          button.focus();
          showDetails(entry);
        }
      });

      const channel = document.createElement("a");
      channel.className = "channel-link";
      channel.href = entryUrl(scenario);
      channel.textContent = channels[scenario.channel].title;
      channel.setAttribute("aria-label", `Deschide scenariul ${scenario.id} în ${channel.textContent}`);
      const codes = [...new Set(result?.red_flags.map((flag) => flag.code))];
      const cells = [
        channel,
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
    table.hidden = visibleEntries.length === 0;
    empty.hidden = visibleEntries.length !== 0;
    empty.textContent = entries.length ? "Niciun scenariu cu verdictul selectat." : "Niciun scenariu încărcat.";
    resultsCount.hidden = entries.length === 0;
    resultsCount.textContent = `${visibleEntries.length} din ${entries.length} afișate`;
  }

  for (const button of scopeButtons) {
    button.addEventListener("click", () => {
      scope = button.dataset.scope;
      for (const option of scopeButtons) option.setAttribute("aria-pressed", String(option === button));
      renderRows();
    });
  }

  for (const button of verdictButtons) {
    button.addEventListener("click", () => {
      verdict = button.dataset.verdict;
      for (const option of verdictButtons) option.setAttribute("aria-pressed", String(option === button));
      renderRows();
    });
  }

  return function updateDashboard(entries, lastImportEntries) {
    allEntries = entries;
    latestEntries = lastImportEntries;
    latestButton.disabled = latestEntries.length === 0;
    renderRows();
  };
}
