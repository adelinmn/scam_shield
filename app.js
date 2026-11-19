import { setupDashboard } from "./dashboard.js";
import { channels, renderChannel } from "./channels.js";

async function readScenario(file) {
  let scenario;
  try {
    scenario = JSON.parse(await file.text());
  } catch {
    throw new Error("Fișierul nu conține un JSON care poate fi citit.");
  }

  if (typeof scenario?.id !== "string" || !scenario.id.trim()
      || !Object.hasOwn(channels, scenario.channel)
      || typeof scenario.sender?.known_contact !== "boolean"
      || [scenario.sender.name, scenario.sender.address].some((value) =>
        value != null && typeof value !== "string")
      || !Array.isArray(scenario.messages) || scenario.messages.length === 0) {
    throw new Error("Completează ID-ul, canalul, expeditorul și lista de mesaje conform formatului din kit.");
  }

  const numbers = new Set();
  for (const message of scenario.messages) {
    if (!Number.isInteger(message?.n) || message.n < 1 || numbers.has(message.n)
        || !["sender", "reader"].includes(message.from) || typeof message.text !== "string") {
      throw new Error("Fiecare mesaj trebuie să aibă un număr unic, un autor și un text.");
    }
    numbers.add(message.n);
  }
  scenario.messages.sort((a, b) => a.n - b.n);
  return scenario;
}

async function analyze(scenario) {
  try {
    const response = await fetch("./api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(scenario),
    });
    const data = await response.json();
    if (!response.ok) {
      const error = typeof data?.error === "string" ? data.error : "Scenariul nu a putut fi analizat.";
      return { scenario, result: null, error };
    }

    const { warning, ...result } = data;
    if (result.id !== scenario.id
        || !["SAFE", "SUSPICIOUS", "SCAM"].includes(result.verdict)
        || !Number.isInteger(result.risk_score) || result.risk_score < 0 || result.risk_score > 100
        || typeof result.scam_type !== "string"
        || (result.first_alert !== null && !scenario.messages.some((message) => message.n === result.first_alert))
        || !Array.isArray(result.red_flags)
        || !result.red_flags.every((flag) => typeof flag?.code === "string"
          && scenario.messages.some((message) => message.n === flag.message_number))) {
      throw new Error("Rezultat incompatibil cu formatul convenit.");
    }
    return { scenario, result, warning };
  } catch {
    return { scenario, result: null, error: "Scenariul nu a putut fi analizat." };
  }
}

const appSet = {
  entries: new Map(),
  failures: [],
  loading: false,
  latestImportKeys: [],
  importSummary: "",
};
let importQueue = Promise.resolve();
let openedAlertRoute;
const renderDashboard = setupDashboard();
const navLinks = [...document.querySelectorAll("nav [data-view]")];
const channelView = document.querySelector("#channel-view");
const dashboard = document.querySelector("#dashboard-view");

function formatImportSummary({ added, updated, invalid }) {
  const parts = [];
  if (added) parts.push(added === 1 ? "1 scenariu adăugat" : `${added} scenarii adăugate`);
  if (updated) parts.push(updated === 1 ? "1 scenariu actualizat" : `${updated} scenarii actualizate`);
  if (invalid) parts.push(invalid === 1 ? "1 fișier invalid" : `${invalid} fișiere invalide`);
  return parts.length ? `${parts.join(", ")}.` : "Niciun scenariu importat.";
}

function renderImportStatus(entries) {
  const summary = document.querySelector("#import-summary");
  summary.textContent = appSet.importSummary;
  summary.hidden = appSet.loading || !appSet.importSummary;

  const pending = entries.filter((entry) => !entry.result && !entry.error).length;
  const failed = entries.filter((entry) => entry.error).length;
  const status = document.querySelector("#dashboard-status");
  if (appSet.loading) {
    status.textContent = "Se încarcă și se analizează scenariile…";
  } else {
    const messages = [];
    if (pending) messages.push(`${pending} scenarii așteaptă integrarea detectorului.`);
    if (failed) messages.push(`${failed} scenarii nu au putut fi analizate.`);
    status.textContent = messages.join(" ");
  }
  status.hidden = !status.textContent;

  const errors = document.querySelector("#dashboard-errors");
  errors.replaceChildren(...appSet.failures.map((failure) => {
    const item = document.createElement("li");
    item.textContent = failure;
    return item;
  }));
  errors.hidden = appSet.failures.length === 0;
}

function showView(focusDetail = false) {
  const route = location.hash;
  const [requestedView, encodedId, destination] = route.slice(1).split("/");
  if (focusDetail) openedAlertRoute = undefined;
  const isChannel = Object.hasOwn(channels, requestedView);
  const activeView = isChannel ? requestedView : "dashboard";
  channelView.hidden = !isChannel;
  dashboard.hidden = isChannel;
  for (const link of navLinks) {
    if (link.dataset.view === activeView) link.setAttribute("aria-current", "page");
    else link.removeAttribute("aria-current");
  }
  if (!isChannel) return;

  let selectedId;
  try {
    selectedId = encodedId && decodeURIComponent(encodedId);
  } catch {
    selectedId = undefined;
  }
  const alertHadFocus = document.activeElement?.matches("#inbox-content .first-alert");
  const alert = renderChannel(activeView, appSet.entries.values(), selectedId);
  if (destination === "alert" && alert && openedAlertRoute !== route) {
    openedAlertRoute = route;
    alert.focus({ preventScroll: true });
    alert.scrollIntoView({ block: "start", inline: "nearest" });
  } else if (destination === "alert" && alertHadFocus && alert) {
    alert.focus({ preventScroll: true });
  } else if (focusDetail && selectedId) {
    document.querySelector("#inbox-content h2")?.focus();
  }
}

function renderDataset() {
  const entries = [...appSet.entries.values()];
  const latestImportEntries = appSet.latestImportKeys.map((key) => appSet.entries.get(key));
  renderDashboard(entries, latestImportEntries);
  renderImportStatus(entries);
  showView();
}

function enqueueImport(loadSources, { manual = false } = {}) {
  importQueue = importQueue.then(async () => {
    appSet.loading = true;
    appSet.failures = [];
    renderDataset();

    const imported = new Map();
    const counts = { added: 0, updated: 0, invalid: 0 };
    try {
      const sources = await loadSources();
      for (const source of sources) {
        if (!source.name.toLowerCase().endsWith(".json")) continue;
        try {
          const scenario = await readScenario(source);
          const key = `${scenario.channel}/${scenario.id}`;
          if (!imported.has(key)) {
            const change = appSet.entries.has(key) ? "updated" : "added";
            counts[change] += 1;
          }
          imported.set(key, scenario);
          // Reimporting a scenario makes it the latest entry for its sender.
          appSet.entries.delete(key);
          appSet.entries.set(key, { scenario, loading: true });
        } catch (error) {
          counts.invalid += 1;
          appSet.failures.push(`${source.name} — ${error.message}`);
        }
      }
      if (!imported.size && !appSet.failures.length) {
        appSet.failures.push("Nu s-a găsit niciun fișier JSON.");
      }
    } catch {
      appSet.failures.push("Setul de validare nu a putut fi încărcat. Pornește aplicația cu python3 server.py.");
    }

    renderDataset();
    for (const [key, scenario] of imported) {
      appSet.entries.set(key, await analyze(scenario));
      renderDataset();
    }
    if (manual) {
      if (imported.size) appSet.latestImportKeys = [...imported.keys()];
      appSet.importSummary = formatImportSummary(counts);
    }
    appSet.loading = false;
    renderDataset();
  });
}

async function validationSources() {
  const response = await fetch("./api/validation-set");
  if (!response.ok) throw new Error("Setul de validare nu este disponibil.");
  const names = await response.json();
  return names.map((name) => ({
    name,
    async text() {
      const file = await fetch(`./validation_set/${encodeURIComponent(name)}`);
      if (!file.ok) throw new Error("Fișierul nu este disponibil.");
      return file.text();
    },
  }));
}

for (const [buttonId, inputId] of [
  ["open-batch", "batch-files"],
  ["open-folder", "batch-folder"],
]) {
  const input = document.querySelector(`#${inputId}`);
  document.querySelector(`#${buttonId}`).addEventListener("click", () => input.click());
  input.addEventListener("change", () => {
    const files = Array.from(input.files);
    input.value = "";
    if (files.length) enqueueImport(() => files, { manual: true });
  });
}

document.querySelector(".skip-link").addEventListener("click", (event) => {
  event.preventDefault();
  document.querySelector("#main").focus();
});

window.addEventListener("hashchange", () => showView(true));
showView();
enqueueImport(validationSources);
