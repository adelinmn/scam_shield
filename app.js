import { setupDashboard } from "./dashboard.js";
import { channels, entryUrl, renderChannel } from "./channels.js";
import { verdictBadge } from "./result-view.js";

let detectorModule;
let warningModule;

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

function loadOptionalModule(path) {
  return import(path).catch((error) => {
    if (error instanceof TypeError) return null;
    throw error;
  });
}

async function analyze(scenario) {
  let result;
  try {
    detectorModule ??= loadOptionalModule("./detector.js");
    const detector = await detectorModule;
    if (!detector) return { scenario, result: null };
    result = await detector.analyzeScenario(scenario);
    if (!["SAFE", "SUSPICIOUS", "SCAM"].includes(result?.verdict)
        || !Number.isInteger(result.risk_score) || result.risk_score < 0 || result.risk_score > 100
        || typeof result.scam_type !== "string"
        || (result.first_alert !== null && !scenario.messages.some((message) => message.n === result.first_alert))
        || !Array.isArray(result.red_flags)
        || !result.red_flags.every((flag) => typeof flag?.code === "string"
          && scenario.messages.some((message) => message.n === flag.message_number))) {
      throw new Error("Rezultat incompatibil cu formatul convenit.");
    }
  } catch {
    return { scenario, result: null, error: "Scenariul nu a putut fi analizat." };
  }

  try {
    warningModule ??= loadOptionalModule("./warnings.js");
    const warnings = await warningModule;
    const warning = warnings ? await warnings.buildWarning(scenario, result) : null;
    return { scenario, result, warning };
  } catch {
    return { scenario, result, warningError: "Avertismentul nu a putut fi afișat." };
  }
}

const appSet = {
  entries: new Map(),
  failures: [],
  loading: false,
  latestImportKeys: [],
  importSummary: "",
};
let scenarioQueue = Promise.resolve();
let queuedImports = 0;
let openedAlertRoute;
let simulationNumber = 0;
let simulationTarget;
const renderDashboard = setupDashboard();
const navLinks = [...document.querySelectorAll("nav [data-view]")];
const channelView = document.querySelector("#channel-view");
const dashboard = document.querySelector("#dashboard-view");
const simulationForm = document.querySelector("#simulation-form");
const simulationRole = document.querySelector("#simulation-role");
const simulationMessage = document.querySelector("#simulation-message");
const simulationStatus = document.querySelector("#simulation-status");
const simulationSubmit = simulationForm.querySelector('button[type="submit"]');

function scenarioKey({ channel, id }) {
  return `${channel}/${id}`;
}

function hasSender(scenario) {
  return scenario.messages.some((message) => message.from === "sender");
}

function updateSimulator(channel, entry, drafting = false) {
  const key = entry ? scenarioKey(entry.scenario) : drafting ? `${channel}/` : undefined;
  if (simulationTarget?.key !== key) simulationMessage.value = "";
  simulationTarget = key === undefined ? undefined : { key, channel, entry };
  simulationForm.hidden = !simulationTarget;
  simulationSubmit.disabled = queuedImports > 0;

  simulationStatus.replaceChildren();
  if (queuedImports > 0) {
    simulationStatus.textContent = "Așteaptă finalizarea importului.";
  } else if (entry?.simulated) {
    if (entry.loading) simulationStatus.textContent = "Se analizează mesajul expeditorului…";
    else if (entry.error) simulationStatus.textContent = entry.error;
    else if (entry.result) simulationStatus.append(verdictBadge(entry.result.verdict));
    else if (hasSender(entry.scenario)) simulationStatus.textContent = "Analiza așteaptă conectarea detectorului.";
    else simulationStatus.textContent = "Așteaptă primul mesaj al expeditorului.";
  }
  simulationStatus.hidden = !simulationStatus.hasChildNodes();
}

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

  const pending = entries.filter((entry) => !entry.result && !entry.error && !entry.loading && hasSender(entry.scenario)).length;
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
  if (!isChannel) {
    updateSimulator();
    return;
  }

  let selectedId;
  try {
    selectedId = encodedId && decodeURIComponent(encodedId);
  } catch {
    selectedId = undefined;
  }
  const drafting = destination === "new" && !selectedId;
  const { alert, entry } = renderChannel(activeView, appSet.entries.values(), selectedId, { drafting });
  updateSimulator(activeView, entry, drafting);
  if (destination === "alert" && alert && openedAlertRoute !== route) {
    openedAlertRoute = route;
    alert.focus({ preventScroll: true });
    alert.scrollIntoView({ block: "start", inline: "nearest" });
  } else if (focusDetail && selectedId) {
    document.querySelector("#inbox-content h2")?.focus();
  } else if (focusDetail && drafting) {
    simulationMessage.focus();
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
  queuedImports += 1;
  simulationSubmit.disabled = true;
  scenarioQueue = scenarioQueue.then(async () => {
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
          const key = scenarioKey(scenario);
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
    }
    if (manual) {
      if (imported.size) appSet.latestImportKeys = [...imported.keys()];
      appSet.importSummary = formatImportSummary(counts);
    }
    appSet.loading = false;
    queuedImports -= 1;
    renderDataset();
  });
}

function newSimulation(channel) {
  let id;
  do {
    simulationNumber += 1;
    id = `SIM-${simulationNumber}`;
  } while (appSet.entries.has(scenarioKey({ channel, id })));

  return {
    id,
    channel,
    sender: { name: `Contact simulat ${simulationNumber}`, address: null, known_contact: false },
    messages: [],
  };
}

document.querySelector("#new-conversation").addEventListener("click", () => {
  const [channel] = location.hash.slice(1).split("/");
  if (Object.hasOwn(channels, channel)) location.hash = `#${channel}//new`;
});

simulationForm.addEventListener("submit", (event) => {
  event.preventDefault();
  if (!simulationTarget || queuedImports > 0) return;

  const text = simulationMessage.value.trim();
  if (!text) {
    simulationStatus.textContent = "Scrie un mesaj înainte de a-l adăuga.";
    simulationStatus.hidden = false;
    simulationMessage.focus();
    return;
  }

  const current = appSet.entries.get(simulationTarget.key);
  const previous = current?.scenario ?? newSimulation(simulationTarget.channel);
  const from = simulationRole.value;
  const n = (previous.messages.at(-1)?.n ?? 0) + 1;
  const scenario = { ...previous, messages: [...previous.messages, { n, from, text }] };
  const key = scenarioKey(scenario);
  const entry = { ...current, scenario, simulated: true };

  if (from === "sender") {
    entry.loading = true;
    entry.error = undefined;
    entry.analysisSnapshot = scenario;
    scenarioQueue = scenarioQueue.then(async () => {
      const result = await analyze(scenario);
      const latest = appSet.entries.get(key);
      // Keep replies added during analysis and let the newest sender turn own the result.
      if (latest?.analysisSnapshot === scenario) {
        appSet.entries.set(key, { ...result, scenario: latest.scenario, simulated: true });
        renderDataset();
      }
    });
  }

  appSet.entries.delete(key);
  appSet.entries.set(key, entry);
  simulationMessage.value = "";
  history.replaceState(null, "", entryUrl(scenario));
  renderDataset();
  simulationMessage.focus();
});

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
