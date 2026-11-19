import { renderConversation, renderResult, verdictBadge } from "./result-view.js";

export const channels = {
  whatsapp: { title: "WhatsApp", inbox: "Conversații", counts: ["conversație", "conversații"], layout: "bubbles" },
  sms: { title: "SMS", inbox: "Conversații", counts: ["conversație", "conversații"], layout: "bubbles" },
  email: { title: "E-mail", inbox: "Primite", counts: ["expeditor", "expeditori"], layout: "mail" },
  call_transcript: { title: "Transcrieri de apel", inbox: "Apeluri", counts: ["apelant", "apelanți"], layout: "transcript" },
  chat: { title: "Chat", inbox: "Conversații", counts: ["conversație", "conversații"], layout: "bubbles" },
};

function contactName(scenario) {
  return scenario.sender.name?.trim() || scenario.sender.address?.trim() || "Expeditor necunoscut";
}

function senderKey({ sender, id }) {
  const address = sender.address?.trim().normalize("NFC").toLowerCase();
  if (address) {
    const phone = /^\+?[\dx\s().-]+$/.test(address) && /\d/.test(address);
    return `address:${phone ? address.replace(/[\s().-]/g, "") : address}`;
  }
  const name = sender.name?.trim().normalize("NFC").toLowerCase().replace(/\s+/g, " ");
  return name ? `name:${name}` : `scenario:${id}`;
}

function groupBySender(entries, channelId) {
  const groups = new Map();
  for (const entry of entries) {
    if (entry.scenario.channel !== channelId) continue;
    const key = senderKey(entry.scenario);
    const thread = groups.get(key) ?? [];
    thread.push(entry);
    groups.delete(key);
    groups.set(key, thread);
  }

  return [...groups.values()].reverse().map((thread) => ({
    entries: thread,
    latest: thread.at(-1),
    alert: thread.findLast((entry) => entry.result?.verdict === "SCAM")
      ?? thread.findLast((entry) => entry.result?.verdict === "SUSPICIOUS"),
  }));
}

export function entryUrl({ channel, id }, { alert = false } = {}) {
  return `#${channel}/${encodeURIComponent(id)}${alert ? "/alert" : ""}`;
}

function createElement(tag, className, text) {
  const element = document.createElement(tag);
  element.className = className;
  if (text !== undefined) element.textContent = text;
  return element;
}

function avatarFor(scenario) {
  const name = contactName(scenario);
  const avatar = createElement("span", "avatar", Array.from(name)[0].toUpperCase());
  avatar.setAttribute("aria-hidden", "true");
  return avatar;
}

export function renderChannel(channelId, entries, selectedId) {
  const channel = channels[channelId];
  const title = document.querySelector("#channel-title");
  const description = document.querySelector("#channel-description");
  const inbox = document.querySelector("#inbox");
  const listTitle = document.querySelector("#inbox-title");
  const list = document.querySelector("#inbox-list");
  const empty = document.querySelector("#channel-empty");
  const detail = document.querySelector("#inbox-content");
  const back = document.querySelector("#back-to-inbox");
  const matching = groupBySender(entries, channelId);
  const explicit = matching.find((thread) => thread.entries.some((entry) => entry.scenario.id === selectedId));
  const selected = explicit ?? matching[0];

  title.textContent = channel.title;
  description.textContent = `${matching.length} ${channel.counts[matching.length === 1 ? 0 : 1]}`;
  listTitle.textContent = channel.inbox;
  empty.textContent = "Nu există încă intrări pe acest canal.";
  empty.hidden = matching.length !== 0;
  inbox.dataset.layout = channel.layout;
  inbox.dataset.detailOpen = String(Boolean(explicit));
  back.href = `#${channelId}`;

  const fragment = document.createDocumentFragment();
  for (const thread of matching) {
    const { latest, alert } = thread;
    const { scenario } = latest;
    const item = createElement("li", "inbox-row");
    const link = createElement("a", "inbox-link");
    link.href = entryUrl((alert ?? latest).scenario);
    if (thread === selected) link.setAttribute("aria-current", "true");
    const copy = createElement("div", "inbox-copy");
    const lastMessage = scenario.messages.at(-1);
    const preview = lastMessage.from === "reader" ? `Tu · ${lastMessage.text}` : lastMessage.text;
    copy.append(
      createElement("strong", "entry-title", contactName(scenario)),
      createElement("p", "message-preview", preview),
    );
    if (alert) copy.append(verdictBadge(alert.result.verdict, "compact"));
    link.append(avatarFor(scenario), copy);
    item.append(link);
    fragment.append(item);
  }
  list.replaceChildren(fragment);
  detail.replaceChildren();
  if (!selected) return;

  const { scenario } = selected.latest;
  const analysisEntry = selected.entries.find((entry) => entry.scenario.id === selectedId)
    ?? selected.alert ?? selected.latest;
  const header = createElement("header", "detail-header");
  const identity = createElement("div", "detail-identity");
  const titleElement = createElement("h2", "entry-title", contactName(scenario));
  titleElement.tabIndex = -1;
  identity.append(titleElement);
  const address = scenario.sender.address?.trim();
  if (address && address !== contactName(scenario)) {
    identity.append(createElement("p", "entry-context", address));
  }
  header.append(avatarFor(scenario), identity);
  if (selected.alert) header.append(verdictBadge(selected.alert.result.verdict, "compact"));
  detail.append(header);

  const analysis = createElement("div", "detail-analysis");
  renderResult(analysis, analysisEntry, { showExplanation: analysisEntry.result?.first_alert == null });
  if (selected.entries.length > 1) {
    analysis.prepend(createElement("p", "entry-context analysis-source", `Analiză pentru ${analysisEntry.scenario.id}`));
  }
  detail.append(analysis);
  return renderConversation(detail, selected.entries, { layout: channel.layout, alertScenarioId: selectedId });
}
