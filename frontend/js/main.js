// App wiring: start screen, capture loading, view switching and the network view.
import { api } from "./api.js";
import { createGraph } from "./graph.js";
import { renderConversation, renderHost, renderOverview } from "./inspector.js";
import { createPacketView } from "./packets.js";
import { renderTimeline } from "./timeline.js";
import { el, fmt, loading, toast } from "./ui.js";

const state = { captureId: null, capture: null, graph: null, protocol: "", minPackets: 1 };

const $ = (id) => document.getElementById(id);
const startScreen = $("start-screen");
const workspace = $("workspace");
const inspector = $("inspector");
const fileInput = $("file-input");

const graph = createGraph($("graph"), {
  onNode: (ip) => showHost(ip),
  onEdge: (edge) => renderConversation(inspector, edge, inspectorActions),
  onClear: () => showOverview(),
});
const packetView = createPacketView(state);

const inspectorActions = {
  onBack: () => { graph.clear(); showOverview(); },
  onHost: (ip) => selectHost(ip),
  onPackets: (filters) => { switchView("packets"); packetView.setFilters(filters); },
};

// ---------- start screen ----------

async function loadSamples() {
  const grid = $("sample-grid");
  try {
    const { samples } = await api.samples();
    grid.replaceChildren(...samples.map((s) =>
      el("button", { class: "sample-card", onclick: () => openCapture(() => api.openSample(s.file), s.title) },
        el("h3", {}, s.title),
        el("p", {}, s.description),
        el("div", { class: "meta" }, el("span", {}, s.file), el("span", {}, fmt.bytes(s.size))),
      )));
  } catch (err) {
    toast(err.message);
  }
}

const dropzone = $("dropzone");
dropzone.addEventListener("click", () => fileInput.click());
dropzone.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") fileInput.click(); });
dropzone.addEventListener("dragover", (e) => { e.preventDefault(); dropzone.classList.add("dragover"); });
dropzone.addEventListener("dragleave", () => dropzone.classList.remove("dragover"));
dropzone.addEventListener("drop", (e) => {
  e.preventDefault();
  dropzone.classList.remove("dragover");
  const file = e.dataTransfer.files[0];
  if (file) openCapture(() => api.upload(file), file.name);
});
fileInput.addEventListener("change", () => {
  const file = fileInput.files[0];
  fileInput.value = "";
  if (file) openCapture(() => api.upload(file), file.name);
});
$("open-button").addEventListener("click", () => {
  if (state.captureId && !startScreen.hidden) {
    startScreen.hidden = true;
    workspace.hidden = false;
  } else if (state.captureId) {
    workspace.hidden = true;
    startScreen.hidden = false;
  } else {
    fileInput.click();
  }
});

// ---------- loading a capture ----------

async function openCapture(load, label) {
  loading(`Reading ${label}…`);
  try {
    const capture = await load();
    state.captureId = capture.id;
    state.capture = capture;
    state.protocol = "";
    state.minPackets = 1;
    setProtocolButtons("");
    $("min-packets").value = 1;
    $("min-packets-value").textContent = "1";

    $("capture-name").textContent = `${capture.name} · ${fmt.number(capture.summary.packets)} packets`;
    $("export-csv").href = `/api/captures/${capture.id}/export?filename=${encodeURIComponent(capture.name.replace(/\.p?cap$/i, ""))}-conversations.csv`;
    $("capture-chip").hidden = false;
    $("view-tabs").hidden = false;
    startScreen.hidden = true;
    workspace.hidden = false;

    switchView("network");
    await refreshGraph();
    renderKpis(capture.summary, state.graph);
    showOverview();
    renderTimeline($("timeline"), $("timeline-caption"), capture.summary.timeline, capture.summary.duration);
    packetView.reset();
  } catch (err) {
    toast(err.message);
  } finally {
    loading(null);
  }
}

function renderKpis(summary, graphData) {
  const kpi = (label, value, sub) =>
    el("div", { class: "kpi" }, el("div", { class: "label" }, label), el("div", { class: "value" }, value), el("div", { class: "sub" }, sub || " "));
  $("kpis").replaceChildren(
    kpi("Packets", fmt.number(summary.packets)),
    kpi("Hosts", fmt.number(summary.hosts), `${graphData.nodes.filter((n) => n.internal).length} internal`),
    kpi("Conversations", fmt.number(graphData.edges.length)),
    kpi("Data", fmt.bytes(summary.bytes)),
    kpi("Duration", fmt.duration(summary.duration), fmt.datetime(summary.start)),
  );
}

// ---------- network view ----------

async function refreshGraph() {
  state.graph = await api.graph(state.captureId, { protocol: state.protocol, minPackets: state.minPackets });
  $("graph-empty").hidden = state.graph.nodes.length > 0;
  graph.render(state.graph);
}

function showOverview() {
  renderOverview(inspector, state.capture.summary, {
    onHost: (ip) => selectHost(ip),
    onPort: (port, protocol) => inspectorActions.onPackets({ port, protocol }),
  });
}

async function showHost(ip) {
  try {
    const host = await api.host(state.captureId, ip);
    const node = state.graph.nodes.find((n) => n.id === ip);
    renderHost(inspector, host, node, graph.edgesOf(ip), inspectorActions);
  } catch (err) {
    toast(err.message);
  }
}

function selectHost(ip) {
  if (graph.select(ip)) {
    showHost(ip);
  } else {
    toast(`${ip} is not in the graph with the current filters.`);
  }
}

function setProtocolButtons(protocol) {
  document.querySelectorAll("#protocol-filter button").forEach((b) => b.classList.toggle("active", b.dataset.protocol === protocol));
}

document.querySelectorAll("#protocol-filter button").forEach((button) => {
  button.addEventListener("click", async () => {
    state.protocol = button.dataset.protocol;
    setProtocolButtons(state.protocol);
    await refreshGraph();
    showOverview();
  });
});

let sliderTimer = null;
$("min-packets").addEventListener("input", (e) => {
  state.minPackets = Number(e.target.value);
  $("min-packets-value").textContent = state.minPackets;
  clearTimeout(sliderTimer);
  sliderTimer = setTimeout(async () => { await refreshGraph(); showOverview(); }, 200);
});

$("host-search").addEventListener("keydown", (e) => {
  if (e.key !== "Enter") return;
  const query = e.target.value.trim();
  if (!query) return;
  const match = state.graph.nodes.find((n) => n.id === query) || state.graph.nodes.find((n) => n.id.startsWith(query));
  if (match) selectHost(match.id);
  else toast(`No host matching "${query}".`);
});

$("fit-graph").addEventListener("click", () => graph.fit());
$("relayout-graph").addEventListener("click", () => graph.relayout());

// ---------- views ----------

function switchView(view) {
  document.querySelectorAll(".view-tab").forEach((t) => t.classList.toggle("active", t.dataset.view === view));
  $("view-network").hidden = view !== "network";
  $("view-packets").hidden = view !== "packets";
  startScreen.hidden = true;
  workspace.hidden = false;
  if (view === "network") requestAnimationFrame(() => graph.resize());
}

document.querySelectorAll(".view-tab").forEach((tab) => tab.addEventListener("click", () => switchView(tab.dataset.view)));

window.addEventListener("resize", () => {
  if (state.capture && !$("view-network").hidden) {
    renderTimeline($("timeline"), $("timeline-caption"), state.capture.summary.timeline, state.capture.summary.duration);
  }
});

loadSamples();
