// Packets view: filtered packet list, layer tree and hex dump with byte highlighting.
import { api } from "./api.js";
import { el, fmt, toast } from "./ui.js";

const PAGE_SIZE = 200;
const BYTES_PER_LINE = 16;

export function createPacketView(state) {
  const rows = document.getElementById("packet-rows");
  const wrap = document.getElementById("packet-table-wrap");
  const count = document.getElementById("packet-count");
  const pageLabel = document.getElementById("page-label");
  const prev = document.getElementById("prev-page");
  const next = document.getElementById("next-page");
  const chips = document.getElementById("packet-filters");
  const detail = document.getElementById("packet-detail");
  const ipInput = document.getElementById("packet-ip");
  const protocolInput = document.getElementById("packet-protocol");
  const portInput = document.getElementById("packet-port");

  let filters = { ip: "", peer: "", protocol: "", port: "" };
  let offset = 0;
  let total = 0;
  let selectedIndex = null;

  prev.addEventListener("click", () => { offset = Math.max(0, offset - PAGE_SIZE); load(); });
  next.addEventListener("click", () => { offset += PAGE_SIZE; load(); });

  let debounce = null;
  const onInput = () => {
    clearTimeout(debounce);
    debounce = setTimeout(() => {
      setFilters({ ...filters, ip: ipInput.value.trim(), protocol: protocolInput.value, port: portInput.value.trim() });
    }, 250);
  };
  ipInput.addEventListener("input", onInput);
  protocolInput.addEventListener("change", onInput);
  portInput.addEventListener("input", onInput);

  function setFilters(newFilters) {
    filters = { ip: "", peer: "", protocol: "", port: "", ...newFilters };
    ipInput.value = filters.ip;
    protocolInput.value = filters.protocol;
    portInput.value = filters.port;
    offset = 0;
    renderChips();
    load();
  }

  function renderChips() {
    const labels = { ip: "Host", peer: "Peer", protocol: "Protocol", port: "Port" };
    chips.replaceChildren(...Object.entries(filters)
      .filter(([, v]) => v !== "")
      .map(([key, value]) => el("span", { class: "filter-chip" }, `${labels[key]}: ${value}`,
        el("button", { title: "Remove filter", onclick: () => setFilters({ ...filters, [key]: "" }) }, "×"))));
  }

  async function load() {
    if (!state.captureId) return;
    try {
      const data = await api.packets(state.captureId, filters, offset, PAGE_SIZE);
      total = data.total;
      rows.replaceChildren(...data.packets.map(row));
      wrap.scrollTop = 0;
      count.textContent = `${fmt.number(total)} packets`;
      const last = Math.min(offset + PAGE_SIZE, total);
      pageLabel.textContent = total ? `${fmt.number(offset + 1)}–${fmt.number(last)} of ${fmt.number(total)}` : "No packets match";
      prev.disabled = offset === 0;
      next.disabled = last >= total;
    } catch (err) {
      toast(err.message);
    }
  }

  function row(p) {
    const tr = el("tr", { dataset: { index: p.index }, class: p.index === selectedIndex ? "selected" : "" },
      el("td", {}, p.index + 1),
      el("td", {}, p.time.toFixed(4)),
      el("td", { class: "addr" }, p.src ?? "—"),
      el("td", { class: "addr" }, p.dst ?? "—"),
      el("td", {}, el("span", { class: `proto ${p.protocol}` }, p.protocol), p.service ? el("span", { class: "svc-tag" }, p.service) : null),
      el("td", {}, p.length),
      el("td", { class: "info" }, p.info),
    );
    tr.addEventListener("click", () => {
      rows.querySelectorAll("tr.selected").forEach((r) => r.classList.remove("selected"));
      tr.classList.add("selected");
      showPacket(p.index);
    });
    return tr;
  }

  async function showPacket(index) {
    selectedIndex = index;
    try {
      renderDetail(await api.packet(state.captureId, index));
    } catch (err) {
      toast(err.message);
    }
  }

  function renderDetail(packet) {
    const bytes = hexToBytes(packet.hex);
    const hex = renderHex(bytes);

    const layerNodes = packet.layers.map((layer, i) => {
      const isLast = i === packet.layers.length - 1;
      const box = el("div", { class: `layer${isLast ? " open" : ""}` });
      const head = el("button", { class: "layer-head" },
        chevron(),
        el("span", { class: "layer-name" }, layer.name),
        el("span", { class: "layer-summary" }, layer.summary),
      );
      head.addEventListener("click", () => box.classList.toggle("open"));
      head.addEventListener("mouseenter", () => hex.highlight(layer.offset, layer.length, "layer-hl"));
      head.addEventListener("mouseleave", () => hex.highlight(0, 0, "layer-hl"));
      const fields = el("div", { class: "layer-fields" }, layer.fields.map((f) => {
        const r = el("div", { class: "field-row" }, el("span", { class: "fname" }, f.name), el("span", { class: "fvalue" }, f.value));
        r.addEventListener("mouseenter", () => hex.highlight(f.offset, f.length, "hl"));
        r.addEventListener("mouseleave", () => hex.highlight(0, 0, "hl"));
        return r;
      }));
      box.append(head, fields);
      return box;
    });

    detail.replaceChildren(...[
      el("div", { class: "detail-head" },
        el("h3", {}, `Packet ${fmt.number(packet.index + 1)}`),
        el("span", { class: "muted small" }, `${packet.length} bytes · ${packet.time.toFixed(6)} s`),
      ),
      packet.decode_error ? el("div", { class: "decode-error" }, `Decoder error: ${packet.decode_error}`) : null,
      el("div", { class: "layers" }, layerNodes),
      el("div", { class: "hex-title" }, "Bytes"),
      hex.node,
    ].filter(Boolean));
  }

  return { load, setFilters, reset: () => { selectedIndex = null; setFilters({}); } };
}

function chevron() {
  const s = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  s.setAttribute("viewBox", "0 0 24 24");
  s.setAttribute("class", "chev");
  const p = document.createElementNS("http://www.w3.org/2000/svg", "path");
  p.setAttribute("d", "M9 6l6 6-6 6");
  s.append(p);
  return s;
}

function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}

function renderHex(bytes) {
  const node = el("div", { class: "hexdump" });
  const spans = [];
  for (let start = 0; start < bytes.length; start += BYTES_PER_LINE) {
    const line = el("div");
    line.append(el("span", { class: "off" }, start.toString(16).padStart(4, "0")));
    const ascii = el("span", { class: "ascii" });
    for (let i = start; i < start + BYTES_PER_LINE; i++) {
      if (i < bytes.length) {
        const b = el("span", { class: "b" }, bytes[i].toString(16).padStart(2, "0"));
        spans[i] = b;
        line.append(b, i % 8 === 7 ? "  " : " ");
        const ch = bytes[i] >= 32 && bytes[i] < 127 ? String.fromCharCode(bytes[i]) : ".";
        ascii.append(ch);
      } else {
        line.append(i % 8 === 7 ? "    " : "   ");
      }
    }
    line.append(ascii);
    node.append(line);
  }
  return {
    node,
    highlight(offset, length, cls) {
      spans.forEach((s, i) => s && s.classList.toggle(cls, i >= offset && i < offset + length));
    },
  };
}
