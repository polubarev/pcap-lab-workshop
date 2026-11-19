// Right-hand panel of the network view: capture overview, or details of the selected host or conversation.
import { el, fmt, PROTOCOL_COLORS } from "./ui.js";

export function renderOverview(panel, summary, { onHost, onPort }) {
  const total = summary.packets || 1;
  const protocols = Object.entries(summary.protocols);

  panel.replaceChildren(
    el("section", {},
      el("h3", {}, "Protocols"),
      el("div", { class: "bars" }, protocols.map(([name, count]) =>
        el("div", { class: "bar-row" },
          el("span", {}, name),
          el("div", { class: "bar-track" },
            el("div", { class: "bar-fill", style: `width:${(count / total) * 100}%;background:${PROTOCOL_COLORS[name] || PROTOCOL_COLORS.Other}` })),
          el("span", { class: "num" }, `${((count / total) * 100).toFixed(1)}%`),
        ))),
    ),
    el("section", {},
      el("h3", {}, "Top talkers"),
      el("table", { class: "mini-table" },
        el("tbody", {}, summary.top_talkers.map((h) =>
          el("tr", { class: "clickable", title: "Show this host", onclick: () => onHost(h.ip) },
            el("td", {}, el("span", { class: "ip" }, h.ip),
              el("span", { class: `badge ${h.internal ? "internal" : "external"}`, style: "margin-left:8px" }, h.internal ? "int" : "ext")),
            el("td", {}, fmt.bytes(h.bytes_sent + h.bytes_received)),
          )))),
    ),
    el("section", {},
      el("h3", {}, "Top ports"),
      el("table", { class: "mini-table" },
        el("tbody", {}, summary.top_ports.map((p) =>
          el("tr", { class: "clickable", title: "Show these packets", onclick: () => onPort(p.port, p.protocol) },
            el("td", {}, el("span", { class: "ip" }, `${p.protocol} ${p.port}`), p.service ? el("span", { class: "svc" }, p.service) : null),
            el("td", {}, `${fmt.number(p.packets)} pkts`),
          )))),
    ),
  );
}

export function renderHost(panel, host, node, edges, { onBack, onHost, onPackets }) {
  const peers = edges
    .map((e) => ({ ip: e.source === host.ip ? e.target : e.source, packets: e.packets, bytes: e.bytes, services: e.services }))
    .sort((a, b) => b.bytes - a.bytes);

  panel.replaceChildren(
    el("section", {},
      el("div", { class: "title-row" },
        el("button", { class: "link-btn", onclick: onBack }, "← Overview"),
        el("button", { class: "btn btn-ghost", onclick: () => onPackets({ ip: host.ip }) }, "Show packets"),
      ),
      el("div", { class: "host-title" }, host.ip),
      el("div", {},
        el("span", { class: `badge ${host.internal ? "internal" : "external"}` }, host.internal ? "Internal" : "External"),
        node?.hub ? el("span", { class: "badge hub", style: "margin-left:6px" }, "Hub") : null,
      ),
    ),
    el("section", {},
      el("div", { class: "stat-grid" },
        stat("Sent", fmt.bytes(host.bytes_sent), `${fmt.number(host.packets_sent)} packets`),
        stat("Received", fmt.bytes(host.bytes_received), `${fmt.number(host.packets_received)} packets`),
        stat("Peers", fmt.number(host.peers)),
        stat("Protocols", host.protocols.join(", ")),
      ),
      el("div", { class: "muted small" }, `Active ${fmt.datetime(host.first_seen)} – ${fmt.datetime(host.last_seen)}`),
    ),
    el("section", {},
      el("h3", {}, `Talks to (${peers.length})`),
      el("table", { class: "mini-table" },
        el("tbody", {}, peers.map((p) =>
          el("tr", { class: "clickable", title: "Show this host", onclick: () => onHost(p.ip) },
            el("td", {}, el("span", { class: "ip" }, p.ip), p.services.length ? el("span", { class: "svc" }, p.services.join(", ")) : null),
            el("td", {}, fmt.bytes(p.bytes)),
          )))),
    ),
  );
}

export function renderConversation(panel, edge, { onBack, onHost, onPackets }) {
  panel.replaceChildren(
    el("section", {},
      el("div", { class: "title-row" },
        el("button", { class: "link-btn", onclick: onBack }, "← Overview"),
        el("button", { class: "btn btn-ghost", onclick: () => onPackets({ ip: edge.source, peer: edge.target }) }, "Show packets"),
      ),
      el("h3", {}, "Conversation"),
      el("div", { class: "peer-list" },
        el("button", { class: "link-btn host-title", style: "text-align:left", onclick: () => onHost(edge.source) }, edge.source),
        el("span", { class: "muted" }, "⇅"),
        el("button", { class: "link-btn host-title", style: "text-align:left", onclick: () => onHost(edge.target) }, edge.target),
      ),
    ),
    el("section", {},
      el("div", { class: "stat-grid" },
        stat("Packets", fmt.number(edge.packets)),
        stat("Data", fmt.bytes(edge.bytes)),
        stat("Protocols", edge.protocols.join(", ")),
        stat("Services", edge.services.join(", ") || "—"),
      ),
    ),
  );
}

function stat(label, value, sub) {
  return el("div", { class: "stat" },
    el("div", { class: "label" }, label),
    el("div", { class: "value" }, value),
    sub ? el("div", { class: "muted small" }, sub) : null,
  );
}
