// Network graph: hosts are nodes, conversations are edges (Cytoscape.js).
import { PROTOCOL_COLORS } from "./ui.js";

const NODE_INTERNAL = "#4589ff";
const NODE_EXTERNAL = "#f1a33c";
const HUB_RING = "#ff7eb6";

const clamp = (value, lo, hi) => Math.max(lo, Math.min(hi, value));

const STYLE = [
  {
    selector: "node",
    style: {
      "background-color": "data(color)",
      width: "data(size)",
      height: "data(size)",
      label: "data(id)",
      color: "#b4bfd6",
      "font-family": "ui-monospace, Cascadia Mono, Consolas, Menlo, monospace",
      "font-size": 10,
      "text-valign": "bottom",
      "text-margin-y": 5,
      "text-outline-color": "#0a0e1a",
      "text-outline-width": 2,
      "border-width": 0,
      "transition-property": "opacity",
      "transition-duration": "150ms",
    },
  },
  { selector: "node[?hub]", style: { "border-width": 3, "border-color": HUB_RING } },
  {
    selector: "edge",
    style: {
      width: "data(width)",
      "line-color": "data(color)",
      opacity: 0.55,
      "curve-style": "bezier",
    },
  },
  { selector: "node:selected", style: { "border-width": 4, "border-color": "#ffffff", color: "#ffffff", "font-weight": "bold" } },
  { selector: "edge:selected", style: { opacity: 1, width: "mapData(width, 1, 8, 3, 10)" } },
  { selector: ".faded", style: { opacity: 0.12 } },
  { selector: "edge.focus", style: { opacity: 0.95 } },
];

export function createGraph(container, { onNode, onEdge, onClear }) {
  const cy = cytoscape({
    container,
    style: STYLE,
    minZoom: 0.15,
    maxZoom: 4,
    userZoomingEnabled: false,
    boxSelectionEnabled: false,
  });

  // Plain scrolling moves the page; Ctrl + scroll (or a trackpad pinch) zooms the graph.
  container.addEventListener("wheel", (event) => {
    if (!event.ctrlKey && !event.metaKey) return;
    event.preventDefault();
    const rect = container.getBoundingClientRect();
    cy.zoom({
      level: cy.zoom() * Math.exp(-event.deltaY * 0.002),
      renderedPosition: { x: event.clientX - rect.left, y: event.clientY - rect.top },
    });
  }, { passive: false });

  cy.on("tap", "node", (event) => {
    focus(event.target);
    onNode(event.target.id(), event.target.data());
  });
  cy.on("tap", "edge", (event) => {
    const edge = event.target;
    cy.elements().addClass("faded");
    edge.removeClass("faded").addClass("focus");
    edge.connectedNodes().removeClass("faded");
    onEdge(edge.data());
  });
  cy.on("tap", (event) => {
    if (event.target === cy) {
      clearFocus();
      onClear();
    }
  });

  function focus(node) {
    cy.elements().removeClass("focus").addClass("faded");
    node.closedNeighborhood().removeClass("faded");
    node.connectedEdges().addClass("focus");
  }

  function clearFocus() {
    cy.elements().removeClass("faded focus").unselect();
  }

  function layout() {
    cy.layout({
      name: "cose",
      animate: false,
      randomize: true,
      nodeRepulsion: () => 400000,
      idealEdgeLength: () => 140,
      edgeElasticity: () => 60,
      nodeOverlap: 20,
      gravity: 0.25,
      numIter: 1500,
      padding: 40,
    }).run();
    cy.fit(undefined, 40);
  }

  return {
    render({ nodes, edges }) {
      cy.elements().remove();
      cy.add(nodes.map((n) => ({
        group: "nodes",
        data: {
          ...n,
          color: n.internal ? NODE_INTERNAL : NODE_EXTERNAL,
          size: clamp(14 + Math.log10(Math.max(n.bytes, 1)) * 6, 18, 60),
        },
      })));
      cy.add(edges.map((e) => ({
        group: "edges",
        data: {
          ...e,
          id: `${e.source}|${e.target}`,
          color: PROTOCOL_COLORS[e.protocol] || PROTOCOL_COLORS.Other,
          width: clamp(1 + Math.log10(e.packets) * 1.8, 1, 8),
        },
      })));
      layout();
    },
    relayout: layout,
    fit: () => cy.fit(undefined, 40),
    clear: clearFocus,
    select(ip) {
      const node = cy.getElementById(ip);
      if (!node.length) return false;
      cy.elements().unselect();
      node.select();
      focus(node);
      cy.animate({ center: { eles: node }, zoom: Math.max(cy.zoom(), 1.2) }, { duration: 300 });
      return true;
    },
    edgesOf(ip) {
      return cy.getElementById(ip).connectedEdges().map((e) => e.data());
    },
    has: (ip) => cy.getElementById(ip).length > 0,
    resize: () => cy.resize(),
  };
}
