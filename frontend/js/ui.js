// DOM and formatting helpers. Text is always set with textContent, never innerHTML,
// so values from a capture (host names, payload text) cannot inject markup.

export function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (value === null || value === undefined || value === false) continue;
    if (key === "class") node.className = value;
    else if (key === "dataset") Object.assign(node.dataset, value);
    else if (key.startsWith("on")) node.addEventListener(key.slice(2), value);
    else if (key === "style") node.style.cssText = value;
    else node.setAttribute(key, value === true ? "" : value);
  }
  for (const child of children.flat()) {
    if (child === null || child === undefined || child === false) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}

export function svg(tag, attrs = {}) {
  const node = document.createElementNS("http://www.w3.org/2000/svg", tag);
  for (const [key, value] of Object.entries(attrs)) node.setAttribute(key, value);
  return node;
}

export const fmt = {
  number: (n) => Number(n || 0).toLocaleString("en-US"),
  bytes(n) {
    n = Number(n || 0);
    if (n < 1024) return `${n} B`;
    if (n < 1024 ** 2) return `${(n / 1024).toFixed(1)} KB`;
    if (n < 1024 ** 3) return `${(n / 1024 ** 2).toFixed(1)} MB`;
    return `${(n / 1024 ** 3).toFixed(2)} GB`;
  },
  duration(seconds) {
    seconds = Number(seconds || 0);
    if (seconds < 60) return `${seconds.toFixed(1)} s`;
    const m = Math.floor(seconds / 60);
    const s = Math.round(seconds % 60);
    return `${m} min ${String(s).padStart(2, "0")} s`;
  },
  clock(seconds) {
    const m = Math.floor(seconds / 60);
    const s = Math.floor(seconds % 60);
    return `${m}:${String(s).padStart(2, "0")}`;
  },
  datetime(epochSeconds) {
    if (!epochSeconds) return "";
    return new Date(epochSeconds * 1000).toLocaleString("en-GB", { dateStyle: "medium", timeStyle: "medium" });
  },
};

export const PROTOCOL_COLORS = {
  TCP: "#4589ff", UDP: "#33c3b2", ICMP: "#fa6b6b", ARP: "#a98bff", Other: "#7d8aa6", Mixed: "#c7d0e3",
};

let toastTimer = null;
export function toast(message) {
  const box = document.getElementById("toast");
  box.textContent = message;
  box.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => (box.hidden = true), 6000);
}

export function loading(text) {
  const overlay = document.getElementById("loading");
  if (text) {
    document.getElementById("loading-text").textContent = text;
    overlay.hidden = false;
  } else {
    overlay.hidden = true;
  }
}
