// Traffic-over-time bar chart (packets per time bucket), drawn as inline SVG.
import { fmt, svg } from "./ui.js";

export function renderTimeline(container, caption, buckets, duration) {
  container.replaceChildren();
  if (!buckets.length) return;

  const width = container.clientWidth - 32 || 800;
  const height = 112;
  const left = 44, bottom = 20, top = 6;
  const plotW = width - left;
  const plotH = height - bottom - top;
  const max = Math.max(...buckets.map((b) => b.packets), 1);
  const bucketWidth = duration / buckets.length;

  const root = svg("svg", { viewBox: `0 0 ${width} ${height}`, preserveAspectRatio: "none" });

  for (const fraction of [0, 0.5, 1]) {
    const y = top + plotH * (1 - fraction);
    root.append(svg("line", { class: "gridline", x1: left, x2: width, y1: y, y2: y }));
    const label = svg("text", { class: "axis", x: left - 8, y: y + 4, "text-anchor": "end" });
    label.textContent = fmt.number(Math.round(max * fraction));
    root.append(label);
  }

  const slot = plotW / buckets.length;
  buckets.forEach((b, i) => {
    const h = (b.packets / max) * plotH;
    const rect = svg("rect", {
      class: "bar", x: left + i * slot + 1, y: top + plotH - h, width: Math.max(slot - 2, 1), height: Math.max(h, 0), rx: 2,
    });
    const title = svg("title");
    title.textContent = `${fmt.clock(b.t)}–${fmt.clock(b.t + bucketWidth)}: ${fmt.number(b.packets)} packets, ${fmt.bytes(b.bytes)}`;
    rect.append(title);
    root.append(rect);
  });

  for (const fraction of [0, 0.25, 0.5, 0.75, 1]) {
    const x = left + plotW * fraction;
    const label = svg("text", {
      class: "axis", x, y: height - 4, "text-anchor": fraction === 0 ? "start" : fraction === 1 ? "end" : "middle",
    });
    label.textContent = fmt.clock(duration * fraction);
    root.append(label);
  }

  container.append(root);
  caption.textContent = `Packets per ${bucketWidth.toFixed(1)} s · peak ${fmt.number(max)}`;
}
