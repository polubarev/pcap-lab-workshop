// Thin wrappers around the PCAP Lab JSON API.

async function request(url, options = {}) {
  const response = await fetch(url, options);
  let body = null;
  try {
    body = await response.json();
  } catch {
    // not JSON
  }
  if (!response.ok) {
    throw new Error(body?.error || `Request failed (${response.status})`);
  }
  return body;
}

export const api = {
  samples: () => request("/api/samples"),
  openSample: (file) => request(`/api/samples/${encodeURIComponent(file)}/open`, { method: "POST" }),
  upload: (file) => {
    const form = new FormData();
    form.append("file", file);
    return request("/api/captures", { method: "POST", body: form });
  },
  graph: (id, { protocol = "", minPackets = 1 } = {}) =>
    request(`/api/captures/${id}/graph?` + new URLSearchParams({ protocol, min_packets: minPackets })),
  host: (id, ip) => request(`/api/captures/${id}/hosts/${encodeURIComponent(ip)}`),
  packets: (id, filters, offset, limit) => {
    const params = new URLSearchParams({ offset, limit });
    for (const [key, value] of Object.entries(filters)) {
      if (value !== "" && value !== null && value !== undefined) params.set(key, value);
    }
    return request(`/api/captures/${id}/packets?` + params);
  },
  packet: (id, index) => request(`/api/captures/${id}/packets/${index}`),
};
