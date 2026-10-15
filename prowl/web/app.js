"use strict";
const $ = (s) => document.querySelector(s);
const esc = (s) => String(s == null ? "" : s).replace(/[&<>"]/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));

let JOB = null;        // latest job id
let RESULT = null;     // latest result
let POLL = null;
let selected = null;   // selected host ip
let view = "map";

async function api(path, opts) {
  const r = await fetch(path, opts);
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).detail || r.statusText);
  return r.json();
}

async function prefill() {
  try {
    const l = await api("/api/local");
    if (l && l.default) $("#subnet").placeholder = l.default;
  } catch (e) { /* server may still be starting */ }
}

async function startScan(demo) {
  const body = { mode: $("#mode").value, demo: !!demo };
  const subnet = $("#subnet").value.trim();
  if (subnet && !demo) body.subnet = subnet;
  setBusy(true);
  try {
    const job = await api("/api/scan", { method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body) });
    JOB = job.id;
    poll();
  } catch (e) {
    $("#status").textContent = "Error: " + e.message;
    setBusy(false);
  }
}

function poll() {
  clearInterval(POLL);
  POLL = setInterval(async () => {
    if (!JOB) return;
    let job;
    try { job = await api("/api/scan/" + JOB); } catch (e) { return; }
    const p = job.progress || {};
    const pct = p.total ? Math.round((p.done / p.total) * 100) : (job.status === "running" ? 10 : 0);
    $("#progress").hidden = false; $("#bar").style.width = pct + "%";
    $("#status").textContent = `${cap(job.status)} — ${p.phase || ""} ${p.done || 0}/${p.total || 0} probed, ${p.found || 0} found`;
    if (job.result) { RESULT = job.result; render(); }
    if (!["queued", "running"].includes(job.status)) {
      clearInterval(POLL); setBusy(false);
      $("#progress").hidden = true;
      if (job.status === "error") $("#status").textContent = "Scan failed: " + job.error;
      else $("#status").textContent = `Done — ${RESULT ? RESULT.count : 0} hosts on ${RESULT ? RESULT.subnet : "?"}`;
      showDownloads(!!RESULT);
    }
  }, 350);
}

function setBusy(b) {
  $("#scanBtn").disabled = b; $("#demoBtn").disabled = b;
  $("#cancelBtn").hidden = !b;
}

function cap(s) { return s ? s[0].toUpperCase() + s.slice(1) : s; }

function showDownloads(on) {
  for (const [id, fmt] of [["#dlCsv", "csv"], ["#dlJson", "json"], ["#dlHtml", "html"]]) {
    const a = $(id); a.hidden = !on; a.href = `/api/report.${fmt}` + (JOB ? `?job=${JOB}` : "");
    if (fmt !== "csv") a.target = "_blank";
  }
}

function render() {
  if (!RESULT) return;
  view === "map" ? renderMap() : renderTable();
}

function renderMap() {
  $("#map").hidden = false; $("#table").hidden = true;
  const hosts = RESULT.hosts || [];
  const gw = hosts.filter((h) => h.is_gateway);
  const rest = hosts.filter((h) => !h.is_gateway);
  $("#map").innerHTML = [...gw, ...rest].map(nodeHtml).join("") ||
    `<p class="muted">No hosts found.</p>`;
  for (const el of document.querySelectorAll(".node")) el.onclick = () => select(el.dataset.ip);
  if (selected) markSelected();
}

function nodeHtml(h) {
  const tags = [];
  if (h.is_gateway) tags.push(`<span class="chip gw">gateway</span>`);
  if (h.device_class) tags.push(`<span class="chip">${esc(h.device_class)}</span>`);
  (h.services || []).slice(0, 6).forEach((s) =>
    tags.push(`<span class="chip${s.secure ? "" : " bad"}">${esc(s.name || s.port)}</span>`));
  return `<div class="node ${h.is_gateway ? "gw" : ""}" data-ip="${esc(h.ip)}">
    ${h.default_creds ? `<span class="redx" title="Default credentials">✕</span>` : ""}
    <div class="ip">${esc(h.ip)}</div>
    <div class="sub">${esc(h.vendor || h.mac || "unknown")}</div>
    ${h.hostname ? `<div class="sub">${esc(h.hostname)}</div>` : ""}
    <div class="tags">${tags.join("")}</div>
  </div>`;
}

function renderTable() {
  $("#map").hidden = true; $("#table").hidden = false;
  const rows = (RESULT.hosts || []).map((h) => `<tr data-ip="${esc(h.ip)}" style="cursor:pointer">
    <td>${esc(h.ip)}${h.is_gateway ? " *" : ""}</td><td>${esc(h.mac || "—")}</td>
    <td>${esc(h.vendor || "—")}</td><td>${esc(h.hostname || "—")}</td>
    <td>${esc(h.device_class || "—")}</td>
    <td>${(h.services || []).map((s) => s.port).join(", ") || "—"}</td>
    <td>${h.default_creds ? "⚠ default" : ""}</td></tr>`).join("");
  $("#table").innerHTML = `<table><thead><tr><th>IP</th><th>MAC</th><th>Vendor</th>
    <th>Host</th><th>Class</th><th>Ports</th><th>Flags</th></tr></thead><tbody>${rows}</tbody></table>`;
  for (const tr of document.querySelectorAll("#table tr[data-ip]")) tr.onclick = () => select(tr.dataset.ip);
}

function select(ip) {
  selected = ip;
  markSelected();
  const h = (RESULT.hosts || []).find((x) => x.ip === ip);
  if (!h) return;
  const rows = [
    ["IP", esc(h.ip)], ["MAC", esc(h.mac || "—")], ["Vendor", esc(h.vendor || "—")],
    ["Hostname", esc(h.hostname || "—")], ["Class", esc(h.device_class || "—")],
    ["Model", esc(h.model || "—")], ["RTT", h.rtt_ms != null ? h.rtt_ms + " ms" : "—"],
    ["Seen via", esc((h.sources || []).join(", "))],
    ["Confidence", esc(h.confidence)],
  ];
  const svcs = (h.services || []).map(svcRow).join("") ||
    `<p class="muted">No open ports recorded (run Deep mode for services).</p>`;
  $("#detail").innerHTML = `<h3>${esc(h.hostname || h.ip)}</h3>
    ${h.default_creds ? `<p style="color:var(--bad)"><b>✕ Accepts default credentials</b></p>` : ""}
    <dl>${rows.map(([k, v]) => `<dt>${k}</dt><dd>${v}</dd>`).join("")}</dl>
    <h4>Services</h4>${svcs}
    <p class="prov">Facts (ports, MAC) are observed; class/model are best-guess.</p>`;
  for (const b of document.querySelectorAll("#detail [data-launch]"))
    b.onclick = () => launch(b.dataset.proto, h.ip, b.dataset.port);
}

function svcRow(s) {
  const label = `${esc(s.name || "tcp")}/${s.port}${s.secure ? "" : " ⚠"}`;
  const web = s.name === "http" || s.name === "https" || [80, 443, 8080, 8443, 8000, 8888].includes(s.port);
  let action;
  if (web) {
    const scheme = (s.name === "https" || [443, 8443].includes(s.port)) ? "https" : "http";
    action = `<a href="${scheme}://PLACEHOLDER" data-web="${scheme}" data-port="${s.port}" target="_blank" rel="noopener">open ↗</a>`;
  } else {
    action = `<button data-launch data-proto="${esc(s.name || "tcp")}" data-port="${s.port}">launch</button>`;
  }
  return `<div class="svc"><span>${label}</span>${action}</div>`;
}

function launch(proto, ip, port) {
  // Mode-1 slice: real local-client launch (ssh/rdp/vnc) lands with the hardened launcher
  // endpoint in the next build slice. For now, explain and offer the raw URI.
  const uri = { ssh: `ssh://${ip}:${port}`, rdp: `rdp://${ip}`, vnc: `vnc://${ip}`,
    telnet: `telnet://${ip}`, smb: `\\\\${ip}` }[proto] || `${proto}://${ip}:${port}`;
  alert(`Launching ${proto} to ${ip}:${port}\n\nThe hardened local launcher arrives in the next build slice.\n` +
    `For now use: ${uri}`);
}

// fix web links to use the selected host ip at click time
document.addEventListener("click", (e) => {
  const a = e.target.closest("a[data-web]");
  if (!a || !selected) return;
  e.preventDefault();
  const port = a.dataset.port;
  const def = (a.dataset.web === "https" && port == 443) || (a.dataset.web === "http" && port == 80);
  window.open(`${a.dataset.web}://${selected}${def ? "" : ":" + port}/`, "_blank", "noopener");
});

function markSelected() {
  for (const el of document.querySelectorAll(".node"))
    el.classList.toggle("sel", el.dataset.ip === selected);
}

// wiring
$("#scanBtn").onclick = () => startScan(false);
$("#demoBtn").onclick = () => startScan(true);
$("#cancelBtn").onclick = async () => { if (JOB) await api("/api/scan/" + JOB + "/cancel", { method: "POST" }); };
for (const b of document.querySelectorAll(".tabs button[data-view]")) {
  b.onclick = () => {
    view = b.dataset.view;
    for (const x of document.querySelectorAll(".tabs button[data-view]")) x.classList.toggle("on", x === b);
    render();
  };
}
prefill();
