"use strict";

const TOKEN_KEY = "ltm_token";
const REFRESH_MS = 30000;
const RISK_LABELS = { safe: "sans risque", low: "réversible", disruptive: "interrompt le service" };
const state = { top: "cpu", openProblems: new Set(), detailTask: null, timer: null };
const $ = (sel) => document.querySelector(sel);

function esc(value) {
  return String(value ?? "").replace(/[&<>"']/g, (c) => (
    { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]
  ));
}

function fmtPct(v) { return v == null ? "–" : `${Number(v).toFixed(1)} %`; }
function fmtNum(v, d = 2) { return v == null ? "–" : Number(v).toFixed(d); }
function fmtBytes(v) {
  if (v == null) return "–";
  const units = ["o", "Ko", "Mo", "Go", "To"];
  let i = 0;
  let n = Number(v);
  while (n >= 1024 && i < units.length - 1) { n /= 1024; i += 1; }
  return `${n.toFixed(n >= 100 || i === 0 ? 0 : 1)} ${units[i]}`;
}
function parseTs(ts) { return new Date(ts); }
function fmtTime(ts) {
  return parseTs(ts).toLocaleString("fr-FR", { dateStyle: "short", timeStyle: "short" });
}
function level(v, warn = 75, crit = 90) {
  if (v == null) return "";
  if (v >= crit) return "critical";
  return v >= warn ? "warning" : "";
}

class Unauthorized extends Error {}

async function api(path, options = {}) {
  const headers = {};
  const token = localStorage.getItem(TOKEN_KEY);
  if (token) headers.Authorization = `Bearer ${token}`;
  const res = await fetch(path, { ...options, headers });
  if (res.status === 401) throw new Unauthorized();
  if (!res.ok) throw new Error(`${path} : HTTP ${res.status}`);
  return res.json();
}

function showLogin() {
  $("#app").hidden = true;
  $("#login").hidden = false;
  $("#token").focus();
}

function renderSummary(sm) {
  const title = sm.source === "ai" ? `Résumé IA <span class="muted">${esc(sm.model)}</span>` : "Résumé";
  const when = sm.created_at ? `<span class="muted">· ${esc(fmtTime(sm.created_at))}</span>` : "";
  const error = sm.error ? `<p class="muted">IA indisponible (${esc(sm.error)}) : résumé automatique affiché.</p>` : "";
  const text = esc(sm.text).replace(/`([^`]+)`/g, "<code>$1</code>");
  $("#summary").innerHTML = `<h2>${title} ${when}</h2><div class="text">${text}</div>${error}`;
}

function renderCards(s, problems) {
  const loadRatio = s.load1 != null && s.cpu_count ? (s.load1 / s.cpu_count) * 100 : null;
  const open = problems.filter((p) => !isAcked(p));
  const critical = open.filter((p) => p.severity === "critical").length;
  const cards = [
    ["Problèmes ouverts", String(open.length), critical ? "critical" : open.length ? "warning" : ""],
    ["CPU", fmtPct(s.cpu_percent), level(s.cpu_percent)],
    ["Mémoire", fmtPct(s.memory_percent), level(s.memory_percent)],
    ["Swap", fmtPct(s.swap_percent), level(s.swap_percent, 50, 80)],
    [`Charge 1 min (${s.cpu_count ?? "?"} cœurs)`, fmtNum(s.load1), level(loadRatio, 100, 200)],
    ["Attente disque (iowait)", fmtPct(s.iowait_percent), level(s.iowait_percent, 10, 25)],
    ["Pression mémoire (PSI)", fmtPct(s.psi_memory_some), level(s.psi_memory_some, 10, 25)],
  ];
  $("#cards").innerHTML = cards.map(([label, value, cls]) => `
    <div class="card ${cls}"><div class="label">${esc(label)}</div>
    <div class="value">${esc(value)}</div></div>`).join("");
}

function lineChart(el, rows, series, { max = null, format = (v) => fmtNum(v, 0) } = {}) {
  const points = rows.filter((r) => r.timestamp);
  if (points.length < 2) {
    el.innerHTML = `<div class="empty">Pas encore assez de données.</div>`;
    return;
  }
  const W = Math.max(el.clientWidth - 16, 300);
  const H = 200;
  const pad = { l: 56, r: 8, t: 8, b: 20 };
  const xs = points.map((r) => parseTs(r.timestamp).getTime());
  const x0 = Math.min(...xs);
  const x1 = Math.max(...xs);
  const values = points.flatMap((r) => series.map((s) => r[s.key]).filter((v) => v != null));
  const yMax = max ?? Math.max(1, ...values) * 1.1;
  const x = (t) => pad.l + ((t - x0) / (x1 - x0 || 1)) * (W - pad.l - pad.r);
  const y = (v) => H - pad.b - (v / yMax) * (H - pad.t - pad.b);
  let svg = "";
  for (let i = 0; i <= 4; i += 1) {
    const v = (yMax * i) / 4;
    svg += `<line class="grid" x1="${pad.l}" x2="${W - pad.r}" y1="${y(v)}" y2="${y(v)}"/>`;
    svg += `<text x="${pad.l - 4}" y="${y(v) + 3}" text-anchor="end">${esc(format(v))}</text>`;
  }
  for (let i = 0; i <= 3; i += 1) {
    const t = x0 + ((x1 - x0) * i) / 3;
    const label = new Date(t).toLocaleTimeString("fr-FR", { hour: "2-digit", minute: "2-digit" });
    const anchor = i === 0 ? "start" : i === 3 ? "end" : "middle";
    svg += `<text x="${x(t)}" y="${H - 4}" text-anchor="${anchor}">${label}</text>`;
  }
  for (const s of series) {
    let d = "";
    points.forEach((r, i) => {
      const v = r[s.key];
      if (v == null) return;
      d += `${d ? "L" : "M"}${x(xs[i]).toFixed(1)},${y(v).toFixed(1)}`;
    });
    if (d) svg += `<path d="${d}" fill="none" stroke="${s.color}" stroke-width="1.6"/>`;
  }
  const legend = series.map((s) => `<span><i style="background:${s.color}"></i>${esc(s.label)}</span>`);
  el.innerHTML = `<svg viewBox="0 0 ${W} ${H}" preserveAspectRatio="none">${svg}</svg>
    <div class="legend">${legend.join("")}</div>`;
}

function renderCharts(history) {
  const css = getComputedStyle(document.documentElement);
  const color = (name) => css.getPropertyValue(name).trim();
  lineChart($("#chart-usage"), history, [
    { key: "cpu_percent", label: "CPU", color: color("--cpu") },
    { key: "memory_percent", label: "Mémoire", color: color("--mem") },
    { key: "swap_percent", label: "Swap", color: color("--swap") },
  ], { max: 100 });
  lineChart($("#chart-load"), history, [
    { key: "load1", label: "Charge 1 min", color: color("--load") },
    { key: "cpu_count", label: "Nombre de cœurs", color: color("--muted") },
    { key: "iowait_percent", label: "iowait %", color: color("--io") },
  ], { format: (v) => fmtNum(v, 1) });
}

function renderDisks(disks) {
  if (!disks.length) {
    $("#disks").innerHTML = `<tr><td class="muted">Aucun disque mesuré.</td></tr>`;
    return;
  }
  $("#disks").innerHTML = `<tr><th>Point de montage</th><th>Utilisé</th><th class="num">Libre</th>
    <th class="num">Inodes</th></tr>` + disks.map((d) => `
    <tr><td>${esc(d.mountpoint)} <span class="muted">${esc(d.fstype)}</span></td>
    <td><div class="bar ${level(d.used_percent, 85, 95)}">
      <span style="width:${Math.min(100, d.used_percent ?? 0)}%"></span></div>
      <span class="muted">${fmtPct(d.used_percent)} de ${fmtBytes(d.total_bytes)}</span></td>
    <td class="num">${fmtBytes(d.free_bytes)}</td>
    <td class="num">${fmtPct(d.inodes_percent)}</td></tr>`).join("");
}

function isAcked(p) { return p.acked_until && parseTs(p.acked_until) > new Date(); }

function renderProblem(p) {
  const r = p.recommendation || {};
  const acked = isAcked(p);
  const causes = (r.probable_causes || []).map((c) => `<li>${esc(c)}</li>`).join("");
  const actions = (r.actions || []).map((a) => `
    <div class="action"><span class="badge ${esc(a.risk)}">${esc(RISK_LABELS[a.risk] || a.risk)}</span>
    <span>${esc(a.title)}</span>
    ${a.command ? `<code>${esc(a.command)}</code>
      <button type="button" data-copy="${esc(a.command)}" title="Copier">Copier</button>` : ""}
    </div>`).join("");
  const diagnostics = (r.diagnostics || []).map((d) => `
    <details><summary>${esc(d.title)} ${d.command ? `<code class="muted">${esc(d.command)}</code>` : ""}</summary>
    <pre>${esc(d.output)}</pre></details>`).join("");
  const ackButton = acked
    ? `<button type="button" data-ack="${p.id}" data-hours="0">Ne plus ignorer</button>`
    : `<button type="button" data-ack="${p.id}" data-hours="24">Ignorer 24 h</button>`;
  return `<details class="problem ${esc(p.severity)} ${acked ? "acked" : ""}" data-id="${p.id}"
      ${state.openProblems.has(p.id) ? "open" : ""}>
    <summary><span class="badge ${esc(p.severity)}">${esc(p.severity)}</span>
      <strong>${esc(r.summary || p.title)}</strong>
      <span class="muted">depuis ${esc(fmtTime(p.first_seen))}${acked ? ` · ignoré jusqu'à ${esc(fmtTime(p.acked_until))}` : ""}</span>
    </summary>
    <div class="body">
      ${causes ? `<h3>Causes probables</h3><ul>${causes}</ul>` : ""}
      ${actions ? `<h3>Actions proposées (non exécutées)</h3>${actions}` : ""}
      ${diagnostics ? `<h3>Diagnostics recueillis</h3>${diagnostics}` : ""}
      <h3>Données</h3><pre>${esc(JSON.stringify(p.evidence, null, 2))}</pre>
      <p>${ackButton}</p>
    </div></details>`;
}

function renderProblems(problems) {
  const open = problems.filter((p) => !isAcked(p)).length;
  $("#problem-count").textContent = `${open} ouvert(s), ${problems.length - open} ignoré(s)`;
  $("#problems").innerHTML = problems.length
    ? problems.map(renderProblem).join("")
    : `<div class="empty">Aucun problème détecté.</div>`;
}

function renderTaskRows(tasks) {
  if (!tasks.length) return `<tr><td class="muted">Aucune tâche.</td></tr>`;
  return `<tr><th>Tâche</th><th class="num">CPU</th><th class="num">Mémoire</th>
    <th class="num">Processus</th></tr>` + tasks.map((t) => `
    <tr class="clickable" data-task="${esc(t.task_id)}">
      <td>${esc(t.name)} <span class="muted">${esc(t.unit && t.unit !== t.name ? t.unit : t.category)}</span>
        ${t.status && t.status !== "ok" ? `<span class="badge ${esc(t.status)}">${esc(t.status)}</span>` : ""}</td>
      <td class="num">${fmtPct(t.cpu_percent)}</td>
      <td class="num">${t.rss_bytes != null ? fmtBytes(t.rss_bytes) : "–"}</td>
      <td class="num">${esc(t.process_count ?? "–")}</td></tr>`).join("");
}

async function loadTasks() {
  const q = $("#search").value.trim();
  const tasks = q
    ? await api(`/tasks?state=active&limit=50&name=${encodeURIComponent(q)}`)
    : await api(`/tasks/top?by=${state.top}&limit=15`);
  $("#tasks").innerHTML = renderTaskRows(tasks);
}

async function showTask(taskId) {
  state.detailTask = taskId;
  const id = encodeURIComponent(taskId);
  const [task, history] = await Promise.all([
    api(`/tasks/${id}`), api(`/tasks/${id}/history?limit=1000`),
  ]);
  const el = $("#task-detail");
  el.hidden = false;
  const kind = task.unit && task.unit !== task.name ? task.unit : task.category;
  el.innerHTML = `<header><h2>${esc(task.name)} <span class="muted">${esc(kind)}
      · ${esc(task.state)} · vu depuis ${esc(fmtTime(task.first_seen))}</span></h2>
      <button type="button" id="close-task">Fermer</button></header>
    ${task.command ? `<pre>${esc(task.command)}</pre>` : ""}
    <div class="grid2"><div><h2>CPU (%)</h2><div id="chart-task-cpu" class="chart"></div></div>
    <div><h2>Mémoire (RSS)</h2><div id="chart-task-mem" class="chart"></div></div></div>
    <h2>Problèmes de la tâche</h2>
    ${task.open_findings.length ? "" : `<div class="empty">Aucun problème ouvert.</div>`}
    <div id="task-problems"></div>`;
  const rows = history.slice().reverse();
  lineChart($("#chart-task-cpu"), rows, [{ key: "cpu_percent", label: "CPU", color: "#2563eb" }]);
  lineChart($("#chart-task-mem"), rows, [{ key: "rss_bytes", label: "RSS", color: "#9333ea" }],
    { format: fmtBytes });
  if (task.open_findings.length) {
    const ids = new Set(task.open_findings.map((f) => f.id));
    const recs = await api("/recommendations?include_acked=true");
    $("#task-problems").innerHTML = recs.filter((p) => ids.has(p.id)).map(renderProblem).join("");
  }
  el.scrollIntoView({ behavior: "smooth" });
}

async function refresh() {
  try {
    const hours = $("#hours").value;
    const [latest, history, disks, problems, summary] = await Promise.all([
      api("/system/latest"),
      api(`/system/history?hours=${hours}`),
      api("/disks/latest"),
      api("/recommendations?include_acked=true"),
      api("/summary"),
    ]);
    $("#login").hidden = true;
    $("#app").hidden = false;
    $("#host").textContent = latest.hostname || "";
    $("#updated").textContent = latest.timestamp ? `dernière mesure ${fmtTime(latest.timestamp)}` : "aucune donnée";
    renderSummary(summary);
    renderCards(latest, problems);
    renderProblems(problems);
    renderCharts(history);
    renderDisks(disks);
    await loadTasks();
  } catch (err) {
    if (err instanceof Unauthorized) { showLogin(); return; }
    $("#updated").innerHTML = `<span class="error">${esc(err.message)}</span>`;
  }
}

function copy(text, button) {
  const done = () => { button.textContent = "Copié"; setTimeout(() => { button.textContent = "Copier"; }, 1500); };
  if (navigator.clipboard && window.isSecureContext) {
    navigator.clipboard.writeText(text).then(done);
    return;
  }
  const area = document.createElement("textarea");
  area.value = text;
  document.body.appendChild(area);
  area.select();
  document.execCommand("copy");
  area.remove();
  done();
}

document.addEventListener("click", async (ev) => {
  const target = ev.target.closest("[data-copy],[data-ack],[data-top],[data-task],#close-task,#refresh");
  if (!target) return;
  if (target.dataset.copy) copy(target.dataset.copy, target);
  else if (target.dataset.ack) {
    await api(`/findings/${target.dataset.ack}/ack?hours=${target.dataset.hours}`, { method: "POST" });
    await refresh();
    if (state.detailTask) await showTask(state.detailTask);
  } else if (target.dataset.top) {
    state.top = target.dataset.top;
    document.querySelectorAll("[data-top]").forEach((b) => b.classList.toggle("active", b === target));
    $("#search").value = "";
    await loadTasks();
  } else if (target.dataset.task) await showTask(target.dataset.task);
  else if (target.id === "close-task") { $("#task-detail").hidden = true; state.detailTask = null; }
  else if (target.id === "refresh") await refresh();
});

document.addEventListener("toggle", (ev) => {
  const el = ev.target;
  if (!el.classList || !el.classList.contains("problem")) return;
  const id = Number(el.dataset.id);
  if (el.open) state.openProblems.add(id); else state.openProblems.delete(id);
}, true);

let searchTimer;
$("#search").addEventListener("input", () => {
  clearTimeout(searchTimer);
  searchTimer = setTimeout(loadTasks, 300);
});
$("#hours").addEventListener("change", refresh);
$("#login").addEventListener("submit", (ev) => {
  ev.preventDefault();
  localStorage.setItem(TOKEN_KEY, $("#token").value.trim());
  refresh();
});

refresh();
state.timer = setInterval(refresh, REFRESH_MS);
