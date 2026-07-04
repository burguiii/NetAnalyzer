/* ===== Monitor de Red · Frontend ===== */
const $ = (s) => document.querySelector(s);
const $$ = (s) => document.querySelectorAll(s);

const VIEWS = {
  conexiones: { title: "Conexiones activas",  sub: "Todo lo que tu PC está enviando y recibiendo ahora mismo." },
  mapa:       { title: "Mapa mundial",         sub: "De dónde salen y a dónde van tus conexiones, en tiempo real." },
  alertas:    { title: "Alertas",             sub: "Patrones sospechosos detectados automáticamente." },
  historico:  { title: "Histórico",           sub: "Busca conexiones pasadas por IP o proceso." },
  confianza:  { title: "IPs de confianza",     sub: "Direcciones que tú marcaste como conocidas y seguras." },
  bloqueadas: { title: "IPs bloqueadas",       sub: "Reglas de firewall creadas por esta app." },
};

let currentView = "conexiones";
let connsCache = [];

/* ---------- Navegación ---------- */
$$(".menu-item").forEach((b) => {
  b.addEventListener("click", () => switchView(b.dataset.view));
});

function switchView(view) {
  currentView = view;
  $$(".menu-item").forEach((b) => b.classList.toggle("active", b.dataset.view === view));
  $$(".view").forEach((v) => (v.hidden = v.id !== `view-${view}`));
  $("#viewTitle").textContent = VIEWS[view].title;
  $("#viewSubtitle").textContent = VIEWS[view].sub;
  $("#cards").style.display = view === "conexiones" ? "grid" : "none";
  if (view === "alertas") loadAlerts();
  if (view === "bloqueadas") loadBlocked();
  if (view === "confianza") loadTrusted();
  // El mapa consume CPU animando: solo corre mientras su vista está abierta.
  if (view === "mapa") WorldMap.start();
  else WorldMap.stop();
}

/* ---------- Utilidades ---------- */
function flagEmoji(cc) {
  if (!cc || cc.length !== 2) return "";
  return cc.toUpperCase().replace(/./g, (c) =>
    String.fromCodePoint(127397 + c.charCodeAt(0)));
}

function reputationTag(score) {
  if (score === null || score === undefined)
    return `<span class="tag tag-neutral">sin datos</span>`;
  if (score >= 50) return `<span class="tag tag-bad">⚠ ${score}/100</span>`;
  if (score >= 15) return `<span class="tag tag-warn">${score}/100</span>`;
  return `<span class="tag tag-ok">✓ limpia</span>`;
}

function stateClass(status) {
  const s = (status || "").toLowerCase();
  if (s.includes("establ")) return "state-established";
  if (s.includes("escuch")) return "state-listen";
  return "state-other";
}

function toast(msg, type = "") {
  const t = $("#toast");
  t.textContent = msg;
  t.className = "toast " + type;
  t.hidden = false;
  clearTimeout(t._timer);
  t._timer = setTimeout(() => (t.hidden = true), 3500);
}

/* ---------- Conexiones (en vivo) ---------- */
async function loadConnections() {
  try {
    const r = await fetch("/api/connections");
    const data = await r.json();
    connsCache = data.connections;
    renderConnections();
    updateCards(data);
    updateAlertBadge(data.pending_alerts);
  } catch (e) {
    $("#connsBody").innerHTML = `<tr><td colspan="9" class="empty">No se pudo conectar con el backend.</td></tr>`;
  }
}

function updateCards(data) {
  const ips = new Set(connsCache.map((c) => c.remote_ip));
  const countries = new Set(connsCache.map((c) => c.country).filter(Boolean));
  $("#statConns").textContent = data.total;
  $("#statIps").textContent = ips.size;
  $("#statCountries").textContent = countries.size;
  $("#statAlerts").textContent = data.pending_alerts;
}

function updateAlertBadge(n) {
  const b = $("#alertBadge");
  if (n > 0) { b.textContent = n; b.hidden = false; }
  else b.hidden = true;
}

const VERDICT = {
  ok:      { dot: "ok",      label: "Normal",       icon: "🟢" },
  warn:    { dot: "warn",    label: "Revisar",      icon: "🟡" },
  bad:     { dot: "bad",     label: "¡Peligro!",    icon: "🔴" },
  unknown: { dot: "unknown", label: "Verificando…", icon: "⚪" },
};
const DIRLABEL = {
  "Saliente":  `<span class="dir dir-out">⬆️ Saliente</span>`,
  "Entrante":  `<span class="dir dir-in">⬇️ Entrante</span>`,
  "Local":     `<span class="dir dir-local">🔁 Interna</span>`,
  "En escucha":`<span class="dir dir-listen">👂 En escucha</span>`,
};
let expandedKey = null;

function connKey(c) { return `${c.pid}-${c.remote_ip}-${c.remote_port}`; }

function renderConnections() {
  const filter = $("#filterConns").value.toLowerCase();
  const hideKnown = $("#hideKnown").checked;
  let rows = connsCache;
  if (hideKnown) {
    rows = rows.filter((c) => {
      const v = (c.explain || {}).verdict;
      return v === "bad" || v === "warn" || (c.explain || {}).direction === "Entrante";
    });
  }
  if (filter) {
    rows = rows.filter((c) =>
      (c.process_name || "").toLowerCase().includes(filter) ||
      (c.remote_ip || "").includes(filter) ||
      (c.country || "").toLowerCase().includes(filter) ||
      ((c.explain || {}).who || "").toLowerCase().includes(filter));
  }
  if (!rows.length) {
    $("#connsBody").innerHTML = `<tr><td colspan="7" class="empty">Sin conexiones que coincidan. 🎉</td></tr>`;
    return;
  }
  $("#connsBody").innerHTML = rows.map((c) => {
    const e = c.explain || {};
    const v = VERDICT[e.verdict] || VERDICT.unknown;
    const flag = c.country_code ? `<span class="flag">${flagEmoji(c.country_code)}</span>` : "";
    const key = connKey(c);
    const isOpen = key === expandedKey;
    const mainRow = `<tr class="conn-row ${isOpen ? "open" : ""}" onclick="toggleRow('${key}')">
      <td title="${v.label}"><span class="dot ${v.dot}"></span></td>
      <td><div class="proc"><span class="proc-dot"></span>${esc(c.process_name)}</div></td>
      <td>${DIRLABEL[e.direction] || "-"}</td>
      <td>${flag}${esc(e.who || c.remote_ip)}</td>
      <td><span class="svc">${esc(e.service || "-")}</span></td>
      <td>${e.trusted ? `<span class="tag tag-ok">✅ De confianza</span> ` : ""}${reputationTag(c.abuse_score)}</td>
      <td class="chev">${isOpen ? "▲" : "▼"}</td>
    </tr>`;
    if (!isOpen) return mainRow;
    return mainRow + detailRow(c, e, v);
  }).join("");
}

function detailRow(c, e, v) {
  const steps = (e.advice || []).map((s) => `<li>${esc(s)}</li>`).join("");
  const bloqueable = e.ip_kind === "internet";
  return `<tr class="detail-row"><td></td><td colspan="6">
    <div class="detail ${v.dot}">
      <div class="detail-verdict">${v.icon} <b>${v.label}</b></div>
      <p class="detail-summary">${esc(e.summary || "")}</p>
      <div class="detail-grid">
        <div><span class="dl">¿Qué es?</span> ${esc(e.service)} — <span class="muted">${esc(e.service_desc || "")}</span></div>
        <div><span class="dl">¿Con quién?</span> ${esc(e.who)}</div>
        <div><span class="dl">¿Lo causaste tú?</span> ${esc(e.caused_by_you || "")}</div>
        <div><span class="dl">Datos técnicos</span> <span class="mono muted">${esc(c.remote_ip)}:${c.remote_port} · ${c.protocol} · ${esc(c.status)} · PID ${c.pid || "-"}</span></div>
        ${c.process_path ? `<div><span class="dl">Programa</span> <span class="mono muted">${esc(c.process_path)}</span></div>` : ""}
      </div>
      <div class="detail-advice">
        <span class="dl">¿Qué hago?</span>
        <ul>${steps}</ul>
      </div>
      ${e.note ? `<div class="detail-note">ℹ️ ${esc(e.note)}</div>` : ""}
      <div class="detail-buttons">
        ${bloqueable && !e.trusted ? `<button class="btn btn-trust btn-sm" onclick="event.stopPropagation(); trustIp('${c.remote_ip}','')">✅ Marcar de confianza</button>` : ""}
        ${e.trusted ? `<button class="btn btn-sm" onclick="event.stopPropagation(); untrustIp('${c.remote_ip}')">Quitar de confianza</button>` : ""}
        ${bloqueable ? `<button class="btn btn-danger btn-sm" onclick="event.stopPropagation(); blockIp('${c.remote_ip}')">🛡️ Bloquear ${esc(c.remote_ip)}</button>` : ""}
      </div>
    </div>
  </td></tr>`;
}

function toggleRow(key) {
  expandedKey = expandedKey === key ? null : key;
  renderConnections();
}
$("#hideKnown").addEventListener("change", renderConnections);

function esc(s) {
  return String(s ?? "").replace(/[&<>"]/g, (m) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[m]));
}

/* ---------- Alertas ---------- */
async function loadAlerts() {
  const onlyPending = $("#onlyPending").checked;
  const r = await fetch(`/api/alerts?resuelta=${onlyPending ? "false" : "all"}`);
  const { alerts } = await r.json();
  const list = $("#alertsList");
  if (!alerts.length) {
    list.innerHTML = `<div class="empty">Sin alertas por ahora. 🎉</div>`;
    return;
  }
  const icons = { Alta: "🚨", Media: "⚠️", Baja: "🔔" };
  const dirTxt = {
    "Entrante": `<span class="dir dir-in">⬇️ Vino de fuera (no lo causaste tú)</span>`,
    "Saliente": `<span class="dir dir-out">⬆️ Salió de tu PC (una app la inició)</span>`,
  };
  list.innerHTML = alerts.map((a) => {
    const flag = a.country_code ? flagEmoji(a.country_code) : "";
    const whoLine = a.who
      ? `<div class="alert-who">🌐 <b>¿De dónde viene?</b> ${flag} ${esc(a.who)}</div>`
      : "";
    const ruleJs = encodeURIComponent(a.rule);
    return `
    <div class="alert-card sev-${a.severity.toLowerCase()}">
      <div class="alert-icon">${icons[a.severity] || "⚠️"}</div>
      <div class="alert-body">
        <div class="alert-title">${esc(a.rule)} <span class="alert-sev">${a.severity}</span></div>
        <div class="alert-desc">${esc(a.description)}</div>
        ${whoLine}
        ${a.direction ? `<div class="alert-dir">${dirTxt[a.direction] || ""}</div>` : ""}
        ${a.advice ? `<div class="alert-advice-box"><b>¿Qué significa y qué hago?</b><br>${esc(a.advice)}</div>` : ""}
        <div class="alert-meta">🕑 ${a.timestamp}${a.remote_ip ? " · 📍 " + esc(a.remote_ip) : ""}${a.process_name ? " · ⚙ " + esc(a.process_name) : ""}</div>
      </div>
      <div class="alert-actions">
        ${a.resuelta ? `<span class="tag tag-ok">revisada</span>` :
          `<button class="btn btn-sm" onclick="resolveAlert(${a.id})">✓ Entendido</button>`}
        ${a.remote_ip ? `<button class="btn btn-trust btn-sm" title="No volver a avisar de ESTO desde esta IP" onclick="trustIp('${a.remote_ip}','${ruleJs}')">✅ Es de confianza</button>` : ""}
        ${a.remote_ip ? `<button class="btn btn-danger btn-sm" onclick="blockIp('${a.remote_ip}')">🛡️ Bloquear IP</button>` : ""}
      </div>
    </div>`;
  }).join("");
}

async function resolveAlert(id) {
  await fetch(`/api/alerts/${id}/resolver`, { method: "POST" });
  toast("Alerta marcada como revisada.", "ok");
  loadAlerts();
}

$("#onlyPending").addEventListener("change", loadAlerts);

/* ---------- Bloqueo de IP ---------- */
async function blockIp(ip) {
  if (!confirm(`¿Bloquear la IP ${ip} en el Firewall de Windows?\n\nSe cortará toda comunicación con esta dirección.`)) return;
  const r = await fetch("/api/block", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ ip }),
  });
  const d = await r.json();
  toast(d.message, d.ok ? "ok" : "err");
}

async function unblockIp(ip) {
  if (!confirm(`¿Desbloquear la IP ${ip}?`)) return;
  const r = await fetch("/api/unblock", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ ip }),
  });
  const d = await r.json();
  toast(d.message, d.ok ? "ok" : "err");
  loadBlocked();
}

/* ---------- Lista de confianza (allowlist) ---------- */
async function trustIp(ip, ruleEncoded) {
  const rule = ruleEncoded ? decodeURIComponent(ruleEncoded) : "*";
  const msg = rule === "*"
    ? `¿Marcar la IP ${ip} como de confianza para TODO?\n\nDejará de generar cualquier alerta. Si hace algo peligroso de verdad (mala reputación) seguirá avisando.`
    : `¿Marcar ${ip} como de confianza para «${rule}»?\n\nNo se volverá a avisar de ESE tipo de aviso desde esta IP.\nSi la misma IP hace algo DISTINTO, sí te avisará.`;
  if (!confirm(msg)) return;
  const r = await fetch("/api/trust", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ ip, rule }),
  });
  const d = await r.json();
  toast(d.message, d.ok ? "ok" : "err");
  loadAlerts();
  loadConnections();
}

async function untrustIp(ip) {
  if (!confirm(`¿Quitar ${ip} de la lista de confianza?\n\nVolverá a avisar si detecta algo.`)) return;
  const r = await fetch("/api/untrust", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ ip }),
  });
  const d = await r.json();
  toast(d.message, "ok");
  loadTrusted();
}

async function loadTrusted() {
  const r = await fetch("/api/trusted");
  const { trusted } = await r.json();
  const list = $("#trustedList");
  if (!trusted.length) {
    list.innerHTML = `<div class="empty">Aún no has marcado ninguna IP como de confianza.<br><span class="muted">Puedes hacerlo desde una alerta o desde el detalle de una conexión.</span></div>`;
    return;
  }
  list.innerHTML = trusted.map((t) => {
    const scope = t.rules === "*"
      ? `<span class="tag tag-ok">Confianza total</span>`
      : `<span class="tag tag-neutral">Solo: ${esc(t.rules.replaceAll("||", ", "))}</span>`;
    const flag = t.country_code ? flagEmoji(t.country_code) : "";
    const location = (t.city || t.country)
      ? `${flag} ${esc([t.city, t.country].filter(Boolean).join(", "))}`
      : `<span class="muted">ubicación desconocida</span>`;
    const rows = [
      ["🏢 Quién es", t.who ? esc(t.who) : `<span class="muted">sin identificar</span>`],
      ["📍 Ubicación", location],
      ["🔗 Nombre de host", t.hostname ? `<span class="mono">${esc(t.hostname)}</span>` : `<span class="muted">no resuelve</span>`],
      ["🛡️ Reputación", reputationTag(t.abuse_score)],
      ["📅 Marcada el", `<span class="muted">${esc(t.added_at || "-")}</span>`],
    ];
    if (t.note) rows.push(["📝 Nota", esc(t.note)]);
    const grid = rows.map(([k, v]) => `<div class="tinfo-row"><span class="tinfo-k">${k}</span><span>${v}</span></div>`).join("");
    return `<div class="trusted-card">
      <div class="trusted-head">
        <span class="trusted-ip mono">✅ ${esc(t.ip)}</span>
        ${scope}
        <button class="btn btn-sm" style="margin-left:auto" onclick="untrustIp('${t.ip}')">Quitar</button>
      </div>
      <div class="tinfo">${grid}</div>
    </div>`;
  }).join("");
}
$("#refreshTrusted").addEventListener("click", loadTrusted);

async function loadBlocked() {
  const r = await fetch("/api/blocked");
  const { blocked } = await r.json();
  const list = $("#blockedList");
  if (!blocked.length) {
    list.innerHTML = `<div class="empty">No hay IPs bloqueadas.</div>`;
    return;
  }
  list.innerHTML = blocked.map((ip) => `
    <div class="blocked-item">
      <span class="mono">🛡️ ${esc(ip)}</span>
      <button class="btn btn-sm" onclick="unblockIp('${ip}')">Desbloquear</button>
    </div>`).join("");
}
$("#refreshBlocked").addEventListener("click", loadBlocked);

/* ---------- Histórico ---------- */
async function searchHistory() {
  const ip = $("#histIp").value.trim();
  const proc = $("#histProc").value.trim();
  const r = await fetch(`/api/history?ip=${encodeURIComponent(ip)}&proceso=${encodeURIComponent(proc)}`);
  const { connections } = await r.json();
  const body = $("#histBody");
  if (!connections.length) {
    body.innerHTML = `<tr><td colspan="6" class="empty">Sin resultados.</td></tr>`;
    return;
  }
  body.innerHTML = connections.map((c) => `
    <tr>
      <td class="mono muted">${c.timestamp}</td>
      <td>${esc(c.process_name)}</td>
      <td class="mono">${esc(c.remote_ip)}</td>
      <td class="mono">${c.remote_port || "-"}</td>
      <td>${c.protocol}</td>
      <td class="state ${stateClass(c.status)}">${esc(c.status)}</td>
    </tr>`).join("");
}
$("#histSearch").addEventListener("click", searchHistory);
$("#filterConns").addEventListener("input", renderConnections);

/* ---------- Reloj y estado lateral ---------- */
function tick() {
  $("#clock").textContent = new Date().toLocaleTimeString("es-ES");
}
async function loadStatus() {
  try {
    const r = await fetch("/api/status");
    const s = await r.json();
    $("#sideStatus").textContent =
      `Refresco ${s.poll_interval}s · Reputación ${s.reputation_enabled ? "ON" : "OFF"}`;
  } catch { /* backend aún arrancando */ }
}

/* ---------- Bucle principal ---------- */
setInterval(tick, 1000);
tick();
loadStatus();
loadConnections();
setInterval(() => {
  if ($("#autoRefresh").checked && currentView === "conexiones") loadConnections();
  else if (currentView !== "conexiones") {
    // mantener el badge de alertas al día aunque no estemos en Conexiones
    fetch("/api/status").then(r => r.json()).then(s => updateAlertBadge(s.pending_alerts)).catch(()=>{});
  }
}, 4000);
