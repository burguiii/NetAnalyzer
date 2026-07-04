/* ===== Mapa mundial animado de conexiones ===== */
/* Proyeccion equirectangular: lon/lat -> x/y. Los continentes se dibujan una
   sola vez en una capa cacheada; cada frame solo anima arcos y "paquetes". */
const WorldMap = (function () {
  let canvas, ctx, W = 0, H = 0, dpr = 1;
  let land = null;            // features del GeoJSON
  let landLayer = null;       // canvas offscreen con los continentes ya pintados
  let home = null;            // { lat, lon, x, y, city, country }
  let dests = [];             // destinos con coords + particulas
  let rafId = null, running = false, lastFetch = 0, hover = null;

  const COLOR = {
    ok:      "#22d3ee",
    warn:    "#eab308",
    bad:     "#ef4444",
    unknown: "#64748b",
  };

  function project(lon, lat) {
    return [((lon + 180) / 360) * W, ((90 - lat) / 180) * H];
  }

  async function loadLand() {
    if (land) return;
    try {
      const r = await fetch("/vendor/world.geojson");
      const j = await r.json();
      land = j.features || [];
    } catch (e) { land = []; }
  }

  function resize() {
    const wrap = canvas.parentElement;
    const cssW = wrap.clientWidth || 800;
    const cssH = Math.max(280, Math.round(cssW / 2));
    dpr = window.devicePixelRatio || 1;
    canvas.style.width = cssW + "px";
    canvas.style.height = cssH + "px";
    canvas.width = Math.round(cssW * dpr);
    canvas.height = Math.round(cssH * dpr);
    W = cssW; H = cssH;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    renderLandLayer();
    computePositions();
  }

  function renderLandLayer() {
    if (!land) return;
    landLayer = document.createElement("canvas");
    landLayer.width = Math.round(W * dpr);
    landLayer.height = Math.round(H * dpr);
    const lc = landLayer.getContext("2d");
    lc.setTransform(dpr, 0, 0, dpr, 0, 0);
    // rejilla suave
    lc.strokeStyle = "rgba(90,130,170,0.10)";
    lc.lineWidth = 1;
    for (let lonG = -180; lonG <= 180; lonG += 30) {
      const [x] = project(lonG, 0);
      lc.beginPath(); lc.moveTo(x, 0); lc.lineTo(x, H); lc.stroke();
    }
    for (let latG = -60; latG <= 90; latG += 30) {
      const [, y] = project(0, latG);
      lc.beginPath(); lc.moveTo(0, y); lc.lineTo(W, y); lc.stroke();
    }
    // continentes
    lc.fillStyle = "rgba(48,72,100,0.55)";
    lc.strokeStyle = "rgba(110,150,190,0.35)";
    lc.lineWidth = 0.5;
    for (const f of land) {
      const g = f.geometry; if (!g) continue;
      const polys = g.type === "Polygon" ? [g.coordinates]
                  : g.type === "MultiPolygon" ? g.coordinates : [];
      for (const poly of polys) {
        for (const ring of poly) {
          lc.beginPath();
          for (let i = 0; i < ring.length; i++) {
            const [x, y] = project(ring[i][0], ring[i][1]);
            i ? lc.lineTo(x, y) : lc.moveTo(x, y);
          }
          lc.closePath(); lc.fill(); lc.stroke();
        }
      }
    }
  }

  function computePositions() {
    if (home) [home.x, home.y] = project(home.lon, home.lat);
    for (const d of dests) {
      [d.x, d.y] = project(d.lon, d.lat);
      if (home) {
        const dx = d.x - home.x, dy = d.y - home.y;
        const dist = Math.hypot(dx, dy) || 1;
        const mx = (home.x + d.x) / 2, my = (home.y + d.y) / 2;
        const nx = -dy / dist, ny = dx / dist;        // perpendicular
        const lift = Math.min(dist * 0.28, H * 0.35);
        d.cx = mx + nx * lift;
        d.cy = my + ny * lift;
        d.dist = dist;
      }
    }
  }

  function bez(t, p0, c, p1) {
    const u = 1 - t;
    return [
      u * u * p0[0] + 2 * u * t * c[0] + t * t * p1[0],
      u * u * p0[1] + 2 * u * t * c[1] + t * t * p1[1],
    ];
  }

  async function refreshData() {
    try {
      const promises = [fetch("/api/connections").then((r) => r.json())];
      if (!home) promises.push(fetch("/api/home").then((r) => r.json()));
      const [conn, homeRes] = await Promise.all(promises);
      if (homeRes) home = { lat: homeRes.lat, lon: homeRes.lon, city: homeRes.city, country: homeRes.country };

      const m = new Map();
      for (const c of (conn.connections || [])) {
        if (c.lat == null || c.lon == null) continue;
        const e = c.explain || {};
        if (e.ip_kind !== "internet") continue;
        if (!m.has(c.remote_ip)) {
          m.set(c.remote_ip, {
            ip: c.remote_ip, lat: c.lat, lon: c.lon,
            who: e.who || c.remote_ip, verdict: e.verdict || "ok", count: 1,
          });
        } else { m.get(c.remote_ip).count++; }
      }
      const prev = new Map(dests.map((d) => [d.ip, d]));
      dests = [...m.values()].map((d) => {
        const old = prev.get(d.ip);
        return Object.assign(d, {
          particles: old ? old.particles : [],
          spawn: old ? old.spawn : Math.random() * 1000,
        });
      });
      computePositions();
      const zones = new Set([...m.values()].map((d) => d.who.split("·").pop().trim()));
      const cnt = document.getElementById("mapCount");
      if (cnt) cnt.textContent = `${dests.length} destinos · ${zones.size} zonas`;
    } catch (e) { /* backend arrancando */ }
  }

  function frame(ts) {
    if (!running) return;
    // fondo (mar)
    const grad = ctx.createLinearGradient(0, 0, 0, H);
    grad.addColorStop(0, "#0b1622");
    grad.addColorStop(1, "#0a1119");
    ctx.fillStyle = grad;
    ctx.fillRect(0, 0, W, H);
    if (landLayer) ctx.drawImage(landLayer, 0, 0, W, H);

    if (home) {
      // arcos + particulas
      for (const d of dests) {
        const col = COLOR[d.verdict] || COLOR.ok;
        const p0 = [home.x, home.y], c = [d.cx, d.cy], p1 = [d.x, d.y];
        // linea del arco tenue
        ctx.strokeStyle = col + "44";
        ctx.lineWidth = 1;
        ctx.beginPath();
        ctx.moveTo(p0[0], p0[1]);
        ctx.quadraticCurveTo(c[0], c[1], p1[0], p1[1]);
        ctx.stroke();

        // generar paquetes periodicamente
        d.spawn -= 16;
        if (d.spawn <= 0) {
          d.particles.push({ t: 0 });
          d.spawn = 900 + Math.random() * 900;
        }
        // mover y dibujar paquetes
        const speed = 0.010 + Math.min(0.012, 60 / (d.dist || 300));
        for (const pt of d.particles) {
          pt.t += speed;
          const [px, py] = bez(pt.t, p0, c, p1);
          ctx.beginPath();
          ctx.arc(px, py, 2.6, 0, Math.PI * 2);
          ctx.fillStyle = col;
          ctx.shadowColor = col;
          ctx.shadowBlur = 10;
          ctx.fill();
          ctx.shadowBlur = 0;
        }
        d.particles = d.particles.filter((pt) => pt.t < 1);

        // punto destino (pulso)
        const pulse = 3 + Math.sin(ts / 400 + d.x) * 1.2;
        ctx.beginPath();
        ctx.arc(d.x, d.y, pulse, 0, Math.PI * 2);
        ctx.fillStyle = col;
        ctx.shadowColor = col; ctx.shadowBlur = 12; ctx.fill(); ctx.shadowBlur = 0;
        if (d.verdict === "bad") {
          ctx.beginPath();
          ctx.arc(d.x, d.y, 6 + (ts / 8 % 14), 0, Math.PI * 2);
          ctx.strokeStyle = col + "88"; ctx.lineWidth = 1.5; ctx.stroke();
        }
      }
      // marcador de casa
      const hp = 5 + Math.sin(ts / 500) * 1.5;
      ctx.beginPath(); ctx.arc(home.x, home.y, hp + 5, 0, Math.PI * 2);
      ctx.strokeStyle = "rgba(59,130,246,0.6)"; ctx.lineWidth = 2; ctx.stroke();
      ctx.beginPath(); ctx.arc(home.x, home.y, hp, 0, Math.PI * 2);
      ctx.fillStyle = "#3b82f6"; ctx.shadowColor = "#3b82f6"; ctx.shadowBlur = 14; ctx.fill(); ctx.shadowBlur = 0;
    }

    // tooltip al pasar el raton
    if (hover) {
      const t = document.getElementById("mapTip");
      if (t) {
        t.hidden = false;
        t.innerHTML = `<b>${hover.who}</b><br><span class="mono">${hover.ip}</span> · ${hover.count} conex.`;
        t.style.left = Math.min(hover.x + 12, W - 180) + "px";
        t.style.top = (hover.y + 12) + "px";
      }
    } else {
      const t = document.getElementById("mapTip"); if (t) t.hidden = true;
    }

    // refrescar datos cada 4s
    if (ts - lastFetch > 4000) { lastFetch = ts; refreshData(); }
    rafId = requestAnimationFrame(frame);
  }

  function onMove(ev) {
    const rect = canvas.getBoundingClientRect();
    const mx = ev.clientX - rect.left, my = ev.clientY - rect.top;
    hover = null; let best = 12;
    for (const d of dests) {
      const dd = Math.hypot(d.x - mx, d.y - my);
      if (dd < best) { best = dd; hover = { ...d, x: mx, y: my }; }
    }
  }

  async function start() {
    canvas = document.getElementById("mapCanvas");
    if (!canvas) return;
    ctx = canvas.getContext("2d");
    await loadLand();
    resize();
    if (!start._bound) {
      window.addEventListener("resize", () => { if (running) resize(); });
      canvas.addEventListener("mousemove", onMove);
      canvas.addEventListener("mouseleave", () => (hover = null));
      start._bound = true;
    }
    await refreshData();
    running = true;
    lastFetch = performance.now();
    rafId = requestAnimationFrame(frame);
  }

  function stop() {
    running = false;
    if (rafId) cancelAnimationFrame(rafId);
    rafId = null;
  }

  return { start, stop };
})();
