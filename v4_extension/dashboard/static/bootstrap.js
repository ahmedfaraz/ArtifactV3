/* bootstrap.js — client-side bridge between the standalone React dashboard
 * and the FastAPI backend. Loaded as a <script defer> after the bundler.
 *
 * Responsibilities:
 *   1. Wait for window.MCP_DATA to be set by the bundle's data.js, then
 *      overlay /api/data on top (in-place mutation so React keeps the same
 *      object identity). Bump a flag so React picks up new values.
 *   2. Add a floating "Live Runs" widget for triggering real scenario
 *      subprocesses via /api/run/... and showing live event stream + log tail.
 *   3. Poll /api/data every 20s to surface result-file changes (e.g. a job
 *      that just finished writes results/<arch>/scenario_X_results.json which
 *      changes the dashboard's metric tiles).
 *
 * The original dashboard's "▶ run scenario X" button is left alone — clicking
 * it still does the animated replay from window.MCP_DATA.events. Real runs
 * happen via the floating widget so the demo flow is: show metrics, replay
 * canned events for narrative, then trigger a live run to prove the wiring.
 */

(function () {
  'use strict';

  const API = {
    data: '/api/data',
    config: '/api/config',
    run: (s, a) => `/api/run/${encodeURIComponent(s)}/${encodeURIComponent(a)}`,
    job: (id) => `/api/jobs/${encodeURIComponent(id)}`,
    stream: (id) => `/api/stream/${encodeURIComponent(id)}`,
    jobs: '/api/jobs',
    cancel: (id) => `/api/jobs/${encodeURIComponent(id)}/cancel`,
  };

  // ──────────────────────────────────────────────────────────────────────
  // 1. Overlay /api/data onto window.MCP_DATA
  // ──────────────────────────────────────────────────────────────────────
  function deepAssign(target, src) {
    if (!src || typeof src !== 'object') return;
    Object.keys(src).forEach((k) => {
      const v = src[k];
      if (v && typeof v === 'object' && !Array.isArray(v) && target[k] && typeof target[k] === 'object' && !Array.isArray(target[k])) {
        deepAssign(target[k], v);
      } else {
        target[k] = v;
      }
    });
  }

  async function fetchData() {
    try {
      const r = await fetch(API.data, { cache: 'no-store' });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      return await r.json();
    } catch (e) {
      console.warn('[bootstrap] /api/data fetch failed:', e);
      return null;
    }
  }

  function waitForMCPData(maxMs = 8000) {
    return new Promise((resolve) => {
      const t0 = Date.now();
      (function poll() {
        if (window.MCP_DATA) return resolve(window.MCP_DATA);
        if (Date.now() - t0 > maxMs) return resolve(null);
        setTimeout(poll, 80);
      })();
    });
  }

  // Trigger a React re-render by dispatching a synthetic click on a hidden
  // marker that lives inside the dashboard. We don't actually have one — so
  // instead we mutate the global, then dispatch a "visibilitychange"-ish
  // event the dashboard doesn't listen for. The actual re-render comes from
  // the user interacting (or from the next render cycle). For metric tiles
  // and infra panel (which both read window.MCP_DATA every render), we force
  // a re-render by quickly toggling document.body's data attribute and back.
  let _refreshSeq = 0;
  function nudgeRerender() {
    _refreshSeq++;
    // The dashboard subscribes to its own state, not DOM attrs — but a
    // user-triggered re-render is reliable. The most lightweight trigger is
    // to dispatch a 'resize' which React's portal observers may pick up.
    try { window.dispatchEvent(new Event('resize')); } catch (e) {}
    // As an extra: poke React state by simulating a tiny scroll
    try { window.scrollBy(0, 0); } catch (e) {}
  }

  async function overlayData() {
    const data = await fetchData();
    if (!data) return false;
    if (!window.MCP_DATA) window.MCP_DATA = {};
    deepAssign(window.MCP_DATA, data);
    // Stash the raw payload on window so the widget can show source banner
    window.__MCP_BACKEND_DATA = data;
    nudgeRerender();
    return true;
  }

  // ──────────────────────────────────────────────────────────────────────
  // 2. Floating "Live Runs" widget
  // ──────────────────────────────────────────────────────────────────────
  const SCENARIOS = ['A', 'B', 'C', 'D'];
  const ARCHS = ['baseline', 'hardened'];

  // State kept on the widget element via dataset
  const widgetState = {
    open: false,
    activeJobId: null,
    eventSource: null,
    config: { baseline_ip: '', hardened_ip: '', attacker_ip: '' },
    lastDataSource: null,
  };

  function el(tag, props = {}, children = []) {
    const e = document.createElement(tag);
    for (const k in props) {
      if (k === 'style') Object.assign(e.style, props.style);
      else if (k === 'class') e.className = props.class;
      else if (k === 'html') e.innerHTML = props.html;
      else if (k.startsWith('on')) e.addEventListener(k.slice(2).toLowerCase(), props[k]);
      else e.setAttribute(k, props[k]);
    }
    (Array.isArray(children) ? children : [children]).forEach((c) => {
      if (c == null) return;
      e.appendChild(typeof c === 'string' ? document.createTextNode(c) : c);
    });
    return e;
  }

  function buildWidget() {
    const root = el('div', { id: 'mcp-live-widget', class: 'mcp-widget collapsed' });

    // Toggle pill
    const toggle = el('button', {
      class: 'mcp-toggle',
      onclick: () => {
        widgetState.open = !widgetState.open;
        root.classList.toggle('collapsed', !widgetState.open);
        root.classList.toggle('open', widgetState.open);
      },
    }, [
      el('span', { class: 'mcp-toggle-dot' }),
      el('span', { class: 'mcp-toggle-label' }, ['LIVE']),
      el('span', { class: 'mcp-toggle-sub' }, ['real scenario runs']),
    ]);
    root.appendChild(toggle);

    // Panel body
    const body = el('div', { class: 'mcp-body' });

    // ─── Header
    body.appendChild(el('div', { class: 'mcp-header' }, [
      el('div', { class: 'mcp-title' }, ['Live Runs']),
      el('div', { class: 'mcp-sub' }, ['execute real scenarios · stream stdout · refresh results']),
    ]));

    // ─── Config card
    const cfg = el('div', { class: 'mcp-card' });
    cfg.appendChild(el('div', { class: 'mcp-card-title' }, ['Target IPs']));
    function ipRow(label, key, placeholder) {
      const inp = el('input', {
        type: 'text', placeholder,
        value: widgetState.config[key] || '',
        oninput: (e) => { widgetState.config[key] = e.target.value; },
      });
      inp.id = `mcp-ip-${key}`;
      return el('label', { class: 'mcp-row' }, [
        el('span', { class: 'mcp-label' }, [label]),
        inp,
      ]);
    }
    cfg.appendChild(ipRow('baseline ECS', 'baseline_ip', 'e.g. 34.244.x.y'));
    cfg.appendChild(ipRow('hardened tunnel', 'hardened_ip', '127.0.0.1 (SSM tunnel)'));
    cfg.appendChild(ipRow('attacker EC2', 'attacker_ip', 'private IP (D-hardened)'));
    cfg.appendChild(el('button', {
      class: 'mcp-btn',
      onclick: saveConfig,
    }, ['save IPs']));
    body.appendChild(cfg);

    // ─── Run grid
    const grid = el('div', { class: 'mcp-grid' });
    SCENARIOS.forEach((s) => {
      ARCHS.forEach((a) => {
        const btn = el('button', {
          class: 'mcp-runbtn',
          'data-s': s, 'data-a': a,
          onclick: () => triggerRun(s, a),
        }, [
          el('span', { class: 'mcp-runbtn-s' }, [`Scenario ${s}`]),
          el('span', { class: `mcp-runbtn-a mcp-arch-${a}` }, [a]),
        ]);
        grid.appendChild(btn);
      });
    });
    body.appendChild(el('div', { class: 'mcp-card' }, [
      el('div', { class: 'mcp-card-title' }, ['Trigger real run']),
      grid,
    ]));

    // ─── Live log
    const log = el('div', { class: 'mcp-log', id: 'mcp-log' }, [
      el('div', { class: 'mcp-log-empty' }, ['no run yet — pick a scenario above']),
    ]);
    const logCard = el('div', { class: 'mcp-card' });
    logCard.appendChild(el('div', { class: 'mcp-card-title-row' }, [
      el('div', { class: 'mcp-card-title' }, ['Event stream']),
      el('div', { class: 'mcp-status', id: 'mcp-status' }, ['idle']),
    ]));
    logCard.appendChild(log);
    logCard.appendChild(el('div', { class: 'mcp-log-actions' }, [
      el('button', {
        class: 'mcp-btn mcp-btn-ghost', onclick: () => {
          if (widgetState.activeJobId) {
            fetch(API.cancel(widgetState.activeJobId), { method: 'POST' }).catch(() => {});
          }
        },
      }, ['cancel current']),
      el('button', {
        class: 'mcp-btn mcp-btn-ghost', onclick: () => overlayData(),
      }, ['refresh metrics']),
    ]));
    body.appendChild(logCard);

    // ─── Data source banner
    body.appendChild(el('div', { class: 'mcp-banner', id: 'mcp-banner' }, [
      'data source: …',
    ]));

    root.appendChild(body);
    return root;
  }

  function appendLogLine(ev) {
    const log = document.getElementById('mcp-log');
    if (!log) return;
    // Clear empty placeholder
    const empty = log.querySelector('.mcp-log-empty');
    if (empty) empty.remove();
    const row = el('div', { class: `mcp-log-row mcp-kind-${ev.kind || 'note'}` }, [
      el('span', { class: 'mcp-log-t' }, [Number(ev.t || 0).toFixed(2)]),
      el('span', { class: 'mcp-log-k' }, [ev.kind || 'note']),
      el('span', { class: 'mcp-log-m' }, [String(ev.msg || '')]),
    ]);
    log.appendChild(row);
    // Cap at 400 rows for performance
    while (log.children.length > 400) log.removeChild(log.firstChild);
    log.scrollTop = log.scrollHeight;
  }

  function setStatus(text, tone = 'idle') {
    const el = document.getElementById('mcp-status');
    if (!el) return;
    el.textContent = text;
    el.dataset.tone = tone;
  }

  function clearLog() {
    const log = document.getElementById('mcp-log');
    if (!log) return;
    log.innerHTML = '';
    log.appendChild(el('div', { class: 'mcp-log-empty' }, ['streaming…']));
  }

  function updateBanner() {
    const banner = document.getElementById('mcp-banner');
    if (!banner) return;
    const meta = (window.MCP_DATA && window.MCP_DATA._source) || {};
    const real = meta.real_runs || 0;
    const tfb = meta.baseline_tf ? 'on' : 'off';
    const tfh = meta.hardened_tf ? 'on' : 'off';
    const last = (window.MCP_DATA && window.MCP_DATA.meta && window.MCP_DATA.meta.lastRun) || '—';
    banner.textContent =
      `real runs on disk: ${real} · terraform baseline: ${tfb} · hardened: ${tfh} · last: ${last}`;
  }

  async function saveConfig() {
    try {
      const r = await fetch(API.config, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(widgetState.config),
      });
      const j = await r.json();
      widgetState.config = j;
      setStatus('saved IPs', 'info');
      await overlayData();
      updateBanner();
    } catch (e) {
      setStatus('save failed: ' + e.message, 'error');
    }
  }

  async function loadConfig() {
    try {
      const r = await fetch(API.config);
      const j = await r.json();
      widgetState.config = j;
      Object.keys(j).forEach((k) => {
        const inp = document.getElementById('mcp-ip-' + k);
        if (inp) inp.value = j[k] || '';
      });
    } catch (e) {
      // silent
    }
  }

  function closeStream() {
    if (widgetState.eventSource) {
      try { widgetState.eventSource.close(); } catch (e) {}
      widgetState.eventSource = null;
    }
  }

  async function triggerRun(scenario, arch) {
    closeStream();
    clearLog();
    setStatus(`launching ${scenario} · ${arch}…`, 'running');
    try {
      const r = await fetch(API.run(scenario, arch), { method: 'POST' });
      const j = await r.json();
      if (!r.ok || j.error) {
        setStatus(j.error || `HTTP ${r.status}`, 'error');
        appendLogLine({ t: 0, kind: 'note', msg: j.error || `HTTP ${r.status}` });
        return;
      }
      widgetState.activeJobId = j.job_id;
      setStatus(`running · job ${j.job_id}`, 'running');
      const es = new EventSource(API.stream(j.job_id));
      widgetState.eventSource = es;
      es.onmessage = (m) => {
        try { appendLogLine(JSON.parse(m.data)); } catch (e) {}
      };
      es.addEventListener('meta', (m) => {
        try {
          const meta = JSON.parse(m.data);
          appendLogLine({ t: 0, kind: 'init', msg: `job ${meta.id} · ${meta.scenario}/${meta.arch}` });
        } catch (e) {}
      });
      es.addEventListener('end', async (m) => {
        let status = 'done';
        try { status = JSON.parse(m.data).status; } catch (e) {}
        setStatus(`finished · ${status}`, status === 'done' ? 'ok' : 'error');
        closeStream();
        // Pull refreshed data — the scenario should have written a new
        // results/<arch>/scenario_X_results.json
        await overlayData();
        updateBanner();
      });
      es.onerror = () => {
        setStatus('stream error', 'error');
      };
    } catch (e) {
      setStatus('launch failed: ' + e.message, 'error');
    }
  }

  // ──────────────────────────────────────────────────────────────────────
  // 3. Boot sequence
  // ──────────────────────────────────────────────────────────────────────
  async function boot() {
    // Wait for the React bundle to set window.MCP_DATA, then overlay
    await waitForMCPData();
    await overlayData();

    // Mount widget
    const widget = buildWidget();
    document.body.appendChild(widget);
    await loadConfig();
    updateBanner();

    // Periodic refresh of data (cheap — just re-renders metrics if disk
    // changed). 20s cadence is more than enough for a viva demo.
    setInterval(async () => {
      await overlayData();
      updateBanner();
    }, 20000);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot);
  } else {
    boot();
  }
})();
