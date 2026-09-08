// proxy-manager dashboard.
//
// Vanilla ES2018, no build step: this file is embedded in the Go binary and
// served from the Pi, so there is no toolchain in the loop and nothing to
// rebuild when it changes.
//
// The API is the source of truth for everything on screen. No local mirror of
// proxy/selection state is kept, because a stale mirror on a control plane that
// intercepts the whole LAN is worse than a slow redraw: every mutation is
// followed by a refetch, and the poller reconciles anything that changed
// out-of-band (a crashed engine, a CLI curl, a second browser tab).

'use strict';

var POLL_IDLE = 5000;     // steady-state status poll
var POLL_BUSY = 1500;     // while a refresh job runs
var POLL_BACKOFF = 15000; // after a transport error, to stop hammering a dead API
var TOKEN_KEY = 'pm.token';
var SUB_KEY = 'pm.subUrl';

var state = {
  status: null,
  nodes: [],
  selection: { auto: false },
  busy: false,      // a mutating request is in flight
  jobRunning: false,
  pollTimer: null,
  lastJobId: null,
  offline: false,
};

// --- small helpers ----------------------------------------------------------

function $(id) { return document.getElementById(id); }

function text(el, s) { if (el) el.textContent = s; }

function token() {
  try { return window.localStorage.getItem(TOKEN_KEY) || ''; } catch (e) { return ''; }
}

function setToken(v) {
  try {
    if (v) window.localStorage.setItem(TOKEN_KEY, v);
    else window.localStorage.removeItem(TOKEN_KEY);
  } catch (e) { /* private mode: token lives for this page only */ }
}

function fmtAgo(iso) {
  if (!iso) return 'never';
  var t = Date.parse(iso);
  // Go marshals the zero time.Time as year 1; treat it as "never" rather than
  // rendering a date from antiquity.
  if (isNaN(t) || t < 0) return 'never';
  var secs = Math.round((Date.now() - t) / 1000);
  if (secs < 0) secs = 0;
  if (secs < 60) return secs + 's ago';
  if (secs < 3600) return Math.round(secs / 60) + 'm ago';
  if (secs < 86400) return Math.round(secs / 3600) + 'h ago';
  return Math.round(secs / 86400) + 'd ago';
}

function toast(msg, kind) {
  var box = $('toasts');
  if (!box) return;
  var el = document.createElement('div');
  el.className = 'pm-toast ' + (kind === 'err' ? 'pm-toast-err' : kind === 'ok' ? 'pm-toast-ok' : '');
  el.setAttribute('role', kind === 'err' ? 'alert' : 'status');
  el.textContent = msg;
  box.appendChild(el);
  window.setTimeout(function () { el.remove(); }, kind === 'err' ? 9000 : 5000);
}

function banner(msg) {
  var el = $('banner');
  if (!el) return;
  if (!msg) { el.classList.add('hidden'); text(el, ''); return; }
  text(el, msg);
  el.classList.remove('hidden');
}

// --- API --------------------------------------------------------------------

// call returns the decoded body and throws an Error carrying .status and the
// server's message on failure. The API answers JSON on every path, including
// errors, so one decode covers both.
function call(method, path, body) {
  var headers = { 'Accept': 'application/json' };
  var tok = token();
  if (tok) headers['Authorization'] = 'Bearer ' + tok;
  var init = { method: method, headers: headers, cache: 'no-store' };
  if (body !== undefined) {
    headers['Content-Type'] = 'application/json';
    init.body = JSON.stringify(body);
  }
  return fetch(path, init).then(function (resp) {
    return resp.text().then(function (raw) {
      var data = null;
      if (raw) { try { data = JSON.parse(raw); } catch (e) { /* not JSON */ } }
      if (!resp.ok) {
        var msg = (data && data.error) || raw || ('HTTP ' + resp.status);
        var err = new Error(msg);
        err.status = resp.status;
        err.data = data;
        throw err;
      }
      return data;
    });
  });
}

// --- rendering --------------------------------------------------------------

function latencyCell(node) {
  // LatencyMS is -1 (store.LatencyUnmeasured) for both "never probed" and
  // "last probe failed"; last_checked_at is what separates them.
  var ms = node.latency_ms;
  if (typeof ms !== 'number' || ms < 0) {
    var probed = node.last_checked_at && Date.parse(node.last_checked_at) > 0;
    return {
      cls: probed ? 'pm-lat-slow' : 'pm-lat-none',
      label: probed ? 'timeout' : '—',
      title: probed ? (node.last_error || 'probe failed') : 'not measured yet',
    };
  }
  if (ms < 200) return { cls: 'pm-lat-good', label: ms + ' ms', title: '' };
  if (ms < 500) return { cls: 'pm-lat-ok', label: ms + ' ms', title: '' };
  return { cls: 'pm-lat-slow', label: ms + ' ms', title: '' };
}

function renderNodes() {
  var tbody = $('node-rows');
  var empty = $('nodes-empty');
  if (!tbody) return;
  tbody.textContent = '';
  if (!state.nodes.length) {
    if (empty) empty.classList.remove('hidden');
    return;
  }
  if (empty) empty.classList.add('hidden');

  var auto = !!state.selection.auto;
  var activeTag = state.selection.auto ? state.selection.auto_pick : state.selection.active;

  state.nodes.forEach(function (n) {
    var tr = document.createElement('tr');
    tr.className = 'cursor-pointer hover:bg-slate-800/60';
    tr.dataset.id = n.id;
    tr.tabIndex = 0;
    // aria-selected marks the pinned node; under auto nothing is pinned, so the
    // row highlight follows urltest's current pick instead.
    var pinned = !!n.selected && !auto;
    var running = !!activeTag && (n.effective_tag === activeTag || n.tag === activeTag);
    tr.setAttribute('aria-selected', pinned ? 'true' : 'false');

    var tagCell = document.createElement('td');
    tagCell.className = 'px-4 py-2 font-medium';
    tagCell.textContent = n.tag;
    if (pinned || running) {
      var mark = document.createElement('span');
      mark.className = 'pm-pill ml-2 border-emerald-700 text-emerald-400';
      mark.textContent = pinned ? 'pinned' : 'live';
      tagCell.appendChild(mark);
    }
    if (!n.in_config) {
      var warn = document.createElement('span');
      warn.className = 'pm-pill ml-2 border-slate-700 text-slate-500';
      warn.textContent = 'not loaded';
      warn.title = 'Not in the running engine config; start or refresh the proxy to select it.';
      tagCell.appendChild(warn);
    }
    tr.appendChild(tagCell);

    var proto = document.createElement('td');
    proto.className = 'pm-mono px-4 py-2 text-slate-400';
    proto.textContent = n.protocol + (n.transport ? ' / ' + n.transport : '');
    tr.appendChild(proto);

    var server = document.createElement('td');
    server.className = 'pm-mono hidden px-4 py-2 text-slate-400 md:table-cell';
    server.textContent = n.server + ':' + n.port;
    tr.appendChild(server);

    var lat = latencyCell(n);
    var latTd = document.createElement('td');
    latTd.className = 'px-4 py-2 ' + lat.cls;
    latTd.textContent = lat.label;
    if (lat.title) latTd.title = lat.title;
    tr.appendChild(latTd);

    var checked = document.createElement('td');
    checked.className = 'pm-muted hidden px-4 py-2 text-xs text-slate-500 sm:table-cell';
    checked.textContent = fmtAgo(n.last_checked_at);
    tr.appendChild(checked);

    var actions = document.createElement('td');
    actions.className = 'px-4 py-2 text-right';
    var btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'pm-btn rounded-md border border-slate-700 px-3 py-1 text-xs hover:bg-slate-800';
    btn.textContent = pinned ? 'Pinned' : 'Activate';
    btn.disabled = state.busy || pinned;
    btn.dataset.action = 'select';
    btn.dataset.id = n.id;
    actions.appendChild(btn);
    tr.appendChild(actions);

    tbody.appendChild(tr);
  });
}

function renderStatus() {
  var st = state.status;
  var pill = $('engine-status');
  if (!st) {
    text(pill, state.offline ? 'Unreachable' : 'Loading…');
    if (pill) pill.className = 'pm-pill rounded-full border px-3 py-1 text-xs font-medium ' +
      (state.offline ? 'border-rose-700 text-rose-400' : 'border-slate-700 text-slate-400');
    return;
  }

  // "Running" means the whole path is up: engine process alive AND rules
  // loaded. Either half alone is a broken gateway, not a running one.
  var full = st.proxy_enabled && st.engine_running && st.tproxy_rules_loaded;
  var label = full ? 'Running' : st.engine_running ? 'Engine up · not intercepting' : 'Stopped';
  text(pill, label);
  if (pill) {
    pill.className = 'pm-pill rounded-full border px-3 py-1 text-xs font-medium ' +
      (full ? 'border-emerald-700 text-emerald-400'
            : st.engine_running ? 'border-amber-700 text-amber-400'
                                : 'border-slate-700 text-slate-400');
  }

  var toggle = $('proxy-toggle');
  if (toggle && document.activeElement !== toggle) toggle.checked = !!st.proxy_enabled;
  if (toggle) toggle.disabled = state.busy;
  text($('proxy-toggle-label'), st.proxy_enabled ? 'on' : 'off');

  text($('stat-engine'), st.engine_running ? 'Running' : 'Stopped');
  text($('stat-pid'), st.engine_pid ? 'pid ' + st.engine_pid : ' ');
  text($('stat-rules'), st.tproxy_rules_loaded ? 'Loaded' : 'Not loaded');
  text($('stat-rules-err'), st.tproxy_rules_error || ' ');
  text($('stat-nodes'), String(st.nodes_total || 0));
  text($('stat-nodes-sub'),
    (st.nodes_enabled || 0) + ' enabled · ' + (st.nodes_healthy || 0) + ' healthy');

  var sel = st.selection || {};
  state.selection = sel;
  var active = sel.auto ? (sel.auto_pick || '—') : (sel.tag || sel.active || '—');
  text($('stat-active'), active);
  text($('stat-active-sub'), sel.auto ? 'auto-switch (urltest)' : 'pinned manually');

  var autoToggle = $('auto-toggle');
  if (autoToggle && document.activeElement !== autoToggle) autoToggle.checked = !!sel.auto;
  if (autoToggle) autoToggle.disabled = state.busy;
  text($('auto-toggle-label'), sel.auto ? 'auto' : 'manual');

  text($('foot-config'), st.config_path || '');
  text($('updated'), 'updated ' + new Date().toLocaleTimeString());
  renderJob(st.refresh || {});
}

function renderJob(job) {
  var wasRunning = state.jobRunning;
  state.jobRunning = job.state === 'running';

  var parts = [];
  if (job.state === 'running') {
    parts.push('Refreshing… fetching sources and probing nodes. This can take minutes on a Pi.');
  } else if (job.state === 'succeeded') {
    parts.push('Last refresh succeeded ' + fmtAgo(job.finished_at) + '.');
  } else if (job.state === 'failed') {
    parts.push('Last refresh failed ' + fmtAgo(job.finished_at) + ': ' + (job.error || 'unknown error'));
  } else {
    parts.push('No refresh has run yet.');
  }
  if (job.state && job.state !== 'idle') {
    parts.push('sources ' + (job.sources_ok || 0) + '/' + (job.sources_total || 0));
    parts.push('parsed ' + (job.nodes_parsed || 0));
    parts.push('+' + (job.nodes_added || 0) + ' new, ' + (job.nodes_updated || 0) + ' updated');
    if (job.nodes_pruned) parts.push(job.nodes_pruned + ' pruned');
    if (job.tested) parts.push('reachable ' + (job.reachable || 0) + '/' + job.tested);
    if (job.engine_reloaded) parts.push('engine reloaded');
  }
  text($('job'), parts.join(' · '));

  var warnBox = $('job-warnings');
  var list = $('job-warnings-list');
  if (warnBox && list) {
    list.textContent = '';
    if (job.warnings && job.warnings.length) {
      warnBox.classList.remove('hidden');
      job.warnings.forEach(function (w) {
        var li = document.createElement('li');
        li.textContent = w;
        list.appendChild(li);
      });
    } else {
      warnBox.classList.add('hidden');
    }
  }

  // A job that just finished changed the node set and their latencies; pull the
  // list once rather than polling /api/nodes on a timer.
  if (wasRunning && !state.jobRunning) {
    fetchNodes();
    if (job.state === 'succeeded') {
      toast('Refresh finished: ' + (job.reachable || 0) + '/' + (job.tested || 0) + ' nodes reachable', 'ok');
    } else if (job.state === 'failed') {
      toast('Refresh failed: ' + (job.error || 'unknown error'), 'err');
    }
  }
  if (job.id) state.lastJobId = job.id;
}

// --- data fetching ----------------------------------------------------------

function handleError(err, what) {
  if (err && err.status === 401) {
    banner('This API requires a bearer token. Click “API token” and paste the value of -token / PROXY_MANAGER_TOKEN.');
    return;
  }
  if (err && typeof err.status === 'number') {
    toast(what + ': ' + err.message, 'err');
    return;
  }
  // No .status: the request never got an HTTP answer.
  state.offline = true;
  banner('Cannot reach the API. The server may be restarting, or interception may have taken the network down.');
}

function fetchStatus() {
  return call('GET', '/api/status').then(function (st) {
    state.status = st;
    state.offline = false;
    banner('');
    renderStatus();
  }).catch(function (err) {
    handleError(err, 'status');
    renderStatus();
    throw err;
  });
}

function fetchNodes() {
  return call('GET', '/api/nodes').then(function (data) {
    state.nodes = (data && data.nodes) || [];
    if (data && data.selection) state.selection = data.selection;
    renderNodes();
  }).catch(function (err) {
    handleError(err, 'nodes');
  });
}

function refreshAll() {
  return fetchStatus().then(fetchNodes, function () { /* status already reported */ });
}

// --- polling ----------------------------------------------------------------

function schedulePoll(delay) {
  if (state.pollTimer) window.clearTimeout(state.pollTimer);
  var wait = delay !== undefined ? delay
    : state.offline ? POLL_BACKOFF
    : state.jobRunning ? POLL_BUSY
    : POLL_IDLE;
  text($('foot-poll'), 'polling every ' + Math.round(wait / 1000) + 's');
  state.pollTimer = window.setTimeout(poll, wait);
}

function poll() {
  // Don't poll a hidden tab: on a Pi this is a background process doing real
  // work, and an idle laptop tab should not keep it busy.
  if (document.hidden) { schedulePoll(POLL_IDLE); return; }
  fetchStatus().then(function () { schedulePoll(); }, function () { schedulePoll(); });
}

// --- actions ----------------------------------------------------------------

// withBusy serialises mutations: two overlapping toggles would race on the
// engine, and the service answers the second with an error anyway.
function withBusy(fn) {
  if (state.busy) return Promise.resolve();
  state.busy = true;
  renderStatus();
  renderNodes();
  return fn().then(function (v) {
    state.busy = false;
    return v;
  }, function (err) {
    state.busy = false;
    throw err;
  });
}

function toggleProxy(want) {
  withBusy(function () {
    return call('POST', '/api/proxy/toggle', { enabled: want }).then(function (res) {
      toast(res.message || (want ? 'Proxy started' : 'Proxy stopped'), 'ok');
    });
  }).catch(function (err) {
    if (err.status === 409) {
      toast('No nodes to start with. Refresh a subscription first.', 'err');
    } else {
      handleError(err, want ? 'start proxy' : 'stop proxy');
    }
  }).then(refreshAll);
}

function setAuto(want) {
  withBusy(function () {
    // {auto:false} alone is rejected by the API: turning auto-switch off means
    // pinning something, so fall back to the fastest node we know of.
    var body;
    if (want) {
      body = { auto: true };
    } else {
      var pick = pickManualNode();
      if (!pick) {
        return Promise.reject(new Error(
          'No node is loaded in the running config to pin. Refresh, or start the proxy first.'));
      }
      body = { node_id: pick.id };
    }
    return call('POST', '/api/proxy/select', body).then(function (res) {
      toast(res.message || 'Selection updated', 'ok');
    });
  }).catch(function (err) {
    handleError(err, 'select');
  }).then(refreshAll);
}

// pickManualNode returns the node to pin when auto-switch is turned off:
// whatever urltest is currently using if we can identify it, else the fastest
// node that is actually in the running config.
function pickManualNode() {
  var activeTag = state.selection.auto_pick || state.selection.active;
  var byTag = null;
  var fastest = null;
  state.nodes.forEach(function (n) {
    if (!n.in_config) return;
    if (activeTag && (n.effective_tag === activeTag || n.tag === activeTag)) byTag = byTag || n;
    if (!fastest && typeof n.latency_ms === 'number' && n.latency_ms >= 0) fastest = n;
  });
  // state.nodes is already sorted fastest-first by the API, so the first match
  // is the best one.
  return byTag || fastest || null;
}

function selectNode(id) {
  var node = null;
  state.nodes.forEach(function (n) { if (n.id === id) node = n; });
  if (node && !node.in_config) {
    toast('“' + node.tag + '” is not in the running engine config. Refresh, or restart the proxy.', 'err');
    return;
  }
  withBusy(function () {
    return call('POST', '/api/proxy/select', { node_id: id }).then(function (res) {
      var name = node ? node.tag : id;
      toast((res.applied ? 'Switched to ' : 'Saved ') + name +
        (res.applied ? '' : '; it takes effect when the proxy starts'), 'ok');
    });
  }).catch(function (err) {
    handleError(err, 'select node');
  }).then(refreshAll);
}

function startRefresh() {
  var prune = $('prune') && $('prune').checked;
  withBusy(function () {
    return call('POST', '/api/nodes/refresh' + (prune ? '?prune=1' : '')).then(function () {
      toast('Refresh started: fetching sources, then probing every node.', 'ok');
      state.jobRunning = true;
    });
  }).catch(function (err) {
    if (err.status === 409) {
      toast('A refresh is already running.', 'err');
      state.jobRunning = true;
    } else if (err.status === 503) {
      banner('No subscription URLs are configured on the server. Restart it with ' +
        '-sub <url> (or set PROXY_MANAGER_SUBS) — the URL box here cannot set them.');
    } else {
      handleError(err, 'refresh');
    }
  }).then(function () {
    return fetchStatus().catch(function () {});
  }).then(function () { schedulePoll(POLL_BUSY); });
}

// --- wiring -----------------------------------------------------------------

function initSubscriptionBox() {
  var input = $('sub-url');
  var note = $('sub-note');
  // Honest labelling: subscription sources come from the server's -sub flag and
  // there is no API to change them. decodeBody uses DisallowUnknownFields, so a
  // URL posted from here would be rejected outright. The box is a local note of
  // which URL this gateway is meant to be pulling, kept in this browser.
  text(note, 'Reference only, saved in this browser. The server refreshes the URLs given ' +
    'to it with -sub / PROXY_MANAGER_SUBS; this field cannot change them.');
  if (!input) return;
  try {
    var saved = window.localStorage.getItem(SUB_KEY);
    if (saved) input.value = saved;
  } catch (e) { /* ignore */ }
  input.addEventListener('change', function () {
    try {
      if (input.value) window.localStorage.setItem(SUB_KEY, input.value);
      else window.localStorage.removeItem(SUB_KEY);
    } catch (e) { /* ignore */ }
  });
}

function init() {
  initSubscriptionBox();

  $('proxy-toggle').addEventListener('change', function (ev) {
    toggleProxy(ev.target.checked);
  });
  $('auto-toggle').addEventListener('change', function (ev) {
    setAuto(ev.target.checked);
  });
  $('refresh-btn').addEventListener('click', startRefresh);

  $('token-btn').addEventListener('click', function () {
    var cur = token();
    var next = window.prompt(
      'Bearer token for /api routes. Leave empty if the server runs without -token.', cur);
    if (next === null) return;
    setToken(next.trim());
    banner('');
    toast(next.trim() ? 'Token saved in this browser.' : 'Token cleared.', 'ok');
    refreshAll();
  });

  // Delegated: rows are replaced on every render, so per-row listeners would
  // have to be rebound each time.
  $('node-rows').addEventListener('click', function (ev) {
    var btn = ev.target.closest('button[data-action="select"]');
    var row = ev.target.closest('tr[data-id]');
    var id = btn ? btn.dataset.id : row ? row.dataset.id : null;
    if (id) selectNode(id);
  });
  $('node-rows').addEventListener('keydown', function (ev) {
    if (ev.key !== 'Enter' && ev.key !== ' ') return;
    var row = ev.target.closest('tr[data-id]');
    if (!row) return;
    ev.preventDefault();
    selectNode(row.dataset.id);
  });

  document.addEventListener('visibilitychange', function () {
    if (!document.hidden) { refreshAll(); schedulePoll(); }
  });

  refreshAll().then(function () { schedulePoll(); }, function () { schedulePoll(); });
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init);
} else {
  init();
}
