// Embedded, dependency-free dashboard. The API is the source of truth;
// browser credentials live only in the server's HttpOnly session cookie.
'use strict';

(function () {
  var POLL_IDLE = 5000;
  var POLL_BUSY = 1500;
  var POLL_BACKOFF = 15000;
  var MAX_LOG_LINES = 500;
  var state = {
    selectedNodes: new Set(), chainHops: [], csrf: '', authenticated: false, exiting: false, busy: false, offline: false,
    status: null, nodes: [], subscriptions: [], selection: {}, settings: null,
    rulesDirty: false, rulesLoaded: false, settingsDirty: false, jobRunning: false, lastJob: null, pollTimer: null,
    inventoryAt: 0, inventoryKey: '', source: null, logWanted: false,
    lastLogID: 0, lastLogTime: 0, logAuthCheck: false
  };

  function $(id) { return document.getElementById(id); }
  function text(el, value) { if (el) el.textContent = value; }
  function element(tag, className, value) {
    var el = document.createElement(tag);
    if (className) el.className = className;
    if (value !== undefined) el.textContent = value;
    return el;
  }
  function notice(message) {
    text($('banner'), message);
    $('banner').hidden = !message;
  }
  function toast(message, kind) {
    if (state.exiting) return;
    var el = element('div', 'toast ' + (kind || ''), message);
    el.setAttribute('role', kind === 'err' ? 'alert' : 'status');
    $('toasts').appendChild(el);
    while ($('toasts').children.length > 4) $('toasts').firstChild.remove();
    window.setTimeout(function () { el.remove(); }, kind === 'err' ? 9000 : 5000);
  }
  function ago(value) {
    var timestamp = Date.parse(value);
    if (!timestamp || timestamp < 0) return 'Never';
    var seconds = Math.max(0, Math.round((Date.now() - timestamp) / 1000));
    if (seconds < 60) return seconds + 's ago';
    if (seconds < 3600) return Math.round(seconds / 60) + 'm ago';
    if (seconds < 86400) return Math.round(seconds / 3600) + 'h ago';
    return Math.round(seconds / 86400) + 'd ago';
  }

  function clearPrivateView() {
    stopLogs();
    state.nodes = [];
    state.subscriptions = [];
    state.status = null;
    state.settings = null;
    state.selection = {};
    state.csrf = '';
    ['subscriptions-list', 'config-nodes', 'log-lines', 'toasts', 'job', 'job-warnings-list', 'routing-rule-list', 'rule-source-list', 'usage-nodes'].forEach(function (id) { text($(id), ''); });
    ['stat-engine', 'stat-rules', 'stat-nodes', 'stat-active'].forEach(function (id) { text($(id), '—'); });
    ['stat-pid', 'stat-rules-err', 'stat-nodes-sub', 'stat-active-sub'].forEach(function (id) { text($(id), ''); });
    state.selectedNodes.clear(); state.chainHops = [];
    ['subscription-form', 'node-form', 'settings-form', 'rules-form', 'chain-builder-form'].forEach(function (id) { $(id).reset(); });
  }
  function signInRequired() {
    if (state.exiting) return;
    state.exiting = true;
    state.authenticated = false;
    window.clearTimeout(state.pollTimer);
    clearPrivateView();
    window.location.replace('/login.html');
  }

  async function call(method, path, body) {
    if (state.exiting) throw new Error('Session ended');
    var headers = { Accept: 'application/json' };
    if (method !== 'GET' && state.csrf) headers['X-CSRF-Token'] = state.csrf;
    var options = { method: method, headers: headers, credentials: 'same-origin', cache: 'no-store' };
    if (body !== undefined) {
      headers['Content-Type'] = 'application/json';
      options.body = JSON.stringify(body);
    }
    var response = await fetch(path, options);
    var raw = await response.text();
    var data = {};
    try { data = raw ? JSON.parse(raw) : {}; } catch (ignored) { /* report malformed response below */ }
    if (!response.ok) {
      var error = new Error(data.error || ('Request failed (HTTP ' + response.status + ').'));
      error.status = response.status;
      error.data = data;
      if (response.status === 401) signInRequired();
      throw error;
    }
    if (raw && !Object.keys(data).length && raw.trim() !== '{}') throw new Error('The API returned an invalid response.');
    return data;
  }

  function handleError(error, action) {
    if (state.exiting || error.status === 401) return;
    if (!error.status) {
      state.offline = true;
      notice('Cannot reach the gateway. Check its connection; status will refresh automatically.');
    }
    toast(action + ': ' + error.message, 'err');
    if (error.data && error.data.refresh) renderJob(error.data.refresh);
  }

  function updateControls() {
    document.querySelectorAll('[data-mutation]').forEach(function (button) {
      button.disabled = !state.authenticated || state.busy ||
        (button.hasAttribute('data-job') && state.jobRunning) ||
        button.dataset.unavailable === 'true';
    });
    $('proxy-toggle').disabled = !state.status || state.busy;
    $('auto-toggle').disabled = !state.status || state.busy;
    $('logout-btn').disabled = state.busy;
    updateBulkControls();
    $('refresh-all-btn').disabled = !state.authenticated || state.busy || state.jobRunning || !state.subscriptions.length;
  }

  function renderStatus() {
    var status = state.status;
    if (!status) { updateControls(); return; }
    var complete = status.proxy_enabled && status.engine_running && status.tproxy_rules_loaded;
    var label = complete ? 'Proxy enabled' : status.engine_running ? 'Engine running · interception off' : 'Proxy stopped';
    if (status.tproxy_rules_loaded && !status.engine_running) label = 'Interception active · engine stopped';
    if (state.offline) label = 'Gateway unreachable';
    text($('engine-status'), label);
    $('engine-status').className = 'pill ' + (state.offline ? 'bad' : complete ? 'good' : status.engine_running || status.tproxy_rules_loaded ? 'warning' : '');
    $('proxy-toggle').checked = !!status.proxy_enabled;
    text($('proxy-toggle-label'), status.proxy_enabled ? 'On' : 'Off');
    text($('stat-engine'), status.engine_running ? 'Running' : 'Stopped');
    text($('stat-pid'), status.engine_pid ? 'Process ' + status.engine_pid : 'Ready when you are');
    text($('stat-rules'), status.tproxy_rules_loaded ? 'Loaded' : 'Not loaded');
    text($('stat-rules-err'), status.tproxy_rules_error || (status.tproxy_rules_loaded ? 'LAN interception enabled' : 'LAN interception disabled'));
    text($('stat-nodes'), String(status.nodes_total || 0));
    text($('stat-nodes-sub'), (status.nodes_enabled || 0) + ' enabled · ' + (status.nodes_healthy || 0) + ' healthy');
    var selection = state.selection;
    var active = selection.auto ? selection.auto_pick || 'Finding a node…' : selection.tag || selection.active || 'No node selected';
    text($('stat-active'), active);
    $('stat-active').title = active;
    text($('stat-active-sub'), selection.auto ? 'Automatically selected' : 'Manually selected');
    $('auto-toggle').checked = !!selection.auto;
    text($('auto-toggle-label'), selection.auto ? 'Auto' : 'Manual');
    updateControls();
  }

  function renderJob(job) {
    var previous = state.lastJob;
    state.lastJob = job;
    state.jobRunning = job.state === 'running';
    $('job-panel').hidden = !job.state || job.state === 'idle';
    $('job-panel').classList.toggle('failed', job.state === 'failed');
    var name = job.kind === 'latency' ? 'Latency test' : job.kind === 'refresh' ? 'Subscription refresh' : 'Background task';
    var parts = [];
    if (state.jobRunning) parts.push(name + ' running. Testing nodes can take a few minutes on a Pi.');
    if (job.state === 'succeeded') parts.push(name + ' completed ' + ago(job.finished_at) + '.');
    if (job.state === 'failed') parts.push(name + ' failed: ' + (job.error || 'Unknown error'));
    if (job.sources_total) parts.push((job.sources_ok || 0) + '/' + job.sources_total + ' sources');
    if (job.nodes_added || job.nodes_updated) parts.push((job.nodes_added || 0) + ' added, ' + (job.nodes_updated || 0) + ' updated');
    if (job.tested) parts.push((job.reachable || 0) + '/' + job.tested + ' reachable');
    if (job.engine_reloaded) parts.push('Engine reloaded');
    text($('job'), parts.join(' · '));
    var warnings = job.warnings || [];
    $('job-warnings').hidden = !warnings.length;
    text($('job-warnings-list'), '');
    warnings.forEach(function (warning) { $('job-warnings-list').appendChild(element('li', '', warning)); });
    if (previous && previous.state === 'running' && !state.jobRunning) {
      state.inventoryAt = 0;
      if (job.state === 'succeeded') toast(name + ' complete.', 'ok');
      if (job.state === 'failed') toast(name + ': ' + (job.error || 'Unknown error'), 'err');
    }
    updateControls();
  }

  function latency(node) {
    if (typeof node.latency_ms !== 'number' || node.latency_ms < 0) {
      var tested = Date.parse(node.last_checked_at) > 0;
      return { label: tested ? 'Failed' : 'Untested', className: tested ? 'slow' : 'muted', title: tested ? node.last_error || 'Last test failed' : 'No latency test yet' };
    }
    return { label: node.latency_ms + ' ms', className: node.latency_ms < 200 ? 'good' : node.latency_ms < 500 ? 'medium' : 'slow', title: 'Latency through this node' };
  }
  function actionButton(label, action, id, unavailable, job) {
    var button = element('button', 'button small-button', label);
    button.type = 'button';
    button.dataset.action = action;
    button.dataset.id = id;
    button.dataset.mutation = '';
    button.dataset.unavailable = unavailable ? 'true' : 'false';
    if (job) button.dataset.job = '';
    return button;
  }
  function makeNodeTable(nodes, emptyMessage) {
    if (!nodes.length) return element('p', 'table-empty', emptyMessage);
    var wrapper = element('div', 'table-wrap');
    var table = element('table', 'node-table');
    var header = element('thead');
    var headingRow = element('tr');
    [ ['Select', ''], ['Configuration', ''], ['Protocol', 'protocol-column'], ['Server', 'server-column'], ['Latency', ''], ['Checked', 'checked-column'], ['Actions', 'action-heading'] ].forEach(function (column) {
      var th = element('th', column[1], column[0]);
      th.scope = 'col';
      headingRow.appendChild(th);
    });
    header.appendChild(headingRow);
    table.appendChild(header);
    var body = element('tbody');
    var activeTag = state.selection.auto ? state.selection.auto_pick : state.selection.active;
    nodes.forEach(function (node) {
      var pinned = !state.selection.auto && (node.selected || state.selection.node_id === node.id);
      var active = !!activeTag && (node.tag === activeTag || node.effective_tag === activeTag);
      var row = element('tr', pinned || active ? 'selected' : '');
      var checkCell = element('td'); var check = document.createElement('input'); check.type = 'checkbox'; check.dataset.selectNode = node.id; check.checked = state.selectedNodes.has(node.id); check.disabled = state.busy; check.setAttribute('aria-label', 'Select ' + (node.tag || node.server)); checkCell.appendChild(check); row.appendChild(checkCell);
      var name = element('td', 'node-name', node.tag || node.server);
      if (pinned || active) name.appendChild(element('span', 'pill good', pinned ? 'Pinned' : 'Active'));
      if (state.status && state.status.engine_running && !node.in_config) name.appendChild(element('span', 'pill', 'Not loaded'));
      row.appendChild(name);
      row.appendChild(element('td', 'node-protocol protocol-column', node.protocol + (node.transport ? ' / ' + node.transport : '')));
      var server = node.server || '';
      if (server.indexOf(':') !== -1) server = '[' + server + ']';
      row.appendChild(element('td', 'node-server server-column', server + ':' + node.port));
      var result = latency(node);
      var resultCell = element('td', 'latency ' + result.className, result.label);
      resultCell.title = result.title;
      row.appendChild(resultCell);
      row.appendChild(element('td', 'muted small checked-column', ago(node.last_checked_at)));
      var actions = element('td');
      var buttons = element('div', 'node-actions');
      var select = actionButton(pinned ? 'Pinned' : 'Activate', 'select-node', node.id, pinned || !node.enabled, false);
      select.setAttribute('aria-label', (pinned ? 'Pinned configuration: ' : 'Activate ') + (node.tag || node.server));
      if (pinned) select.classList.add('active-button');
      buttons.appendChild(select);
      actions.appendChild(buttons);
      row.appendChild(actions);
      body.appendChild(row);
    });
    table.appendChild(body);
    wrapper.appendChild(table);
    return wrapper;
  }

  function isManual(node) { return node.manual === true || (node.manual === undefined && !(node.subscription_ids || []).length); }
  function renderInventory() {
    var key = JSON.stringify([state.nodes, state.subscriptions, state.selection, state.status && state.status.engine_running]);
    if (key === state.inventoryKey) { updateControls(); return; }
    state.inventoryKey = key;
    var focused = document.activeElement;
    var focusAction = focused && focused.dataset.action;
    var focusID = focused && focused.dataset.id;
    text($('subscriptions-list'), '');
    text($('subscription-count'), String(state.subscriptions.length));
    $('subscriptions-empty').hidden = !!state.subscriptions.length;
    state.subscriptions.forEach(function (subscription) {
      var card = element('article', 'card');
      var heading = element('div', 'subscription-heading');
      var details = element('div');
      var title = element('div', 'subscription-name');
      title.appendChild(element('h3', '', subscription.name || 'Subscription'));
      var nodes = state.nodes.filter(function (node) { return (node.subscription_ids || []).indexOf(subscription.id) !== -1; });
      title.appendChild(element('span', 'count', String(nodes.length)));
      details.appendChild(title);
      var source = element('details', 'subscription-source');
      source.appendChild(element('summary', '', 'Show source URL'));
      source.appendChild(element('p', 'muted', subscription.url));
      details.appendChild(source);
      heading.appendChild(details);
      var actions = element('div', 'subscription-buttons');
      actions.appendChild(actionButton('Refresh', 'refresh-subscription', subscription.id, false, true));
      heading.appendChild(actions);
      card.appendChild(heading);
      $('subscriptions-list').appendChild(card);
    });
    var validIDs = new Set(state.nodes.map(function(n){return n.id;}));
    state.selectedNodes.forEach(function(id){if(!validIDs.has(id))state.selectedNodes.delete(id);});
    text($('config-nodes'), ''); $('configs-empty').hidden = !!state.nodes.length;
    $('config-nodes').appendChild(makeNodeTable(state.nodes, 'No configurations yet.'));
    renderChainBuilder();
    updateControls();
    if (focusAction && focusID) {
      var replacement = Array.from(document.querySelectorAll('[data-action]')).find(function (button) { return button.dataset.action === focusAction && button.dataset.id === focusID; });
      if (replacement && !replacement.disabled) replacement.focus({ preventScroll: true });
    }
  }

  function renderSettings(settings) {
    state.settings = settings;
    if (state.settingsDirty) return;
    $('dns-server').value = settings.dns_server || '';
    $('iran-bypass').checked = !!settings.iran_bypass;
    text($('iran-label'), settings.iran_bypass ? 'On' : 'Off');
  }

  async function fetchStatus() {
    var status = await call('GET', '/api/status');
    if (state.exiting) return;
    state.status = status;
    state.selection = status.selection || {};
    state.offline = false;
    notice('');
    renderJob(status.refresh || {});
    renderStatus();
    renderInventory();
    text($('updated'), 'Updated ' + new Date().toLocaleTimeString());
  }
  async function fetchInventory() {
    var responses = await Promise.all([call('GET', '/api/nodes'), call('GET', '/api/subscriptions')]);
    if (state.exiting) return;
    state.nodes = responses[0].nodes || [];
    state.selection = responses[0].selection || state.selection;
    state.subscriptions = responses[1].subscriptions || [];
    state.inventoryAt = Date.now();
    renderInventory();
    renderStatus();
  }
  async function reconcile() {
    await fetchStatus();
    await fetchInventory();
  }
  function schedulePoll(delay) {
    window.clearTimeout(state.pollTimer);
    if (state.exiting) return;
    var wait = delay || (state.offline ? POLL_BACKOFF : state.jobRunning ? POLL_BUSY : POLL_IDLE);
    text($('foot-poll'), 'Updates every ' + Math.round(wait / 1000) + 's');
    state.pollTimer = window.setTimeout(poll, wait);
  }
  async function poll() {
    if (state.exiting) return;
    if (document.hidden || state.busy) { schedulePoll(); return; }
    try {
      await fetchStatus();
      if (Date.now() - state.inventoryAt > 15000) await fetchInventory();
      if (!state.settings) renderSettings(await call('GET', '/api/settings'));
      if (window.location.hash === '#configurations') renderUsage(await call('GET', '/api/usage'));
      if (state.rulesLoaded || window.location.hash === '#settings') renderRules(await call('GET', '/api/rules'));
    } catch (error) {
      if (!state.exiting) {
        state.offline = true;
        notice(error.status ? 'Could not refresh gateway status: ' + error.message : 'Cannot reach the gateway. Check its connection; status will refresh automatically.');
        renderStatus();
      }
    }
    schedulePoll();
  }

  async function mutate(action, operation) {
    if (state.busy || state.exiting || !state.authenticated) return;
    state.busy = true;
    window.clearTimeout(state.pollTimer);
    updateControls();
    try { await operation(); }
    catch (error) { handleError(error, action); }
    try { if (!state.exiting) await reconcile(); }
    catch (error) { handleError(error, 'Refresh status'); }
    state.busy = false;
    renderStatus();
    updateControls();
    schedulePoll();
  }
  function startJob(path, body, message) {
    return mutate('Start task', async function () {
      var response = await call('POST', path, body);
      if (response.refresh) renderJob(response.refresh);
      state.jobRunning = true;
      toast(message, 'ok');
    });
  }
  function selectNode(id) {
    return mutate('Activate config', async function () {
      var response = await call('POST', '/api/proxy/select', { node_id: id });
      toast(response.message || 'Node selection saved.', 'ok');
    });
  }
  function manualPick() {
    var activeTag = state.selection.auto_pick || state.selection.active;
    var available = state.nodes.filter(function (node) { return node.enabled && (!state.status.engine_running || node.in_config); });
    return available.find(function (node) { return node.effective_tag === activeTag || node.tag === activeTag; }) || available[0];
  }

  function activateTab(name, focus) {
    var tabs = Array.from(document.querySelectorAll('[data-tab]'));
    if (['subscriptions','manual','usage'].includes(name)) name = 'configurations';
    if (name === 'rules') name = 'settings';
    if (!tabs.some(function (tab) { return tab.dataset.tab === name; })) name = 'configurations';
    tabs.forEach(function (tab) {
      var active = tab.dataset.tab === name;
      tab.setAttribute('aria-selected', active ? 'true' : 'false');
      tab.tabIndex = active ? 0 : -1;
      $(tab.getAttribute('aria-controls')).hidden = !active;
      if (active && focus) tab.focus();
    });
    window.history.replaceState(null, '', '#' + name);
  }

  function stopLogs() {
    if (state.source) { state.source.close(); state.source = null; }
    state.logWanted = false;
    $('logs-toggle').checked = false;
    text($('logs-label'), 'Off');
    text($('log-status'), 'Stream is off. Existing lines stay in this view.');
    $('log-dot').classList.remove('live');
  }
  function appendLog(event) {
    if (!state.logWanted || state.exiting) return;
    var entry;
    try { entry = JSON.parse(event.data); } catch (ignored) { return; }
    if (!entry || typeof entry.message !== 'string') return;
    var id = Number(event.lastEventId || entry.id);
    var eventTime = Date.parse(entry.time) || 0;
    if (Number.isFinite(id) && id > 0 && id <= state.lastLogID && eventTime <= state.lastLogTime) return;
    if (Number.isFinite(id) && id > 0) { state.lastLogID = id; state.lastLogTime = eventTime; }
    var box = $('log-lines');
    var following = box.scrollHeight - box.scrollTop - box.clientHeight < 70;
    var placeholder = $('logs-empty');
    if (placeholder) placeholder.remove();
    var level = String(entry.level || 'INFO').toUpperCase();
    var row = element('div', 'log-line');
    if (level === 'ERROR' || level === 'FATAL') row.classList.add('error');
    if (level === 'WARN' || level === 'WARNING') row.classList.add('warn');
    var timestamp = new Date(entry.time);
    var when = isNaN(timestamp.getTime()) ? '—' : timestamp.toLocaleTimeString([], { hour12: false });
    var time = element('time', 'log-time', when);
    if (!isNaN(timestamp.getTime())) time.dateTime = timestamp.toISOString();
    row.appendChild(time);
    row.appendChild(element('span', 'log-level', level));
    row.appendChild(element('span', 'log-source', String(entry.source || 'service')));
    // textContent prevents escape sequences or provider-controlled HTML in logs
    // from becoming executable markup in an authenticated admin session.
    row.appendChild(element('span', 'log-message', entry.message));
    box.appendChild(row);
    while (box.children.length > MAX_LOG_LINES) box.firstChild.remove();
    text($('log-count'), box.children.length + ' lines');
    if (following) box.scrollTop = box.scrollHeight;
  }
  function startLogs() {
    if (state.source || state.exiting) return;
    if (!window.EventSource) {
      $('logs-toggle').checked = false;
      toast('This browser does not support live log streaming.', 'err');
      return;
    }
    state.logWanted = true;
    $('logs-toggle').checked = true;
    text($('logs-label'), 'On');
    text($('log-status'), 'Connecting to the log stream…');
    var source = new EventSource('/api/logs');
    state.source = source;
    source.addEventListener('log', appendLog);
    source.onopen = function () {
      if (state.source !== source) return;
      text($('log-status'), 'Connected · receiving Go service and sing-box logs');
      $('log-dot').classList.add('live');
    };
    source.onerror = async function () {
      if (state.source !== source || !state.logWanted) return;
      $('log-dot').classList.remove('live');
      text($('log-status'), 'Connection interrupted. Reconnecting…');
      // EventSource hides HTTP status codes. Check the session separately so an
      // expired cookie redirects to login instead of retrying forever.
      if (state.logAuthCheck) return;
      state.logAuthCheck = true;
      try {
        var session = await call('GET', '/api/auth/session');
        if (session.auth_required && !session.authenticated) signInRequired();
        else if (source.readyState === EventSource.CLOSED && state.source === source) {
          stopLogs();
          text($('log-status'), 'Log stream unavailable. Turn it on to retry.');
        }
      } catch (ignored) { /* ordinary status polling reports a disconnected Pi */ }
      state.logAuthCheck = false;
    };
  }

  function wireEvents() {
    document.querySelectorAll('[data-tab]').forEach(function (tab) {
      tab.addEventListener('click', function () { activateTab(tab.dataset.tab, false); });
      tab.addEventListener('keydown', function (event) {
        var tabs = Array.from(document.querySelectorAll('[data-tab]'));
        var index = tabs.indexOf(tab);
        if (event.key === 'ArrowRight') index = (index + 1) % tabs.length;
        else if (event.key === 'ArrowLeft') index = (index + tabs.length - 1) % tabs.length;
        else if (event.key === 'Home') index = 0;
        else if (event.key === 'End') index = tabs.length - 1;
        else return;
        event.preventDefault();
        activateTab(tabs[index].dataset.tab, true);
      });
    });
    document.addEventListener('click', function (event) {
      var button = event.target.closest('[data-action]');
      if (!button || button.disabled) return;
      var id = button.dataset.id;
      if (button.dataset.action === 'select-node') selectNode(id);
      if (button.dataset.action === 'test-subscription') startJob('/api/subscriptions/test', { subscription_id: id }, 'Subscription latency test started.');
      if (button.dataset.action === 'refresh-subscription') startJob('/api/subscriptions/refresh', { subscription_id: id }, 'Subscription refresh started.');
    });
    $('proxy-toggle').addEventListener('change', function (event) {
      var enabled = event.target.checked;
      mutate('Toggle proxy', async function () {
        var response = await call('POST', '/api/proxy/toggle', { enabled: enabled });
        toast(response.message || (enabled ? 'Proxy enabled.' : 'Proxy disabled.'), 'ok');
      });
    });
    $('auto-toggle').addEventListener('change', function (event) {
      var auto = event.target.checked;
      mutate('Change selection', async function () {
        var pick = auto ? null : manualPick();
        if (!auto && !pick) { toast('Add or refresh a configuration before pinning a node.', 'err'); return; }
        var response = await call('POST', '/api/proxy/select', auto ? { auto: true } : { node_id: pick.id });
        toast(response.message || 'Selection updated.', 'ok');
      });
    });
    $('subscription-form').addEventListener('submit', function (event) {
      event.preventDefault();
      var payload = { name: $('sub-name').value.trim(), url: $('sub-url').value.trim() };
      mutate('Add subscription', async function () {
        await call('POST', '/api/subscriptions', payload);
        $('subscription-form').reset();
        toast('Subscription saved. Use Refresh to import its nodes.', 'ok');
      });
    });
    $('node-form').addEventListener('submit', function (event) {
      event.preventDefault();
      var link = $('node-link').value.trim();
      mutate('Add config', async function () {
        var response = await call('POST', '/api/nodes', { link: link });
        $('node-form').reset();
        toast(response.message || 'Configuration added.', 'ok');
      });
    });
    $('refresh-all-btn').addEventListener('click', function () { startJob('/api/nodes/refresh', undefined, 'All subscriptions are refreshing and testing.'); });
    $('settings-form').addEventListener('input', function () {
      state.settingsDirty = true;
      text($('settings-note'), 'Unsaved changes');
      text($('iran-label'), $('iran-bypass').checked ? 'On' : 'Off');
    });
    $('settings-form').addEventListener('submit', function (event) {
      event.preventDefault();
      var settings = { dns_server: $('dns-server').value.trim(), iran_bypass: $('iran-bypass').checked };
      mutate('Save settings', async function () {
        var response = await call('PUT', '/api/settings', settings);
        state.settingsDirty = false;
        renderSettings(response);
        text($('settings-note'), 'Settings saved');
        toast('DNS and routing settings saved.', 'ok');
      });
    });
    $('logs-toggle').addEventListener('change', function (event) { if (event.target.checked) startLogs(); else stopLogs(); });
    $('clear-logs-btn').addEventListener('click', function () { text($('log-lines'), ''); text($('log-count'), '0 lines'); });
    $('logout-btn').addEventListener('click', async function () {
      if (state.busy) return;
      state.busy = true;
      updateControls();
      stopLogs();
      try { await call('POST', '/api/auth/logout', {}); signInRequired(); }
      catch (error) { handleError(error, 'Sign out'); state.busy = false; updateControls(); }
    });
    document.addEventListener('visibilitychange', function () {
      if (!document.hidden && !state.exiting) { state.inventoryAt = 0; schedulePoll(100); }
    });
    window.addEventListener('pagehide', function () { stopLogs(); window.clearTimeout(state.pollTimer); });
    window.addEventListener('pageshow', function (event) { if (event.persisted) window.location.reload(); });
  }

  function updateBulkControls() {
    var count=state.selectedNodes.size;
    text($('selected-count'), count+' selected');
    $('bulk-ping').disabled=$('bulk-delete').disabled=!count || state.busy || state.jobRunning || !state.authenticated;
    $('select-all-nodes').disabled=state.busy || !state.nodes.length;
    $('select-all-nodes').checked=!!state.nodes.length && count===state.nodes.length;
    $('select-all-nodes').indeterminate=count>0 && count<state.nodes.length;
    document.querySelectorAll('[data-select-node]').forEach(function(box){box.checked=state.selectedNodes.has(box.dataset.selectNode);box.disabled=state.busy;});
    $('chain-save').disabled=state.busy || state.jobRunning || state.chainHops.length<2 || !state.authenticated;
    $('chain-add-hop').disabled=state.busy || state.chainHops.length>=8 || !$('chain-builder-node').value || !state.authenticated;
  }
  function renderChainBuilder() {
    var select=$('chain-builder-node'),previous=select.value; text(select,'');
    state.nodes.filter(function(n){return n.enabled && !n.detour_id && !n.detour && !state.chainHops.includes(n.id);}).forEach(function(n){var option=element('option','',n.tag+' · '+n.server);option.value=n.id;select.appendChild(option);});
    if(Array.from(select.options).some(function(o){return o.value===previous;}))select.value=previous;
    var label=function(id){var n=state.nodes.find(function(n){return n.id===id;});return n?n.tag:'Unavailable node';};
    text($('chain-hops'),'');
    state.chainHops.forEach(function(id,index){var row=element('li','',label(id)+' ');
      [['↑',-1],['↓',1],['Remove',0]].forEach(function(action){var b=element('button','button subtle',action[0]);b.type='button';b.dataset.mutation='';b.setAttribute('aria-label',action[0]+' hop '+(index+1));b.addEventListener('click',function(){if(action[1]===0)state.chainHops.splice(index,1);else{var next=index+action[1];if(next<0||next>=state.chainHops.length)return;var tmp=state.chainHops[next];state.chainHops[next]=id;state.chainHops[index]=tmp;}renderChainBuilder();updateControls();});row.appendChild(b);});$('chain-hops').appendChild(row);
    });
    text($('chain-preview'),state.chainHops.map(label).join(' → '));
  }
  function wireBatchEvents() {
    document.addEventListener('change',function(event){var id=event.target.dataset.selectNode;if(!id)return;if(event.target.checked)state.selectedNodes.add(id);else state.selectedNodes.delete(id);updateBulkControls();});
    $('select-all-nodes').addEventListener('change',function(){state.selectedNodes=new Set(this.checked?state.nodes.map(function(n){return n.id;}):[]);updateBulkControls();});
    $('bulk-ping').addEventListener('click',function(){startJob('/api/nodes/test',{node_ids:Array.from(state.selectedNodes)},'Selected latency tests started.');});
    $('bulk-delete').addEventListener('click',function(){var ids=Array.from(state.selectedNodes);if(!window.confirm('Delete '+ids.length+' selected configurations? Deleting the active config switches to Auto; deleting all configs stops the proxy. Subscription refresh may reimport provider nodes.'))return;mutate('Bulk delete',async function(){await call('POST','/api/nodes/delete',{node_ids:ids});state.selectedNodes.clear();toast('Selected configurations deleted.','ok');});});
    $('chain-builder-node').addEventListener('change',updateBulkControls);
    $('chain-add-hop').addEventListener('click',function(){var id=$('chain-builder-node').value;if(id && !state.chainHops.includes(id) && state.chainHops.length<8)state.chainHops.push(id);renderChainBuilder();updateControls();});
    $('chain-builder-form').addEventListener('submit',function(event){event.preventDefault();var payload={name:$('chain-builder-name').value.trim(),node_ids:state.chainHops.slice()};mutate('Save chain',async function(){await call('POST','/api/chains',payload);state.chainHops=[];$('chain-builder-name').value='';renderChainBuilder();toast('New chained configuration saved.','ok');});});
  }

  function addRuleSource(source) {
    var row = element('article','card routing-rule');
    ruleField(row,'Unique tag (custom-...)','tag',source.tag); ruleField(row,'HTTPS .srs URL','url',source.url);
    ruleField(row,'Enabled','enabled',source.enabled); ruleField(row,'Action','action',source.action,['direct','proxy','reject']);
    [['Move up',function(){if(row.previousElementSibling)row.parentNode.insertBefore(row,row.previousElementSibling);}],['Move down',function(){if(row.nextElementSibling)row.parentNode.insertBefore(row.nextElementSibling,row);}],['Delete',function(){row.remove();}]].forEach(function(item){var b=element('button','button subtle',item[0]);b.type='button';b.dataset.mutation='';b.addEventListener('click',function(){item[1]();state.rulesDirty=true;text($('rules-note'),'Unsaved changes');});row.appendChild(b);});
    $('rule-source-list').appendChild(row); updateControls();
  }
  function byteCount(n) { var units=['B','KiB','MiB','GiB','TiB'];var i=0;while(n>=1024&&i<4){n/=1024;i++;}return n.toFixed(i?2:0)+' '+units[i]; }
  function renderUsage(response) {
    var u=response.usage; var total=u.total || {};
    text($('usage-total'),'Upload '+byteCount(total.upload||0)+' · Download '+byteCount(total.download||0)+' · Total '+byteCount((total.upload||0)+(total.download||0)));
    text($('usage-status'),'Last sample: '+ago(u.last_sample)+(u.error?' · '+u.error:'')+(!response.supported?' · Clash statistics unavailable':''));
    var list=$('usage-nodes');text(list,'');var table=element('table','node-table');var head=element('tr');['Configuration / route (estimated)','Upload','Download'].forEach(function(label){head.appendChild(element('th','',label));});table.appendChild(head);
    var values=u.outbounds||{};var keys=Array.from(new Set(['direct'].concat(state.nodes.map(function(n){return n.id;}),Object.keys(values))));
    keys.forEach(function(key){var n=state.nodes.find(function(n){return n.id===key;});var value=values[key]||{};var row=element('tr');row.appendChild(element('td','',key==='direct'?'Direct / bypass':n?n.tag:key));row.appendChild(element('td','',byteCount(value.upload||0)));row.appendChild(element('td','',byteCount(value.download||0)));table.appendChild(row);});list.appendChild(table);
  }

  function ruleField(row, label, name, value, choices) {
    var wrap = element('div', 'field');
    var caption = element('label', '', label);
    var input = document.createElement(choices ? 'select' : name === 'values' ? 'textarea' : 'input');
    input.dataset.field = name;
    input.setAttribute('aria-label', label);
    if (choices) choices.forEach(function (choice) { var option = element('option', '', choice); option.value = choice; input.appendChild(option); });
    if (name === 'enabled') { input.type = 'checkbox'; input.checked = value; }
    else { input.value = Array.isArray(value) ? value.join('\n') : value; input.required = true; }
    if (name === 'name') input.maxLength = 100;
    caption.appendChild(input); wrap.appendChild(caption); row.appendChild(wrap);
    return input;
  }
  function addRoutingRule(rule) {
    var row = element('article', 'card routing-rule');
    ruleField(row, 'Name', 'name', rule.name);
    ruleField(row, 'Enabled', 'enabled', rule.enabled);
    ruleField(row, 'Match type', 'match', rule.match, ['domain', 'domain_suffix', 'ip_cidr']);
    ruleField(row, 'Match values (one per line)', 'values', rule.values);
    ruleField(row, 'Action', 'action', rule.action, ['direct', 'proxy', 'reject']);
    var controls = element('div', 'form-footer');
    [['Move up', function () { if (row.previousElementSibling) row.parentNode.insertBefore(row, row.previousElementSibling); }],
      ['Move down', function () { if (row.nextElementSibling) row.parentNode.insertBefore(row.nextElementSibling, row); }],
      ['Delete', function () { row.remove(); }]].forEach(function (item) {
        var button = element('button', 'button subtle', item[0]); button.type = 'button'; button.dataset.mutation = '';
        button.addEventListener('click', function () { item[1](); state.rulesDirty = true; text($('rules-note'), 'Unsaved changes'); }); controls.appendChild(button);
      });
    row.appendChild(controls); $('routing-rule-list').appendChild(row);
  }
  function renderRules(status) {
    state.rulesLoaded = true;
    text($('rules-status'), 'Last successful update: ' + ago(status.last_update) +
      (!String(status.next_update).startsWith('0001') ? ' · Next due: ' + (Date.parse(status.next_update) > Date.now() ? new Date(status.next_update).toLocaleString() : 'within a minute when no other task is running') : ' · Automatic updates off') +
      (status.error ? ' · Last error: ' + status.error : '') + ' · Files: ' + (Object.values(status.files || {}).join(', ') || 'Not downloaded by manager yet'));
    if (state.rulesDirty) return;
    var p = status.policy;
    $('calendar-mode').value = p.schedule || 'interval'; $('calendar-time').value = p.time_of_day || '03:00'; $('calendar-day').value = String(p.weekday || 0); $('calendar-zone').value = p.timezone || 'Asia/Tehran';
    text($('rule-source-list'), ''); (p.sources || []).forEach(addRuleSource);
    syncCalendarControls();
    $('rules-days').value = p.update_days;
    $('rules-schedule').value = [0, 1, 7, 30].includes(p.update_days) ? String(p.update_days) : 'custom';
    $('rules-geoip').value = p.geoip_url; $('rules-geosite').value = p.geosite_url; $('rules-iran-action').value = p.iran_action;
    text($('routing-rule-list'), ''); (p.rules || []).forEach(addRoutingRule);
    updateControls();
  }
  function readRulePolicy() {
    return { schedule: $('calendar-mode').value, time_of_day: $('calendar-time').value, weekday: Number($('calendar-day').value), timezone: $('calendar-zone').value.trim(), sources: Array.from($('rule-source-list').children).map(function(row) { var get = function(name) { return row.querySelector('[data-field="' + name + '"]'); }; return {tag:get('tag').value.trim(), url:get('url').value.trim(), action:get('action').value, enabled:get('enabled').checked}; }), update_days: Number($('rules-days').value), geoip_url: $('rules-geoip').value.trim(), geosite_url: $('rules-geosite').value.trim(), iran_action: $('rules-iran-action').value,
      rules: Array.from($('routing-rule-list').children).map(function (row) {
        var get = function (name) { return row.querySelector('[data-field="' + name + '"]'); };
        return { name: get('name').value.trim(), enabled: get('enabled').checked, match: get('match').value, action: get('action').value, values: get('values').value.split(/\r?\n/).map(function (v) { return v.trim(); }).filter(Boolean) };
      }) };
  }
  function syncCalendarControls() {
    var mode = $('calendar-mode').value;
    ['rules-schedule','rules-days'].forEach(function(id){$(id).disabled = mode !== 'interval';});
    ['calendar-time','calendar-zone'].forEach(function(id){$(id).disabled = mode === 'interval';});
    $('calendar-day').disabled = mode !== 'weekly';
  }
  function wireRuleEvents() {
    $('calendar-mode').addEventListener('change',syncCalendarControls);

    $('source-add').addEventListener('click', function () { addRuleSource({tag:'custom-',url:'',enabled:true,action:'direct'}); state.rulesDirty = true; });

    $('rules-form').addEventListener('input', function () { state.rulesDirty = true; text($('rules-note'), 'Unsaved changes'); });
    $('rules-schedule').addEventListener('change', function () { if (this.value !== 'custom') $('rules-days').value = this.value; });
    $('rules-add').addEventListener('click', function () { addRoutingRule({ name: '', enabled: true, match: 'domain_suffix', values: [], action: 'direct' }); state.rulesDirty = true; text($('rules-note'), 'Unsaved changes'); updateControls(); });
    $('rules-form').addEventListener('submit', function (event) {
      event.preventDefault(); var policy = readRulePolicy();
      mutate('Save routing rules', async function () { var result = await call('PUT', '/api/rules', policy); state.rulesDirty = false; renderRules(result); text($('rules-note'), 'Rules saved'); toast('Routing rules saved.', 'ok'); });
    });
    $('rules-update').addEventListener('click', function () {
      if (state.rulesDirty) { toast('Save your routing changes before updating rule sets.', 'err'); return; }
      mutate('Update rule sets', async function () { await call('POST', '/api/rules/update', {}); toast('GeoIP/geosite update started.', 'ok'); });
    });
  }

  async function init() {
    // Remove the previous dashboard's persisted bearer token during migration.
    // Never read or reuse it; this dashboard authenticates with a session cookie.
    try { window.localStorage.removeItem('pm.token'); window.localStorage.removeItem('pm.subUrl'); } catch (ignored) {}
    wireEvents();
    wireRuleEvents();
    wireBatchEvents();
    updateControls();
    activateTab(window.location.hash.slice(1), false);
    try {
      var session = await call('GET', '/api/auth/session');
      if (session.auth_required && !session.authenticated) { signInRequired(); return; }
      state.authenticated = true;
      state.csrf = session.csrf_token || '';
      $('logout-btn').hidden = !session.auth_required;
      await reconcile();
      renderSettings(await call('GET', '/api/settings'));
      renderRules(await call('GET', '/api/rules'));
      renderUsage(await call('GET', '/api/usage'));
    } catch (error) {
      handleError(error, 'Load dashboard');
      // A session check must succeed before enabling any controls. Reloading
      // obtains a fresh CSRF token after a restart or initial transport failure.
      if (!state.authenticated && !state.exiting) {
        text($('foot-poll'), 'Retrying connection…');
        state.pollTimer = window.setTimeout(function () { window.location.reload(); }, POLL_BACKOFF);
        return;
      }
    }
    schedulePoll();
  }
  init();
}());
