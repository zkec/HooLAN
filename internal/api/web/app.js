// Embedded, dependency-free dashboard. The API is the source of truth;
// browser credentials live only in the server's HttpOnly session cookie.
'use strict';

(function () {
  var POLL_IDLE = 5000;
  var POLL_BUSY = 1500;
  var POLL_BACKOFF = 15000;
  var MAX_LOG_LINES = 500;
  var state = {
    speedResults: new Map(), telegramLoaded: false, qrLoad: null, qrGeneration: 0, groupSelections: new Map(), groupOpen: new Map(), editingNode: null, chainEditingID: null, chainExistingNodes: [], chainHops: [], csrf: '', authenticated: false, exiting: false, busy: false, offline: false,
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
    ['subscriptions-list', 'manual-group', 'log-lines', 'toasts', 'job', 'job-warnings-list', 'routing-rule-list', 'rule-source-list', 'usage-nodes', 'usage-devices'].forEach(function (id) { text($(id), ''); });
    ['stat-engine', 'stat-rules', 'stat-nodes', 'stat-active'].forEach(function (id) { text($(id), '—'); });
    ['stat-pid', 'stat-rules-err', 'stat-nodes-sub', 'stat-active-sub'].forEach(function (id) { text($(id), ''); });
    state.groupSelections.clear(); state.chainHops = []; state.chainExistingNodes = []; state.chainEditingID = null;
    if ($('qr-dialog').open) $('qr-dialog').close();
    if ($('node-editor').open) $('node-editor').close();
    ['balance-form', 'telegram-form', 'subscription-form', 'node-form', 'settings-form', 'rules-form', 'chain-builder-form'].forEach(function (id) { $(id).reset(); });
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
    $('stat-active').toggleAttribute('data-no-i18n', !!(selection.auto ? selection.auto_pick : selection.tag || selection.active));
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
    var name = ({telegram:'Telegram test',speed:'Speed test',restore:'Restore backup',health:'Active node health check',latency:'Latency test',refresh:'Subscription refresh'})[job.kind] || 'Background task';
    if (job.kind === 'speed' && job.node_id) state.speedResults.set(job.node_id, {state:job.state,mbps:job.speed && job.speed.mbps,server:job.speed && job.speed.server,error:job.error});
    if (previous && previous.state === 'running' && job.kind === 'restore' && job.state === 'succeeded') { state.settings = null; state.settingsDirty = false; state.rulesDirty = false; state.telegramLoaded = false; state.speedResults.clear(); }
    if (job.kind === 'telegram') text($('telegram-status'), job.state === 'running' ? 'Sending test message…' : job.state === 'succeeded' ? 'Test message sent.' : job.error || 'Telegram test failed');
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
  function makeNodeTable(nodes, emptyMessage, group) {
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
    var activeTag = state.selection.auto ? (state.selection.auto_pick || state.selection.active) : state.selection.active;
    nodes.forEach(function (node) {
      var pinned = !state.selection.auto && (node.selected || state.selection.node_id === node.id);
      var active = !!activeTag && (node.tag === activeTag || node.effective_tag === activeTag);
      var row = element('tr', pinned || active ? 'selected' : '');
      var checkCell = element('td'); var check = document.createElement('input'); check.type = 'checkbox'; check.dataset.selectNode = node.id; check.dataset.group = group; check.checked = groupSelection(group).has(node.id); check.disabled = state.busy; check.setAttribute('aria-label', 'Select ' + (node.tag || node.server)); checkCell.appendChild(check); row.appendChild(checkCell);
      var name = element('td', 'node-name'); var nodeName = element('span', '', node.tag || node.server); nodeName.dataset.noI18n = ''; name.appendChild(nodeName);
      if (pinned || active) name.appendChild(element('span', 'pill good', pinned ? 'Pinned' : 'Active'));
      if (state.status && state.status.engine_running && !node.in_config) name.appendChild(element('span', 'pill', 'Not loaded'));
      row.appendChild(name);
      row.appendChild(element('td', 'node-protocol protocol-column', node.protocol === 'loadbalance' ? 'Load Balanced' : node.protocol + (node.transport ? ' / ' + node.transport : '')));
      var server = node.server || '';
      if (server.indexOf(':') !== -1) server = '[' + server + ']';
      row.appendChild(element('td', 'node-server server-column', node.protocol === 'loadbalance' ? String(node.member_count) + ' members' : server + ':' + node.port));
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
      if (node.protocol !== 'loadbalance' && (node.chain_id || isManual(node))) buttons.appendChild(actionButton('Edit', node.chain_id ? 'edit-chain' : 'edit-node', node.id, false, true));
      var speed = state.speedResults.get(node.id);
      var speedButton = actionButton(speed && speed.state === 'running' ? 'Testing…' : 'Speed Test', 'speed-node', node.id, !node.enabled || node.protocol === 'loadbalance', true);
      if (speed && speed.state === 'running') { speedButton.classList.add('testing'); speedButton.setAttribute('aria-busy','true'); }
      buttons.appendChild(speedButton);
      if (speed && speed.state === 'succeeded') { var result = element('span','speed-result',Number(speed.mbps).toFixed(2)+' Mbps'); result.title = speed.server || ''; buttons.appendChild(result); }
      if (speed && speed.state === 'failed') { var failed = element('span','muted small','Speed test failed'); failed.title = speed.error || ''; buttons.appendChild(failed); }
      var qr = actionButton('QR Code','qr-node',node.id,!!(node.chain_id || node.detour_id || node.detour || node.protocol === 'loadbalance'),false);
      if (qr.dataset.unavailable === 'true') qr.title = 'Chains cannot be shared as one mobile link';
      buttons.appendChild(qr);
      actions.appendChild(buttons);
      row.appendChild(actions);
      body.appendChild(row);
    });
    table.appendChild(body);
    wrapper.appendChild(table);
    return wrapper;
  }

  function isManual(node) { return node.manual === true || (node.manual === undefined && !(node.subscription_ids || []).length); }
  function groupSelection(group) {
    if (!state.groupSelections.has(group)) state.groupSelections.set(group, new Set());
    return state.groupSelections.get(group);
  }
  function groupNodes(group) {
    return state.nodes.filter(function (node) {
      return group === 'manual' ? isManual(node) : (node.subscription_ids || []).includes(group);
    });
  }
  function makeConfigGroup(group, name, subscription) {
    var nodes = groupNodes(group), selected = groupSelection(group);
    selected.forEach(function (id) { if (!nodes.some(function (n) { return n.id === id; })) selected.delete(id); });
    var card = element(subscription ? 'details' : 'article', 'card config-group'); card.dataset.configGroup = group;
    if (subscription) { card.open = state.groupOpen.has(group) ? state.groupOpen.get(group) : false; card.addEventListener('toggle', function () { if (card.isConnected) state.groupOpen.set(group, card.open); }); }
    var heading = element(subscription ? 'summary' : 'div', 'subscription-heading'), details = element('div'), title = element('div', 'subscription-name');
    var groupTitle = element('h3', '', name); if (subscription) groupTitle.dataset.noI18n = ''; title.appendChild(groupTitle); title.appendChild(element('span', 'count', String(nodes.length))); details.appendChild(title);
    if (!subscription) details.appendChild(element('p', 'muted small', 'Manually added configurations, saved chains and load balancers'));
    heading.appendChild(details); card.appendChild(heading);
    if (subscription) {
      var source = element('details', 'subscription-source group-source'); source.appendChild(element('summary', '', 'Show source URL'));
      var url = element('p', 'muted', subscription.url); url.dataset.noI18n = ''; source.appendChild(url); card.appendChild(source);
    }
    var bar = element('div', 'bulk-bar'); bar.setAttribute('role', 'group'); bar.setAttribute('aria-label', name + ' actions');
    var label = element('label'), all = document.createElement('input'); all.type = 'checkbox'; all.dataset.selectGroup = group;
    label.appendChild(all); label.appendChild(document.createTextNode(' Select all')); bar.appendChild(label);
    var count = element('span'); count.dataset.groupCount = group; count.setAttribute('role', 'status'); bar.appendChild(count);
    ['ping', 'delete'].forEach(function (action) {
      var button = element('button', 'button', action === 'ping' ? 'Bulk Ping' : 'Bulk Delete'); button.type = 'button';
      button.dataset.bulkAction = action; button.dataset.group = group; button.dataset.mutation = ''; button.dataset.job = ''; bar.appendChild(button);
    });
    if (subscription) bar.appendChild(actionButton('Refresh', 'refresh-subscription', subscription.id, false, true));
    card.appendChild(bar); card.appendChild(makeNodeTable(nodes, 'No configurations in this group yet.', group)); return card;
  }
  function renderInventory() {
    var key = JSON.stringify([state.nodes, state.subscriptions, state.selection, state.status && state.status.engine_running, Array.from(state.speedResults.entries())]);
    if (key === state.inventoryKey) { updateControls(); return; }
    state.inventoryKey = key;
    var focused = document.activeElement, focusAction = focused && focused.dataset.action, focusID = focused && focused.dataset.id;
    text($('manual-group'), ''); $('manual-group').appendChild(makeConfigGroup('manual', 'Manual configurations'));
    text($('subscriptions-list'), ''); text($('subscription-count'), String(state.subscriptions.length));
    $('subscriptions-empty').hidden = !!state.subscriptions.length;
    state.subscriptions.forEach(function (subscription) {
      $('subscriptions-list').appendChild(makeConfigGroup(subscription.id, subscription.name || 'Subscription', subscription));
    });
    state.groupSelections.forEach(function (_, group) {
      if (group !== 'manual' && !state.subscriptions.some(function (s) { return s.id === group; })) state.groupSelections.delete(group);
    });
    renderChainBuilder(); updateControls();
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
      if (!state.telegramLoaded) await loadTelegram();
      if (!state.settings) renderSettings(await call('GET', '/api/settings'));
      if (window.location.hash === '#usage') renderUsage(await call('GET', '/api/usage'));
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
    if (['subscriptions','manual'].includes(name)) name = 'configurations';
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
    if (name === 'usage' && state.authenticated) schedulePoll(100);
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
    var row = element('div', 'log-line'); row.dataset.noI18n = '';
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
        if (document.documentElement.dir === 'rtl') { if (event.key === 'ArrowRight') index = (index + tabs.length - 2) % tabs.length; else if (event.key === 'ArrowLeft') index = (index + 2) % tabs.length; }
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
      if (button.dataset.action === 'speed-node') startJob('/api/nodes/speed', {node_id:id}, 'Speed test started (up to 26 MB with fallback).');
      if (button.dataset.action === 'qr-node') showQR(id);
      if (button.dataset.action === 'edit-node') openNodeEditor(id);
      if (button.dataset.action === 'edit-chain') openChainEditor(id);
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

  function balanceSelection() {
    var ids = new Set(); state.groupSelections.forEach(function(selected) { selected.forEach(function(id) { ids.add(id); }); });
    return Array.from(ids).filter(function(id) { return state.nodes.some(function(n) { return n.id === id && n.enabled && n.protocol !== 'loadbalance'; }); });
  }
  function updateBulkControls() {
    var count = balanceSelection().length;
    text($('balance-selected'), count + ' selected');
    $('balance-create').disabled = state.busy || state.jobRunning || !state.authenticated || count < 2 || count > 32;
    document.querySelectorAll('[data-config-group]').forEach(function (card) {
      var group = card.dataset.configGroup, count = groupSelection(group).size, total = groupNodes(group).length;
      text(card.querySelector('[data-group-count]'), count + ' selected');
      var all = card.querySelector('[data-select-group]');
      all.disabled = state.busy || !state.authenticated || !total;
      all.checked = !!total && count === total; all.indeterminate = count > 0 && count < total;
      card.querySelectorAll('[data-bulk-action]').forEach(function (button) { button.disabled = !count || state.busy || state.jobRunning || !state.authenticated || (button.dataset.bulkAction === 'ping' && groupNodes(group).some(function(n) { return n.protocol === 'loadbalance' && groupSelection(group).has(n.id); })); });
      card.querySelectorAll('[data-select-node]').forEach(function (box) { box.checked = groupSelection(group).has(box.dataset.selectNode); box.disabled = state.busy || !state.authenticated; });
    });
    $('chain-save').disabled=state.busy || state.jobRunning || state.chainHops.length<2 || !state.authenticated;
    $('chain-add-hop').disabled=state.busy || state.chainHops.length>=8 || !$('chain-builder-node').value || !state.authenticated;
  }
  function renderChainBuilder() {
    text($('chain-save'), state.chainEditingID ? 'Save chain changes' : 'Save as new configuration');
    $('chain-cancel-edit').hidden = $('chain-editing-note').hidden = !state.chainEditingID;
    var select=$('chain-builder-node'),previous=select.value; text(select,'');
    chainOptions().filter(function(n){return !state.chainHops.includes(n.id);}).forEach(function(n){var option=element('option','',n.tag+' · '+n.server);option.value=n.id;option.dataset.noI18n='';select.appendChild(option);});
    if(Array.from(select.options).some(function(o){return o.value===previous;}))select.value=previous;
    var label=function(id){var n=chainOptions().find(function(n){return n.id===id;});return n?n.tag:'Unavailable node';};
    text($('chain-hops'),'');
    state.chainHops.forEach(function(id,index){var row=element('li');var hopName=element('span','',label(id)+' ');hopName.dataset.noI18n='';row.appendChild(hopName);
      [['↑',-1],['↓',1],['Remove',0]].forEach(function(action){var b=element('button','button subtle',action[0]);b.type='button';b.dataset.mutation='';b.setAttribute('aria-label',action[0]+' hop '+(index+1));b.addEventListener('click',function(){if(action[1]===0)state.chainHops.splice(index,1);else{var next=index+action[1];if(next<0||next>=state.chainHops.length)return;var tmp=state.chainHops[next];state.chainHops[next]=id;state.chainHops[index]=tmp;}renderChainBuilder();updateControls();});row.appendChild(b);});$('chain-hops').appendChild(row);
    });
    $('chain-preview').dataset.noI18n = ''; text($('chain-preview'),state.chainHops.map(label).join(' → '));
  }
  function wireBatchEvents() {
    document.addEventListener('change', function (event) {
      var target = event.target, id = target.dataset.selectNode, group = target.dataset.selectGroup;
      if (id) { var selected = groupSelection(target.dataset.group); if (target.checked) selected.add(id); else selected.delete(id); }
      else if (group) state.groupSelections.set(group, new Set(target.checked ? groupNodes(group).map(function (n) { return n.id; }) : []));
      else return;
      updateBulkControls();
    });
    document.addEventListener('click', function (event) {
      var button = event.target.closest('[data-bulk-action]'); if (!button || button.disabled) return;
      var group = button.dataset.group, ids = Array.from(groupSelection(group)); if (!ids.length) return;
      if (button.dataset.bulkAction === 'ping') { startJob('/api/nodes/test', {node_ids: ids}, 'Selected latency tests started.'); return; }
      if (!window.confirm(window.I18n.t('Delete ' + ids.length + ' selected configurations? Shared configurations are removed from every group. Deleting the active config switches to Auto; deleting all configs stops the proxy. Subscription refresh may reimport provider nodes.'))) return;
      mutate('Bulk delete', async function () {
        await call('POST', '/api/nodes/delete', {node_ids: ids});
        state.groupSelections.forEach(function (selected) { ids.forEach(function (id) { selected.delete(id); }); });
        toast('Selected configurations deleted.', 'ok');
      });
    });
    $('balance-form').addEventListener('submit',function(event) {
      event.preventDefault(); var ids=balanceSelection(), name=$('balance-name').value.trim();
      mutate('Create Load Balancer',async function() {
        await call('POST','/api/load-balancers',{name:name,node_ids:ids});
        state.groupSelections.clear();$('balance-form').reset();toast('Load balancer saved','ok');
      });
    });
    $('chain-builder-node').addEventListener('change',updateBulkControls);
    $('chain-add-hop').addEventListener('click',function(){var id=$('chain-builder-node').value;if(id && !state.chainHops.includes(id) && state.chainHops.length<8)state.chainHops.push(id);renderChainBuilder();updateControls();});
    $('chain-cancel-edit').addEventListener('click', resetChainEditor);
    $('chain-builder-form').addEventListener('submit', function (event) {
      event.preventDefault(); var editing = state.chainEditingID;
      var payload = {name: $('chain-builder-name').value.trim(), node_ids: state.chainHops.slice()};
      if (editing) payload.node_id = editing;
      mutate('Save chain', async function () { await call(editing ? 'PUT' : 'POST', '/api/chains', payload); resetChainEditor(); toast(editing ? 'Chain updated.' : 'New chained configuration saved.', 'ok'); });
    });
    $('node-edit-cancel').addEventListener('click', function () { $('node-editor').close(); });
    $('node-editor').addEventListener('close', function () { state.editingNode = null; text($('node-edit-fields'), ''); });
    $('node-edit-form').addEventListener('submit', function (event) {
      event.preventDefault(); if (!state.editingNode) return;
      var payload = {node_id: state.editingNode};
      $('node-edit-fields').querySelectorAll('[data-edit-field]').forEach(function (input) {
        if (input.dataset.secret && input.value === '') return;
        payload[input.dataset.editField] = input.type === 'checkbox' ? input.checked : input.type === 'number' ? Number(input.value) : input.value;
      });
      mutate('Edit configuration', async function () { await call('PUT', '/api/nodes/edit', payload); $('node-editor').close(); toast('Configuration updated.', 'ok'); });
    });
  }

  async function loadTelegram() {
    var settings = await call('GET','/api/telegram');
    $('telegram-enabled').checked = settings.enabled; $('telegram-proxy').checked = !!settings.use_proxy; $('telegram-chat').value = settings.chat_id || '';
    text($('telegram-status'), settings.last_error || (settings.token_set ? 'Token stored' : 'No token stored'));
    state.telegramLoaded = true;
  }
  async function binaryRequest(method, path, body) {
    var headers = {}; if (method !== 'GET') { headers['Content-Type'] = 'application/zip'; if (state.csrf) headers['X-CSRF-Token'] = state.csrf; }
    var response = await fetch(path, {method:method, body:body, headers:headers, credentials:'same-origin', cache:'no-store'});
    if (!response.ok) { var data = await response.json(); var error = new Error(data.error || 'Request failed'); error.status = response.status; if (error.status === 401) signInRequired(); throw error; }
    return response;
  }
  function wireAdvancedEvents() {
    async function saveTelegram() {
      var payload = {enabled:$('telegram-enabled').checked,use_proxy:$('telegram-proxy').checked,chat_id:$('telegram-chat').value.trim()};
      if ($('telegram-clear').checked) payload.token = ''; else if ($('telegram-token').value) payload.token = $('telegram-token').value.trim();
      await call('PUT','/api/telegram',payload);
      $('telegram-token').value='';$('telegram-clear').checked=false;
      await loadTelegram();
    }
    $('telegram-form').addEventListener('submit',function(event){
      event.preventDefault();
      mutate('Save notifications',async function(){await saveTelegram();toast('Notification settings saved','ok');});
    });
    $('telegram-test').addEventListener('click',function(){
      mutate('Telegram test',async function(){
        await saveTelegram();
        var result = await call('POST','/api/telegram/test',{});
        renderJob(result.refresh);text($('telegram-status'),'Sending test message…');
      });
    });
    $('download-backup').addEventListener('click',function(){mutate('Download Backup',async function(){
      var response = await binaryRequest('GET','/api/backup'); var url = URL.createObjectURL(await response.blob());
      var link = document.createElement('a');link.href=url;link.download='backup.zip';document.body.appendChild(link);link.click();link.remove();window.setTimeout(function(){URL.revokeObjectURL(url);},30000);
    });});
    $('restore-backup').addEventListener('click',function(){
      var file=$('restore-file').files[0];if (!file) { toast('Select a backup ZIP first.','err');return; }
      if (file.size>32*1024*1024) {toast('Backup must be at most 32 MiB.','err');return;}
      if (!window.confirm(window.I18n.t('Replace all saved configurations, device mappings and firewall settings with this backup? The active proxy will restart.'))) return;
      mutate('Restore backup',async function(){var response=await binaryRequest('POST','/api/restore',file);var result=await response.json();renderJob(result.refresh);$('restore-file').value='';toast('Restore started.','ok');});
    });
    $('qr-close').addEventListener('click',function(){$('qr-dialog').close();});
    $('qr-dialog').addEventListener('close',function(){state.qrGeneration++;$('qr-link').value='';text($('qr-image'),'');$('qr-image').removeAttribute('title');});
  }
  function loadQRCode() {
    if (window.QRCode) return Promise.resolve();
    if (!state.qrLoad) state.qrLoad = new Promise(function(resolve,reject){
      var script=document.createElement('script');script.src='https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js';script.referrerPolicy='no-referrer';script.async=true;
      var timer=window.setTimeout(function(){script.remove();reject(new Error('QR renderer unavailable. Copy the share link instead.'));},15000);
      script.onload=function(){window.clearTimeout(timer);if(window.QRCode)resolve();else reject(new Error('QR renderer unavailable. Copy the share link instead.'));};
      script.onerror=function(){window.clearTimeout(timer);script.remove();reject(new Error('QR renderer unavailable. Copy the share link instead.'));};document.head.appendChild(script);
    }).catch(function(error){state.qrLoad=null;throw error;});
    return state.qrLoad;
  }
  function showQR(id) {
    mutate('QR Code',async function(){
      var response=await call('POST','/api/nodes/share',{node_id:id});var generation=++state.qrGeneration;
      $('qr-link').value=response.link;text($('qr-image'),'');text($('qr-status'),'Loading QR renderer…');$('qr-dialog').showModal();
      // Only the renderer is downloaded; the credential-bearing link stays in this browser.
      loadQRCode().then(function(){if(generation!==state.qrGeneration||!$('qr-dialog').open)return;
        try {new window.QRCode($('qr-image'),{text:response.link,width:280,height:280,correctLevel:window.QRCode.CorrectLevel.M});text($('qr-status'),'');}
        catch (_) {text($('qr-status'),'Link is too large for this QR code. Copy the share link instead.');}
      }).catch(function(error){if(generation===state.qrGeneration)text($('qr-status'),error.message);});
    });
  }

  function chainOptions() {
    var originals = state.nodes.filter(function (n) { return n.enabled && !n.detour_id && !n.detour && !n.chain_id && n.protocol !== 'loadbalance'; });
    var ids = new Set(originals.map(function (n) { return n.id; }));
    return originals.concat(state.chainExistingNodes.filter(function (n) { return !ids.has(n.id); }));
  }
  function resetChainEditor() {
    state.chainEditingID = null; state.chainExistingNodes = []; state.chainHops = []; $('chain-builder-name').value = '';
    renderChainBuilder(); updateControls();
  }
  function openChainEditor(id) {
    mutate('Edit chain', async function () {
      var response = await call('GET', '/api/chains?node_id=' + encodeURIComponent(id));
      state.chainEditingID = id; state.chainExistingNodes = response.hops; state.chainHops = response.hops.map(function (hop) { return hop.id; });
      $('chain-builder-name').value = response.name; renderChainBuilder(); activateTab('configurations', false);
      $('chain-builder-form').scrollIntoView({behavior: 'smooth', block: 'center'});
    });
  }
  function openNodeEditor(id) {
    mutate('Edit configuration', async function () {
      var node = await call('GET', '/api/nodes/edit?node_id=' + encodeURIComponent(id));
      state.editingNode = id; var fields = $('node-edit-fields'); text(fields, '');
      var schema = [
        ['name', 'Name'], ['server', 'Server IP / hostname'], ['port', 'Port', 'number'],
        ['sni', 'TLS server name'], ['security', 'Security', ['', 'tls', 'reality']],
        ['transport', 'Transport', ['tcp', 'ws', 'grpc', 'http']], ['path', 'Path'], ['host', 'Host header'],
        ['service_name', 'gRPC service name'], ['fingerprint', 'TLS fingerprint'], ['insecure', 'Allow insecure TLS', 'checkbox']
      ];
      if (['vless', 'vmess'].includes(node.protocol)) schema.splice(3, 0, ['uuid', 'UUID', 'password']);
      else schema.splice(3, 0, ['password', 'Password', 'password']);
      if (node.protocol === 'shadowsocks') schema.push(['method', 'Cipher']);
      if (node.protocol === 'vless') schema.push(['flow', 'Flow'], ['public_key', 'Reality public key'], ['short_id', 'Reality short ID']);
      schema.forEach(function (field) {
        var wrap = element('div', 'field'), label = element('label', '', field[1]); var choices = Array.isArray(field[2]) ? field[2] : null;
        var input = document.createElement(choices ? 'select' : 'input'); input.dataset.editField = field[0]; input.id = 'edit-' + field[0]; label.htmlFor = input.id;
        if (choices) choices.forEach(function (value) { var option = element('option', '', value || 'None'); option.value = value; input.appendChild(option); });
        else input.type = field[2] || 'text';
        if (input.type === 'password') { input.dataset.secret = 'true'; input.placeholder = 'Leave blank to keep current'; input.autocomplete = 'new-password'; }
        else if (input.type === 'checkbox') input.checked = !!node[field[0]];
        else input.value = node[field[0]] === undefined ? '' : node[field[0]];
        if (field[0] === 'transport' && !input.value) input.value = 'tcp';
        if (field[0] === 'port') { input.min = 1; input.max = 65535; }
        if (['name', 'server', 'port'].includes(field[0])) input.required = true;
        input.dataset.mutation = ''; wrap.appendChild(label); wrap.appendChild(input); fields.appendChild(wrap);
      });
      $('node-editor').showModal();
    });
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
    keys.filter(function(key){var v=values[key]||{};return (v.upload||0)>0 || (v.download||0)>0;}).forEach(function(key){var n=state.nodes.find(function(n){return n.id===key;});var value=values[key]||{};var row=element('tr');var caption=element('td','',key==='direct'?'Direct / bypass':n?n.tag:key);if(key!=='direct')caption.dataset.noI18n='';row.appendChild(caption);row.appendChild(element('td','',byteCount(value.upload||0)));row.appendChild(element('td','',byteCount(value.download||0)));table.appendChild(row);});list.appendChild(table);
    if (table.rows.length === 1) list.appendChild(element('p', 'muted', 'No configuration has recorded traffic yet.'));
    renderDevices(response, false);
  }

  function renderDevices(response, force) {
    var list = $('usage-devices');
    // Polling must not discard a name being typed or close an open dropdown.
    if (!force && list.contains(document.activeElement)) return;
    text(list, '');
    var values = response.usage.devices || {}, aliases = response.device_aliases || {}, routes = response.device_routes || {}, limits = response.device_limits || {};
    var ips = Array.from(new Set(Object.keys(values).concat(Object.keys(aliases), Object.keys(routes), Object.keys(limits)))).sort(function (a, b) { return a.localeCompare(b, undefined, {numeric: true}); });
    if (!ips.length) { list.appendChild(element('p', 'muted', 'No LAN devices observed yet. Use the internet through the proxy to populate this list.')); return; }
    var table = element('table', 'node-table device-table'), header = element('tr');
    ['Device IP', 'Device name', 'Upload', 'Download', 'Route through', 'Speed Limit (Mbps)'].forEach(function (name) { header.appendChild(element('th', '', name)); }); table.appendChild(header);
    ips.forEach(function (ip) {
      var value = values[ip] || {}, row = element('tr'); row.appendChild(element('td', 'node-server', ip));
      var nameCell = element('td'), nameForm = element('form', 'device-name-form'), input = document.createElement('input');
      input.value = aliases[ip] || ''; input.maxLength = 80; input.placeholder = 'Device name'; input.setAttribute('aria-label', 'Name for ' + ip); input.dataset.mutation = ''; input.dataset.job = '';
      var save = element('button', 'button subtle', 'Save name'); save.type = 'submit'; save.dataset.mutation = ''; save.dataset.job = '';
      nameForm.appendChild(input); nameForm.appendChild(save); nameCell.appendChild(nameForm); row.appendChild(nameCell);
      nameForm.addEventListener('submit', function (event) {
        event.preventDefault(); var alias = input.value;
        mutate('Save device name', async function () { await call('PUT', '/api/devices', {ip: ip, alias: alias}); toast('Device name saved.', 'ok'); });
      });
      row.appendChild(element('td', '', byteCount(value.upload || 0))); row.appendChild(element('td', '', byteCount(value.download || 0)));
      var routeCell = element('td'), select = document.createElement('select'); select.setAttribute('aria-label', 'Route for ' + ip); select.dataset.mutation = ''; select.dataset.job = '';
      var fallback = element('option', '', 'Global Default'); fallback.value = ''; select.appendChild(fallback);
      var direct = element('option', '', 'Direct'); direct.value = 'direct'; select.appendChild(direct);
      var included = new Set();
      function addOptions(name, nodes, userLabel) {
        var group = document.createElement('optgroup'); group.label = name; if (userLabel) group.dataset.noI18n = '';
        nodes.forEach(function (node) {
          if (included.has(node.id)) return; included.add(node.id);
          var option = element('option', '', (node.tag || node.server) + (!node.enabled ? ' (disabled; Global Default)' : '')); option.value = node.id; option.dataset.noI18n = ''; option.disabled = !node.enabled; group.appendChild(option);
        });
        if (group.children.length) select.appendChild(group);
      }
      addOptions('Manual configurations', groupNodes('manual'));
      state.subscriptions.forEach(function (sub) { addOptions(sub.name || 'Subscription', groupNodes(sub.id), !!sub.name); });
      addOptions('Other configurations', state.nodes);
      var assigned = routes[ip] || '';
      if (assigned && assigned !== 'direct' && !included.has(assigned)) { var unavailable = element('option', '', 'Unavailable node (using Global Default)'); unavailable.value = assigned; unavailable.disabled = true; select.appendChild(unavailable); }
      select.value = assigned;
      select.addEventListener('change', function () {
        var nodeID = select.value;
        mutate('Save device route', async function () {
          try { await call('PUT', '/api/devices', {ip: ip, node_id: nodeID}); toast('Device route saved and applied.', 'ok'); }
          finally { if (!state.exiting) renderDevices(await call('GET', '/api/usage'), true); }
        });
      });
      routeCell.appendChild(select); row.appendChild(routeCell);
      var limitCell=element('td'), limitForm=element('form','device-name-form'), limit=document.createElement('input');
      limit.type='number';limit.min='0';limit.max='10000';limit.step='0.01';limit.placeholder='Unlimited';limit.value=limits[ip] || '';limit.setAttribute('aria-label','Speed Limit (Mbps)');limit.dataset.mutation='';limit.dataset.job='';
      var limitSave=element('button','button subtle','Save limit');limitSave.type='submit';limitSave.dataset.mutation='';limitSave.dataset.job='';
      limitForm.appendChild(limit);limitForm.appendChild(limitSave);limitCell.appendChild(limitForm);limitCell.appendChild(element('p','muted small','Each direction; blank or 0 is unlimited.'));row.appendChild(limitCell);
      limitForm.addEventListener('submit',function(event){event.preventDefault();var mbps=Number(limit.value);
        mutate('Save device limit',async function(){
          try {await call('PUT','/api/devices',{ip:ip,speed_limit_mbps:mbps});toast('Device speed limit saved and applied.','ok');}
          finally {if(!state.exiting)renderDevices(await call('GET','/api/usage'),true);}
        });
      });
      table.appendChild(row);
    });
    list.appendChild(table); updateControls();
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
    wireAdvancedEvents();
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
      await loadTelegram();
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
