// node scripts/test-dashboard.cjs — no packages required.
// Exercise the dashboard closure with a minimal DOM, without starting polling.
function checkDashboard(source) {
  function assert(ok, message) { if (!ok) throw new Error(message); }
  const elements = new Map();
  const document = {activeElement: null, events: {},
    createElement: tag => new Element(tag), createTextNode: value => new Element('#text', value),
    getElementById(id) { if (!elements.has(id)) elements.set(id, new Element('div')); return elements.get(id); },
    querySelectorAll() { return []; }, addEventListener(name, fn) { this.events[name] = fn; }
  };
  class Element {
    constructor(tag, value = '') { this.tag = tag; this.children = []; this.dataset = {}; this.events = {}; this.value = ''; this.scrollTop = 0; this._text = value; this.attrs = {}; }
    set textContent(value) { this._text = value; this.children = []; }
    get textContent() { return this._text + this.children.map(c => c.textContent).join(''); }
    get rows() { return this.children.flatMap(c => c.tag === 'tr' ? [c] : c.rows); }
    appendChild(child) { if(child.parentNode) child.parentNode.children = child.parentNode.children.filter(c => c !== child); this.children.push(child); child.parentNode = this; return child; }
    setAttribute(name, value) { this.attrs[name] = value; }
    addEventListener(name, fn) { this.events[name] = fn; }
    focus() { document.activeElement = this; }
    contains(node) { return node === this || this.children.some(c => c.contains(node)); }
    querySelectorAll(selector) {
      const match = node => selector[0] === '.' ? (node.className || '').split(' ').includes(selector.slice(1)) :
        selector === '[data-balance-node]' ? !!node.dataset.balanceNode : false;
      return this.children.flatMap(c => [...(match(c) ? [c] : []), ...c.querySelectorAll(selector)]);
    }
  }
  const window = {};
  const entry = '  init();\n}());';
  assert(source.includes(entry), 'dashboard entry point changed; update fixture');
  eval(source.replace(entry, '  window.test = {state:state, nodeTable:makeNodeTable, balanceSelection:balanceSelection, picker:renderBalancePicker, filter:filterBalancePicker, wire:wireBatchEvents, usage:renderUsage, devices:renderDevices, limits:deviceLimitSummary, settings:renderSettings, fakeControls:updateFakeDNSControls, groupIDs:groupActionIDs};\n}());'));
  const app = window.test, state = app.state;
  app.settings({dns_server:'9.9.9.9', iran_bypass:true, fake_dns:{enabled:true,listen:'192.168.3.5'}});
  assert(document.getElementById('fakedns-enabled').checked && !document.getElementById('direct-dns').disabled, 'FakeDNS form not rendered');
  assert(document.getElementById('fakedns-listen').value === '192.168.3.5', 'FakeDNS listen address lost');
  assert(document.getElementById('direct-dns').value === '9.9.9.9', 'legacy resolver migration missing');
  app.settings({tunneled_doh:'https://dns.example/dns-query',direct_dns:'192.168.3.1'});
  assert(document.getElementById('tunneled-doh').value === 'https://dns.example/dns-query' && document.getElementById('direct-dns').value === '192.168.3.1', 'split resolvers not rendered');
  state.settingsDirty=true;
  document.getElementById('fakedns-listen').value='10.42.42.1';
  app.settings({fake_dns:{enabled:false}});
  assert(document.getElementById('fakedns-listen').value === '10.42.42.1', 'poll overwrote FakeDNS edits');
  state.settingsDirty=false;
  app.settings({});
  assert(!document.getElementById('direct-dns').disabled && !document.getElementById('fakedns-listen').disabled, 'legacy settings did not disable FakeDNS');
  const counters = {a:{upload:200,download:2}, b:{upload:20,download:10000}, c:{download:2}};

  state.authenticated = true;
  state.nodes = [
    {id:'a',tag:'Alpha',server:'one.example',enabled:true,manual:true},
    {id:'b',tag:'Beta chain',server:'two.example',enabled:true,protocol:'chain',subscription_ids:['sub']},
    {id:'off',tag:'Disabled',enabled:false,manual:true},
    {id:'lb',tag:'Existing balancer',enabled:true,protocol:'loadbalance',manual:true},
    {id:'zero',tag:'No traffic',enabled:true,manual:true}
  ];
  state.subscriptions = [{id:'sub',name:'Provider'}];
  // Bulk-row selections must not silently become load balancer members.
  state.groupSelections.set('manual', new Set(['zero']));
  state.balanceMembers = new Set(['a','b','off','lb','removed']);
  app.picker();
  assert(app.balanceSelection().join() === 'a,b', 'eligible independent members');
  assert(state.balanceMembers.size === 2, 'removed/disabled/nested members not pruned');
  const picker = document.getElementById('balance-members');
  assert(picker.querySelectorAll('[data-balance-node]').length === 3, 'picker inventory eligibility');
  app.picker();
  assert(picker.querySelectorAll('[data-balance-node]').filter(c => c.checked).length === 2, 'poll lost selection');
  document.getElementById('balance-search').value = 'two.example'; app.filter();
  assert(picker.querySelectorAll('.balance-option').filter(c => !c.hidden).length === 1, 'server search');
  app.wire();
  ['proxy_upload_mbps','proxy_download_mbps','direct_upload_mbps','direct_download_mbps'].forEach(key => document.getElementById('device-'+key).value = '5');
  document.getElementById('device-alias').value = 'Phone';
  document.getElementById('device-reset-limits').events.click();
  assert(['proxy_upload_mbps','proxy_download_mbps','direct_upload_mbps','direct_download_mbps'].every(key => document.getElementById('device-'+key).value === ''), 'reset must clear all four limits');
  assert(document.getElementById('device-alias').value === 'Phone', 'reset changed device alias');
  const box = picker.querySelectorAll('[data-balance-node]').find(c => c.dataset.balanceNode === 'b');
  box.checked = false; picker.events.change({target:box});
  assert(app.balanceSelection().join() === 'a' && document.getElementById('balance-create').disabled, 'member checkbox/minimum');
  box.checked = true; picker.events.change({target:box});
  assert(!document.getElementById('balance-create').disabled, 'two members cannot create');
  const response = {supported:true, usage:{total:{upload:220,download:10002},outbounds:counters,
    devices:{'192.168.3.2':{upload:5,download:200},'192.168.3.10':{upload:600,download:1}}},
    device_limits:{'192.168.3.2':{proxy_upload_mbps:2,direct_download_mbps:10}}};
  app.usage(response);
  let table = document.getElementById('usage-nodes').children[0];
  assert(table.rows[1].children[0].textContent === 'Beta chain', 'rendered node download order');
  assert(!table.textContent.includes('No traffic'), 'zero usage node shown');
  let devices = document.getElementById('usage-devices').children[0];
  assert(devices.rows[1].children[0].textContent === '192.168.3.2', 'rendered device download order');
  assert(devices.rows[0].children[5].children[0].children[0].textContent === 'Speed set', 'speed column heading missing');
  assert(devices.rows[1].children[5].textContent.includes('2 Mbps') && devices.rows[1].children[6].textContent === 'Settings', 'settings must follow speed in a separate column');
  assert(devices.rows[1].textContent.includes('Settings') && devices.rows[1].textContent.includes('2 Mbps'), 'settings/limits missing');
  devices.rows[0].children[2].children[0].events.click();
  devices = document.getElementById('usage-devices').children[0];
  assert(devices.rows[1].children[0].textContent === '192.168.3.10', 'device upload sort event');
  table.rows[0].children[1].children[0].events.click();
  table = document.getElementById('usage-nodes').children[0];
  assert(table.rows[1].children[0].textContent === 'Alpha', 'node upload sort event');
  assert(table.rows[0].children[1].attrs['aria-sort'] === 'descending', 'header sort direction missing');
  table.rows[0].children[1].children[0].events.click();
  assert(table.rows[0].children[1].attrs['aria-sort'] === 'ascending', 'repeat click did not reverse order');
  assert(table.rows[1].children[0].textContent === 'c', 'raw zero upload not sorted first');
  app.usage(response); table = document.getElementById('usage-nodes').children[0];
  assert(table.rows[1].children[0].textContent === 'c', 'poll reset selected sort');
  devices = document.getElementById('usage-devices').children[0];
  devices.rows[0].children[0].children[0].events.click();
  assert(devices.rows[1].children[0].textContent === '192.168.3.2', 'IP addresses sorted lexically');
  devices.rows[0].children[0].children[0].events.click();
  assert(devices.rows[1].children[0].textContent === '192.168.3.10', 'IP descending sort');
  const named = {...response, device_aliases:{'192.168.3.2':'Zulu','192.168.3.10':'Alpha'}};
  app.devices(named,true); devices = document.getElementById('usage-devices').children[0];
  devices.rows[0].children[1].children[0].events.click();
  assert(devices.rows[1].children[1].textContent === 'Alpha', 'alias sort');
  devices.rows[0].children[5].children[0].events.click();
  assert(devices.rows[1].children[0].textContent === '192.168.3.2', 'limited speed should sort before unlimited');
  app.settings({fake_dns:{enabled:true,listen:'192.168.3.5'}});
  assert(!document.getElementById('fakedns-details').hidden, 'enabled FakeDNS details hidden');
  document.getElementById('fakedns-enabled').checked = false; app.fakeControls();
  assert(document.getElementById('fakedns-details').hidden, 'disabled FakeDNS details visible');
  assert(document.getElementById('fakedns-listen').value === '192.168.3.5', 'hiding listener changed saved address');
  document.getElementById('fakedns-enabled').checked = true; app.fakeControls();
  assert(!document.getElementById('fakedns-details').hidden, 'FakeDNS details did not reappear');
  const configs = [
    {id:'slow',tag:'Node 10',protocol:'trojan',server:'10.0.0.10',port:443,latency_ms:200,last_checked_at:'2026-01-01T01:00:00Z'},
    {id:'fast',tag:'Node 2',protocol:'vless',server:'10.0.0.2',port:443,latency_ms:20,last_checked_at:'2026-02-01T01:00:00Z'},
    {id:'failed',tag:'Node 20 failed',protocol:'vless',server:'10.0.0.4',port:443,latency_ms:-1,last_checked_at:'2026-01-01T01:00:00Z'},
    {id:'unknown',tag:'Untested',protocol:'vmess',server:'10.0.0.3',port:443,latency_ms:-1}
  ];
  let configTable = app.nodeTable(configs,'','test').children[0];
  assert(!configTable.rows[1].children[6].children[0].children.some(button => button.dataset.action === 'ping-node'), 'manual testing uses group actions');
  configTable.rows[0].children[4].children[0].events.click();
  assert(configTable.rows[1].sortKey === 'fast' && configTable.rows[3].sortKey === 'failed' && configTable.rows[4].sortKey === 'unknown', 'latency numeric order/missing');
  configTable.rows[0].children[4].children[0].events.click();
  assert(configTable.rows[1].sortKey === 'slow' && configTable.rows[3].sortKey === 'failed' && configTable.rows[4].sortKey === 'unknown', 'latency reverse/missing');
  configTable = app.nodeTable(configs,'','test').children[0];
  assert(configTable.rows[1].sortKey === 'slow', 'configuration sort reset on poll');
  configTable.rows[0].children[1].children[0].events.click();
  assert(configTable.rows[1].sortKey === 'fast', 'natural configuration name sort');
  configTable.rows[0].children[5].children[0].events.click();
  assert(configTable.rows[1].sortKey === 'fast', 'checked timestamp sort');
  state.nodes = [{id:'one',manual:true,protocol:'vless'},{id:'two',manual:true,protocol:'trojan'},{id:'group',manual:true,protocol:'loadbalance'},{id:'sub',manual:false,subscription_ids:['s'],protocol:'vless'}];
  state.groupSelections.clear();
  assert(app.groupIDs('manual','delete').join(',') === 'one,two,group', 'delete all must stay within the group');
  assert(app.groupIDs('manual','ping').join(',') === 'one,two', 'ping all excludes unsupported load balancers');
  state.groupSelections.set('manual',new Set(['two']));
  assert(app.groupIDs('manual','delete').join(',') === 'two' && app.groupIDs('manual','ping').join(',') === 'two', 'checked rows must narrow actions');
  assert(app.groupIDs('empty','delete').length === 0, 'empty group action');
  assert(app.limits({}).textContent === 'Unlimited', 'zero limits must be unlimited');
  const limits = app.limits({proxy_download_mbps:12.5,direct_upload_mbps:1});
  assert(limits.children.length === 4 && limits.textContent.includes('12.5 Mbps'), 'four-way fractional limits');
}
if (typeof require === 'function') {
  const fs = require('node:fs'), path = require('node:path');
  checkDashboard(fs.readFileSync(path.join(__dirname, '../internal/api/web/app.js'), 'utf8'));
  console.log('Dashboard sorting, load balancer and device limit checks passed');
}
