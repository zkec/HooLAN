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
    constructor(tag, value = '') { this.tag = tag; this.children = []; this.dataset = {}; this.events = {}; this.value = ''; this.scrollTop = 0; this._text = value; this.attrs = {}; this.classList = {toggle() {}}; }
    set textContent(value) { this._text = value; this.children = []; }
    get textContent() { return this._text + this.children.map(c => c.textContent).join(''); }
    get rows() { return this.children.flatMap(c => c.tag === 'tr' ? [c] : c.rows); }
    appendChild(child) { if(child.parentNode) child.parentNode.children = child.parentNode.children.filter(c => c !== child); this.children.push(child); child.parentNode = this; return child; }
    setAttribute(name, value) { this.attrs[name] = value; }
    get firstChild() {return this.children[0] || null;}
    insertBefore(child, reference) {if (child.parentNode) child.parentNode.children = child.parentNode.children.filter(c => c !== child); const index = this.children.indexOf(reference); if (index < 0) this.children.push(child); else this.children.splice(index,0,child); child.parentNode = this; return child;}
    addEventListener(name, fn) { this.events[name] = fn; }
    focus() { document.activeElement = this; }
    showModal() {this.open = true;}
    close() {this.open = false;}
    reset() {}
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
  eval(source.replace(entry, '  window.test = {state:state, nodeTable:makeNodeTable, balanceSelection:balanceSelection, picker:renderBalancePicker, filter:filterBalancePicker, wire:wireBatchEvents, usage:renderUsage, devices:renderDevices, containers:renderContainers, containerEditor:openContainerSettings, wireContainers:wireContainerSettings, pagination:wireUsagePagination, limits:deviceLimitSummary, settings:renderSettings, fakeControls:updateFakeDNSControls, groupIDs:groupActionIDs};\n}());'));
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
  // Containers use the same outbound selector as devices and show presence by name.
  const key = 'a'.repeat(64);
  const containerResponse = {enabled:true,updated_at:new Date().toISOString(),error:'',containers:[
    {key,name:'Example',image:'image:latest',state:'running',supported:true,bindings:[{ip:'172.18.0.3',network:'stack'}],settings:{proxy:true,node_id:'one',qos:{proxy_upload_mbps:5}}},
    {key:'b'.repeat(64),name:'Host service',image:'host:latest',state:'exited',supported:false,reason:'Container is not running',bindings:[],settings:{}}
  ]};
  app.containers(containerResponse);
  const containerTable = document.getElementById('containers-list').children[0];
  assert(containerTable.rows.length === 3, 'container inventory lost rows');
  assert(containerTable.rows[0].children.length === 6, 'container status/proxy columns were not removed');
  const lamp = containerTable.rows[1].children[0].children[0].children[0];
  assert(lamp.attrs['aria-label'] === 'Online' && lamp.className.includes('is-online'), 'running container indicator missing');
  const offlineLamp = containerTable.rows[2].children[0].children[0].children[0];
  assert(offlineLamp.attrs['aria-label'] === 'Offline' && !offlineLamp.className.includes('is-online'), 'offline container indicator shown');
  assert(containerTable.rows[2].children[5].children[0].dataset.unavailable === 'true', 'unsupported container editable');
  assert(containerTable.rows[1].children[4].textContent.includes('5 Mbps'), 'container limits not shown');
  app.containerEditor(key);
  assert(document.getElementById('container-settings').open && document.getElementById('container-proxy_upload_mbps').value === 5, 'container editor did not load limits');
  assert(document.getElementById('container-route').value === 'one', 'container pin lost');
  containerResponse.containers[0].settings = {};
  app.containers(containerResponse); app.containerEditor(key);
  assert(document.getElementById('container-route').value === 'direct' && document.getElementById('container-route').children[0].value === 'direct', 'new container must default to Direct');
  const routeOptions = document.getElementById('container-route').children;
  assert(routeOptions.some(option => option.value === '') && routeOptions.some(option => option.value === 'direct'), 'container selector missing Global Default or Direct');
  app.wireContainers();
  document.getElementById('container-reset-limits').events.click();
  assert(['proxy_upload_mbps','proxy_download_mbps','direct_upload_mbps','direct_download_mbps'].every(field => document.getElementById('container-'+field).value === ''), 'container reset must clear all four fields');
  app.devices({...response,container_ips:['192.168.3.2']}, true);
  assert(!document.getElementById('usage-devices').textContent.includes('192.168.3.2'), 'container was also shown as a LAN device');
  app.pagination();
  const many = {supported:true,usage:{total:{},outbounds:{},devices:{}},device_presence:{}};
  for (let i=1;i<=27;i++) {
    many.usage.outbounds['node-'+i] = {upload:i,download:100-i};
    many.usage.devices['192.168.5.'+i] = {upload:100-i,download:i};
    many.device_presence['192.168.5.'+i] = {online:i<=14};
  }
  state.tableSorts.clear(); state.tablePages.usage={size:10,page:0}; state.tablePages.devices={size:10,page:0};
  app.usage(many,true);
  let usageTable = document.getElementById('usage-nodes').children[0];
  function visibleRows(table) {return table.rows.slice(1).filter(row => !row.hidden);}
  assert(visibleRows(usageTable).length === 10 && document.getElementById('usage-page-status').textContent === 'Showing 1–10 of 27', 'usage default must show 10 rows');
  document.getElementById('usage-page-next').events.click(); usageTable = document.getElementById('usage-nodes').children[0];
  assert(visibleRows(usageTable).length === 10 && visibleRows(usageTable)[0].sortKey === 'node-11', 'usage next page lost sorting');
  usageTable.rows[0].children[1].children[0].events.click();
  assert(state.tablePages.usage.page === 0 && visibleRows(usageTable)[0].sortKey === 'node-27', 'sorting must happen before pagination and return to page 1');
  const usageCount = document.getElementById('usage-page-size'); usageCount.value='20'; usageCount.events.change.call(usageCount);
  assert(visibleRows(document.getElementById('usage-nodes').children[0]).length === 20, 'usage size selector ignored');
  usageCount.value='0'; usageCount.events.change.call(usageCount);
  assert(visibleRows(document.getElementById('usage-nodes').children[0]).length === 27, 'All should show every entry');
  let deviceTable = document.getElementById('usage-devices').children[0];
  assert(visibleRows(deviceTable).length === 14 && visibleRows(deviceTable).every(row => row.online), '14 online devices must override the 10-row cap');
  assert(deviceTable.rows.slice(1,15).every(row => row.online) && !deviceTable.rows[15].online, 'online devices not sorted first');
  deviceTable.rows[0].children[2].children[0].events.click();
  assert(visibleRows(deviceTable).every(row => row.online), 'column sorting hid an online device');
  document.getElementById('devices-page-next').events.click(); deviceTable=document.getElementById('usage-devices').children[0];
  assert(visibleRows(deviceTable).length === 13 && visibleRows(deviceTable).every(row => !row.online), 'offline devices inaccessible on next page');
  const deviceCount=document.getElementById('devices-page-size');deviceCount.value='20';deviceCount.events.change.call(deviceCount);
  assert(visibleRows(document.getElementById('usage-devices').children[0]).length === 20 && state.tablePages.devices.page === 0, 'device size selection ignored');
  many.device_presence = {};
  state.tablePages.devices={size:10,page:0}; app.devices(many,true);
  assert(visibleRows(document.getElementById('usage-devices').children[0]).length === 10, 'offline list should retain the row cap');
  app.devices({usage:{devices:{}},device_presence:{}},true);
  assert(document.getElementById('devices-pagination').hidden, 'empty device list retained stale pagination');
  assert(app.limits({}).textContent === 'Unlimited', 'zero limits must be unlimited');
  const limits = app.limits({proxy_download_mbps:12.5,direct_upload_mbps:1});
  assert(limits.children.length === 4 && limits.textContent.includes('12.5 Mbps'), 'four-way fractional limits');
}
if (typeof require === 'function') {
  const fs = require('node:fs'), path = require('node:path');
  checkDashboard(fs.readFileSync(path.join(__dirname, '../internal/api/web/app.js'), 'utf8'));
  console.log('Dashboard sorting, load balancer and device limit checks passed');
}
