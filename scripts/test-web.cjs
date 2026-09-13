// Optional development check: node scripts/test-web.cjs (Node built-ins only).
// Kept outside embedded assets. Exercises translation behavior with a small DOM
// fixture; browser layout/focus/visual checks remain a separate manual check.
function checkWeb(sources) {
  function assert(condition, message) { if (!condition) throw new Error(message); }
  function element(tag) {
    const node = {nodeType: 1, tag, childNodes: [], attrs: {}, dataset: {}, events: {}, parentNode: null,
      hasAttribute(name) { return Object.hasOwn(this.attrs, name); },
      getAttribute(name) { return this.attrs[name] ?? null; },
      setAttribute(name, value) { this.attrs[name] = String(value); },
      addEventListener(name, callback) { this.events[name] = callback; },
      appendChild(child) { child.parentNode = child.parentElement = this; this.childNodes.push(child); return child; },
      closest(selector) { for (let p = this; p; p = p.parentNode) { if (selector === '[data-no-i18n]' ? p.hasAttribute('data-no-i18n') : ['script','style','code'].includes(p.tag)) return p; } return null; }
    };
    Object.defineProperty(node, 'textContent', {get() {return this.childNodes.map(n=>n.data ?? n.textContent).join('');},set(value) {this.childNodes=[];this.appendChild(textNode(value));}});
    Object.defineProperty(node, 'isConnected', {get() {return this === root || !!this.parentNode?.isConnected;}});
    return node;
  }
  function textNode(data) { return {nodeType: 3, data, parentNode: null, parentElement: null, get isConnected() {return !!this.parentNode?.isConnected;}}; }
  const root = element('html'); root.lang = 'fa';
  const title = root.appendChild(element('h2')); title.textContent = 'Device settings';
  const field = root.appendChild(element('input')); field.setAttribute('placeholder','Device name');
  const user = root.appendChild(element('span')); user.setAttribute('data-no-i18n',''); user.textContent='Device name';
  const themeButton = root.appendChild(element('button')), languageButton=root.appendChild(element('button')), favicon=root.appendChild(element('link'));
  const document = {documentElement: root, events: {}, getElementById(id) {return {'theme-toggle':themeButton,'language-toggle':languageButton,'favicon':favicon}[id] || null;}, addEventListener(name, cb) {this.events[name]=cb;}};
  const observers=[];
  class MutationObserver { constructor(callback) {this.callback=callback; observers.push(this);} disconnect() {} observe() {} }
  const window = {matchMedia() {return {matches:false};}};
  const localStorage = {getItem() {return null;}, setItem() {}};
  eval(sources.i18n);
  assert(title.textContent==='تنظیمات دستگاه','initial Persian translation');
  assert(field.getAttribute('placeholder')==='نام دستگاه','attribute translation');
  assert(user.textContent==='Device name','user content changed');
  root.lang='en'; window.I18n.refresh();
  assert(title.textContent==='Device settings','English round trip lost source');
  root.lang='fa'; window.I18n.refresh();
  const added=root.appendChild(element('div')); added.textContent='Settings';
  observers[0].callback([{type:'childList',addedNodes:[added]},{type:'childList',addedNodes:added.childNodes}]);
  assert(added.textContent==='تنظیمات','overlapping mutations lost translation');
  // Attribute updates must not traverse an existing subtree.
  Object.defineProperty(added,'childNodes',{get(){throw new Error('attribute mutation walked descendants');},configurable:true});
  added.setAttribute('title','Device settings');
  observers[0].callback([{type:'attributes',target:added}]);
  assert(added.getAttribute('title')==='تنظیمات دستگاه','attribute update not translated');
  Object.defineProperty(added,'childNodes',{value:[],writable:true});
  const detached=element('div'); detached.textContent='Settings';
  observers[0].callback([{type:'childList',addedNodes:[detached]}]);
  assert(detached.textContent==='Settings','detached tree retained/worked');
  eval(sources.preferences);
  document.events.DOMContentLoaded();
  let refreshes=0; const refresh=window.I18n.refresh; window.I18n.refresh=function(){refreshes++;refresh();};
  themeButton.events.click();
  assert(root.dataset.theme==='light' && refreshes===0,'theme toggle retraversed document');
  assert(favicon.getAttribute('href')==='/hoo-logo-light.svg','favicon does not follow light theme');
  themeButton.events.click();
  assert(favicon.getAttribute('href')==='/hoo-logo-dark.svg','favicon does not follow dark theme');
  languageButton.events.click();
  assert(root.lang==='fa' && root.dir==='rtl' && refreshes===1,'language toggle failed');
  languageButton.events.click();
  assert(root.lang==='en' && root.dir==='ltr' && title.textContent==='Device settings','LTR round trip failed');
}
if (typeof require === 'function') {
  const fs = require('node:fs'), path = require('node:path');
  const root = path.resolve(__dirname,'..');
  checkWeb({i18n:fs.readFileSync(path.join(root,'internal/api/web/i18n.js'),'utf8'),preferences:fs.readFileSync(path.join(root,'internal/api/web/preferences.js'),'utf8')});
  console.log('Localization and theme checks passed');
}
