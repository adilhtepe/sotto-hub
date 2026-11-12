// Renders the LuCI view in Node with a tiny fake DOM that mimics luci.js's E(): a nested array child
// becomes text "[object ...]" (the bug that once hid the stream-name input). Usage: node test_luci_render.js <hub.js>
const fs = require('fs');
const src = fs.readFileSync(process.argv[2], 'utf8').replace(/^'use strict';/m, '').replace(/^'require .*$/mg, '');
let bad = [];
class Node_ { constructor(tag, attrs) { this.tag = tag; this.attrs = attrs || {}; this.kids = []; this.style = {}; this.listeners = {}; this._text = ''; }
  appendChild(c) { this.kids.push(c); c.parentNode = this; return c; } addEventListener(t, f) { this.listeners[t] = f; }
  set innerHTML(v) { this.kids = []; this._text = ''; } set textContent(v) { this.kids = []; this._text = String(v); } get textContent() { return this._text + this.kids.map(k => k.textContent).join(''); }
  get childNodes() { return this.kids; } }
const document = { createTextNode: t => { const n = new Node_('#text'); n._text = t; return n; }, getElementById: () => null };
function add(node, ch) {
  if (ch == null) return;
  if (Array.isArray(ch)) { ch.forEach(c => { if (c instanceof Node_) node.appendChild(c); else if (c != null) { if (Array.isArray(c)) bad.push('nested array child'); node.appendChild(document.createTextNode(String(c))); } }); }
  else if (ch instanceof Node_) node.appendChild(ch); else node.appendChild(document.createTextNode(String(ch)));
}
function E(tag, attrs, ch) {
  if (typeof tag !== 'string') { const n = new Node_('#frag'); add(n, tag); return n; }
  if (attrs && (Array.isArray(attrs) || attrs instanceof Node_ || typeof attrs !== 'object')) { ch = attrs; attrs = {}; }
  const n = new Node_(tag, attrs); add(n, ch); return n;
}
String.prototype.format = function(...a) { let i = 0; return this.replace(/%[ds%]/g, m => m === '%%' ? '%' : String(a[i++])); };
const data = { endpoint: [
  { '.name': 'tx1', '.type': 'endpoint', role: 'tx', name: 'Studio PC', ip: '192.168.2.50', stream: 'Mic One', gain: '80' },
  { '.name': 'rx1', '.type': 'endpoint', role: 'rx', name: 'Phone', ip: '192.168.2.60', port: '6980', stream: 'Out Name', mute: '1' },
  { '.name': 'tx2', '.type': 'endpoint', role: 'tx', name: 'Laptop', ip: '192.168.2.70' },
  { '.name': 'rx2', '.type': 'endpoint', role: 'rx', name: 'Speaker', ip: '192.168.2.80' } ],
  route: [ { '.name': 'r1', '.type': 'route', from: 'tx1', to: 'rx1' } ] };
const uci = { sections: (c, t) => data[t] || [], get: (c, s, o) => { const x = [...data.endpoint, ...data.route].find(e => e['.name'] === s); return o ? (x && x[o]) : x; },
  set() {}, save: () => Promise.resolve(), remove() {}, add: () => 'new1' };
class Opt { constructor(){ this.deps = []; } depends() {} value() {} }
class Sec { option(cls) { return new Opt(); } }
class FMap { constructor() { this.data = { remove() {} }; } section() { return new Sec(); } render() { return Promise.resolve(E('div', {}, 'MAPFORM')); } save() { return Promise.resolve(); } }
const form = { Map: FMap, NamedSection: 1, GridSection: 1, Flag: 1, Value: 1, ListValue: 1, DynamicList: 1, DummyValue: 1 };
const view = { extend: o => { const C = function() {}; Object.assign(C.prototype, o); return C; } };
let tabsInited = 0;
const ui = { tabs: { initTabGroup: p => {   // same precondition as LuCI's: the pane group must already have a parent
    const group = p[0].parentNode;
    if (!group || !group.parentNode) throw new TypeError("Cannot read properties of null (reading 'insertBefore')");
    tabsInited = p.length; } }, addNotification() {}, showModal() {}, hideModal() {} };
const fsm = { exec: () => Promise.resolve({ code: 0 }), read_direct: () => Promise.resolve('{}') };
const rpc = { declare: () => () => Promise.resolve({}) }, poll = { add() {} }, widgets = { NetworkSelect: 1 };
const L = { resolveDefault: p => p, env: {} };
const V = new Function('view', 'form', 'uci', 'fs', 'ui', 'poll', 'rpc', 'widgets', 'E', '_', 'L', 'document', src)(view, form, uci, fsm, ui, poll, rpc, widgets, E, s => s, L, document);
const st = { uptime: 5, master: 100, listen: [{ name: 'br-lan', up: 1 }], routes: [ { src: '192.168.2.50', src_stream: 'Mic One', dst: '192.168.2.60', dst_port: 6980, dst_stream: 'Out Name', gain: 100, pkts: 50, bytes: 1, lost: 0, age: 1 } ],
  streams: [ { ip: '192.168.2.50', port: 5000, stream: 'Mic One', sub: 0, hz: 48000, samples: 64, channels: 2, fmt: 1, codec: 0, kind: 0, routed: 1, pkts: 100, bytes: 1, rate: 750, age: 1 } ], discovered: [], scan: { active: 0, age: -1 } };
new V().render([null, st, {}]).then(root => {
  const t = root.textContent; let ok = true;
  const need = (c, m) => { if (!c) { console.log('FAIL:', m); ok = false; } };
  need(tabsInited === 2, 'two tab panes (got ' + tabsInited + ')');
  need(!/\[object/.test(t), 'no "[object" text');
  need(bad.length === 0, 'nested array children: ' + bad.length);
  for (const w of ['any', 'same as input', 'Laptop', 'Speaker', 'Inputs', 'Outputs', 'Studio PC', 'Phone', 'Mic One', 'Out Name', 'Master volume', 'receiving', '48 kHz', 'MAPFORM', 'Routing matrix'])
    need(t.includes(w), 'page contains ' + w);
  const tabsDiv = root.kids[1];
  need(tabsDiv.kids[0].attrs['data-tab-title'] === 'Mixer' && tabsDiv.kids[1].attrs['data-tab-title'] === 'Settings', 'tab titles Mixer / Settings (first tab = Mixer)');
  const mixer = tabsDiv.kids[0].textContent, settings = tabsDiv.kids[1].textContent;
  need(mixer.includes('Studio PC') && mixer.includes('Phone') && mixer.includes('Master volume'), 'Mixer tab has inputs, outputs, master');
  need(!mixer.includes('Routing matrix') && !mixer.includes('MAPFORM'), 'Mixer tab has none of the settings');
  need(settings.includes('MAPFORM') && settings.includes('Routing matrix') && !settings.includes('Master volume'), 'Settings tab has the rest');
  console.log(ok ? 'PASS' : 'FAILED'); process.exit(ok ? 0 : 1);
}).catch(e => { console.log('EXCEPTION', e.stack); process.exit(2); });
