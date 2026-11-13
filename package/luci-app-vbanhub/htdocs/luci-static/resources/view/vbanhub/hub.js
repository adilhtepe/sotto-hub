'use strict';
'require view';
'require form';
'require uci';
'require fs';
'require ui';
'require poll';
'require rpc';
'require tools.widgets as widgets';

/* VBAN Hub: settings, endpoints, routing matrix, live status, learn/adopt.
 * Status comes from /var/run/vbanhub/status.json (written by the daemon every 2s). */

var FMT = [ 'uint8', 'int16', 'int24', 'int32', 'float32', 'float64', '12-bit', '10-bit' ];
var SUB = { 0: 'audio', 32: 'serial', 64: 'text', 96: 'service' };

function streamFormat(x) {
	if (x.sub !== 0)
		return SUB[x.sub] || _('sub-protocol 0x%02x').format(x.sub);
	return [ x.hz ? (x.hz / 1000) + ' kHz' : '?', x.channels + ' ch', FMT[x.fmt] || '?', x.codec ? _('codec 0x%02x').format(x.codec) : '' ]
		.filter(Boolean).join(' · ');
}

function kindLabel(k) { return k === 1 ? _('broadcast') : (k === 2 ? _('multicast') : _('unicast')); }

function streamsOf(st, ip) { return (st.streams || []).filter(function(x) { return x.ip === ip; }); }

/* Delete routes whose transmitter or receiver endpoint is gone (the init script does the same on the router). */
function pruneRoutes() {
	var n = 0;
	uci.sections('vbanhub', 'route').forEach(function(r) {
		var f = r.from && uci.get('vbanhub', r.from), t = r.to && uci.get('vbanhub', r.to);
		if (!f || !t || f['.type'] !== 'endpoint' || t['.type'] !== 'endpoint') {
			uci.remove('vbanhub', r['.name']);
			n++;
		}
	});
	return n;
}

/* Volume control for a route or the master ('main'): mute button + slider. Changes are applied right away
 * (debounced); the hub re-reads its config without restarting or dropping packets. */
var volChain = Promise.resolve();

function volumeWidget(sec) {
	var gain = parseInt(uci.get('vbanhub', sec, 'gain'));
	if (isNaN(gain)) gain = 100;
	var mute = uci.get('vbanhub', sec, 'mute') === '1';
	var label = E('span', { 'style': 'display:inline-block;min-width:9em;text-align:left' });
	var slider = E('input', { 'type': 'range', 'min': 0, 'max': 150, 'step': 1, 'value': gain, 'style': 'width:11em;vertical-align:middle' });
	var btn = E('button', { 'class': 'cbi-button', 'style': 'min-width:2.6em' });
	var timer;

	function show() {
		var db = gain > 0 ? (20 * Math.log10(gain / 100)).toFixed(1) + ' dB' : '-∞ dB';
		label.textContent = (mute ? _('muted') + ' · ' : '') + gain + ' % (' + db + ')';
		btn.textContent = mute ? '🔇' : '🔊';
		btn.title = mute ? _('Unmute') : _('Mute');
		slider.style.opacity = mute ? '0.45' : '1';
	}
	function commit() {
		clearTimeout(timer);
		timer = setTimeout(function() {
			/* not uci.apply(): this session may not call it. The init script validates, commits and reloads. */
			volChain = volChain.then(function() {
				return fs.exec('/etc/init.d/vbanhub', [ 'setvol', sec, String(gain), mute ? '1' : '0' ]);
			}).then(function(r) {
				if (r && r.code)
					ui.addNotification(null, E('p', _('Could not apply the volume: %s').format((r.stderr || '').trim() || r.code)), 'warning');
			}).catch(function(e) { ui.addNotification(null, E('p', _('Could not apply the volume: %s').format((e && e.message) || e)), 'warning'); });
		}, 300);
	}
	slider.addEventListener('input', function() { gain = +slider.value; show(); commit(); });
	btn.addEventListener('click', function(ev) { ev.preventDefault(); mute = !mute; show(); commit(); });
	show();
	return E('div', { 'style': 'white-space:nowrap' }, [ btn, ' ', slider, ' ', label ]);
}

var callHostHints = rpc.declare({ object: 'luci-rpc', method: 'getHostHints', expect: { '': {} } });

/* Add-device dialog used by both "Known devices" and "Discovered devices".
 * pre: { name, ip, port, role, stream } -- everything stays editable. */
function openAdd(pre) {
	var name = E('input', { 'class': 'cbi-input-text', type: 'text', value: pre.name || '' });
	var role = E('select', { 'class': 'cbi-input-select' }, [
		E('option', { value: 'rx', selected: pre.role === 'rx' ? '' : null }, _('Receiver (gets audio from the hub)')),
		E('option', { value: 'tx', selected: pre.role === 'tx' ? '' : null }, _('Transmitter (sends audio to the hub)'))
	]);
	var ip = E('input', { 'class': 'cbi-input-text', type: 'text', value: pre.ip || '' });
	var port = E('input', { 'class': 'cbi-input-text', type: 'number', min: 1, max: 65535, value: pre.port || 6980 });
	var dl = E('datalist', { id: 'vbanhub-streams' }, (pre.suggest || []).map(function(n) { return E('option', { value: n }); }));
	var stream = E('input', { 'class': 'cbi-input-text', type: 'text', maxlength: 16, list: 'vbanhub-streams', value: pre.stream || '' });
	var err = E('p', { 'class': 'alert-message', 'style': 'display:none' });
	var portRow = E('div', { 'class': 'cbi-value' }, [ E('label', { 'class': 'cbi-value-title' }, _('Port (receivers)')), E('div', { 'class': 'cbi-value-field' }, port) ]);
	function sync() { portRow.style.display = role.value === 'rx' ? '' : 'none'; }
	role.addEventListener('change', sync); sync();

	function row(t, w, d) {
		return E('div', { 'class': 'cbi-value' }, [ E('label', { 'class': 'cbi-value-title' }, t),
			E('div', { 'class': 'cbi-value-field' }, [ w, d ? E('div', { 'class': 'cbi-value-description' }, d) : '' ]) ]);
	}

	ui.showModal(_('Add device'), [
		row(_('Name'), name), row(_('Role'), role), row(_('IP address'), ip), portRow,
		row(_('Stream name (optional)'), E('span', {}, [ stream, dl ]), _('Leave empty in most cases. Transmitter: empty = accept any stream from this IP; fill it only to pick one of several streams it sends. Receiver: empty = keep the name the transmitter used; fill it only if the receiver accepts just one specific name. Max 16 characters, spaces allowed.')),
		err,
		E('div', { 'class': 'right' }, [
			E('button', { 'class': 'cbi-button', 'click': ui.hideModal }, _('Cancel')), ' ',
			E('button', { 'class': 'cbi-button cbi-button-positive', 'click': function() {
				var bad = null;
				if (!/^(\d{1,3}\.){3}\d{1,3}$/.test(ip.value)) bad = _('Invalid IPv4 address');
				else if (stream.value && (stream.value.length > 16 || /[\t\r\n*]/.test(stream.value))) bad = _('A stream name is at most 16 characters, without tabs or *');
				else if (role.value === 'rx' && !(port.value >= 1 && port.value <= 65535)) bad = _('Invalid port');
				if (bad) { err.textContent = bad; err.style.display = ''; return; }
				var id = uci.add('vbanhub', 'endpoint');
				uci.set('vbanhub', id, 'name', name.value || ip.value);
				uci.set('vbanhub', id, 'role', role.value);
				uci.set('vbanhub', id, 'ip', ip.value);
				if (role.value === 'rx') uci.set('vbanhub', id, 'port', String(port.value));
				if (stream.value) uci.set('vbanhub', id, 'stream', stream.value);
				uci.save().then(function() { ui.hideModal(); location.reload(); });
			} }, _('Add'))
		])
	]);
}

function readStatus() {
	return L.resolveDefault(fs.read_direct('/var/run/vbanhub/status.json'), '{}').then(function(t) {
		try { return JSON.parse(t); } catch (e) { return {}; }
	});
}

var TYPES = [ [1, 'receiver'], [2, 'transmitter'], [4, 'receiver (spot)'], [8, 'transmitter (spot)'],
	[0x10, 'virtual device'], [0x20, 'virtual mixer'], [0x40, 'matrix'], [0x80, 'DAW'], [0x01000000, 'server'] ];

function typeLabel(t) {
	var l = TYPES.filter(function(x) { return t & x[0]; }).map(function(x) { return x[1]; });
	return l.length ? l.join(', ') : '-';
}

function ago(s) { return s < 0 ? '-' : s + 's ago'; }

/* ---- secure VBAN: the hub's certificate authority (vbanhub cert, via the init script) ---- */
var UPLOAD = '/etc/vbanhub/upload/upload';

/* Uploads go to a root-only directory, mode 0600 (never the shared /tmp). */
function upload(ext, text) {
	return certCmd([ 'prepare' ]).then(function() { return fs.write(UPLOAD + ext, text, 384 /* 0600 */); });
}

function certCmd(args) {
	return fs.exec('/etc/init.d/vbanhub', [ 'cert' ].concat(args)).then(function(r) {
		if (r.code)
			throw new Error((r.stderr || '').trim() || _('failed (%d)').format(r.code));
		return r.stdout || '';
	});
}

function dateOf(t) { return t > 32503680000 ? _('never') : new Date(t * 1000).toISOString().slice(0, 10); }

function download(name, text) {
	var a = E('a', { href: URL.createObjectURL(new Blob([ text ], { type: 'application/x-pem-file' })), download: name });
	document.body.appendChild(a); a.click(); a.remove();
}

/* A file chooser that reads a small text file in the browser; nothing leaves it until used. */
function fileInput(onText) {
	var inp = E('input', { type: 'file', accept: '.req,.crt,.key,.pem,.txt' });
	inp.addEventListener('change', function() {
		var f = inp.files[0];
		if (!f) return onText(null);
		if (f.size > 4096) { ui.addNotification(null, E('p', _('That file is too large for a VBAN key or certificate.')), 'warning'); return; }
		var r = new FileReader();
		r.onload = function() { onText(String(r.result)); };
		r.readAsText(f);
	});
	return inp;
}

function notifyErr(e) { ui.addNotification(null, E('p', (e && e.message) || String(e)), 'danger'); }

return view.extend({
	load: function() {
		return Promise.all([ uci.load('vbanhub'), readStatus(), L.resolveDefault(callHostHints(), {}) ]);
	},

	renderMatrix: function() {
		var eps = uci.sections('vbanhub', 'endpoint');
		var txs = eps.filter(function(e) { return e.role === 'tx'; });
		var rxs = eps.filter(function(e) { return e.role === 'rx'; });

		if (!txs.length || !rxs.length)
			return E('p', { 'class': 'cbi-section-descr' }, _('Add at least one transmitter and one receiver (and save) to build the matrix.'));

		function find(from, to) {
			return uci.sections('vbanhub', 'route').filter(function(r) { return r.from === from && r.to === to; })[0];
		}

		var head = [ E('th', {}, _('Transmitter \\ Receiver')) ].concat(rxs.map(function(r) {
			return E('th', {}, r.name || r['.name']);
		}));

		var rows = txs.map(function(t) {
			return E('tr', { 'class': 'tr' }, [ E('td', { 'class': 'td' }, t.name || t['.name']) ].concat(rxs.map(function(r) {
				var cb = E('input', { type: 'checkbox', checked: find(t['.name'], r['.name']) ? '' : null });
				cb.addEventListener('change', function() {
					var s = find(t['.name'], r['.name']);
					if (cb.checked && !s) {
						var id = uci.add('vbanhub', 'route');
						uci.set('vbanhub', id, 'from', t['.name']);
						uci.set('vbanhub', id, 'to', r['.name']);
					} else if (!cb.checked && s) {
						uci.remove('vbanhub', s['.name']);
					}
				});
				return E('td', { 'class': 'td', 'style': 'text-align:center' }, cb);
			})));
		});

		return E('table', { 'class': 'table' }, [ E('tr', { 'class': 'tr table-titles' }, head) ].concat(rows));
	},

	/* Tab 1: inputs (transmitters) and outputs (receivers), each with its own live state and volume.
	 * Built once; the poll only updates the live cells so a slider being dragged is never rebuilt. */
	renderMixer: function(st) {
		var live = this.mixLive = [];
		var eps = uci.sections('vbanhub', 'endpoint');
		var routes = uci.sections('vbanhub', 'route').filter(function(r) { return r.enabled !== '0'; });

		function nameOf(id) { var e = uci.get('vbanhub', id); return e ? (e.name || e.ip || id) : id; }
		function dot(on) {
			return E('span', { 'style': 'color:' + (on ? '#3fb950' : '#8b949e') + ';font-size:1.3em;vertical-align:middle' }, '●');
		}
		function liveCell(f) {
			var el = E('span');
			function draw(s) {
				var r = f(s || {});
				el.innerHTML = '';
				el.appendChild(dot(r.on));
				el.appendChild(document.createTextNode(' ' + r.text));
			}
			draw(st);
			live.push(draw);
			return el;
		}
		function links(e, field, other) {
			var l = routes.filter(function(r) { return r[field] === e['.name']; }).map(function(r) { return nameOf(r[other]); });
			return l.length ? l.join(', ') : '-';
		}
		function tbl(titles, rows, empty) {
			return E('table', { 'class': 'table' }, [ E('tr', { 'class': 'tr table-titles' }, titles.map(function(t) { return E('th', { 'class': 'th' }, t); })) ]
				.concat(rows.length ? rows : [ E('tr', {}, E('td', { 'class': 'td', 'colspan': titles.length }, E('em', empty))) ]));
		}

		var inputs = eps.filter(function(e) { return e.role !== 'rx'; }).map(function(e) {
			return E('tr', { 'class': 'tr' }, [
				E('td', { 'class': 'td' }, E('strong', {}, e.name || e.ip)),
				E('td', { 'class': 'td' }, e.cert ? '🔒 ' + e.cert : e.ip),
				E('td', { 'class': 'td' }, e.stream || E('em', {}, _('any'))),
				E('td', { 'class': 'td' }, liveCell(function(s) {
					var hs = (s.streams || []).filter(function(x) {
						return (e.cert ? x.cert === e.cert : (x.ip === e.ip && !x.cert)) && (!e.stream || x.stream === e.stream); })
						.sort(function(a, b) { return a.age - b.age; });
					if (!hs.length) return { on: false, text: _('no signal') };
					var h = hs[0], on = h.age <= 3;
					return { on: on, text: (e.stream ? '' : h.stream + ' · ') + streamFormat(h) + (on ? ' · ' + _('%d pkt/s').format(h.rate) : ' · ' + ago(h.age)) +
						(hs.length > 1 ? ' ' + _('(+%d more)').format(hs.length - 1) : '') };
				})),
				E('td', { 'class': 'td' }, links(e, 'from', 'to')),
				E('td', { 'class': 'td' }, volumeWidget(e['.name']))
			]);
		});

		var outputs = eps.filter(function(e) { return e.role === 'rx'; }).map(function(e) {
			var port = +(e.port || 6980);
			return E('tr', { 'class': 'tr' }, [
				E('td', { 'class': 'td' }, E('strong', {}, e.name || e.ip)),
				E('td', { 'class': 'td' }, e.cert ? '🔒 ' + e.cert : e.ip + ':' + port),
				E('td', { 'class': 'td' }, e.stream || E('em', {}, _('same as input'))),
				E('td', { 'class': 'td' }, liveCell(function(s) {
					if (e.cert && !((s.secure && s.secure.peers) || []).some(function(x) { return x.name === e.cert; }))
						return { on: false, text: _('not connected (secure)') };
					var rs = (s.routes || []).filter(function(r) {
						return (e.cert ? r.dst_cert === e.cert : (r.dst === e.ip && r.dst_port === port)) && r.dst_stream === (e.stream || '*'); });
					var ages = rs.map(function(r) { return r.age; }).filter(function(a) { return a >= 0; });
					var on = ages.some(function(a) { return a <= 3; });
					if (!rs.length) return { on: false, text: _('no input routed') };
					return { on: on, text: on ? _('receiving') : (ages.length ? _('idle, last %s').format(ago(Math.min.apply(null, ages))) : _('no data yet')) };
				})),
				E('td', { 'class': 'td' }, links(e, 'to', 'from')),
				E('td', { 'class': 'td' }, volumeWidget(e['.name']))
			]);
		});

		return E('div', {}, [
			E('h3', {}, _('Master volume')),
			E('div', { 'class': 'cbi-section-descr' }, _('Applied to every output on top of the input and output volumes.')),
			volumeWidget('main'),
			E('h3', { 'style': 'margin-top:1.5em' }, _('Inputs')),
			E('div', { 'class': 'cbi-section-descr' }, _('Transmitters sending to the hub. The volume is applied to everything this input sends.')),
			tbl([ _('Name'), _('Address'), _('Stream'), _('Signal'), _('Sends to'), _('Volume') ], inputs,
				_('No inputs yet. Add transmitters in the Settings tab.')),
			E('h3', { 'style': 'margin-top:1.5em' }, _('Outputs')),
			E('div', { 'class': 'cbi-section-descr' }, _('Receivers the hub sends to. The volume is applied to everything this output receives.')),
			tbl([ _('Name'), _('Address'), _('Stream'), _('State'), _('Receives from'), _('Volume') ], outputs,
				_('No outputs yet. Add receivers in the Settings tab.'))
		]);
	},

	/* Tab 3: secure VBAN. Built from `vbanhub cert status`; every action re-renders it. */
	renderSecurity: function(st) {
		var self = this, box = this.secBox;
		box.innerHTML = '';
		box.appendChild(E('p', { 'class': 'spinning' }, _('Loading…')));
		return certCmd([ 'status' ]).then(function(out) {
			var cs = JSON.parse(out || '{}');
			box.innerHTML = '';
			box.appendChild(self.securityContent(cs, st || self.lastSt || {}));
		}).catch(function(e) {
			box.innerHTML = '';
			box.appendChild(E('div', { 'class': 'alert-message warning' }, _('Certificate tools are not available: %s').format(e.message)));
		});
	},

	securityContent: function(cs, st) {
		var self = this;
		function row(t, w, d) {
			return E('div', { 'class': 'cbi-value' }, [ E('label', { 'class': 'cbi-value-title' }, t),
				E('div', { 'class': 'cbi-value-field' }, [ w, d ? E('div', { 'class': 'cbi-value-description' }, d) : '' ]) ]);
		}
		function act(label, cls, fn) {
			return E('button', { 'class': 'cbi-button ' + (cls || ''), 'click': ui.createHandlerFn(self, function() {
				return fn().then(function(go) { if (go !== false) return self.renderSecurity(); }).catch(notifyErr);
			}) }, label);
		}
		function th(list) { return E('tr', { 'class': 'tr table-titles' }, list.map(function(t) { return E('th', { 'class': 'th' }, t); })); }
		function td(x) { return E('td', { 'class': 'td' }, x); }
		var hostname = (uci.get('vbanhub', 'main', 'hub_name') || 'VBAN hub').slice(0, 32);
		var intro = E('p', { 'class': 'cbi-section-descr' }, _('Secure VBAN authenticates and encrypts audio between this hub and devices built on the VBAN SDK (PC, Android, ESP32). Every device has its own key and a certificate signed by your certificate authority (CA). Voicemeeter and other plain devices keep working unencrypted: the hub bridges between them.'));

		if (!cs.ca) {
			var caName = E('input', { 'class': 'cbi-input-text', type: 'text', maxlength: 32, value: 'Studio CA' });
			var years = E('input', { 'class': 'cbi-input-text', type: 'number', min: 1, max: 50, value: 10 });
			var hubName = E('input', { 'class': 'cbi-input-text', type: 'text', maxlength: 32, value: hostname });
			var crtText = null, keyText = null;
			return E('div', {}, [ intro,
				E('h3', {}, _('Create a certificate authority on this router')),
				row(_('CA name'), caName), row(_('Valid for (years)'), years),
				row(_('Hub name'), hubName, _('The name devices see when they connect.')),
				E('p', {}, act(_('Create CA'), 'cbi-button-positive', function() {
					return certCmd([ 'init', caName.value, String(years.value), hubName.value ]);
				})),
				E('h3', {}, _('Or use an existing CA')),
				E('p', { 'class': 'cbi-section-descr' }, _('Upload its certificate (ca.crt from vban_cert ca). Add its key (ca.key) if this router should sign device certificates; without the key the router shows a request that you sign with your CA and upload back.')),
				row(_('CA certificate'), fileInput(function(t) { crtText = t; })),
				row(_('CA key (optional)'), fileInput(function(t) { keyText = t; }), _('Stored on the router with mode 0600 and kept over upgrades.')),
				E('p', {}, act(_('Import CA'), 'cbi-button-action', function() {
					if (!crtText) return Promise.reject(new Error(_('Choose the CA certificate file first.')));
					return upload('.crt', crtText).then(function() { return keyText ? fs.write(UPLOAD + '.key', keyText, 384) : null; }).then(function() { return certCmd([ 'import', hubName.value ].concat(keyText ? [ 'withkey' ] : [])); });
				}))
			]);
		}

		var running = st.secure && st.secure.on;
		var parts = [ intro, E('h3', {}, _('Certificate authority')),
			E('table', { 'class': 'table' }, [
				E('tr', { 'class': 'tr' }, [ td(_('CA')), td(E('strong', {}, cs.ca.name)), td(_('fingerprint %s').format(cs.ca.fingerprint)),
					td(_('valid until %s').format(dateOf(cs.ca.not_after))), td(cs.ca.has_key ? _('key on this router') : _('key kept elsewhere')) ]),
				E('tr', { 'class': 'tr' }, [ td(_('Hub')), td(cs.hub ? E('strong', {}, cs.hub.name) : E('em', {}, _('no certificate yet'))),
					td(cs.hub ? (cs.hub.valid ? _('valid') : E('span', { 'style': 'color:#d73a49' }, _('NOT valid for this CA or date'))) : ''),
					td(cs.hub ? _('valid until %s').format(dateOf(cs.hub.not_after)) : ''),
					td(running ? _('secure VBAN active') : _('not active: enable and start the hub')) ])
			]),
			E('p', {}, [
				E('button', { 'class': 'cbi-button', 'click': function() { certCmd([ 'export-ca' ]).then(function(t) { download('ca.crt', t); }).catch(notifyErr); } }, _('Download CA certificate')), ' ',
				cs.ca.has_key ? act(_('Renew hub certificate'), '', function() { return certCmd([ 'hub-renew', cs.hub ? cs.hub.name : hostname, '3650' ]); }) : '', ' ',
				act(_('Remove CA…'), 'cbi-button-negative', function() {
					if (!confirm(_('Delete the CA, the hub certificate and the list of issued certificates? Devices cannot connect securely until you set up a CA again.')))
						return Promise.resolve(false);
					return certCmd([ 'reset' ]);
				})
			]) ];

		if (cs.hub_request) {
			var signed = null;
			parts.push(E('h3', {}, _('Hub certificate request')),
				E('p', { 'class': 'cbi-section-descr' }, _('Sign this request with your CA (vban_cert sign ca.key ca.crt hub.req 3650 hub.crt) and upload the result.')),
				E('p', {}, E('button', { 'class': 'cbi-button', 'click': function() { certCmd([ 'hub-request' ]).then(function(t) { download('hub.req', t); }).catch(notifyErr); } }, _('Download hub.req'))),
				row(_('Signed hub certificate'), fileInput(function(t) { signed = t; })),
				E('p', {}, act(_('Install hub certificate'), 'cbi-button-positive', function() {
					if (!signed) return Promise.reject(new Error(_('Choose the certificate file first.')));
					return upload('.crt', signed).then(function() { return certCmd([ 'hub-cert' ]); });
				})));
		}

		if (cs.ca.has_key) {
			var reqText = null, days = E('input', { 'class': 'cbi-input-text', type: 'number', min: 1, max: 36500, value: 365 });
			var paste = E('textarea', { 'class': 'cbi-input-textarea', rows: 4, style: 'width:100%;font-family:monospace', placeholder: '-----BEGIN VBAN REQUEST-----' });
			parts.push(E('h3', {}, _('Add a device')),
				E('p', { 'class': 'cbi-section-descr' }, _('On the device: vban_cert key dev.key, then vban_cert req dev.key "Name" tx|rx|txrx dev.req. Upload or paste dev.req here and sign it. Give the device its certificate and ca.crt; its private key never leaves it. Then add an endpoint with this certificate name.')),
				row(_('Request file'), fileInput(function(t) { reqText = t; if (t) paste.value = t; })),
				row(_('… or paste it'), paste),
				row(_('Valid for (days)'), days),
				E('p', {}, act(_('Sign'), 'cbi-button-positive', function() {
					var t = (paste.value || reqText || '').trim();
					if (t.indexOf('BEGIN VBAN REQUEST') < 0) return Promise.reject(new Error(_('That is not a VBAN certificate request.')));
					return upload('.req', t + '\n').then(function() { return certCmd([ 'sign', String(days.value) ]); }).then(function(crt) {
						ui.showModal(_('Certificate issued'), [
							E('p', {}, _('Give the device this certificate and the CA certificate.')),
							E('textarea', { 'class': 'cbi-input-textarea', rows: 7, readonly: '', style: 'width:100%;font-family:monospace' }, crt),
							E('div', { 'class': 'right' }, [
								E('button', { 'class': 'cbi-button', 'click': function() { download('device.crt', crt); } }, _('Download device.crt')), ' ',
								E('button', { 'class': 'cbi-button', 'click': function() { certCmd([ 'export-ca' ]).then(function(c) { download('ca.crt', c); }).catch(notifyErr); } }, _('Download ca.crt')), ' ',
								E('button', { 'class': 'cbi-button cbi-button-positive', 'click': function() { ui.hideModal(); self.renderSecurity(); } }, _('Done'))
							])
						]);
						return false;
					});
				})));
		}

		var peers = (st.secure && st.secure.peers) || [];
		function online(name) { return peers.some(function(x) { return x.name === name; }); }
		var issued = (cs.issued || []).slice().sort(function(a, b) { return a.name.localeCompare(b.name); });
		parts.push(E('h3', {}, _('Device certificates')),
			E('table', { 'class': 'table' }, [ th([ _('Name'), _('Role'), _('Serial'), _('Valid until'), _('State'), '' ]) ].concat(issued.length ? issued.map(function(c) {
				return E('tr', { 'class': 'tr' }, [
					td(E('strong', {}, c.name)), td(c.role.join(' + ')), td(c.serial), td(dateOf(c.not_after)),
					td(c.revoked ? E('span', { 'style': 'color:#d73a49' }, _('revoked')) : (online(c.name) ? _('connected') : _('valid'))),
					td(c.revoked ? '' : act(_('Revoke'), 'cbi-button-negative', function() {
						if (!confirm(_('Revoke the certificate of "%s"? Its session ends now and it cannot connect again.').format(c.name))) return Promise.resolve(false);
						return certCmd([ 'revoke', c.serial ]);
					}))
				]);
			}) : [ E('tr', {}, E('td', { 'class': 'td', 'colspan': 6 }, E('em', {}, _('None yet.')))) ])),
			E('h3', {}, _('Connected secure devices')),
			E('table', { 'class': 'table' }, [ th([ _('Name'), _('Address'), _('Serial'), _('Session') ]) ].concat(peers.length ? peers.map(function(x) {
				return E('tr', { 'class': 'tr' }, [ td(x.name), td(x.ip + ':' + x.port), td(x.serial), td(_('up %ds (rekeyed every 2 min)').format(x.up)) ]);
			}) : [ E('tr', {}, E('td', { 'class': 'td', 'colspan': 4 }, E('em', {}, _('No device connected.')))) ])),
			running ? E('p', { 'class': 'cbi-section-descr' }, _('Encrypted packets received: %d, rejected: %d, handshakes refused: %d, dropped for a secure output without session: %d.')
				.format(st.secure.rx, st.secure.bad, st.secure.hs_refused, st.secure.no_peer)) : '');
		return E('div', {}, parts);
	},

	updateMixer: function(st) {
		(this.mixLive || []).forEach(function(draw) { draw(st); });
		if (this.mixBanner)
			this.mixBanner.style.display = Object.keys(st).length ? 'none' : '';
	},

	renderStatus: function(st) {
		var self = this;
		var routes = (st.routes || []).map(function(r) {
			return E('tr', { 'class': 'tr' }, [
				E('td', { 'class': 'td' }, r.src + ' / ' + (r.src_stream === '*' ? _('any stream') : r.src_stream)),
				E('td', { 'class': 'td' }, r.dst + ':' + r.dst_port + ' / ' + (r.dst_stream === '*' ? _('name kept') : r.dst_stream)),
				E('td', { 'class': 'td' }, String(r.pkts)),
				E('td', { 'class': 'td' }, String(r.lost)),
				E('td', { 'class': 'td' }, r.gain === 100 ? '100 %' : (r.gain === 0 ? _('muted') : r.gain + ' %')),
				E('td', { 'class': 'td' }, ago(r.age))
			]);
		});

		var heard = (st.streams || []).slice().sort(function(x, y) { return x.age - y.age; }).map(function(l) {
			var known = uci.sections('vbanhub', 'endpoint').some(function(e) { return e.ip === l.ip && e.stream === l.stream; });
			return E('tr', { 'class': 'tr' }, [
				E('td', { 'class': 'td' }, l.ip + ':' + l.port),
				E('td', { 'class': 'td' }, E('strong', {}, l.stream)),
				E('td', { 'class': 'td' }, streamFormat(l)),
				E('td', { 'class': 'td' }, _('%d pkt/s').format(l.rate)),
				E('td', { 'class': 'td' }, kindLabel(l.kind)),
				E('td', { 'class': 'td' }, l.routed ? _('routed') : _('not routed')),
				E('td', { 'class': 'td' }, ago(l.age)),
				E('td', { 'class': 'td' }, known ? E('em', {}, _('already added')) : E('button', {
					'class': 'cbi-button cbi-button-add',
					'click': function() {
						openAdd({ name: l.stream, ip: l.ip, role: 'tx', stream: l.stream,   /* a specific stream was picked, keep its name */
							suggest: streamsOf(st, l.ip).map(function(x) { return x.stream; }) });
					}
				}, _('Add as transmitter')))
			]);
		});

		function tbl(titles, rows, empty) {
			return E('table', { 'class': 'table' }, [ E('tr', { 'class': 'tr table-titles' }, titles.map(function(t) { return E('th', { 'class': 'th' }, t); })) ]
				.concat(rows.length ? rows : [ E('tr', {}, E('td', { 'class': 'td', 'colspan': titles.length }, E('em', empty))) ]));
		}

		var eps = uci.sections('vbanhub', 'endpoint');
		function have(ip, role) { return eps.some(function(e) { return e.ip === ip && e.role === role; }); }
		function addEp(d, role) {
			var mine = streamsOf(st, d.ip), names = mine.map(function(x) { return x.stream; });
			openAdd({ name: d.host || d.device || d.ip, ip: d.ip, port: d.port, role: role,
				stream: '',
				suggest: role === 'tx' ? names : (st.streams || []).map(function(x) { return x.stream; }) });
		}
		var found = (st.discovered || []).map(function(d) {
			var rx = d.type & 0x5, tx = d.type & 0xA, any = !rx && !tx, btns = [];
			function btn(role, label) {
				return have(d.ip, role) ? E('em', {}, _('already added') + ' ') :
					E('button', { 'class': 'cbi-button cbi-button-add', 'click': function() { addEp(d, role); } }, label);
			}
			if (rx || any) btns.push(btn('rx', _('Add as receiver')));
			if (tx || any) btns.push(btn('tx', _('Add as transmitter')));
			return E('tr', { 'class': 'tr' }, [
				E('td', { 'class': 'td' }, d.ip + ':' + d.port),
				E('td', { 'class': 'td' }, d.host || '-'),
				E('td', { 'class': 'td' }, [ d.app, d.device ].filter(Boolean).join(' / ') || '-'),
				E('td', { 'class': 'td' }, typeLabel(d.type)),
				E('td', { 'class': 'td' }, btns)
			]);
		});
		var hints = this.hints || {};
		var known = Object.keys(hints).map(function(mac) {
			var h = hints[mac], ips = (h.ipaddrs || (h.ipv4 ? [ h.ipv4 ] : [])).filter(function(x) { return x; });
			return ips.length ? { mac: mac, name: h.name || '', ip: ips[0] } : null;
		}).filter(Boolean).sort(function(x, y) { return x.ip.localeCompare(y.ip, undefined, { numeric: true }); }).map(function(k) {
			var mine = streamsOf(st, k.ip);
			var added = eps.filter(function(e) { return e.ip === k.ip; }).map(function(e) { return e.role === 'rx' ? _('receiver') : _('transmitter'); });
			return E('tr', { 'class': 'tr' }, [
				E('td', { 'class': 'td' }, k.name || '-'), E('td', { 'class': 'td' }, k.ip), E('td', { 'class': 'td' }, k.mac),
				E('td', { 'class': 'td' }, mine.length ? mine.map(function(x) { return x.stream; }).join(', ') : '-'),
				E('td', { 'class': 'td' }, [
					added.length ? E('em', {}, _('added as %s').format(added.join(', ')) + ' ') : '',
					E('button', { 'class': 'cbi-button cbi-button-add', 'click': function() {
						var names = mine.map(function(x) { return x.stream; });
						openAdd({ name: k.name || k.ip, ip: k.ip, port: 6980, role: names.length ? 'tx' : 'rx',
							stream: '',
							suggest: names.length ? names : (st.streams || []).map(function(x) { return x.stream; }) });
					} }, _('Add…'))
				])
			]);
		});
		var scanning = st.scan && st.scan.active;

		var running = Object.keys(st).length > 0;

		return E('div', {}, [
			running ? '' : E('div', { 'class': 'alert-message warning' }, _('The VBAN hub is not running, so nothing is received, routed or scanned. Tick Enable in Settings and use Save & Apply (the service starts by itself).')),
			E('h4', {}, _('Devices connected to this router')),
			E('p', { 'class': 'cbi-section-descr' }, _('From DHCP leases and the neighbour table. Add any of them as a receiver or transmitter and choose the stream name yourself.')),
			tbl([ _('Hostname'), _('IP address'), _('MAC address'), _('Streams heard'), '' ], known, _('No devices known.')),
			E('h4', {}, _('Discovered devices (VBAN ping)')),
			E('p', {}, [
				E('button', { 'class': 'cbi-button cbi-button-action', 'click': function() {
					return fs.exec('/etc/init.d/vbanhub', [ 'scan' ]).then(function(r) {
						if (r && r.code)
							ui.addNotification(null, E('p', (r.stderr || '').trim() || _('Scan failed: the VBAN hub is not running.')), 'warning');
					}).catch(function(e) { ui.addNotification(null, E('p', e.message)); });
				} }, _('Scan LAN')),
				' ', scanning ? _('Scanning…') : (st.scan && st.scan.age >= 0 ? _('Last scan %ds ago').format(st.scan.age) : '')
			]),
			tbl([ _('Address'), _('Host'), _('Application / device'), _('Type'), '' ], found,
				_('Nothing found yet. Start the service and press Scan LAN. Devices must answer VBAN PING (Voicemeeter, VBAN apps do).')),
			E('p', { 'class': 'cbi-section-descr' }, _('Ping discovery does not carry stream names. For transmitters the name is taken from the stream heard from that IP (see "Streams heard"); for receivers type the name the device expects.')),
			E('p', {}, _('Listening on: %s').format((st.listen || []).map(function(l) { return l.name + (l.up ? '' : ' (down)'); }).join(', ') || _('all interfaces')) +
				(st.master !== undefined && st.master !== 100 ? ' — ' + _('master volume %d %%').format(st.master) : '') +
				(st.filtered ? ' — ' + _('%d packets from other interfaces dropped').format(st.filtered) : '')),
			E('p', {}, _('Received: %d, forwarded: %d, send errors: %d, malformed: %d, unrouted: %d')
				.format(st.rx || 0, st.tx || 0, st.txerr || 0, st.bad || 0, st.unknown || 0)),
			E('h4', {}, _('Active routes')),
			tbl([ _('From (ip / stream)'), _('To (ip:port / stream)'), _('Packets'), _('Lost'), _('Volume'), _('Last seen') ], routes, _('No routes or daemon not running.')),
			E('h4', {}, _('Streams heard')),
			E('p', { 'class': 'cbi-section-descr' }, _('Every VBAN stream that reaches the hub (sent to it or broadcast on the LAN), with the name and format read from its packets. Point a transmitter at this router or broadcast on port 6980 and it shows up here.')),
			tbl([ _('Source'), _('Stream name'), _('Format'), _('Rate'), _('Delivery'), _('Routing'), _('Last seen'), '' ], heard, _('Nothing heard yet.'))
		]);
	},

	render: function(data) {
		var self = this, m, s, o;
		this.hints = data[2] || {};
		var statusBox = E('div', { 'id': 'vbanhub-status' }, this.renderStatus(data[1]));

		m = new form.Map('vbanhub', '',
			_('Receives VBAN streams from transmitters and forwards them to selected receivers. Point each transmitter at this router\'s IP and the hub port; stream names are optional (the hub matches inputs by IP and keeps the name unless you set one for an output).'));

		s = m.section(form.NamedSection, 'main', 'vbanhub', _('Settings'));
		o = s.option(form.Flag, 'enabled', _('Enable'));
		o.rmempty = false;
		o = s.option(form.Value, 'port', _('Listen port'));
		o.datatype = 'port'; o.placeholder = '6980';
		o = s.option(form.Value, 'dscp', _('DSCP'), _('46 = EF (WMM voice queue on Wi-Fi).'));
		o.datatype = 'range(0,63)'; o.placeholder = '46';

		o = s.option(widgets.NetworkSelect, 'network', _('Listen on networks'),
			_('The hub only accepts packets arriving on these networks; everything else is dropped. Do not select WAN.'));
		o.multiple = true; o.nocreate = true; o.rmempty = false; o.default = 'lan';
		o = s.option(form.Value, 'hub_name', _('Name shown to VBAN apps'),
			_('The hub answers VBAN pings as a receiver and transmitter with this name, so apps that stream list it as a destination.'));
		o.placeholder = _('<hostname> VBAN hub'); o.datatype = 'maxlength(63)';
		o = s.option(form.Flag, 'open_firewall', _('Open UDP port in firewall'),
			_('Adds an accept rule for the port in the firewall zones of the selected networks (never WAN). Zones that already accept input, like the default LAN, need none.'));
		o.default = '1';
		o = s.option(form.Flag, 'internet', _('Secure devices from the internet'),
			_('Lets devices with a certificate from this hub connect over the internet (create the CA in the Security tab first). Only authenticated, encrypted VBAN is accepted from that network; plain VBAN and pings never are. Opens the hub port in that network\'s firewall zone.'));
		o.default = '0';
		o = s.option(widgets.NetworkSelect, 'internet_network', _('Internet network'));
		o.nocreate = true; o.default = 'wan'; o.depends('internet', '1');
		o = s.option(form.Value, 'scan_interval', _('Auto-scan interval (s)'), _('0 = only when you press Scan LAN.'));
		o.datatype = 'uinteger'; o.placeholder = '0';
		o = s.option(form.Value, 'scan_ports', _('Scan ports'), _('Comma-separated UDP ports devices listen on.'));
		o.placeholder = '6980';
		o = s.option(form.DynamicList, 'scan_target', _('Extra scan targets'), _('Unicast pings for hosts that do not receive broadcasts (other subnets, Wi-Fi isolation).'));
		o.datatype = 'ip4addr';
		o = s.option(form.Flag, 'mdns', _('Announce via mDNS'), _('Publishes _vban._udp (needs the umdns package).'));
		o.default = '1';

		s = m.section(form.GridSection, 'route', _('Routes'), _('Pause a route without deleting it. Routes created in the matrix appear here after saving and reloading the page.'));
		s.anonymous = true; s.addremove = false;
		function epName(id) {
			var e = uci.get('vbanhub', id);
			return e ? ((e.name || id) + (e.stream ? ' (' + e.stream + ')' : '')) : id;
		}
		o = s.option(form.DummyValue, 'from', _('From'));
		o.cfgvalue = function(sid) { return epName(uci.get('vbanhub', sid, 'from')); };
		o = s.option(form.DummyValue, 'to', _('To'));
		o.cfgvalue = function(sid) { return epName(uci.get('vbanhub', sid, 'to')); };
		o = s.option(form.Flag, 'enabled', _('Enabled'));
		o.default = '1'; o.rmempty = false;
		o = s.option(form.DummyValue, 'gain', _('Volume'));
		o.renderWidget = function(section_id) { return volumeWidget(section_id); };

		s = m.section(form.GridSection, 'endpoint', _('Endpoints'));
		s.addremove = true; s.anonymous = true; s.sortable = true;
		/* Removing an endpoint also removes the routes that used it, and refreshes the matrix. */
		s.handleRemove = function(section_id, ev) {
			var cfg = this.uciconfig || this.map.config;
			this.map.data.remove(cfg, section_id);
			pruneRoutes();
			return this.map.save(null, true).then(function() {
				if (self.matrixBox) { self.matrixBox.innerHTML = ''; self.matrixBox.appendChild(self.renderMatrix()); }
				if (self.mixerBox) { self.mixerBox.innerHTML = ''; self.mixerBox.appendChild(self.renderMixer(self.lastSt || {})); }
			});
		};
		o = s.option(form.Value, 'name', _('Name'));
		o = s.option(form.ListValue, 'role', _('Role'));
		o.value('tx', _('Transmitter')); o.value('rx', _('Receiver')); o.default = 'tx';
		o = s.option(form.Value, 'ip', _('IP address'), _('Not needed for a secure endpoint: it is found by its certificate.'));
		o.datatype = 'ip4addr'; o.rmempty = true;
		o.validate = function(section_id, value) {
			var c = this.map.lookupOption('cert', section_id);
			var cert = c ? c[0].formvalue(section_id) : uci.get('vbanhub', section_id, 'cert');
			return (value || cert) ? true : _('An IP address, or a certificate name for a secure device');
		};
		o = s.option(form.Value, 'cert', _('Certificate (secure)'), _('Secure VBAN: the name in this device\'s certificate (Security tab). Its audio is then accepted only from its encrypted session, from any address, and outputs to it are encrypted.'));
		o.datatype = 'maxlength(32)'; o.rmempty = true;
		o.validate = function(section_id, value) { return (value && /[\t\r\n]/.test(value)) ? _('No tabs or line breaks') : true; };
		o = s.option(form.Value, 'port', _('Port (receivers)'));
		o.datatype = 'port'; o.placeholder = '6980';
		o.depends('role', 'rx');
		o = s.option(form.Value, 'stream', _('Stream name (optional)'), _('Usually leave empty. Transmitter: any stream from this IP is accepted; fill it to pick one of several. Receiver: the name the transmitter used is kept; fill it only if the receiver accepts one specific name.'));
		/* this LuCI has no 'regexp' validator (an unknown type makes every value invalid) */
		o.datatype = 'maxlength(16)'; o.rmempty = true;
		o.validate = function(section_id, value) {
			if (value == null || value === '') return true;
			if (/[\t\r\n*]/.test(value)) return _('No tabs, line breaks or * in a stream name');
			return true;
		};

		return m.render().then(function(mapNode) {
			self.lastSt = data[1];
			poll.add(function() {
				return readStatus().then(function(st) {
					self.lastSt = st;
					self.updateMixer(st);
					var box = document.getElementById('vbanhub-status');
					if (box) { box.innerHTML = ''; box.appendChild(self.renderStatus(st)); }
				});
			}, 3);

			self.map = m;
			self.matrixBox = E('div', {}, self.renderMatrix());
			self.mixerBox = E('div', {}, self.renderMixer(data[1]));
			self.mixBanner = E('div', { 'class': 'alert-message warning', 'style': Object.keys(data[1]).length ? 'display:none' : '' },
				_('The VBAN hub is not running, so nothing is received or routed. Open the Settings tab, tick Enable and use Save & Apply (the service starts by itself).'));

			/* initTabGroup() inserts the tab menu next to the group, so the group needs a parent already */
			self.secBox = E('div');
			self.renderSecurity(data[1]);
			var tabs = E('div', {}, [
				E('div', { 'data-tab': 'mixer', 'data-tab-title': _('Mixer') }, [ self.mixBanner, self.mixerBox ]),
				E('div', { 'data-tab': 'settings', 'data-tab-title': _('Settings') }, [
					mapNode,
					E('h3', {}, _('Routing matrix')),
					E('div', { 'class': 'cbi-section-descr' }, _('Tick a cell to send that transmitter to that receiver. Save endpoint changes before editing the matrix.')),
					self.matrixBox,
					E('h3', {}, _('Live status')),
					statusBox
				]),
				E('div', { 'data-tab': 'security', 'data-tab-title': _('Security') }, [ self.secBox ])
			]);
			var page = E('div', {}, [ E('h2', {}, _('VBAN Hub')), tabs ]);
			ui.tabs.initTabGroup(tabs.childNodes);

			return page;
		});
	},

	handleSave: function() {
		/* after saving, drop routes left without endpoints (also done on the router at apply time) */
		return this.map.save().then(function() { if (pruneRoutes()) return uci.save(); });
	}
});
