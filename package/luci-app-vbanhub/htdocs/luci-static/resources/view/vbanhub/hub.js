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
	var stream = E('input', { 'class': 'cbi-input-text', type: 'text', maxlength: 16, list: 'vbanhub-streams', value: pre.stream || 'Stream1' });
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
		row(_('Stream name'), E('span', {}, [ stream, dl ]), _('Max 16 characters, spaces allowed. Transmitter: the name it sends (suggestions are the names heard from this IP). Receiver: the name it expects.')),
		err,
		E('div', { 'class': 'right' }, [
			E('button', { 'class': 'cbi-button', 'click': ui.hideModal }, _('Cancel')), ' ',
			E('button', { 'class': 'cbi-button cbi-button-positive', 'click': function() {
				var bad = null;
				if (!/^(\d{1,3}\.){3}\d{1,3}$/.test(ip.value)) bad = _('Invalid IPv4 address');
				else if (!stream.value || stream.value.length > 16 || /[\t\r\n*]/.test(stream.value)) bad = _('Stream name must be 1-16 characters, without tabs or *');
				else if (role.value === 'rx' && !(port.value >= 1 && port.value <= 65535)) bad = _('Invalid port');
				if (bad) { err.textContent = bad; err.style.display = ''; return; }
				var id = uci.add('vbanhub', 'endpoint');
				uci.set('vbanhub', id, 'name', name.value || ip.value);
				uci.set('vbanhub', id, 'role', role.value);
				uci.set('vbanhub', id, 'ip', ip.value);
				if (role.value === 'rx') uci.set('vbanhub', id, 'port', String(port.value));
				uci.set('vbanhub', id, 'stream', stream.value);
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
				E('td', { 'class': 'td' }, e.ip),
				E('td', { 'class': 'td' }, e.stream || '-'),
				E('td', { 'class': 'td' }, liveCell(function(s) {
					var h = (s.streams || []).filter(function(x) { return x.ip === e.ip && x.stream === e.stream; })[0];
					if (!h) return { on: false, text: _('no signal') };
					var on = h.age <= 3;
					return { on: on, text: streamFormat(h) + (on ? ' · ' + _('%d pkt/s').format(h.rate) : ' · ' + ago(h.age)) };
				})),
				E('td', { 'class': 'td' }, links(e, 'from', 'to')),
				E('td', { 'class': 'td' }, volumeWidget(e['.name']))
			]);
		});

		var outputs = eps.filter(function(e) { return e.role === 'rx'; }).map(function(e) {
			var port = +(e.port || 6980);
			return E('tr', { 'class': 'tr' }, [
				E('td', { 'class': 'td' }, E('strong', {}, e.name || e.ip)),
				E('td', { 'class': 'td' }, e.ip + ':' + port),
				E('td', { 'class': 'td' }, e.stream || '-'),
				E('td', { 'class': 'td' }, liveCell(function(s) {
					var rs = (s.routes || []).filter(function(r) { return r.dst === e.ip && r.dst_port === port && r.dst_stream === e.stream; });
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
			tbl([ _('Name'), _('Address'), _('Stream name'), _('Signal'), _('Sends to'), _('Volume') ], inputs,
				_('No inputs yet. Add transmitters in the Settings tab.')),
			E('h3', { 'style': 'margin-top:1.5em' }, _('Outputs')),
			E('div', { 'class': 'cbi-section-descr' }, _('Receivers the hub sends to. The volume is applied to everything this output receives.')),
			tbl([ _('Name'), _('Address'), _('Stream name'), _('State'), _('Receives from'), _('Volume') ], outputs,
				_('No outputs yet. Add receivers in the Settings tab.'))
		]);
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
				E('td', { 'class': 'td' }, r.src + ' / ' + r.src_stream),
				E('td', { 'class': 'td' }, r.dst + ':' + r.dst_port + ' / ' + r.dst_stream),
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
						openAdd({ name: l.stream, ip: l.ip, role: 'tx', stream: l.stream,
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
				stream: (role === 'tx' && names.length) ? names[0] : 'Stream1',
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
							stream: names.length ? names[0] : 'Stream1',
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
			_('Receives VBAN streams from transmitters and forwards them to selected receivers, rewriting the stream name. Point each transmitter at this router\'s IP and the hub port, using the stream name set below.'));

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
			return e ? ((e.name || id) + ' (' + (e.stream || '?') + ')') : id;
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
		o = s.option(form.Value, 'ip', _('IP address'));
		o.datatype = 'ip4addr'; o.rmempty = false;
		o = s.option(form.Value, 'port', _('Port (receivers)'));
		o.datatype = 'port'; o.placeholder = '6980';
		o.depends('role', 'rx');
		o = s.option(form.Value, 'stream', _('Stream name'), _('Max 16 characters, spaces allowed. Transmitters: name they send. Receivers: name they expect.'));
		/* this LuCI has no 'regexp' validator (an unknown type makes every value invalid) */
		o.datatype = 'maxlength(16)'; o.rmempty = false;
		o.validate = function(section_id, value) {
			if (value == null || value === '') return _('A stream name is required');
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

			var tabs = E('div', {}, [
				E('div', { 'data-tab': 'mixer', 'data-tab-title': _('Mixer') }, [ self.mixBanner, self.mixerBox ]),
				E('div', { 'data-tab': 'settings', 'data-tab-title': _('Settings') }, [
					mapNode,
					E('h3', {}, _('Routing matrix')),
					E('div', { 'class': 'cbi-section-descr' }, _('Tick a cell to send that transmitter to that receiver. Save endpoint changes before editing the matrix.')),
					self.matrixBox,
					E('h3', {}, _('Live status')),
					statusBox
				])
			]);
			ui.tabs.initTabGroup(tabs.childNodes);

			return E('div', {}, [ E('h2', {}, _('VBAN Hub')), tabs ]);
		});
	},

	handleSave: function() {
		/* after saving, drop routes left without endpoints (also done on the router at apply time) */
		return this.map.save().then(function() { if (pruneRoutes()) return uci.save(); });
	}
});
