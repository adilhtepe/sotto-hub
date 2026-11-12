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
	var stream = E('input', { 'class': 'cbi-input-text', type: 'text', maxlength: 16, value: pre.stream || 'Stream1' });
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
		row(_('Stream name'), stream, _('Max 16 characters, no spaces. Transmitter: name it sends. Receiver: name it expects.')),
		err,
		E('div', { 'class': 'right' }, [
			E('button', { 'class': 'cbi-button', 'click': ui.hideModal }, _('Cancel')), ' ',
			E('button', { 'class': 'cbi-button cbi-button-positive', 'click': function() {
				var bad = null;
				if (!/^(\d{1,3}\.){3}\d{1,3}$/.test(ip.value)) bad = _('Invalid IPv4 address');
				else if (!stream.value || stream.value.length > 16 || /\s/.test(stream.value) || stream.value === '*') bad = _('Stream name must be 1-16 characters without spaces');
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

	renderStatus: function(st) {
		var self = this;
		var routes = (st.routes || []).map(function(r) {
			return E('tr', { 'class': 'tr' }, [
				E('td', { 'class': 'td' }, r.src + ' / ' + r.src_stream),
				E('td', { 'class': 'td' }, r.dst + ':' + r.dst_port + ' / ' + r.dst_stream),
				E('td', { 'class': 'td' }, String(r.pkts)),
				E('td', { 'class': 'td' }, String(r.lost)),
				E('td', { 'class': 'td' }, ago(r.age))
			]);
		});

		var learned = (st.learned || []).map(function(l) {
			var spaced = /\s/.test(l.stream);
			var known = spaced || uci.sections('vbanhub', 'endpoint').some(function(e) { return e.ip === l.ip && e.stream === l.stream; });
			return E('tr', { 'class': 'tr' }, [
				E('td', { 'class': 'td' }, l.ip),
				E('td', { 'class': 'td' }, l.stream),
				E('td', { 'class': 'td' }, String(l.pkts)),
				E('td', { 'class': 'td' }, ago(l.age)),
				E('td', { 'class': 'td' }, known ? '' : E('button', {
					'class': 'cbi-button cbi-button-add',
					'click': function() {
						var id = uci.add('vbanhub', 'endpoint');
						uci.set('vbanhub', id, 'name', l.stream + ' (' + l.ip + ')');
						uci.set('vbanhub', id, 'role', 'tx');
						uci.set('vbanhub', id, 'ip', l.ip);
						uci.set('vbanhub', id, 'stream', l.stream);
						uci.save().then(function() { location.reload(); });
					}
				}, _('Adopt as transmitter')))
			]);
		});

		function tbl(titles, rows, empty) {
			return E('table', { 'class': 'table' }, [ E('tr', { 'class': 'tr table-titles' }, titles.map(function(t) { return E('th', { 'class': 'th' }, t); })) ]
				.concat(rows.length ? rows : [ E('tr', {}, E('td', { 'class': 'td', 'colspan': titles.length }, E('em', empty))) ]));
		}

		var eps = uci.sections('vbanhub', 'endpoint');
		function have(ip, role) { return eps.some(function(e) { return e.ip === ip && e.role === role; }); }
		function addEp(d, role) {
			var hit = (st.learned || []).filter(function(l) { return l.ip === d.ip && !/\s/.test(l.stream); })[0];
			openAdd({ name: d.host || d.device || d.ip, ip: d.ip, port: d.port, role: role,
				stream: (role === 'tx' && hit) ? hit.stream : 'Stream1' });
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
			var added = eps.filter(function(e) { return e.ip === k.ip; }).map(function(e) { return e.role === 'rx' ? _('receiver') : _('transmitter'); });
			return E('tr', { 'class': 'tr' }, [
				E('td', { 'class': 'td' }, k.name || '-'), E('td', { 'class': 'td' }, k.ip), E('td', { 'class': 'td' }, k.mac),
				E('td', { 'class': 'td' }, [
					added.length ? E('em', {}, _('added as %s').format(added.join(', ')) + ' ') : '',
					E('button', { 'class': 'cbi-button cbi-button-add', 'click': function() {
						openAdd({ name: k.name || k.ip, ip: k.ip, port: 6980, role: 'rx', stream: 'Stream1' });
					} }, _('Add…'))
				])
			]);
		});
		var scanning = st.scan && st.scan.active;

		return E('div', {}, [
			E('h4', {}, _('Devices connected to this router')),
			E('p', { 'class': 'cbi-section-descr' }, _('From DHCP leases and the neighbour table. Add any of them as a receiver or transmitter and choose the stream name yourself.')),
			tbl([ _('Hostname'), _('IP address'), _('MAC address'), '' ], known, _('No devices known.')),
			E('h4', {}, _('Discovered devices (VBAN ping)')),
			E('p', {}, [
				E('button', { 'class': 'cbi-button cbi-button-action', 'click': function() {
					return fs.exec('/etc/init.d/vbanhub', [ 'scan' ]).catch(function(e) { ui.addNotification(null, E('p', e.message)); });
				} }, _('Scan LAN')),
				' ', scanning ? _('Scanning…') : (st.scan && st.scan.age >= 0 ? _('Last scan %ds ago').format(st.scan.age) : '')
			]),
			tbl([ _('Address'), _('Host'), _('Application / device'), _('Type'), '' ], found,
				_('Nothing found yet. Start the service and press Scan LAN. Devices must answer VBAN PING (Voicemeeter, VBAN apps do).')),
			E('p', { 'class': 'cbi-section-descr' }, _('Stream names are not part of discovery: receivers get the placeholder "Stream1" (edit it to the name the device expects); transmitters use the name heard in "Unrouted senders" if available.')),
			E('p', {}, _('Listening on: %s').format((st.listen || []).map(function(l) { return l.name + (l.up ? '' : ' (down)'); }).join(', ') || _('all interfaces')) +
				(st.filtered ? ' — ' + _('%d packets from other interfaces dropped').format(st.filtered) : '')),
			E('p', {}, _('Received: %d, forwarded: %d, send errors: %d, malformed: %d, unrouted: %d')
				.format(st.rx || 0, st.tx || 0, st.txerr || 0, st.bad || 0, st.unknown || 0)),
			E('h4', {}, _('Active routes')),
			tbl([ _('From (ip / stream)'), _('To (ip:port / stream)'), _('Packets'), _('Lost'), _('Last seen') ], routes, _('No routes or daemon not running.')),
			E('h4', {}, _('Unrouted senders seen (learn)')),
			tbl([ _('IP'), _('Stream'), _('Packets'), _('Last seen'), '' ], learned, _('Nothing heard yet.'))
		]);
	},

	render: function(data) {
		var self = this, m, s, o;
		this.hints = data[2] || {};
		var statusBox = E('div', { 'id': 'vbanhub-status' }, this.renderStatus(data[1]));

		m = new form.Map('vbanhub', _('VBAN Hub'),
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

		s = m.section(form.GridSection, 'endpoint', _('Endpoints'));
		s.addremove = true; s.anonymous = true; s.sortable = true;
		o = s.option(form.Value, 'name', _('Name'));
		o = s.option(form.ListValue, 'role', _('Role'));
		o.value('tx', _('Transmitter')); o.value('rx', _('Receiver')); o.default = 'tx';
		o = s.option(form.Value, 'ip', _('IP address'));
		o.datatype = 'ip4addr'; o.rmempty = false;
		o = s.option(form.Value, 'port', _('Port (receivers)'));
		o.datatype = 'port'; o.placeholder = '6980';
		o.depends('role', 'rx');
		o = s.option(form.Value, 'stream', _('Stream name'), _('Max 16 chars, no spaces. Transmitters: name they send. Receivers: name they expect.'));
		o.datatype = 'and(maxlength(16),regexp(/^[^ \\t]+$/))'; o.rmempty = false;

		return m.render().then(function(mapNode) {
			poll.add(function() {
				return readStatus().then(function(st) {
					var box = document.getElementById('vbanhub-status');
					if (box) { box.innerHTML = ''; box.appendChild(self.renderStatus(st)); }
				});
			}, 3);

			self.map = m;
			return E([
				mapNode,
				E('h3', {}, _('Routing matrix')),
				E('div', { 'class': 'cbi-section-descr' }, _('Tick a cell to send that transmitter to that receiver. Save endpoint changes before editing the matrix.')),
				self.renderMatrix(),
				E('h3', {}, _('Live status')),
				statusBox
			]);
		});
	},

	handleSave: function() { return this.map.save(); }
});
