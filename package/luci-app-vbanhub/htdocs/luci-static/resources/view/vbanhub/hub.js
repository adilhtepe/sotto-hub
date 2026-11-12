'use strict';
'require view';
'require form';
'require uci';
'require fs';
'require ui';
'require poll';

/* VBAN Hub: settings, endpoints, routing matrix, live status, learn/adopt.
 * Status comes from /var/run/vbanhub/status.json (written by the daemon every 2s). */

function readStatus() {
	return L.resolveDefault(fs.read_direct('/var/run/vbanhub/status.json'), '{}').then(function(t) {
		try { return JSON.parse(t); } catch (e) { return {}; }
	});
}

function ago(s) { return s < 0 ? '-' : s + 's ago'; }

return view.extend({
	load: function() {
		return Promise.all([ uci.load('vbanhub'), readStatus() ]);
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

		return E('div', {}, [
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
