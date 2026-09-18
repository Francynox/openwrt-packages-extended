'use strict';
'require view';
'require ui';
'require rpc';
'require uci';
'require form';
'require tools.firewall as fwtool';
'require tools.widgets as widgets';
'require tools.firewall-hybrid as hybridtool';

function rule_proto_txt(s, ctHelpers) {
	const family = (uci.get('firewall', s, 'family') || '').toLowerCase().replace(/^(?:all|\*)$/, 'any');
	const dip = uci.get('firewall', s, 'dest_ip') || '';
	const ipv4 = !family && !dip.includes(':') || family === 'any' || (!family && !dip) || family === 'ipv4';
	const ipv6 = !family && dip.includes(':') || family === 'any' || family === 'ipv6';

	const proto = hybridtool.parseProto(uci.get('firewall', s, 'proto'), uci.get('firewall', s, 'icmp_type'));
	const h = hybridtool.parseHelper(uci.get('firewall', s, 'helper'), ctHelpers);
	const f = hybridtool.parseMark(uci.get('firewall', s, 'mark'));

	const familyItems = [];
	const famText = (ipv4 && ipv6) ? 'IPv4+IPv6' : (ipv4 ? 'IPv4' : (ipv6 ? 'IPv6' : null));
	if (famText) familyItems.push(hybridtool.renderCapsule('Family', famText));

	const protoItems = [];
	const icmpItems = [];
	if (proto && proto.length) {
		proto.forEach(p => {
			protoItems.push(hybridtool.renderCapsule('Proto', p.name.toUpperCase()));
			(p.types || []).forEach(t => icmpItems.push(hybridtool.renderCapsule('ICMP', t)));
		});
	} else {
		protoItems.push(hybridtool.renderCapsule('Proto', _('Any')));
	}

	const matchItems = [
		f ? hybridtool.renderMarkCapsule(f) : null,
		h ? hybridtool.renderHelperCapsule(h) : null
	].filter(Boolean);

	const children = [
		familyItems.length && hybridtool.renderGroup('family-group', familyItems),
		protoItems.length && hybridtool.renderGroup('proto-group', protoItems),
		icmpItems.length && hybridtool.renderGroup('icmp-group', icmpItems),
		matchItems.length && hybridtool.renderGroup('match-group', matchItems)
	].filter(Boolean);

	return children.length ? E('div', { style: 'display:flex; flex-direction:column; gap:4px;' }, children) : E('em', { style: 'color:#999;' }, _('Any Protocol'));
}

function rule_src_txt(s, hosts) {
	const z = uci.get('firewall', s, 'src');
	const baseItems = [hybridtool.renderZoneBadge(z)];
	const addrItems = [];

	(fwtool.map_invert(uci.get('firewall', s, 'src_ip'), 'toLowerCase') || []).forEach(ip => {
		addrItems.push(hybridtool.renderCapsule('IP', ip.ival, ip.inv));
	});

	(fwtool.map_invert(uci.get('firewall', s, 'src_mac'), 'toUpperCase') || []).forEach(mac => {
		addrItems.push(hybridtool.renderCapsule('MAC', mac.ival, mac.inv, hosts[mac.val]?.name));
	});

	(fwtool.map_invert(uci.get('firewall', s, 'src_port')) || []).forEach(p => {
		addrItems.push(hybridtool.renderCapsule('Port', p.ival, p.inv));
	});

	const children = [
		baseItems.length && hybridtool.renderGroup('base-group', baseItems, true),
		addrItems.length && hybridtool.renderGroup('addr-group', addrItems)
	].filter(Boolean);

	return E('div', { style: 'display:flex; flex-direction:column; gap:4px;' }, children);
}

function rule_dest_txt(s) {
	const addrItems = [];

	(fwtool.map_invert(uci.get('firewall', s, 'src_dip'), 'toLowerCase') || []).forEach(ip => {
		addrItems.push(hybridtool.renderCapsule('IP', ip.ival, ip.inv));
	});

	(fwtool.map_invert(uci.get('firewall', s, 'src_dport')) || []).forEach(p => {
		addrItems.push(hybridtool.renderCapsule('Port', p.ival, p.inv));
	});

	return addrItems.length ? hybridtool.renderGroup('addr-group', addrItems) : E('em', { style: 'color:#999;' }, _('Any'));
}

function rule_target_txt(s) {
	const z = uci.get('firewall', s, 'dest');
	const dest_ip = (uci.get('firewall', s, 'dest_ip') || '').toLowerCase();
	const dest_port = uci.get('firewall', s, 'dest_port');

	const baseItems = [hybridtool.renderZoneBadge(z, 'To Zone')];
	if (dest_ip) baseItems.push(hybridtool.renderCapsule(_('To IP'), dest_ip));
	if (dest_port) baseItems.push(hybridtool.renderCapsule(_('To Port'), dest_port));

	if (uci.get('firewall', s, 'reflection') !== '0') {
		const srcText = uci.get('firewall', s, 'reflection_src') === 'external' ? _('External') : _('Internal');
		const loopbackStyle = 'background:rgba(0,123,255,0.08); color:#007bff; border-color:rgba(0,123,255,0.18); margin-top:2px;';
		baseItems.push(hybridtool.renderCapsule(_('Loopback'), srcText, false, null, null, loopbackStyle));
	}
	return E('div', { style: 'display:flex; flex-direction:column; gap:4px; align-items:flex-start;' }, baseItems);
}

function validate_opt_family(m, section_id, opt) {
	const dopt = m.section.getOption('dest_ip');
	const fmopt = m.section.getOption('family');

	if ((!dopt.isValid(section_id) && opt !== 'dest_ip') || (!fmopt.isValid(section_id) && opt !== 'family'))
		return true;

	const dip = dopt.formvalue(section_id) || '';
	const fm = fmopt.formvalue(section_id) || '';

	if (!fm || (fm === 'any' && !dip) || (fm === 'ipv6' && (dip.includes(':') || !dip)) || (fm === 'ipv4' && !dip.includes(':')))
		return true;

	return _('Address family, Internal IP address must match');
}

return view.extend({
	callHostHints: rpc.declare({
		object: 'luci-rpc',
		method: 'getHostHints',
		expect: { '': {} }
	}),

	callConntrackHelpers: rpc.declare({
		object: 'luci',
		method: 'getConntrackHelpers',
		expect: { result: [] }
	}),

	callNetworkDevices: rpc.declare({
		object: 'luci-rpc',
		method: 'getNetworkDevices',
		expect: { '': {} }
	}),

	load() {
		return Promise.all([
			this.callHostHints(),
			this.callConntrackHelpers(),
			this.callNetworkDevices(),
			uci.load('firewall')
		]);
	},

	render(data) {
		return this.renderForwards(data);
	},

	renderForwards([hosts, ctHelpers, devs]) {
		const m = new form.Map('firewall', null, null);

		const searchInput = hybridtool.createSearchInput(_('Live Filter (e.g. "wan", "192.168.1")...'));

		const zones = uci.sections('firewall', 'zone');
		zones.sort((a, b) => (a.name || '').localeCompare(b.name || ''));

		const createSection = (title, filterFn, handleAddFn, isBlockHeader = false) => {
			const s = m.section(form.GridSection, 'redirect', title);
			s.anonymous = true;
			s.addremove = true;
			s.sortable = true;
			s.cloneable = true;
			s.nodescriptions = true;

			s.filter = filterFn;
			s.handleAdd = handleAddFn;

			s.sectiontitle = function (section_id) {
				return uci.get('firewall', section_id, 'name') || _('Unnamed forward');
			};

			s.tab('general', _('General Settings'));
			s.tab('advanced', _('Advanced Settings'));

			const oName = s.taboption('general', form.Value, 'name', _('Name'));
			oName.placeholder = _('Unnamed forward');
			oName.modalonly = true;

			const oFamily = s.taboption('general', form.ListValue, 'family', _('Restrict to address family'));
			oFamily.modalonly = true;
			oFamily.rmempty = true;
			oFamily.value('any', _('IPv4 and IPv6'));
			oFamily.value('ipv4', _('IPv4 only'));
			oFamily.value('ipv6', _('IPv6 only'));
			oFamily.value('', _('automatic'));
			oFamily.cfgvalue = function (section_id) {
				const val = this.map.data.get(this.map.config, section_id, 'family');
				if (!val) return '';
				if (val === 'any' || val === 'all' || val === '*') return 'any';
				if (val === 'inet' || String(val).includes('4')) return 'ipv4';
				if (String(val).includes('6')) return 'ipv6';
			};
			oFamily.validate = function (section_id, value) {
				fwtool.updateHostHints(this.map, section_id, 'dest_ip', value, hosts);
				return validate_opt_family(this, section_id, 'family');
			};

			// Hybrid separated columns
			const oProto = s.option(form.DummyValue, '_proto', _('Protocol'));
			oProto.modalonly = false;
			oProto.textvalue = function (sid) {
				return rule_proto_txt(sid, ctHelpers);
			};

			const oSrc = s.option(form.DummyValue, '_src', _('Source'));
			oSrc.modalonly = false;
			oSrc.textvalue = function (sid) {
				return rule_src_txt(sid, hosts);
			};

			const oDest = s.option(form.DummyValue, '_dest_capsules', _('Destination'));
			oDest.modalonly = false;
			oDest.textvalue = function (sid) {
				const dest = rule_dest_txt(sid);
				const limit = hybridtool.rule_limit_txt(sid);
				const ipset = uci.get('firewall', sid, 'ipset');

				const items = [
					dest && E('div', { style: 'padding: 2px 0;' }, dest),
					ipset && E('div', { style: 'padding: 2px 0;' }, hybridtool.renderCapsule('IPSet', ipset)),
					limit && E('div', { style: 'padding: 2px 0;' }, limit)
				].filter(Boolean);

				return E('div', { style: 'font-size: 0.95em;' }, items);
			};

			const oAction = s.option(form.DummyValue, '_action', _('Action'));
			oAction.modalonly = false;
			oAction.textvalue = function (sid) {
				return rule_target_txt(sid);
			};

			const oEnabled = s.option(form.Flag, 'enabled', _('Enable'));
			oEnabled.modalonly = false;
			oEnabled.default = oEnabled.enabled;
			oEnabled.editable = true;

			let o;

			o = s.taboption('general', fwtool.CBIProtocolSelect, 'proto', _('Protocol'));
			o.modalonly = true;
			o.default = 'tcp udp';

			o = s.taboption('general', widgets.ZoneSelect, 'src', _('Source zone'));
			o.modalonly = true;
			o.rmempty = false;
			o.nocreate = true;
			o.default = 'wan';

			o = s.taboption('advanced', form.Value, 'ipset', _('Use ipset'));
			uci.sections('firewall', 'ipset', function (s_ipset) {
				if (typeof (s_ipset.name) == 'string')
					o.value(s_ipset.name, s_ipset.comment ? '%s (%s)'.format(s_ipset.name, s_ipset.comment) : s_ipset.name);
			});
			o.modalonly = true;
			o.rmempty = true;

			fwtool.addMACOption(s, 'advanced', 'src_mac', _('Source MAC address'), _('Only match incoming traffic from these MACs.'), hosts);
			o = s.getOption ? s.getOption('src_mac') : null;
			if (o) {
				o.rmempty = true;
				o.datatype = 'list(neg(macaddr))';
			}

			fwtool.addIPOption(s, 'advanced', 'src_ip', _('Source IP address'), _('Only match incoming traffic from this IP or range.'), '', hosts);
			o = s.getOption ? s.getOption('src_ip') : null;
			if (o) {
				o.rmempty = true;
				o.datatype = 'neg(ipmask("true"))';
			}

			o = s.taboption('advanced', form.Value, 'src_port', _('Source port'), _('Only match incoming traffic originating from the given source port or port range on the client host'));
			o.modalonly = true;
			o.rmempty = true;
			o.datatype = 'neg(portrange)';
			o.placeholder = _('any');
			o.depends({ proto: 'tcp', '!contains': true });
			o.depends({ proto: 'udp', '!contains': true });

			fwtool.addLocalIPOption(s, 'advanced', 'src_dip', _('External IP address'), _('Only match incoming traffic directed at the given IP address.'), devs);
			o = s.getOption ? s.getOption('src_dip') : null;
			if (o) {
				o.datatype = 'neg(ipmask("true"))';
				o.rmempty = true;
			}

			o = s.taboption('general', form.Value, 'src_dport', _('External port'), _('Match incoming traffic directed at the given destination port or port range on this host'));
			o.modalonly = true;
			o.rmempty = false;
			o.datatype = 'neg(portrange)';
			o.depends({ proto: 'tcp', '!contains': true });
			o.depends({ proto: 'udp', '!contains': true });

			o = s.taboption('general', widgets.ZoneSelect, 'dest', _('Internal zone'));
			o.modalonly = true;
			o.rmempty = true;
			o.nocreate = true;

			fwtool.addIPOption(s, 'general', 'dest_ip', _('Internal IP address'), _('Redirect matched incoming traffic to the specified internal host'), '', hosts);
			o = s.getOption ? s.getOption('dest_ip') : null;
			if (o) {
				o.rmempty = true;
				o.datatype = 'ipmask';
				o.validate = function (section_id, value) {
					return validate_opt_family(this, section_id, 'dest_ip');
				};
			}

			o = s.taboption('general', form.Value, 'dest_port', _('Internal port'), _('Redirect matched incoming traffic to the given port on the internal host'));
			o.modalonly = true;
			o.rmempty = true;
			o.placeholder = _('any');
			o.datatype = 'portrange';
			o.depends({ proto: 'tcp', '!contains': true });
			o.depends({ proto: 'udp', '!contains': true });

			o = s.taboption('advanced', form.Flag, 'reflection', _('Enable NAT Loopback'));
			o.modalonly = true;
			o.rmempty = true;
			o.default = o.enabled;

			o = s.taboption('advanced', form.ListValue, 'reflection_src', _('Loopback source IP'), _('Specifies whether to use the external or the internal IP address for reflected traffic.'));
			o.modalonly = true;
			o.depends('reflection', '1');
			o.value('internal', _('Use internal IP address'));
			o.value('external', _('Use external IP address'));
			o.write = function (section_id, value) {
				uci.set('firewall', section_id, 'reflection_src', (value != 'internal') ? value : null);
			};

			o = s.taboption('advanced', widgets.ZoneSelect, 'reflection_zone', _('Reflection zones'), _('Zones from which reflection rules shall be created. If unset, only the destination zone is used.'));
			o.nocreate = true;
			o.multiple = true;
			o.modalonly = true;
			o.depends('reflection', '1');

			o = s.taboption('advanced', form.Value, 'helper', _('Match helper'), _('Match traffic using the specified connection tracking helper.'));
			o.modalonly = true;
			o.placeholder = _('any');
			ctHelpers.forEach(cth => o.value(cth.name, '%s (%s)'.format(cth.description, cth.name.toUpperCase())));
			o.validate = function (section_id, value) {
				if (value === '' || value == null) return true;
				const cleanVal = value.replace(/^!\s*/, '');
				if (ctHelpers.some(cth => cleanVal === cth.name)) return true;
				return _('Unknown or not installed conntrack helper "%s"').format(value);
			};

			fwtool.addMarkOption(s, false);
			fwtool.addLimitOption(s);
			fwtool.addLimitBurstOption(s);

			o = s.taboption('advanced', form.Flag, 'log', _('Enable logging'), _('Log matched packets to syslog.'));
			o.modalonly = true;

			o = s.taboption('advanced', form.Value, 'log_limit', _('Limit log messages'));
			o.depends('log', '1');
			o.placeholder = '10/minute';
			o.modalonly = true;



			s.render = function () {
				return form.GridSection.prototype.render.apply(this, arguments).then(node => {
					return hybridtool.createSectionAccordion(title, node, isBlockHeader, this.cfgsections().length > 0);
				});
			};
		};

		// Block 2 Header
		const h2 = m.section(form.TypedSection, 'redirect', _('Zone-specific Port Forwards'));
		h2.anonymous = true;
		h2.render = function () {
			return E('div', { style: 'margin-top: 0.5em; border-bottom: 2px solid #ccc; padding-bottom: 0.3em; display: flex; justify-content: space-between; align-items: center;' }, [
				E('h2', { style: 'margin: 0; font-size: 1.3em;' }, [this.title]),
				E('button', {
					class: 'btn cbi-button-add',
					click: ui.createHandlerFn(this, function () {
						const select = E('select', { class: 'cbi-input-select' },
							zones.map(z => E('option', { value: z.name }, [z.name]))
						);

						ui.showModal(_('Add Port Forward to Zone'), [
							E('p', _('Select the source zone for the new port forward:')),
							E('div', { style: 'margin: 1em 0;' }, [select]),
							E('div', { class: 'right' }, [
								E('button', {
									class: 'btn cbi-button-neutral',
									style: 'margin-right: 0.5em;',
									click: () => ui.hideModal()
								}, [_('Cancel')]),
								E('button', {
									class: 'btn cbi-button-action important',
									click: ui.createHandlerFn(this, function () {
										const chosenZone = select.value;
										ui.hideModal();
										if (!chosenZone) return;

										const config_name = this.uciconfig || this.map.config;
										const section_id = uci.add(config_name, this.sectiontype);
										uci.set(config_name, section_id, 'src', chosenZone);
										uci.set(config_name, section_id, 'dest', 'lan');
										uci.set(config_name, section_id, 'target', 'DNAT');
										this.map.addedSection = section_id;

										const gridSec = this.map.children.find(s => s instanceof form.GridSection && s.filter(section_id));
										if (gridSec) {
											gridSec.renderMoreOptionsModal(section_id);
										}
									})
								}, [_('Add')])
							])
						]);
					})
				}, [_('Add Port Forward to Zone')])
			]);
		};
		h2.filter = function () { return false; };

		// Block 2 Content
		zones.forEach(z => {
			const srcZone = z.name;
			const title = _('Source Zone: %s').format(srcZone);
			createSection(title, function (sid) {
				const s_src = uci.get('firewall', sid, 'src');
				return s_src === srcZone && uci.get('firewall', sid, 'target') != 'SNAT';
			}, function (ev) {
				const config_name = this.uciconfig || this.map.config;
				const section_id = uci.add(config_name, this.sectiontype);
				uci.set(config_name, section_id, 'src', srcZone);
				uci.set(config_name, section_id, 'dest', 'lan');
				uci.set(config_name, section_id, 'target', 'DNAT');
				this.map.addedSection = section_id;
				this.renderMoreOptionsModal(section_id);
			});
		});

		return m.render().then(mapDom => {
			return E('div', { class: 'cbi-map' }, [
				E('h2', {}, [_('Firewall - Port Forwards (Hybrid)')]),
				E('div', { class: 'cbi-map-descr' }, [_('Port forwarding allows remote computers on the Internet to connect to a specific computer or service within the private LAN. Blocks are collapsible.')]),
				searchInput,
				mapDom
			]);
		});
	}
});
