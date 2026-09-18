'use strict';
'require view';
'require ui';
'require rpc';
'require uci';
'require form';
'require tools.firewall as fwtool';
'require tools.widgets as widgets';
'require tools.firewall-hybrid as hybridtool';

function rule_proto_txt(s) {
	const family = (uci.get('firewall', s, 'family') || '').toLowerCase().replace(/^(?:all|\*)$/, 'any');
	const sip = uci.get('firewall', s, 'src_ip') || '';
	const dip = uci.get('firewall', s, 'dest_ip') || '';
	const rwip = uci.get('firewall', s, 'snat_ip') || '';
	const ipv4 = family === 'ipv4' || family === 'any' || (!family && !sip.includes(':') && !dip.includes(':') && !rwip.includes(':'));
	const ipv6 = family === 'ipv6' || family === 'any' || (!family && (sip.includes(':') || dip.includes(':') || rwip.includes(':')));

	const proto = hybridtool.parseProto(uci.get('firewall', s, 'proto'));
	const f = hybridtool.parseMark(uci.get('firewall', s, 'mark'));

	const famText = (ipv4 && ipv6) ? 'IPv4+IPv6' : (ipv4 ? 'IPv4' : (ipv6 ? 'IPv6' : null));
	const familyItems = famText ? [hybridtool.renderCapsule('Family', famText)] : [];

	const protoItems = proto && proto.length
		? proto.map(p => hybridtool.renderCapsule('Proto', p.name.toUpperCase()))
		: [hybridtool.renderCapsule('Proto', _('Any'))];

	const matchItems = [f && hybridtool.renderMarkCapsule(f)].filter(Boolean);

	const children = [
		familyItems.length && hybridtool.renderGroup('family-group', familyItems),
		protoItems.length && hybridtool.renderGroup('proto-group', protoItems),
		matchItems.length && hybridtool.renderGroup('match-group', matchItems)
	].filter(Boolean);

	return children.length ? E('div', { style: 'display:flex; flex-direction:column; gap:4px;' }, children) : E('em', { style: 'color:#999;' }, _('Any Protocol'));
}

function rule_src_txt(s, hosts) {
	const addrItems = [];

	(fwtool.map_invert(uci.get('firewall', s, 'src_ip'), 'toLowerCase') || []).forEach(ip => {
		addrItems.push(hybridtool.renderCapsule('IP', ip.ival, ip.inv));
	});

	(fwtool.map_invert(uci.get('firewall', s, 'src_port')) || []).forEach(p => {
		addrItems.push(hybridtool.renderCapsule('Port', p.ival, p.inv));
	});

	return addrItems.length ? hybridtool.renderGroup('addr-group', addrItems) : E('em', { style: 'color:#999;' }, _('Any'));
}

function rule_dest_txt(s) {
	const z = uci.get('firewall', s, 'src');
	const d = uci.get('firewall', s, 'device');

	const baseItems = [
		hybridtool.renderZoneBadge(z),
		d ? hybridtool.renderCapsule('IF', d) : null
	].filter(Boolean);

	const addrItems = [];
	(fwtool.map_invert(uci.get('firewall', s, 'dest_ip'), 'toLowerCase') || []).forEach(ip => {
		addrItems.push(hybridtool.renderCapsule('IP', ip.ival, ip.inv));
	});

	(fwtool.map_invert(uci.get('firewall', s, 'dest_port')) || []).forEach(p => {
		addrItems.push(hybridtool.renderCapsule('Port', p.ival, p.inv));
	});

	const children = [
		baseItems.length && hybridtool.renderGroup('base-group', baseItems, true),
		addrItems.length && hybridtool.renderGroup('addr-group', addrItems)
	].filter(Boolean);

	return E('div', { style: 'display:flex; flex-direction:column; gap:4px;' }, children);
}

function rule_target_txt(sid) {
	const t = uci.get('firewall', sid, 'target');
	const snat_ip = uci.get('firewall', sid, 'snat_ip');
	const snat_port = uci.get('firewall', sid, 'snat_port');

	let style = '';
	let val = t;
	let details = '';

	if (t === 'SNAT') {
		style = 'background:rgba(23,162,184,0.15); color:#17a2b8; border-color:rgba(23,162,184,0.25);';
		val = _('SNAT');
		details = [snat_ip, snat_port].filter(Boolean).join(':');
	} else if (t === 'MASQUERADE') {
		style = 'background:rgba(40,167,69,0.15); color:#28a745; border-color:rgba(40,167,69,0.25);';
		val = _('Masquerade');
	} else if (t === 'ACCEPT') {
		style = 'background:rgba(220,53,69,0.15); color:#dc3545; border-color:rgba(220,53,69,0.25);';
		val = _('Accept (No Rewrite)');
	}

	return hybridtool.renderCapsule(_('Action'), details ? `${val} (${details})` : val, false, null, null, style);
}

function validate_opt_family(m, section_id, opt) {
	const opts = {
		src_ip: m.section.getOption('src_ip'),
		dest_ip: m.section.getOption('dest_ip'),
		snat_ip: m.section.getOption('snat_ip'),
		family: m.section.getOption('family'),
		target: m.section.getOption('target')
	};

	for (const [k, o] of Object.entries(opts)) {
		if (o && !o.isValid(section_id) && opt !== k)
			return true;
	}

	const sip = opts.src_ip?.formvalue(section_id) || '';
	const dip = opts.dest_ip?.formvalue(section_id) || '';
	const rwip = opts.snat_ip?.formvalue(section_id) || '';
	const fm = opts.family?.formvalue(section_id) || '';
	const tg = opts.target?.formvalue(section_id);

	const isV6 = (sip.includes(':') || !sip) && (dip.includes(':') || !dip) && ((rwip.includes(':') && tg === 'SNAT') || !rwip);
	const isV4 = !sip.includes(':') && !dip.includes(':') && ((!rwip.includes(':') && tg === 'SNAT') || !rwip);

	if (fm === 'ipv6' && isV6) return true;
	if (fm === 'ipv4' && isV4) return true;
	if ((!fm || fm === 'any') && (isV6 || isV4)) return true;

	return _('Address family, source address, destination address, rewrite IP address must match');
}

return view.extend({
	callHostHints: rpc.declare({
		object: 'luci-rpc',
		method: 'getHostHints',
		expect: { '': {} }
	}),

	callNetworkDevices: rpc.declare({
		object: 'luci-rpc',
		method: 'getNetworkDevices',
		expect: { '': {} }
	}),

	load() {
		return Promise.all([
			this.callHostHints(),
			this.callNetworkDevices(),
			uci.load('firewall')
		]);
	},

	render(data) {
		return this.renderNats(data);
	},

	renderNats([hosts, devs]) {
		const m = new form.Map('firewall', null, null);

		const searchInput = hybridtool.createSearchInput(_('Live Filter (e.g. "wan", "192.168.1")...'));

		const zones = uci.sections('firewall', 'zone');
		zones.sort((a, b) => (a.name || '').localeCompare(b.name || ''));

		const createSection = (title, filterFn, handleAddFn, isBlockHeader = false) => {
			const s = m.section(form.GridSection, 'nat', title);
			s.anonymous = true;
			s.addremove = true;
			s.sortable = true;
			s.cloneable = true;
			s.filterrow = true;

			s.filter = filterFn;
			s.handleAdd = handleAddFn;

			s.tab('general', _('General Settings'));
			s.tab('advanced', _('Advanced Settings'));
			s.tab('timed', _('Time Restrictions'));

			s.sectiontitle = function (section_id) {
				return uci.get('firewall', section_id, 'name') || _('Unnamed NAT');
			};

			const oName = s.taboption('general', form.Value, 'name', _('Name'));
			oName.placeholder = _('Unnamed NAT');
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
				fwtool.updateHostHints(this.map, section_id, 'src_ip', value, hosts);
				fwtool.updateHostHints(this.map, section_id, 'dest_ip', value, hosts);
				return validate_opt_family(this, section_id, 'family');
			};

			// Hybrid separated columns
			const oProto = s.option(form.DummyValue, '_proto', _('Protocol'));
			oProto.modalonly = false;
			oProto.textvalue = function (sid) {
				return rule_proto_txt(sid);
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
				const targetCapsule = rule_target_txt(sid);
				const timeCapsule = hybridtool.rule_time_txt(sid);
				return timeCapsule
					? E('div', { style: 'display:flex; flex-direction:column; gap:4px; align-items:flex-start;' }, [targetCapsule, timeCapsule])
					: targetCapsule;
			};

			const oEnabled = s.option(form.Flag, 'enabled', _('Enable'));
			oEnabled.modalonly = false;
			oEnabled.default = oEnabled.enabled;
			oEnabled.editable = true;

			let o;

			o = s.taboption('general', fwtool.CBIProtocolSelect, 'proto', _('Protocol'));
			o.modalonly = true;
			o.default = 'all';

			o = s.taboption('general', widgets.ZoneSelect, 'src', _('Outbound zone'));
			o.modalonly = true;
			o.rmempty = false;
			o.nocreate = true;
			o.allowany = true;
			o.default = 'lan';

			o = fwtool.addIPOption(s, 'general', 'src_ip', _('Source address'), _('Match forwarded traffic from this IP or range.'), '', hosts);
			o = s.getOption ? s.getOption('src_ip') : null;
			if (o) {
				o.rmempty = true;
				o.datatype = 'neg(ipmask("true"))';
				o.validate = function (section_id, value) {
					return validate_opt_family(this, section_id, 'src_ip');
				};
			}

			o = s.taboption('general', form.Value, 'src_port', _('Source port'), _('Match forwarded traffic originating from the given source port or port range.'));
			o.modalonly = true;
			o.rmempty = true;
			o.datatype = 'neg(portrange)';
			o.placeholder = _('any');
			o.depends({ proto: 'tcp', '!contains': true });
			o.depends({ proto: 'udp', '!contains': true });

			fwtool.addIPOption(s, 'general', 'dest_ip', _('Destination address'), _('Match forwarded traffic directed at the given IP address.'), '', hosts);
			o = s.getOption ? s.getOption('dest_ip') : null;
			if (o) {
				o.rmempty = true;
				o.datatype = 'neg(ipmask("true"))';
				o.validate = function (section_id, value) {
					return validate_opt_family(this, section_id, 'dest_ip');
				};
			}

			o = s.taboption('general', form.Value, 'dest_port', _('Destination port'), _('Match forwarded traffic directed at the given destination port or port range.'));
			o.modalonly = true;
			o.rmempty = true;
			o.placeholder = _('any');
			o.datatype = 'neg(portrange)';
			o.depends({ proto: 'tcp', '!contains': true });
			o.depends({ proto: 'udp', '!contains': true });

			o = s.taboption('general', form.ListValue, 'target', _('Action'));
			o.modalonly = true;
			o.default = 'SNAT';
			o.value('SNAT', _('SNAT - Rewrite to specific source IP or port'));
			o.value('MASQUERADE', _('MASQUERADE - Automatically rewrite to outbound interface IP'));
			o.value('ACCEPT', _('ACCEPT - Disable address rewriting'));
			o.validate = function (section_id, value) {
				return validate_opt_family(this, section_id, 'target');
			};

			fwtool.addLocalIPOption(s, 'general', 'snat_ip', _('Rewrite IP address'), _('Rewrite matched traffic to the specified source IP address.'), devs);
			o = s.getOption ? s.getOption('snat_ip') : null;
			if (o) {
				o.placeholder = null;
				o.depends('target', 'SNAT');
				o.validate = function (section_id, value) {
					const a = this.formvalue(section_id);
					const p = this.section.formvalue(section_id, 'snat_port');

					if ((a == null || a == '') && (p == null || p == '') && value == '')
						return _('A rewrite IP must be specified!');

					return validate_opt_family(this, section_id, 'snat_ip');
				};
			}

			o = s.taboption('general', form.Value, 'snat_port', _('Rewrite port'), _('Rewrite matched traffic to the specified source port or port range.'));
			o.modalonly = true;
			o.rmempty = true;
			o.placeholder = _('do not rewrite');
			o.datatype = 'portrange';
			o.depends({ proto: 'tcp', '!contains': true });
			o.depends({ proto: 'udp', '!contains': true });

			o = s.taboption('advanced', widgets.DeviceSelect, 'device', _('Outbound device'), _('Matches forwarded traffic using the specified outbound network device.'));
			o.noaliases = true;
			o.modalonly = true;
			o.rmempty = true;

			fwtool.addMarkOption(s, false);
			fwtool.addLimitOption(s);
			fwtool.addLimitBurstOption(s);

			o = s.taboption('advanced', form.Flag, 'log', _('Enable logging'), _('Log matched packets to syslog.'));
			o.modalonly = true;

			hybridtool.addTimeRestrictions(s);

			s.render = function () {
				return form.GridSection.prototype.render.apply(this, arguments).then(node => {
					return hybridtool.createSectionAccordion(title, node, isBlockHeader, this.cfgsections().length > 0);
				});
			};
		};

		const addNatSection = srcZone => function (ev) {
			const config_name = this.uciconfig || this.map.config;
			const section_id = uci.add(config_name, this.sectiontype);
			uci.set(config_name, section_id, 'src', srcZone);
			uci.set(config_name, section_id, 'target', 'SNAT');
			this.map.addedSection = section_id;
			this.renderMoreOptionsModal(section_id);
		};

		// Block 1
		createSection(_('Global NAT Rules'), function (sid) {
			const s_src = uci.get('firewall', sid, 'src');
			return (s_src === undefined || s_src === '' || s_src === '*');
		}, addNatSection('*'), true);

		// Block 2 Header
		const h2 = m.section(form.TypedSection, 'nat', _('Outbound Zone-specific NAT Rules'));
		h2.anonymous = true;
		h2.render = function () {
			return E('div', { style: 'margin-top: 1.5em; border-bottom: 2px solid #ccc; padding-bottom: 0.3em; display: flex; justify-content: space-between; align-items: center;' }, [
				E('h2', { style: 'margin: 0; font-size: 1.3em;' }, [this.title]),
				E('button', {
					class: 'btn cbi-button-add',
					click: ui.createHandlerFn(this, function () {
						const select = E('select', { class: 'cbi-input-select' },
							zones.map(z => E('option', { value: z.name }, [z.name]))
						);

						ui.showModal(_('Add NAT Rule to Zone'), [
							E('p', _('Select the outbound zone for the new NAT rule:')),
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
										uci.set(config_name, section_id, 'target', 'SNAT');
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
				}, [_('Add NAT Rule to Zone')])
			]);
		};
		h2.filter = function () { return false; };

		// Block 2 Content
		zones.forEach(z => {
			const srcZone = z.name;
			const title = _('Outbound Zone: %s').format(srcZone);
			createSection(title, function (sid) {
				const s_src = uci.get('firewall', sid, 'src');
				return s_src === srcZone;
			}, addNatSection(srcZone));
		});

		return m.render().then(mapDom => E('div', { class: 'cbi-map' }, [
			E('h2', {}, [_('Firewall - NAT Rules (Hybrid)')]),
			E('div', { class: 'cbi-map-descr' }, [_('NAT rules allow fine grained control over the source IP to use for outbound or forwarded traffic. Blocks are collapsible.')]),
			searchInput,
			mapDom
		]));
	}
});
