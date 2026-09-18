'use strict';
'require view';
'require uci';
'require form';
'require tools.firewall-hybrid as hybridtool';


function ipset_details_txt(sid) {
	const items = [];

	L.toArray(uci.get('firewall', sid, 'entry')).forEach(e => items.push(hybridtool.renderCapsule('Entry', e)));

	['File:loadfile', 'Max Elem:maxelem'].forEach(x => {
		const [label, field] = x.split(':');
		const val = uci.get('firewall', sid, field);
		if (val) items.push(hybridtool.renderCapsule(label, val));
	});

	const timeout = uci.get('firewall', sid, 'timeout');
	if (timeout && timeout !== '0') {
		items.push(hybridtool.renderCapsule('Timeout', timeout + 's'));
	}

	if (uci.get('firewall', sid, 'counters') === '1') {
		items.push(hybridtool.renderCapsule('Counters', _('Enabled')));
	}

	if (items.length === 0) {
		return E('em', { style: 'color:#999;' }, _('No entries'));
	}

	return E('div', { style: 'display:flex; flex-flow:row wrap; gap:4px;' }, items);
}


return view.extend({

	load() {
		return Promise.all([
			uci.load('firewall')
		]);
	},

	render() {
		const m = new form.Map('firewall', null, null);

		const searchInput = hybridtool.createSearchInput(_('Live Filter (e.g. "ipv4", "hash", "name")...'));

		const createSection = (title, filterFn, handleAddFn, isBlockHeader = false) => {
			const s = m.section(form.GridSection, 'ipset', title);
			s.addremove = true;
			s.anonymous = true;
			s.sortable = true;
			s.cloneable = true;
			s.nodescriptions = true;

			s.filter = filterFn;
			s.handleAdd = handleAddFn;

			s.sectiontitle = function (section_id) {
				return uci.get('firewall', section_id, 'name') || _('Unnamed set');
			};

			/* refer to: https://ipset.netfilter.org/ipset.man.html */
			let o;
			o = s.option(form.Value, 'name', _('Name'));
			o.optional = false;
			o.rmempty = false;
			o.validate = (section_id, value) => /^[a-zA-Z_.][a-zA-Z0-9/_.-]*$/.test(value) || _('Invalid set name');
			o.placeholder = _('Unnamed set');
			o.modalonly = true;

			/* comment requires https://git.openwrt.org/?p=project/firewall4.git;a=commitdiff;h=39e8c70957c795bf0c12f04299170ae86c6efdf8 */
			o = s.option(form.Value, 'comment', _('Comment'));
			o.placeholder = _('Comment');
			o.modalonly = true;
			o.rmempty = true;

			o = s.option(form.ListValue, 'family', _('Family'));
			o.value('any', _('IPv4 and IPv6'));
			o.value('ipv4', _('IPv4'));
			o.value('ipv6', _('IPv6'));
			o.default = 'ipv4';
			o.modalonly = true;

			/* Direction src, dst; (Data)Types: ip, port, mac, net or set
			   Tuples: direction_datatype e.g. src_port, dest_net */
			o = s.option(form.DynamicList, 'match', _('Packet Field Match'),
				_('Packet fields to match upon.<br />' +
					'Syntax: <em>direction_datatype</em>. e.g.: <code>src_port, dest_net</code>.<br />' +
					'Directions: <code>src, dst</code>. Datatypes: <code>ip, port, mac, net</code>.<br />' +
					'Direction prefixes are optional.'));
			o.value('ip', _('ip: IP addr'));
			o.value('port', _('port: Port'));
			o.value('mac', _('mac: MAC addr'));
			o.value('net', _('net: (sub)net'));
			o.value('src_ip', _('src_ip: Source IP'));
			o.value('src_port', _('src_port: Source Port'));
			o.value('src_mac', _('src_mac: Source MAC addr'));
			o.value('src_net', _('src_net: Source (sub)net'));
			o.value('dest_ip', _('dest_ip: Destination IP'));
			o.value('dest_port', _('dest_port: Destination Port'));
			o.value('dest_mac', _('dest_mac: Destination MAC addr'));
			o.value('dest_net', _('dest_net: Destination (sub)net'));
			o.optional = false;
			o.rmempty = false;
			o.modalonly = true;

			// Dummy capsule columns
			const oFamily = s.option(form.DummyValue, '_family', _('Family'));
			oFamily.modalonly = false;
			oFamily.textvalue = function (sid) {
				const f = uci.get('firewall', sid, 'family') || 'ipv4';
				const label = f === 'any' ? 'IPv4+IPv6' : (f === 'ipv6' ? 'IPv6' : 'IPv4');
				return hybridtool.renderCapsule('Family', label);
			};

			const oMatch = s.option(form.DummyValue, '_match', _('Packet Field Match'));
			oMatch.modalonly = false;
			oMatch.textvalue = function (sid) {
				const mVal = L.toArray(uci.get('firewall', sid, 'match'));
				return mVal.length
					? E('div', { style: 'display:flex; flex-flow:row wrap; gap:4px;' }, mVal.map(val => hybridtool.renderCapsule('Match', val)))
					: E('em', { style: 'color:#999;' }, _('None'));
			};

			const oDetails = s.option(form.DummyValue, '_details', _('Details'));
			oDetails.modalonly = false;
			oDetails.textvalue = function (sid) {
				return ipset_details_txt(sid);
			};

			o = s.option(form.DynamicList, 'entry', _('IPs/Networks/MACs'),
				_('macaddr|ip[/cidr]<br />'));
			o.datatype = 'or(ipaddr,macaddr)';
			o.rmempty = true;
			o.modalonly = true;

			o = s.option(form.Value, 'maxelem', _('Max Entries'),
				_('up to 65536 entries.'));
			o.datatype = 'port'; //covers 16 bit size
			o.modalonly = true;
			o.rmempty = true;

			o = s.option(form.FileUpload, 'loadfile', _('Include File'),
				_('Path to file of CIDRs, subnets, host IPs, etc.<br />'));
			o.root_directory = '/etc/luci-uploads';
			o.enable_delete = true;
			o.enable_upload = true;
			o.datatype = 'file';
			o.rmempty = true;
			o.modalonly = true;

			o = s.option(form.Value, 'timeout', _('Timeout'),
				_('Unit: seconds. Default <code>0</code> means the entry is added permanently to the set.<br />' +
					'Max: 2147483 seconds.'));
			o.placeholder = _('0');
			o.modalonly = true;
			o.rmempty = true;

			o = s.option(form.Flag, 'counters', _('Counters'),
				_('Enables packet and byte count tracking for the set.'));
			o.modalonly = true;
			o.rmempty = true;
			o.default = false;

			o = s.option(form.Flag, 'enabled', _('Enabled'));
			o.default = true;
			o.editable = true;
			o.modalonly = false;

			s.render = function () {
				return form.GridSection.prototype.render.apply(this, arguments).then(node => {
					return hybridtool.createSectionAccordion(title, node, isBlockHeader, this.cfgsections().length > 0);
				});
			};
		};

		const addIpsetSection = family => function(ev) {
			const config_name = this.uciconfig || this.map.config;
			const section_id = uci.add(config_name, this.sectiontype);
			uci.set(config_name, section_id, 'family', family);
			this.map.addedSection = section_id;
			this.renderMoreOptionsModal(section_id);
		};

		// Block 1: Dual-stack IP Sets
		createSection(_('Dual-Stack IP Sets (IPv4 and IPv6)'),
			sid => uci.get('firewall', sid, 'family') === 'any',
			addIpsetSection('any'), true);

		// Block 2: IPv4 IP Sets
		createSection(_('IPv4 IP Sets'), sid => {
			const f = uci.get('firewall', sid, 'family');
			return (!f || f === 'ipv4');
		}, addIpsetSection('ipv4'), true);

		// Block 2: IPv6 IP Sets
		createSection(_('IPv6 IP Sets'),
			sid => uci.get('firewall', sid, 'family') === 'ipv6',
			addIpsetSection('ipv6'), true);

		return m.render().then(mapDom => E('div', { class: 'cbi-map' }, [
			E('h2', {}, [_('Firewall - IP Sets (Hybrid)')]),
			E('div', { class: 'cbi-map-descr' }, [_('firewall4 supports referencing and creating IP sets to simplify matching of large address lists without the need to create one rule per item to match. Port ranges in ipsets are unsupported by firewall4. Blocks are collapsible.')]),
			searchInput,
			mapDom
		]));
	}
});