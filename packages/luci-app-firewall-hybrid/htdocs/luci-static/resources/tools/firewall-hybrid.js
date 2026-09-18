'use strict';
'require baseclass';
'require uci';
'require form';
'require firewall as fwmodel';
'require tools.firewall as fwtool';

function renderCapsule(label, val, inv, hint, valueStyle, containerStyle, valueClass) {
	const attr = {
		style: 'display:inline-block; font-size:0.85em; padding:2px 6px; border:1px solid var(--border-color, rgba(128,128,128,0.2)); border-radius:4px; background:rgba(128,128,128,0.05); color:inherit; line-height:1.2; white-space:nowrap;' + (containerStyle || '')
	};
	if (hint) attr['data-tooltip'] = hint;

	return E('span', attr, [
		E('strong', { style: 'margin-right:4px; font-weight:600; opacity:0.7;' }, label + ':'),
		E('span', { class: valueClass || null, style: valueStyle || '' }, (inv ? '! ' : '') + val)
	]);
}

function renderGroup(className, items, isVertical) {
	const style = isVertical ?
		'display:flex; flex-direction:column; gap:4px; align-items:flex-start;' :
		'display:flex; flex-flow:row wrap; gap:4px;';
	return E('div', { class: `target-group ${className}`, style }, items);
}

function renderZoneBadge(z, label) {
	const zName = (z === '*') ? _('Any') : (z || _('Device'));
	const zStyle = `${fwmodel.getZoneColorStyle(z)}; padding:1px 4px; border-radius:3px;`;
	return renderCapsule(label || 'Zone', zName, false, null, zStyle, null, 'zonebadge');
}

function parseMark(markVal) {
	if (!markVal) return null;
	const m = String(markVal).match(/^(!\s*)?(0x[0-9a-f]{1,8}|[0-9]{1,10})(?:\/(0x[0-9a-f]{1,8}|[0-9]{1,10}))?$/i);
	return m ? {
		val: m[0].toUpperCase().replace(/X/g, 'x'),
		inv: m[1],
		num: '0x%02X'.format(+m[2]),
		mask: m[3] ? '0x%02X'.format(+m[3]) : null
	} : null;
}

function parseHelper(helperVal, ctHelpers) {
	if (!helperVal) return null;
	const m = String(helperVal).match(/^(!\s*)?(\S+)$/);
	return m ? {
		val: m[0].toUpperCase(),
		inv: m[1],
		name: ctHelpers.find(ctH => ctH.name.toLowerCase() === m[2].toLowerCase())?.description
	} : null;
}

function parseProto(protoVal, icmpTypes) {
	return L.toArray(protoVal || 'tcp udp')
		.filter(p => p !== '*' && p !== 'any' && p !== 'all')
		.map(p => {
			const pr = fwtool.lookupProto(p);
			return {
				num: pr[0],
				name: pr[1],
				types: (icmpTypes && (pr[0] === 1 || pr[0] === 58)) ? L.toArray(icmpTypes) : null
			};
		});
}

function renderMarkCapsule(f) {
	if (!f) return null;
	return renderCapsule('Mark', f.val + (f.mask ? '/' + f.mask : ''), f.inv);
}

function renderHelperCapsule(h) {
	if (!h) return null;
	return renderCapsule('Helper', h.val, h.inv, h.name);
}

function addTimeRestrictions(s) {
	let o;
	const writeSpaceSeparated = function (section_id, value) {
		return this.super('write', [section_id, L.toArray(value).join(' ')]);
	};

	o = s.taboption('timed', form.MultiValue, 'weekdays', _('Week Days'));
	o.modalonly = true;
	o.multiple = true;
	o.display = 5;
	o.placeholder = _('Any day');
	const days = [['Sun', _('Sunday')], ['Mon', _('Monday')], ['Tue', _('Tuesday')], ['Wed', _('Wednesday')], ['Thu', _('Thursday')], ['Fri', _('Friday')], ['Sat', _('Saturday')]];
	days.forEach(d => o.value(d[0], d[1]));
	o.write = writeSpaceSeparated;

	o = s.taboption('timed', form.MultiValue, 'monthdays', _('Month Days'));
	o.modalonly = true;
	o.multiple = true;
	o.display_size = 15;
	o.placeholder = _('Any day');
	o.write = writeSpaceSeparated;
	for (let i = 1; i <= 31; i++)
		o.value(i);

	o = s.taboption('timed', form.Value, 'start_time', _('Start Time (hh:mm:ss)')); o.modalonly = true; o.datatype = 'timehhmmss';
	o = s.taboption('timed', form.Value, 'stop_time', _('Stop Time (hh:mm:ss)')); o.modalonly = true; o.datatype = 'timehhmmss';
	o = s.taboption('timed', form.Value, 'start_date', _('Start Date (yyyy-mm-dd)')); o.modalonly = true; o.datatype = 'dateyyyymmdd';
	o = s.taboption('timed', form.Value, 'stop_date', _('Stop Date (yyyy-mm-dd)')); o.modalonly = true; o.datatype = 'dateyyyymmdd';
	o = s.taboption('timed', form.Flag, 'utc_time', _('Time in UTC')); o.modalonly = true; o.default = o.disabled;
}

function rule_limit_txt(sid, formatMode) {
	const limit = uci.get('firewall', sid, 'limit');
	const m = limit ? String(limit).match(/^(\d+)\/([smhd])\w*$/i) : null;
	const l = m ? {
		num: +m[1],
		unit: ({ s: _('second'), m: _('minute'), h: _('hour'), d: _('day') })[m[2].toLowerCase()],
		burst: uci.get('firewall', sid, 'limit_burst')
	} : null;

	if (!l)
		return (formatMode === 'text') ? '' : null;

	return (formatMode === 'text')
		? fwtool.fmt(_('Limit matching to <var>%{limit.num}</var> packets per <var>%{limit.unit}</var>%{limit.burst? burst <var>%{limit.burst}</var>}'), { limit: l })
		: renderCapsule(_('Limit'), fwtool.fmt(_('%{limit.num}/%{limit.unit}%{limit.burst? burst %{limit.burst}}'), { limit: l }));
}

function rule_time_txt(sid) {
	const weekdays = uci.get('firewall', sid, 'weekdays');
	const monthdays = uci.get('firewall', sid, 'monthdays');
	const start_time = uci.get('firewall', sid, 'start_time');
	const stop_time = uci.get('firewall', sid, 'stop_time');
	const start_date = uci.get('firewall', sid, 'start_date');
	const stop_date = uci.get('firewall', sid, 'stop_date');
	const utc = uci.get('firewall', sid, 'utc_time') === '1';

	if (!weekdays && !monthdays && !start_time && !stop_time && !start_date && !stop_date)
		return null;

	const parts = [];
	if (start_time && stop_time)
		parts.push(_('Time: %s - %s').format(start_time, stop_time));
	else if (start_time)
		parts.push(_('From %s').format(start_time));
	else if (stop_time)
		parts.push(_('Until %s').format(stop_time));

	if (weekdays)
		parts.push(_('Weekdays: %s').format(weekdays));
	if (monthdays)
		parts.push(_('Month days: %s').format(monthdays));

	if (start_date && stop_date)
		parts.push(_('Dates: %s - %s').format(start_date, stop_date));
	else if (start_date)
		parts.push(_('From %s').format(start_date));
	else if (stop_date)
		parts.push(_('Until %s').format(stop_date));

	if (utc)
		parts.push(_('UTC'));

	const tooltipText = parts.join(', ');
	const style = 'background:rgba(111,66,193,0.1); color:#6f42c1; border-color:rgba(111,66,193,0.25);';

	let displayVal = _('Scheduled');
	if (start_time && stop_time)
		displayVal = '%s-%s'.format(start_time.substring(0, 5), stop_time.substring(0, 5));
	else if (weekdays) {
		const wd = weekdays.split(' ');
		displayVal = wd.length <= 3 ? wd.join(',') : _('Scheduled');
	}

	return renderCapsule('🕒 ' + _('Time'), displayVal, false, tooltipText, null, style);
}

function createSearchInput(placeholderText) {
	let debounceTimer = null;

	return E('input', {
		type: 'text',
		placeholder: placeholderText || _('Live Filter...'),
		class: 'cbi-input-text',
		style: 'width:100%; margin-bottom:1em; padding:0.5em;',
		input: ev => {
			clearTimeout(debounceTimer);
			debounceTimer = setTimeout(() => {
				const query = ev.target.value.toLowerCase();
				document.querySelectorAll('.zone-pair-accordion').forEach(acc => {
					if (acc.getAttribute('data-initial-hidden') === null)
						acc.setAttribute('data-initial-hidden', acc.style.display === 'none' ? 'true' : 'false');

					let visibleInAcc = 0;
					acc.querySelectorAll('tr.cbi-section-table-row').forEach(row => {
						const cells = row.querySelectorAll('td:not(.cbi-section-actions)');
						const text = Array.from(cells).map(c => c.textContent).join(' ').toLowerCase();
						const matches = text.includes(query);
						row.style.display = matches ? '' : 'none';
						if (matches) visibleInAcc++;
					});

					if (query === '') {
						acc.open = false;
						acc.style.display = (acc.getAttribute('data-initial-hidden') === 'true') ? 'none' : '';
					} else if (visibleInAcc > 0) {
						acc.open = true;
						acc.style.display = '';
					} else {
						acc.style.display = 'none';
					}
				});
			}, 150);
		}
	});
}

function createSectionAccordion(title, node, isBlockHeader, hasSections) {
	let style = 'margin-bottom:1em; border:1px solid var(--border-color, rgba(128,128,128,0.2)); border-radius:4px;';
	let summaryStyle = 'cursor:pointer; background:rgba(128,128,128,0.05); padding:0.8em; font-weight:bold; border-bottom:1px solid var(--border-color, rgba(128,128,128,0.2)); color:inherit;';

	if (isBlockHeader) {
		summaryStyle += ' background:rgba(128,128,128,0.12); font-size: 1.1em; color:inherit;';
		style += ' margin-top: 1.5em; border: 2px solid var(--border-color, rgba(128,128,128,0.3));';
	} else if (!hasSections) {
		style += ' display: none;';
	}

	return E('details', { class: 'zone-pair-accordion', style }, [
		E('summary', { style: summaryStyle }, [title]),
		E('div', { style: 'padding:0.5em; overflow-x:auto;' }, [node])
	]);
}

return baseclass.extend({
	renderCapsule,
	renderGroup,
	renderZoneBadge,
	parseMark,
	parseHelper,
	parseProto,
	renderMarkCapsule,
	renderHelperCapsule,
	addTimeRestrictions,
	rule_limit_txt,
	rule_time_txt,
	createSearchInput,
	createSectionAccordion,
});
