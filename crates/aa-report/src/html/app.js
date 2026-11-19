/* Analyze Anything — the interactive view of a report.
 *
 * Everything shown comes from the two JSON blocks in this file: the report itself and the view
 * data the renderer derived from it (words in both languages, finding texts with their params
 * filled in). Report content is hostile input. It reaches the page only as text nodes and
 * attribute values set through the DOM API — never through innerHTML, document.write, eval or
 * a URL built from report text. The few links are built from a fixed prefix and digits or a
 * strictly matched identifier.
 */
(function () {
  'use strict';

  var doc = document;
  var R, V, lang;
  var SEVERITIES = ['high', 'medium', 'low', 'info'];
  var CONFIDENCES = ['verified', 'derived', 'heuristic'];
  var SECTIONS = ['overview', 'identity', 'provenance', 'structure', 'composition', 'capabilities',
    'hardening', 'network', 'secrets', 'privacy', 'code', 'anomalies'];
  // A shape for each level, so the meaning does not rest on colour alone.
  var SEVERITY_MARK = { high: '▲', medium: '◆', low: '●', info: '○' };
  var CONFIDENCE_MARK = { verified: '✓', derived: '→', heuristic: '≈' };
  var PAGE = 100; // findings added to a chapter per step
  var ROW = 28; // height of a tree row in px; matches .row in the stylesheet
  var VALUE_CUT = 600; // characters of an evidence value shown before "show all"

  var state = {
    severity: {}, confidence: {}, chapter: 'all', query: '',
    shown: {}, // section -> number of findings rendered
    treeQuery: '', treeFindingsOnly: false, selected: null, cursor: 0
  };

  /* ---------- small helpers ---------- */

  // Invisible and direction-changing characters are shown as their code point (see sanitize.rs).
  var DECEPTIVE = /[\u0000-\u0008\u000b-\u001f\u007f-\u009f\u00ad\u061c\u180e\u200b-\u200f\u2028-\u202e\u2060-\u2064\u2066-\u2069\ufeff\ufff9-\ufffb]|\udb40[\udc00-\udc7f]/g;
  function vis(text) {
    return String(text).replace(DECEPTIVE, function (c) {
      var code = c.codePointAt(0).toString(16).toUpperCase();
      return '[U+' + ('0000' + code).slice(-Math.max(4, code.length)) + ']';
    });
  }

  function add(parent, child) {
    if (child == null || child === false) return;
    if (Array.isArray(child)) { for (var i = 0; i < child.length; i++) add(parent, child[i]); return; }
    parent.appendChild(child.nodeType ? child : doc.createTextNode(vis(child)));
  }

  // el('div', {class: 'x', onclick: f}, child, ...). Attribute names are always literals in this
  // file; values may be report text and are set with setAttribute, which cannot create markup.
  function el(tag, props) {
    var node = doc.createElement(tag);
    if (props) {
      for (var key in props) {
        var value = props[key];
        if (value == null || value === false) continue;
        if (key === 'class') node.className = value;
        else if (key.slice(0, 2) === 'on') node.addEventListener(key.slice(2), value);
        else node.setAttribute(key, value === true ? '' : vis(value));
      }
    }
    for (var i = 2; i < arguments.length; i++) add(node, arguments[i]);
    return node;
  }

  function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); return node; }

  function t(key, n, m) {
    var word = V.words[lang][key];
    if (word == null) return '?' + key;
    if (n != null) word = word.replace('{n}', n);
    if (m != null) word = word.replace('{m}', m);
    return word;
  }
  function sectionName(key) { return V.words[lang].sections[key] || key; }
  function severityName(key) { return V.words[lang].severities[key] || key; }
  function confidenceName(key) { return V.words[lang].confidences[key] || key; }

  function group(n) { return String(n).replace(/\B(?=(\d{3})+(?!\d))/g, ','); }
  function bytes(n) {
    if (typeof n !== 'number') return '';
    if (n < 1024) return n + ' B';
    var units = ['KiB', 'MiB', 'GiB', 'TiB', 'PiB'];
    var i = -1;
    do { n /= 1024; i++; } while (n >= 1024 && i < units.length - 1);
    return (n >= 100 ? n.toFixed(0) : n >= 10 ? n.toFixed(1) : n.toFixed(2)) + ' ' + units[i];
  }

  var toastTimer = 0;
  function toast(message) {
    var node = doc.getElementById('toast');
    if (!node) return;
    node.textContent = message;
    node.classList.add('on');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(function () { node.classList.remove('on'); }, 1600);
  }

  function copy(text) {
    function fallback() {
      var area = el('textarea', { class: 'offscreen', 'aria-hidden': 'true' });
      area.value = text;
      doc.body.appendChild(area);
      area.select();
      var ok = false;
      try { ok = doc.execCommand('copy'); } catch (e) { ok = false; }
      doc.body.removeChild(area);
      toast(t(ok ? 'copied' : 'copy_failed'));
    }
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(function () { toast(t('copied')); }, fallback);
    } else fallback();
  }

  function copyButton(text, label) {
    return el('button', {
      type: 'button', class: 'copy', title: t('copy') + (label ? ': ' + label : ''),
      'aria-label': t('copy') + (label ? ': ' + label : ''),
      onclick: function (event) { event.stopPropagation(); copy(text); }
    }, '⧉');
  }

  function titleOf(ruleId) {
    var rule = R.rules[ruleId];
    return rule ? (lang === 'zh' ? rule.title_zh : rule.title_en) : ruleId;
  }
  function ruleText(code) {
    var rule = R.rules[code];
    return rule ? (lang === 'zh' ? rule.text_zh : rule.text_en) : '';
  }
  function textOf(index) { return V.texts[index][lang === 'zh' ? 0 : 1]; }

  /* ---------- derived data, built once ---------- */

  var bySection = {}; // section -> finding indices, most severe first
  var byArtifact = null; // path -> finding indices
  var haystacks = null; // lower-case searchable text per finding
  var artifactIndex = null; // path -> index in R.artifacts

  function prepare() {
    var rank = { high: 0, medium: 1, low: 2, info: 3 };
    SECTIONS.forEach(function (s) { bySection[s] = []; });
    R.findings.forEach(function (f, i) { (bySection[f.section] || (bySection[f.section] = [])).push(i); });
    Object.keys(bySection).forEach(function (s) {
      // Array.prototype.sort is stable, so findings of equal severity keep their report order.
      bySection[s].sort(function (a, b) { return rank[R.findings[a].severity] - rank[R.findings[b].severity]; });
      if (SECTIONS.indexOf(s) < 0) SECTIONS.push(s);
    });
    SEVERITIES.forEach(function (s) { state.severity[s] = true; });
    CONFIDENCES.forEach(function (c) { state.confidence[c] = true; });
    byArtifact = new Map();
    R.findings.forEach(function (f, i) {
      var seen = {};
      f.evidence.forEach(function (e) {
        if (seen[e.artifact]) return;
        seen[e.artifact] = true;
        var list = byArtifact.get(e.artifact);
        if (!list) byArtifact.set(e.artifact, list = []);
        list.push(i);
      });
    });
    artifactIndex = new Map();
    R.artifacts.forEach(function (a, i) { artifactIndex.set(a.path, i); });
  }

  function evidenceValue(findingIndex, evidenceIndex) {
    var value = R.findings[findingIndex].evidence[evidenceIndex].value;
    if (typeof value === 'string') return value;
    var exact = V.values[findingIndex];
    return exact && exact[evidenceIndex] != null ? exact[evidenceIndex] : JSON.stringify(value);
  }

  function haystack(i) {
    if (!haystacks) haystacks = new Array(R.findings.length);
    if (haystacks[i] != null) return haystacks[i];
    var f = R.findings[i];
    var rule = R.rules[f.rule];
    var parts = [f.rule, f.analyzer, f.id, V.texts[i][0], V.texts[i][1], f.references.join(' ')];
    if (rule) parts.push(rule.title_zh, rule.title_en);
    f.evidence.forEach(function (e, j) { parts.push(e.artifact, evidenceValue(i, j).slice(0, 500)); });
    return (haystacks[i] = parts.join('\n').toLowerCase());
  }

  function filtersActive() {
    return state.query !== '' || state.chapter !== 'all' ||
      SEVERITIES.some(function (s) { return !state.severity[s]; }) ||
      CONFIDENCES.some(function (c) { return !state.confidence[c]; });
  }

  function matching(section) {
    var tokens = state.query.toLowerCase().split(/\s+/).filter(Boolean);
    return bySection[section].filter(function (i) {
      var f = R.findings[i];
      if (!state.severity[f.severity] || !state.confidence[f.confidence]) return false;
      if (!tokens.length) return true;
      var hay = haystack(i);
      return tokens.every(function (token) { return hay.indexOf(token) >= 0; });
    });
  }

  /* ---------- JSON viewer (facts) ---------- */

  function pointer(base, key) { return base + '/' + String(key).replace(/~/g, '~0').replace(/\//g, '~1'); }

  function jsonScalar(value, ptr) {
    if (value === null) return el('span', { class: 'jv jnull' }, 'null');
    if (typeof value === 'number') return el('span', { class: 'jv jnum' }, V.exact[ptr] || String(value));
    if (typeof value === 'boolean') return el('span', { class: 'jv jbool' }, String(value));
    var text = JSON.stringify(String(value));
    if (text.length <= 1200) return el('span', { class: 'jv jstr' }, text);
    var span = el('span', { class: 'jv jstr' }, text.slice(0, 1200) + '…');
    var more = el('button', {
      type: 'button', class: 'link', onclick: function () { span.textContent = vis(text); more.remove(); }
    }, t('show_full_value', group(text.length)));
    return [span, ' ', more];
  }

  function jsonNode(key, value, ptr, open) {
    var label = key == null ? null : el('span', { class: 'jk' }, typeof key === 'number' ? '[' + key + ']' : key);
    if (value === null || typeof value !== 'object') {
      return el('div', { class: 'jrow' }, label, label ? ': ' : null, jsonScalar(value, ptr));
    }
    var isArray = Array.isArray(value);
    var keys = isArray ? null : Object.keys(value);
    var count = isArray ? value.length : keys.length;
    var body = el('div', { class: 'jbody' });
    var filled = 0;
    function fill() {
      var end = Math.min(count, filled + 100);
      var old = body.querySelector(':scope > .jmore');
      if (old) old.remove();
      for (; filled < end; filled++) {
        var k = isArray ? filled : keys[filled];
        body.appendChild(jsonNode(k, value[k], pointer(ptr, k), false));
      }
      if (filled < count) {
        body.appendChild(el('button', { type: 'button', class: 'link jmore', onclick: fill },
          t('show_next', Math.min(100, count - filled)) + ' · ' + group(filled) + ' / ' + group(count)));
      }
    }
    var details = el('details', { class: 'jnode', open: open },
      el('summary', null, label, label ? ' ' : null,
        el('span', { class: 'jmeta' }, isArray ? '[ ' + t('items', group(count)) + ' ]' : '{ ' + t('keys', group(count)) + ' }')),
      body);
    details.addEventListener('toggle', function () { if (details.open && filled === 0) fill(); });
    if (open) fill();
    return details;
  }

  function factsView(map, base) {
    var keys = Object.keys(map);
    return el('div', { class: 'json' }, keys.map(function (key) {
      return jsonNode(key, map[key], pointer(base, key), keys.length <= 4);
    }));
  }

  /* ---------- findings ---------- */

  function badge(kind, key) {
    var severity = kind === 'severity';
    return el('span', { class: 'badge ' + (severity ? 'sev sev-' : 'conf conf-') + key },
      el('span', { class: 'mark', 'aria-hidden': 'true' }, (severity ? SEVERITY_MARK : CONFIDENCE_MARK)[key] || '·'),
      severity ? severityName(key) : confidenceName(key));
  }

  function referenceNode(reference) {
    var url = null;
    var cwe = /^CWE-(\d{1,6})$/.exec(reference);
    var masvs = /^MASVS-[A-Z]{2,16}-\d{1,2}$/.exec(reference);
    if (cwe) url = 'https://cwe.mitre.org/data/definitions/' + cwe[1] + '.html';
    else if (masvs) url = 'https://mas.owasp.org/MASVS/controls/' + masvs[0] + '/';
    // Anything else is shown as text. A link is only ever a plain <a> the reader may click.
    if (!url) return el('span', { class: 'ref' }, reference);
    return el('a', { class: 'ref', href: url, target: '_blank', rel: 'noopener noreferrer' }, reference);
  }

  function locationText(location) {
    if (location && typeof location === 'object') {
      if (location.bytes) {
        var offset = location.bytes.offset;
        return t('offset') + ' ' + group(offset) + ' (0x' + Number(offset).toString(16).toUpperCase() + ') · ' +
          t('length') + ' ' + group(location.bytes.length) + ' ' + t('bytes');
      }
      if (location.field != null) return t('field') + ' ' + location.field;
    }
    return t('whole_file');
  }

  function pathNode(path) {
    if (!artifactIndex.has(path)) return el('span', { class: 'path' }, path);
    return el('button', {
      type: 'button', class: 'path link', title: t('open_in_files'),
      onclick: function () { revealArtifact(path); }
    }, path);
  }

  function valueNode(text) {
    var pre = el('pre', { class: 'value' }, text.length > VALUE_CUT ? text.slice(0, VALUE_CUT) + '…' : text);
    if (text.length <= VALUE_CUT) return pre;
    var more = el('button', {
      type: 'button', class: 'link', onclick: function () { pre.textContent = vis(text); more.remove(); }
    }, t('show_full_value', group(text.length)));
    return [pre, more];
  }

  function fillEvidence(list, index, all) {
    var evidence = R.findings[index].evidence;
    var from = list.children.length ? list.querySelectorAll(':scope > li.ev').length : 0;
    var to = all ? evidence.length : Math.min(evidence.length, from + 50);
    var old = list.querySelector(':scope > li.more');
    if (old) old.remove();
    for (var j = from; j < to; j++) {
      list.appendChild(el('li', { class: 'ev' },
        el('div', { class: 'evhead' }, pathNode(evidence[j].artifact),
          el('span', { class: 'loc' }, locationText(evidence[j].location))),
        valueNode(evidenceValue(index, j))));
    }
    if (to < evidence.length) {
      list.appendChild(el('li', { class: 'more' }, el('button', {
        type: 'button', class: 'link', onclick: function () { fillEvidence(list, index, false); }
      }, t('show_more', Math.min(50, evidence.length - to)))));
    }
  }

  // `compact` cards sit inside another list (a group row, a file's details) and carry no anchor;
  // `inPlace` ones are already where "go to this finding" would lead.
  function findingCard(index, compact, inPlace) {
    var f = R.findings[index];
    var list = el('ol', { class: 'evlist' });
    var details = el('details', { class: 'evidence' },
      el('summary', null, t('evidence') + ' (' + group(f.evidence.length) + ')'), list);
    details.addEventListener('toggle', function () {
      if (details.open && !list.children.length) fillEvidence(list, index, false);
    });
    return el('article', { class: 'finding sev-' + f.severity, id: compact ? null : 'f-' + index, tabindex: compact ? null : '-1', 'data-index': index },
      el('div', { class: 'fhead' }, badge('severity', f.severity), badge('confidence', f.confidence),
        el(compact ? 'h5' : 'h4', { class: 'ftitle' }, titleOf(f.rule))),
      el('p', { class: 'ftext' }, textOf(index)),
      el('div', { class: 'fmeta' },
        f.references.length ? el('span', { class: 'refs' }, el('span', { class: 'k' }, t('references')), f.references.map(referenceNode)) : null,
        el('span', null, el('span', { class: 'k' }, t('rule')), el('code', null, f.rule)),
        el('span', { class: 'fid' }, el('span', { class: 'k' }, t('finding_id')),
          el('code', { title: f.id }, f.id.slice(0, 16)), copyButton(f.id, t('finding_id'))),
        compact && !inPlace ? el('button', { type: 'button', class: 'link', onclick: function () { revealFinding(index); } }, t('go_to_finding')) : null),
      f.evidence.length ? details : null);
  }

  /* ---------- groups: the findings of one rule as one entry ---------- */

  // Mirrors group.rs: one group per rule, in the order the report first mentions each rule (the
  // engine puts the most severe first, then the analyzers' reading order); inside a group one
  // variant per distinct sentence, in order of appearance. `indices` must already list anything
  // above "info" before "info" and otherwise keep report order, as bySection does.
  var RANK = { high: 0, medium: 1, low: 2, info: 3 };
  function groupsOf(indices) {
    var byRule = new Map();
    indices.forEach(function (i) {
      var rule = R.findings[i].rule;
      var g = byRule.get(rule);
      if (!g) byRule.set(rule, g = { rule: rule, first: i, indices: [], variants: [], byText: new Map() });
      if (i < g.first) g.first = i;
      g.indices.push(i);
      var text = textOf(i);
      var v = g.byText.get(text);
      if (!v) { v = { text: text, indices: [] }; g.byText.set(text, v); g.variants.push(v); }
      v.indices.push(i);
    });
    var list = Array.from(byRule.values());
    list.forEach(function (g) { g.severity = R.findings[g.indices[0]].severity; });
    list.sort(function (a, b) { return a.first - b.first; });
    return list;
  }

  function subjectNode(index) {
    var f = R.findings[index];
    if (!f.evidence.length) return el('span', { class: 'path' }, t('subject_none'));
    return el('span', { class: 'path', title: f.evidence[0].artifact }, V.subjects[index] || f.evidence[0].artifact);
  }

  // One finding inside a group: a line that opens into the full finding.
  function instanceRow(index, withText, compact) {
    var f = R.findings[index];
    var body = el('div', { class: 'instbody' });
    var row = el('details', { class: 'inst', id: compact ? null : 'f-' + index, 'data-index': index },
      el('summary', null, subjectNode(index), withText ? el('span', { class: 'itext' }, textOf(index)) : null), body);
    row.addEventListener('toggle', function () {
      if (row.open && !body.firstChild) body.appendChild(findingCard(index, true, !compact));
    });
    return row;
  }

  function groupCard(g, compact) {
    var first = compact ? 5 : (g.severity === 'info' ? 10 : 30);
    var total = g.indices.length;
    var counts = {}, confidences = {};
    g.indices.forEach(function (i) {
      counts[R.findings[i].severity] = (counts[R.findings[i].severity] || 0) + 1;
      confidences[R.findings[i].confidence] = true;
    });
    var host = el('div', { class: 'variants' });
    var shownVariants = 0;
    var lists = []; // per variant: {fill(upTo), details}
    function variantNode(v) {
      if (v.indices.length === 1) {
        lists.push(null);
        return instanceRow(v.indices[0], true, compact);
      }
      var list = el('div', { class: 'insts' });
      var filled = 0;
      function fill(upTo) {
        var old = list.querySelector(':scope > .pager');
        if (old) old.remove();
        var end = Math.min(v.indices.length, Math.max(upTo, filled));
        for (; filled < end; filled++) list.appendChild(instanceRow(v.indices[filled], false, compact));
        if (filled < v.indices.length) {
          list.appendChild(el('div', { class: 'pager' },
            el('button', { type: 'button', class: 'btn', onclick: function () { fill(filled + 100); } }, t('show_more', group(Math.min(100, v.indices.length - filled)))),
            el('button', { type: 'button', class: 'btn', onclick: function () { fill(v.indices.length); } }, t('show_all', group(v.indices.length)))));
        }
      }
      var names = [];
      for (var k = 0; k < v.indices.length && names.length < 4; k++) {
        var name = V.subjects[v.indices[k]];
        if (name && names.indexOf(name) < 0) names.push(name);
      }
      var details = el('details', { class: 'shared' },
        el('summary', null, t('group_shared', group(v.indices.length)) + ': ',
          el('span', { class: 'path' }, names.join(', ') + (v.indices.length > names.length ? ' …' : ''))), list);
      details.addEventListener('toggle', function () { if (details.open && !filled) fill(50); });
      lists.push({ fill: fill, details: details });
      return el('div', { class: 'variant' }, el('p', { class: 'ftext' }, v.text), details);
    }
    function showVariants(upTo) {
      var old = host.querySelector(':scope > .pager');
      if (old) old.remove();
      var end = Math.min(g.variants.length, Math.max(upTo, shownVariants));
      for (; shownVariants < end; shownVariants++) host.appendChild(variantNode(g.variants[shownVariants]));
      if (shownVariants < g.variants.length) {
        var rest = 0;
        for (var k = shownVariants; k < g.variants.length; k++) rest += g.variants[k].indices.length;
        host.appendChild(el('div', { class: 'pager' },
          el('button', { type: 'button', class: 'btn', onclick: function () { showVariants(shownVariants + 50); } }, t('show_more', group(Math.min(50, g.variants.length - shownVariants)))),
          el('button', { type: 'button', class: 'btn', onclick: function () { showVariants(g.variants.length); } }, t('show_all', group(g.variants.length))),
          el('span', { class: 'muted rest' }, t('group_rest', group(rest)))));
      }
    }
    showVariants(first);
    var card = el('article', { class: 'finding group sev-' + g.severity, 'data-rule': g.rule },
      el('div', { class: 'fhead' },
        SEVERITIES.filter(function (s) { return counts[s]; }).map(function (s) {
          var b = badge('severity', s);
          add(b, ' × ' + group(counts[s]));
          return b;
        }),
        CONFIDENCES.filter(function (c) { return confidences[c]; }).map(function (c) { return badge('confidence', c); }),
        el(compact ? 'h5' : 'h4', { class: 'ftitle' }, titleOf(g.rule)),
        el('span', { class: 'gcount' }, t('group_count', group(total)))),
      host,
      el('div', { class: 'fmeta' }, el('span', null, el('span', { class: 'k' }, t('rule')), el('code', null, g.rule))));
    // Brings the row of finding `index` on screen, opening whatever hides it.
    card.reveal = function (index) {
      for (var vi = 0; vi < g.variants.length; vi++) {
        var at = g.variants[vi].indices.indexOf(index);
        if (at < 0) continue;
        showVariants(vi + 1);
        if (lists[vi]) { lists[vi].details.open = true; lists[vi].fill(at + 1); }
        return doc.getElementById('f-' + index);
      }
      return null;
    };
    return card;
  }

  function entryNode(g, compact) {
    return g.indices.length === 1 ? findingCard(g.indices[0], compact, false) : groupCard(g, compact);
  }

  function renderChapter(section) {
    var host = doc.getElementById('ch-' + section);
    if (!host) return;
    var body = host.querySelector('.chbody');
    var all = bySection[section];
    var hits = matching(section);
    var hidden = state.chapter !== 'all' && state.chapter !== section;
    host.hidden = hidden;
    var groups = groupsOf(hits);
    var count = host.querySelector('.count');
    count.hidden = all.length === 0;
    count.textContent = t('chapter_counts', group(groups.length), group(hits.length)) + (filtersActive() ? ' · ' + t('of_total', group(all.length)) : '');
    var nav = doc.getElementById('nav-' + section);
    if (nav) {
      nav.querySelector('.n').textContent = group(hits.length);
      nav.classList.toggle('empty', hits.length === 0);
    }
    clear(body);
    if (hidden) return hits.length;
    if (!all.length) body.appendChild(el('p', { class: 'none' }, t('no_findings_here')));
    else if (!hits.length) body.appendChild(el('p', { class: 'none' }, t('no_match_chapter', group(all.length))));
    var limit = Math.min(groups.length, state.shown[section] || PAGE);
    var fragment = doc.createDocumentFragment();
    for (var i = 0; i < limit; i++) fragment.appendChild(entryNode(groups[i], false));
    body.appendChild(fragment);
    if (limit < groups.length) {
      var rest = groups.length - limit;
      body.appendChild(el('div', { class: 'pager' },
        el('button', { type: 'button', class: 'btn', onclick: function () { state.shown[section] = limit + PAGE; renderChapter(section); } },
          t('show_more', group(Math.min(PAGE, rest)))),
        rest > PAGE ? el('button', { type: 'button', class: 'btn', onclick: function () { state.shown[section] = Infinity; renderChapter(section); } },
          t('show_all', group(groups.length))) : null));
    }
    return hits.length;
  }

  function renderFindings() {
    var total = 0;
    SECTIONS.forEach(function (s) { total += renderChapter(s) || 0; });
    var status = doc.getElementById('fstatus');
    if (status) status.textContent = t('showing', group(total), group(R.findings.length));
    var reset = doc.getElementById('freset');
    if (reset) reset.hidden = !filtersActive();
    var attention = doc.getElementById('attention');
    if (attention) attention.hidden = state.chapter !== 'all';
    var none = doc.getElementById('fnone');
    if (none) none.hidden = total > 0 || R.findings.length === 0;
    SEVERITIES.concat(CONFIDENCES).forEach(function (key) {
      var chip = doc.getElementById('chip-' + key);
      if (chip) chip.setAttribute('aria-pressed', String(!!(state.severity[key] || state.confidence[key])));
    });
  }

  function resetFilters() {
    SEVERITIES.forEach(function (s) { state.severity[s] = true; });
    CONFIDENCES.forEach(function (c) { state.confidence[c] = true; });
    state.chapter = 'all';
    state.query = '';
    state.shown = {};
    var input = doc.getElementById('fsearch');
    if (input) input.value = '';
    var select = doc.getElementById('fchapter');
    if (select) select.value = 'all';
  }

  function only(kind, key) {
    resetFilters();
    (kind === 'severity' ? SEVERITIES : CONFIDENCES).forEach(function (k) { state[kind][k] = k === key; });
    renderFindings();
    jump('findings');
  }

  function jump(id) {
    var node = doc.getElementById(id);
    if (node) node.scrollIntoView();
  }

  function revealFinding(index) {
    var f = R.findings[index];
    resetFilters();
    state.shown[f.section] = Infinity;
    renderFindings();
    var card = doc.getElementById('f-' + index);
    if (!card) {
      var cards = doc.querySelectorAll('#ch-' + f.section + ' .group');
      for (var i = 0; i < cards.length && !card; i++) {
        if (cards[i].getAttribute('data-rule') === f.rule && cards[i].reveal) card = cards[i].reveal(index);
      }
    }
    if (!card) return;
    if (card.tagName === 'DETAILS') card.open = true;
    else card.setAttribute('tabindex', '-1');
    card.scrollIntoView({ block: 'center' });
    (card.tagName === 'DETAILS' ? card.querySelector('summary') : card).focus({ preventScroll: true });
    card.classList.add('flash');
    setTimeout(function () { card.classList.remove('flash'); }, 1600);
  }

  function filterBar() {
    var timer = 0;
    function chip(kind, key, count) {
      return el('button', {
        type: 'button', class: 'chip ' + (kind === 'severity' ? 'sev-' : 'conf-') + key, id: 'chip-' + key, 'aria-pressed': 'true',
        onclick: function () { state[kind][key] = !state[kind][key]; state.shown = {}; renderFindings(); }
      }, el('span', { class: 'mark', 'aria-hidden': 'true' }, (kind === 'severity' ? SEVERITY_MARK : CONFIDENCE_MARK)[key]),
      kind === 'severity' ? severityName(key) : confidenceName(key), el('span', { class: 'n' }, group(count)));
    }
    function count(field, key) { return R.findings.filter(function (f) { return f[field] === key; }).length; }
    var select = el('select', {
      id: 'fchapter', 'aria-label': t('chapter'),
      onchange: function () { state.chapter = select.value; state.shown = {}; renderFindings(); }
    }, el('option', { value: 'all' }, t('all_chapters')), SECTIONS.map(function (s, i) {
      return el('option', { value: s }, (i + 1) + '  ' + sectionName(s) + ' (' + bySection[s].length + ')');
    }));
    select.value = state.chapter;
    var input = el('input', {
      type: 'search', id: 'fsearch', placeholder: t('search_findings'), 'aria-label': t('search_findings'),
      autocomplete: 'off', spellcheck: 'false',
      oninput: function () {
        clearTimeout(timer);
        timer = setTimeout(function () { state.query = input.value.trim(); state.shown = {}; renderFindings(); }, 120);
      }
    });
    input.value = state.query;
    return el('div', { class: 'filters', role: 'search', 'aria-label': t('filters') },
      el('div', { class: 'frow' }, input, select),
      el('div', { class: 'frow' },
        el('div', { class: 'chips', role: 'group', 'aria-label': t('severity') },
          el('span', { class: 'k' }, t('severity')), SEVERITIES.map(function (s) { return chip('severity', s, count('severity', s)); })),
        el('div', { class: 'chips', role: 'group', 'aria-label': t('confidence') },
          el('span', { class: 'k' }, t('confidence')), CONFIDENCES.map(function (c) { return chip('confidence', c, count('confidence', c)); }))),
      el('div', { class: 'frow fstatus' },
        el('span', { id: 'fstatus', role: 'status', 'aria-live': 'polite' }),
        el('button', { type: 'button', class: 'link', id: 'freset', hidden: true, onclick: function () { resetFilters(); renderFindings(); } }, t('reset'))));
  }

  /* ---------- file tree ---------- */

  var root = null; // node: {name, parent, kids: Map|Array|null, art, depth, open, size, files, hits}
  var nodes = []; // every node, parents before children
  var nodeOfArtifact = [];
  var flat = []; // the rows currently in the list, top to bottom
  var treeBox = null, treeRows = null, treePad = null, detailBox = null;

  function buildTree() {
    root = { name: '', parent: null, kids: new Map(), art: -1, depth: -1, open: true, size: 0, files: 0, hits: 0 };
    nodes = [root];
    R.artifacts.forEach(function (artifact, index) {
      var parts = artifact.path.split('/');
      var node = root;
      for (var i = 0; i < parts.length; i++) {
        if (!node.kids) node.kids = new Map();
        var kid = node.kids.get(parts[i]);
        if (!kid) {
          kid = { name: parts[i], parent: node, kids: null, art: -1, depth: node.depth + 1, open: false, size: 0, files: 0, hits: 0 };
          node.kids.set(parts[i], kid);
          nodes.push(kid);
        }
        node = kid;
      }
      node.art = index;
      nodeOfArtifact[index] = node;
    });
    // Children were created after their parents, so one pass from the end sums every subtree.
    for (var i = nodes.length - 1; i > 0; i--) {
      var node = nodes[i];
      if (node.art >= 0) {
        var artifact = R.artifacts[node.art];
        node.size += artifact.size;
        node.files += 1;
        node.hits += (byArtifact.get(artifact.path) || []).length;
      }
      node.parent.size += node.size;
      node.parent.files += node.files;
      node.parent.hits += node.hits;
    }
    // Open the top of the tree as far as it does not branch, plus one level.
    var node = root;
    while (kidsOf(node).length === 1) { node = kidsOf(node)[0]; node.open = true; }
    kidsOf(node).forEach(function (kid) { if (kidsOf(kid).length && kidsOf(node).length <= 3) kid.open = true; });
  }

  function kidsOf(node) {
    if (!node.kids) return [];
    if (!Array.isArray(node.kids)) {
      var list = Array.from(node.kids.values());
      list.sort(function (a, b) {
        var fa = a.kids ? 0 : 1, fb = b.kids ? 0 : 1;
        return fa - fb || (a.name < b.name ? -1 : a.name > b.name ? 1 : 0);
      });
      node.kids = list;
    }
    return node.kids;
  }

  function pathOf(node) {
    var parts = [];
    for (var n = node; n && n.parent; n = n.parent) parts.push(n.name);
    return parts.reverse().join('/');
  }

  function flatten() {
    flat = [];
    var query = state.treeQuery.toLowerCase();
    if (query) {
      for (var i = 0; i < R.artifacts.length; i++) {
        var node = nodeOfArtifact[i];
        if (state.treeFindingsOnly && !byArtifact.has(R.artifacts[i].path)) continue;
        if (R.artifacts[i].path.toLowerCase().indexOf(query) >= 0) flat.push(node);
      }
      return;
    }
    var stack = kidsOf(root).slice().reverse();
    while (stack.length) {
      var n = stack.pop();
      if (state.treeFindingsOnly && !n.hits) continue;
      flat.push(n);
      if (n.open && n.kids) {
        var kids = kidsOf(n);
        for (var k = kids.length - 1; k >= 0; k--) stack.push(kids[k]);
      }
    }
  }

  function rowNode(node, index) {
    var searching = state.treeQuery !== '';
    var artifact = node.art >= 0 ? R.artifacts[node.art] : null;
    var row = el('div', {
      class: 'row' + (node === state.selected ? ' sel' : '') + (index === state.cursor ? ' cur' : ''),
      role: 'treeitem', id: 'row-' + index, 'data-i': index,
      'aria-level': searching ? 1 : node.depth + 1, 'aria-selected': node === state.selected ? 'true' : 'false',
      'aria-expanded': node.kids && !searching ? String(!!node.open) : null
    },
      el('span', { class: 'tw' + (node.kids && !searching ? ' has' : '') + (node.open ? ' open' : ''), 'aria-hidden': 'true' }),
      el('span', { class: 'nm' + (node.kids ? ' dir' : '') }, searching ? pathOf(node) : (node.name === '' ? '/' : node.name)),
      artifact && artifact.kind ? el('span', { class: 'kd' }, artifact.kind) : null,
      artifact && artifact.unpacked_by ? el('span', { class: 'kd', title: t('unpacked_by_note', artifact.unpacked_by) }, '⇲ ' + artifact.unpacked_by) : null,
      node.hits ? el('span', { class: 'hc', title: t('findings_citing') }, group(node.hits)) : null,
      el('span', { class: 'sz' }, bytes(artifact ? artifact.size : node.size)));
    row.style.paddingLeft = (8 + (searching ? 0 : Math.min(node.depth, 24) * 14)) + 'px';
    return row;
  }

  var windowStart = -1, windowEnd = -1;
  function drawRows(force) {
    if (!treeBox) return;
    if (force) treePad.style.height = (flat.length * ROW) + 'px';
    var start = Math.max(0, Math.floor(treeBox.scrollTop / ROW) - 8);
    var end = Math.min(flat.length, start + Math.ceil(treeBox.clientHeight / ROW) + 16);
    if (!force && start === windowStart && end === windowEnd) return;
    windowStart = start; windowEnd = end;
    treeRows.style.transform = 'translateY(' + (start * ROW) + 'px)';
    clear(treeRows);
    var fragment = doc.createDocumentFragment();
    for (var i = start; i < end; i++) fragment.appendChild(rowNode(flat[i], i));
    treeRows.appendChild(fragment);
    treeBox.setAttribute('aria-activedescendant', flat.length ? 'row-' + state.cursor : '');
    var empty = doc.getElementById('tree-empty');
    if (empty) empty.hidden = flat.length > 0;
  }

  function refreshTree(keepNode) {
    flatten();
    var status = doc.getElementById('tree-status');
    if (status) {
      var filtered = state.treeQuery !== '' || state.treeFindingsOnly;
      var files = filtered ? flat.filter(function (n) { return n.art >= 0; }).length : R.artifacts.length;
      status.textContent = t('files_count', group(files)) + (filtered ? ' / ' + group(R.artifacts.length) : '');
    }
    var at = keepNode ? flat.indexOf(keepNode) : -1;
    state.cursor = at >= 0 ? at : Math.min(state.cursor, Math.max(0, flat.length - 1));
    drawRows(true);
  }

  function showCursor() {
    var top = state.cursor * ROW;
    if (top < treeBox.scrollTop) treeBox.scrollTop = top;
    else if (top + ROW > treeBox.scrollTop + treeBox.clientHeight) treeBox.scrollTop = top + ROW - treeBox.clientHeight;
    drawRows(true);
  }

  function select(node) {
    state.selected = node;
    drawRows(true);
    renderDetail();
  }

  function toggle(node, open) {
    if (!node.kids || state.treeQuery) return;
    node.open = open == null ? !node.open : open;
    refreshTree(node);
  }

  function treeKey(event) {
    var node = flat[state.cursor];
    var page = Math.max(1, Math.floor(treeBox.clientHeight / ROW) - 1);
    var move = null;
    switch (event.key) {
      case 'ArrowDown': move = state.cursor + 1; break;
      case 'ArrowUp': move = state.cursor - 1; break;
      case 'PageDown': move = state.cursor + page; break;
      case 'PageUp': move = state.cursor - page; break;
      case 'Home': move = 0; break;
      case 'End': move = flat.length - 1; break;
      case 'ArrowRight':
        if (node && node.kids && !node.open) toggle(node, true);
        else if (node && node.kids) move = state.cursor + 1;
        break;
      case 'ArrowLeft':
        if (node && node.kids && node.open && !state.treeQuery) toggle(node, false);
        else if (node && node.parent && node.parent !== root) move = flat.indexOf(node.parent);
        break;
      case 'Enter':
      case ' ':
        if (node) { select(node); if (node.art < 0) toggle(node); }
        break;
      default: return;
    }
    event.preventDefault();
    if (move != null && flat.length) {
      state.cursor = Math.max(0, Math.min(flat.length - 1, move));
      showCursor();
    }
  }

  function treeClick(event) {
    var row = event.target.closest ? event.target.closest('.row') : null;
    if (!row) return;
    var index = Number(row.getAttribute('data-i'));
    var node = flat[index];
    if (!node) return;
    state.cursor = index;
    var onTwisty = event.target.classList.contains('tw');
    if (node.kids && (onTwisty || node.art < 0)) {
      state.selected = node;
      toggle(node);
      renderDetail();
    } else {
      select(node);
      // On a narrow screen the details sit below the tree; bring them into view.
      if (detailBox.offsetTop > treeBox.offsetTop + treeBox.offsetHeight / 2) detailBox.scrollIntoView({ block: 'nearest' });
    }
  }

  function revealArtifact(path) {
    var index = artifactIndex.get(path);
    if (index == null || !treeBox) return;
    var node = nodeOfArtifact[index];
    state.treeQuery = '';
    state.treeFindingsOnly = false;
    var input = doc.getElementById('tsearch');
    if (input) input.value = '';
    var box = doc.getElementById('tonly');
    if (box) box.checked = false;
    for (var n = node.parent; n && n !== root; n = n.parent) n.open = true;
    state.selected = node;
    refreshTree(node);
    jump('files');
    treeBox.scrollTop = Math.max(0, state.cursor * ROW - treeBox.clientHeight / 2);
    drawRows(true);
    renderDetail();
    var title = detailBox.querySelector('h4');
    if (title) title.focus({ preventScroll: true });
  }

  function field(label, value, mono, copyText) {
    if (value == null || value === '') return null;
    return [el('dt', null, label), el('dd', { class: mono ? 'mono' : null }, value, copyText ? copyButton(copyText, label) : null)];
  }

  function renderDetail() {
    if (!detailBox) return;
    clear(detailBox);
    var node = state.selected;
    if (!node) { detailBox.appendChild(el('p', { class: 'none' }, t('select_file'))); return; }
    var path = pathOf(node);
    var artifact = node.art >= 0 ? R.artifacts[node.art] : null;
    add(detailBox, el('h4', { tabindex: '-1', class: 'dpath' }, path === '' ? '/' : path, copyButton(path, t('path'))));
    if (!artifact) {
      add(detailBox, el('dl', { class: 'kv' },
        field(t('kind'), t('folder')), field(t('files_inside'), group(node.files)),
        field(t('total_size'), bytes(node.size) + ' (' + group(node.size) + ' ' + t('bytes') + ')'),
        node.hits ? field(t('findings_title'), group(node.hits)) : null));
      return;
    }
    var entropy = artifact.entropy == null ? null : el('span', { class: 'entropy' },
      el('span', { class: 'bar', 'aria-hidden': 'true' }, (function () {
        var fill = el('span', null);
        fill.style.width = Math.max(0, Math.min(100, artifact.entropy / 8 * 100)) + '%';
        return fill;
      })()), artifact.entropy.toFixed(4) + ' / 8');
    add(detailBox, el('dl', { class: 'kv' },
      field(t('file_size'), bytes(artifact.size) + (artifact.size >= 1024 ? ' (' + group(artifact.size) + ' ' + t('bytes') + ')' : '')),
      field(t('kind'), artifact.kind || (node.kids ? null : t('unknown'))),
      field(t('mime'), artifact.detected ? artifact.detected.mime : t('unknown')),
      field(t('usual_extension'), artifact.detected && artifact.detected.usual_extension),
      field(t('entropy'), entropy || t('unknown')),
      field(t('unpacked_by'), artifact.unpacked_by),
      node.kids ? field(t('files_inside'), group(node.files - 1)) : null,
      artifact.parent != null ? field(t('parent_container'), pathNode(artifact.parent)) : null,
      artifact.digests ? [field('SHA-256', artifact.digests.sha256, true, artifact.digests.sha256),
        field('SHA-1', artifact.digests.sha1, true, artifact.digests.sha1),
        field('MD5', artifact.digests.md5, true, artifact.digests.md5)] : field(t('digests'), t('unknown'))));
    var cited = byArtifact.get(artifact.path) || [];
    add(detailBox, el('h5', null, t('findings_citing') + ' (' + group(cited.length) + ')'));
    if (!cited.length) add(detailBox, el('p', { class: 'none' }, t('no_findings_citing')));
    else {
      var host = el('div', { class: 'cited' });
      var shown = 0;
      (function more() {
        var old = host.querySelector(':scope > .pager');
        if (old) old.remove();
        var end = Math.min(cited.length, shown + 20);
        for (; shown < end; shown++) host.appendChild(findingCard(cited[shown], true));
        if (shown < cited.length) host.appendChild(el('div', { class: 'pager' },
          el('button', { type: 'button', class: 'btn', onclick: more }, t('show_more', Math.min(20, cited.length - shown)))));
      })();
      add(detailBox, host);
    }
    var factKeys = Object.keys(artifact.facts || {});
    add(detailBox, el('h5', null, t('facts') + ' (' + factKeys.length + ')'));
    add(detailBox, factKeys.length ? factsView(artifact.facts, 'a' + node.art) : el('p', { class: 'none' }, t('no_facts')));
  }

  function filesSection() {
    var timer = 0;
    var input = el('input', {
      type: 'search', id: 'tsearch', placeholder: t('filter_files'), 'aria-label': t('filter_files'), autocomplete: 'off', spellcheck: 'false',
      oninput: function () {
        clearTimeout(timer);
        timer = setTimeout(function () { state.treeQuery = input.value.trim(); state.cursor = 0; treeBox.scrollTop = 0; refreshTree(null); }, 120);
      }
    });
    input.value = state.treeQuery;
    var onlyBox = el('input', {
      type: 'checkbox', id: 'tonly',
      onchange: function () { state.treeFindingsOnly = onlyBox.checked; state.cursor = 0; treeBox.scrollTop = 0; refreshTree(null); }
    });
    onlyBox.checked = state.treeFindingsOnly;
    function setAll(open) {
      for (var i = 1; i < nodes.length; i++) if (nodes[i].kids) nodes[i].open = open;
      state.cursor = 0;
      treeBox.scrollTop = 0;
      refreshTree(null);
    }
    treeRows = el('div', { class: 'rows' });
    treePad = el('div', { class: 'pad' }, treeRows);
    treeBox = el('div', {
      class: 'tree', role: 'tree', tabindex: '0', 'aria-label': t('file_tree'),
      onkeydown: treeKey, onclick: treeClick,
      onscroll: function () { requestAnimationFrame(function () { drawRows(false); }); }
    }, treePad);
    detailBox = el('div', { class: 'detail', id: 'detail', 'aria-live': 'polite' });
    return el('section', { id: 'files', class: 'block' },
      el('h2', null, t('inventory'), el('span', { class: 'count' }, group(R.artifacts.length))),
      el('div', { class: 'ttools noprint' }, input,
        el('label', { class: 'check' }, onlyBox, t('with_findings_only')),
        el('button', { type: 'button', class: 'btn', onclick: function () { setAll(true); } }, t('expand_all')),
        el('button', { type: 'button', class: 'btn', onclick: function () { setAll(false); } }, t('collapse_all')),
        el('span', { id: 'tree-status', class: 'muted', role: 'status', 'aria-live': 'polite' })),
      el('div', { class: 'files noprint' },
        el('div', { class: 'treewrap' }, treeBox, el('p', { class: 'none', id: 'tree-empty', hidden: true }, t('no_files_match'))),
        detailBox),
      el('div', { id: 'print-inventory', class: 'printonly' }));
  }

  /* ---------- summary, coverage, page frame ---------- */

  function meter(part, whole) {
    var fill = el('span', null);
    fill.style.width = (whole > 0 ? Math.max(part > 0 ? 2 : 0, Math.round(part / whole * 100)) : 0) + '%';
    return el('span', { class: 'bar', 'aria-hidden': 'true' }, fill);
  }

  function summarySection() {
    var w = V.words[lang];
    var limitations = R.limitations.length;
    // "Partial" is for content that was skipped or unreadable; limitations alone are notes on scope.
    var cut = R.coverage.truncated || R.coverage.content_lost > 0 || R.coverage.artifacts_analyzed < R.coverage.artifacts_total;
    var partial = cut || limitations > 0;
    var sha = R.input.sha256;
    var rootArtifact = R.input.kind === 'file' ? R.artifacts[artifactIndex.get(R.input.name)] : null;
    var overview = bySection.overview.slice(0, 4);
    function levelRows(kind, keys, field) {
      return el('ul', { class: 'levels' }, keys.map(function (key) {
        var count = R.findings.filter(function (f) { return f[field] === key; }).length;
        return el('li', null, el('button', {
          type: 'button', class: 'level ' + (kind === 'severity' ? 'sev-' : 'conf-') + key, disabled: count === 0,
          onclick: function () { only(kind, key); }
        }, el('span', { class: 'mark', 'aria-hidden': 'true' }, (kind === 'severity' ? SEVERITY_MARK : CONFIDENCE_MARK)[key]),
        el('span', { class: 'lname' }, kind === 'severity' ? severityName(key) : confidenceName(key)),
        meter(count, R.findings.length), el('span', { class: 'n' }, group(count))));
      }));
    }
    return el('section', { id: 'summary', class: 'block' },
      el('p', { class: 'eyebrow' }, w.title),
      el('h1', null, R.input.name),
      el('dl', { class: 'kv head' },
        field(w.tool, R.tool.name + ' ' + R.tool.version),
        field(w.input_sha256, sha || (R.input.kind === 'directory' ? w.not_applicable : w.unknown), !!sha, sha)),
      partial ? el('div', { class: 'banner', role: 'note' },
        el('strong', null, el('span', { 'aria-hidden': 'true' }, '◆ '), t(cut ? 'partial_title' : 'limits_title')),
        R.coverage.truncated ? el('span', null, w.truncated) : null,
        el('span', null, t('files_analyzed') + ' ' + group(R.coverage.artifacts_analyzed) + ' / ' + group(R.coverage.artifacts_total)),
        limitations ? el('span', null, t('limitations_recorded', group(limitations))) : null,
        el('a', { href: '#coverage' }, t('see_coverage'))) : null,
      el('div', { class: 'cards' },
        el('div', { class: 'card' }, el('h3', null, t('what_it_is')),
          el('dl', { class: 'kv' },
            field(w.input, w.input_kinds[R.input.kind] || R.input.kind),
            rootArtifact ? [field(w.kind, rootArtifact.kind || (rootArtifact.detected && rootArtifact.detected.mime)),
              field(t('file_size'), bytes(rootArtifact.size))] : null,
            field(t('files_total'), group(R.coverage.artifacts_total))),
          overview.length ? el('ul', { class: 'plain' }, overview.map(function (i) { return el('li', null, textOf(i)); })) : null),
        el('div', { class: 'card' }, el('h3', null, w.findings, el('span', { class: 'count' }, group(R.findings.length))),
          el('p', { class: 'k' }, w.by_severity), levelRows('severity', SEVERITIES, 'severity')),
        el('div', { class: 'card' }, el('h3', null, t('by_confidence')), levelRows('confidence', CONFIDENCES, 'confidence')),
        el('div', { class: 'card' }, el('h3', null, t('coverage_short')),
          el('dl', { class: 'kv' },
            field(t('files_analyzed'), [group(R.coverage.artifacts_analyzed) + ' / ' + group(R.coverage.artifacts_total),
              meter(R.coverage.artifacts_analyzed, R.coverage.artifacts_total)]),
            field(w.containers, group(R.coverage.containers_unpacked)),
            field(w.bytes_read, [bytes(R.coverage.bytes_analyzed) + ' ', el('span', { class: 'exact' }, group(R.coverage.bytes_analyzed) + ' ' + t('bytes'))])))),
      el('div', { class: 'guide' }, el('h3', null, w.reading_guide), el('p', null, w.reading_guide_text), el('p', null, t('grouping_guide_html'))),
      Object.keys(R.summary).length ? el('details', { class: 'sumfacts', id: 'summary-facts' },
        el('summary', null, t('summary_facts'), el('span', { class: 'count' }, Object.keys(R.summary).length)),
        el('p', { class: 'muted' }, t('summary_facts_note')), factsView(R.summary, 's')) : null);
  }

  // Every finding above "info", whatever the filters say, grouped like the chapters.
  function attentionSection() {
    var indices = [];
    R.findings.forEach(function (f, i) { if (f.severity !== 'info') indices.push(i); });
    indices.sort(function (a, b) { return RANK[R.findings[a].severity] - RANK[R.findings[b].severity] || a - b; });
    var groups = groupsOf(indices);
    return el('section', { id: 'attention', class: 'chapter' },
      el('h3', null, el('span', { class: 'num', 'aria-hidden': 'true' }, '!'), t('attention'), indices.length ? el('span', { class: 'count' }, t('chapter_counts', group(groups.length), group(indices.length))) : null),
      el('p', { class: indices.length ? 'muted lead' : 'none' }, t(indices.length ? 'attention_text' : 'attention_none')),
      groups.map(function (g) { return entryNode(g, true); }));
  }

  function coverageSection() {
    var w = V.words[lang];
    var codes = [];
    var groups = {};
    R.limitations.forEach(function (l) {
      if (!groups[' ' + l.code]) { groups[' ' + l.code] = []; codes.push(l.code); }
      groups[' ' + l.code].push(l);
    });
    codes.sort();
    return el('section', { id: 'coverage', class: 'block' },
      el('h2', null, w.coverage, el('span', { class: 'count' }, group(R.limitations.length))),
      el('p', { class: R.coverage.truncated ? 'banner' : null }, R.coverage.truncated ? w.truncated : w.complete),
      R.limitations.length ? null : el('p', { class: 'none' }, w.no_limitations),
      codes.map(function (code) {
        var list = groups[' ' + code];
        var host = el('ul', { class: 'lims' });
        var shown = 0;
        function more(all) {
          var old = host.querySelector(':scope > li.more');
          if (old) old.remove();
          var end = all ? list.length : Math.min(list.length, shown + 30);
          for (; shown < end; shown++) {
            var l = list[shown];
            host.appendChild(el('li', null, l.artifact != null ? pathNode(l.artifact) : el('span', null, w.whole_run),
              l.detail ? el('span', { class: 'muted' }, ' — ' + l.detail) : null));
          }
          if (shown < list.length) host.appendChild(el('li', { class: 'more' },
            el('button', { type: 'button', class: 'link', onclick: function () { more(false); } }, t('show_more', Math.min(30, list.length - shown))), ' ',
            el('button', { type: 'button', class: 'link', onclick: function () { more(true); } }, t('show_all', group(list.length)))));
        }
        more(false);
        host.expand = function () { more(true); };
        return el('div', { class: 'lim' },
          el('h3', null, titleOf(code), el('span', { class: 'count' }, group(list.length)), el('code', { class: 'muted' }, code)),
          ruleText(code) ? el('p', null, ruleText(code)) : null, host);
      }));
  }

  function navigation() {
    function item(href, label, count, id) {
      return el('li', null, el('a', { href: '#' + href, id: id }, el('span', { class: 'l' }, label),
        count == null ? null : el('span', { class: 'n' }, group(count))));
    }
    return el('nav', { class: 'side noprint', id: 'nav', 'aria-label': t('navigation') },
      el('ul', null,
        item('summary', V.words[lang].summary),
        el('li', { class: 'sep', role: 'presentation' }, t('chapters')),
        SECTIONS.map(function (s, i) {
          var entry = item('ch-' + s, [el('span', { class: 'num' }, i + 1), sectionName(s)], bySection[s].length, 'nav-' + s);
          return s !== 'overview' ? entry : [entry, item('attention', [el('span', { class: 'num' }, '!'), t('attention')],
            R.findings.filter(function (f) { return f.severity !== 'info'; }).length)];
        }),
        el('li', { class: 'sep', role: 'presentation' }),
        item('files', V.words[lang].inventory, R.artifacts.length),
        item('coverage', V.words[lang].coverage, R.limitations.length)));
  }

  function setTheme(next) {
    var rootNode = doc.documentElement;
    var dark = next != null ? next === 'dark'
      : !(rootNode.getAttribute('data-theme') === 'dark' ||
          (!rootNode.getAttribute('data-theme') && window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches));
    rootNode.setAttribute('data-theme', dark ? 'dark' : 'light');
    var button = doc.getElementById('theme');
    if (button) button.textContent = dark ? '☀ ' + t('theme_light') : '☾ ' + t('theme_dark');
  }

  function topBar() {
    function langButton(code, label) {
      return el('button', {
        type: 'button', class: 'seg', 'aria-pressed': String(lang === code), lang: code,
        onclick: function () { if (lang !== code) { lang = code; render(); } }
      }, label);
    }
    var rootNode = doc.documentElement;
    var dark = rootNode.getAttribute('data-theme') === 'dark' ||
      (!rootNode.getAttribute('data-theme') && window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches);
    return el('header', { class: 'top noprint' },
      el('a', { class: 'skip', href: '#main' }, t('skip')),
      el('div', { class: 'brand' }, el('span', { class: 'eyebrow' }, V.words[lang].title), el('span', { class: 'name' }, R.input.name)),
      el('div', { class: 'tools' },
        el('div', { class: 'segs', role: 'group', 'aria-label': t('language') }, langButton('zh', '中文'), langButton('en', 'English')),
        el('button', { type: 'button', class: 'btn', id: 'theme', 'aria-label': t('theme'), onclick: function () { setTheme(); } },
          dark ? '☀ ' + t('theme_light') : '☾ ' + t('theme_dark')),
        el('button', { type: 'button', class: 'btn', onclick: function () { window.print(); } }, t('print'))));
  }

  /* ---------- print ---------- */

  // Printing shows everything that matches the current filters, with the evidence opened, and a
  // plain table of the first files in place of the interactive tree.
  function preparePrint() {
    SECTIONS.forEach(function (s) {
      if (matching(s).length > (state.shown[s] || PAGE)) { state.shown[s] = Infinity; renderChapter(s); }
    });
    var open = doc.querySelectorAll('#findings details.evidence:not([open])');
    for (var i = 0; i < open.length; i++) {
      var list = open[i].querySelector('.evlist');
      if (!list.children.length) fillEvidence(list, Number(open[i].parentNode.getAttribute('data-index')), false);
      open[i].open = true;
    }
    var lims = doc.querySelectorAll('#coverage .lims');
    for (var j = 0; j < lims.length; j++) if (lims[j].expand) lims[j].expand();
    var facts = doc.getElementById('summary-facts');
    if (facts) facts.open = true;
    var host = doc.getElementById('print-inventory');
    if (!host || host.firstChild) return;
    var w = V.words[lang];
    var rows = R.artifacts.slice(0, V.inventory_rows);
    add(host, el('table', { class: 'inv' },
      el('thead', null, el('tr', null, [w.path, w.size, w.kind, w.entropy, 'SHA-256'].map(function (h) { return el('th', null, h); }))),
      el('tbody', null, rows.map(function (a) {
        var kind = a.kind && a.detected ? a.kind + ' (' + a.detected.mime + ')' : a.kind || (a.detected ? a.detected.mime : w.unknown);
        if (a.unpacked_by) kind += ' · ' + t('unpacked_by_note', a.unpacked_by);
        return el('tr', null, el('td', null, a.path), el('td', { class: 'num' }, group(a.size)), el('td', null, kind),
          el('td', { class: 'num' }, a.entropy == null ? w.unknown : a.entropy.toFixed(4)),
          el('td', { class: 'mono' }, a.digests ? a.digests.sha256 : w.unknown));
      }))));
    if (R.artifacts.length > rows.length) add(host, el('p', { class: 'muted' }, t('print_inventory_note', group(rows.length), group(R.artifacts.length))));
  }

  /* ---------- whole page ---------- */

  // Height of what stays stuck to the top of the window over the findings: the filter bar on
  // wide screens. Anchors and the navigation leave that much room.
  var stuck = 0;
  function measure() {
    var bar = doc.querySelector('.sticky');
    stuck = bar && getComputedStyle(bar).position === 'sticky' ? bar.offsetHeight : 0;
    doc.documentElement.style.setProperty('--stuck', stuck + 'px');
  }

  function markCurrent() {
    var links = doc.querySelectorAll('#nav a');
    var current = null;
    var line = 120 + stuck;
    for (var i = 0; i < links.length; i++) {
      var target = doc.getElementById(links[i].getAttribute('href').slice(1));
      if (target && !target.hidden && target.getBoundingClientRect().top <= line) current = links[i];
    }
    for (var j = 0; j < links.length; j++) {
      if (links[j] === current) links[j].setAttribute('aria-current', 'true');
      else links[j].removeAttribute('aria-current');
    }
    // As a horizontal strip (narrow screens) the navigation follows the reader.
    var nav = doc.getElementById('nav');
    if (current && nav && nav.scrollWidth > nav.clientWidth) nav.scrollLeft = current.offsetLeft - nav.clientWidth / 3;
  }

  function render() {
    var app = doc.getElementById('app');
    var scroll = window.scrollY;
    doc.documentElement.lang = lang === 'zh' ? 'zh-CN' : 'en';
    doc.title = V.words[lang].title + ': ' + vis(R.input.name);
    clear(app);
    add(app, [
      topBar(),
      el('div', { class: 'layout' },
        navigation(),
        el('main', { id: 'main', tabindex: '-1' },
          summarySection(),
          el('section', { id: 'findings', class: 'block' },
            el('h2', null, t('findings_title'), el('span', { class: 'count' }, group(R.findings.length))),
            el('div', { class: 'noprint sticky' }, filterBar()),
            el('p', { class: 'none', id: 'fnone', hidden: true }, t('no_match')),
            SECTIONS.map(function (s, i) {
              var chapter = el('section', { class: 'chapter', id: 'ch-' + s },
                el('h3', null, el('span', { class: 'num' }, i + 1), sectionName(s), el('span', { class: 'count' })),
                el('div', { class: 'chbody' }));
              // The overview opens the report; what needs attention follows it directly.
              return s === 'overview' ? [chapter, attentionSection()] : chapter;
            })),
          filesSection(),
          coverageSection(),
          el('footer', { class: 'foot' }, R.tool.name + ' ' + R.tool.version + ' · report.json schema ' + R.schema_version))),
      el('div', { id: 'toast', class: 'toast', role: 'status', 'aria-live': 'polite' })
    ]);
    renderFindings();
    refreshTree(state.selected);
    renderDetail();
    measure();
    window.scrollTo(0, scroll);
    markCurrent();
  }

  function start() {
    R = JSON.parse(doc.getElementById('report-data').textContent);
    V = JSON.parse(doc.getElementById('view-data').textContent);
    lang = V.lang === 'en' ? 'en' : 'zh';
    prepare();
    buildTree();
    // The static copy goes first: the page must never show the report twice.
    var fallback = doc.getElementById('static');
    if (fallback) fallback.hidden = true;
    doc.getElementById('app').hidden = false;
    render();
    if (fallback) fallback.parentNode.removeChild(fallback);
    var ticking = false;
    window.addEventListener('scroll', function () {
      if (ticking) return;
      ticking = true;
      requestAnimationFrame(function () { ticking = false; markCurrent(); });
    }, { passive: true });
    window.addEventListener('resize', function () { drawRows(true); measure(); });
    window.addEventListener('beforeprint', preparePrint);
    if (window.matchMedia) {
      var media = window.matchMedia('print');
      var onPrint = function (event) { if (event.matches) preparePrint(); };
      if (media.addEventListener) media.addEventListener('change', onPrint);
      else if (media.addListener) media.addListener(onPrint);
    }
  }

  try {
    start();
  } catch (error) {
    // The static copy of the report stays on the page; say why the interactive one is missing.
    var app = doc.getElementById('app');
    if (app) app.hidden = true;
    var fallback = doc.getElementById('static');
    if (fallback) fallback.hidden = false;
    var note = doc.getElementById('script-failed');
    if (note) note.hidden = false;
    if (window.console && console.error) console.error(error);
  }
})();
