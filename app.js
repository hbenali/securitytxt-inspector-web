/* security.txt Validator: validates a pasted security.txt against RFC 9116 and generates one.
   Makes no network call (CSP connect-src 'none'). No dependencies, no inline code (CSP: script-src 'self'). */
(function () {
  'use strict';

  var $ = function (id) { return document.getElementById(id); };
  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = text;
    return e;
  }

  // ---- RFC 9116 field table ----
  // multi: may appear more than once. uri: allowed schemes for the value.
  var FIELDS = {
    'contact': { name: 'Contact', multi: true, schemes: ['mailto', 'https', 'tel'] },
    'expires': { name: 'Expires', multi: false },
    'encryption': { name: 'Encryption', multi: true, schemes: ['https', 'dns', 'openpgp4fpr'] },
    'acknowledgments': { name: 'Acknowledgments', multi: true, schemes: ['https'] },
    'preferred-languages': { name: 'Preferred-Languages', multi: false },
    'canonical': { name: 'Canonical', multi: true, schemes: ['https'] },
    'policy': { name: 'Policy', multi: true, schemes: ['https'] },
    'hiring': { name: 'Hiring', multi: true, schemes: ['https'] },
    'csaf': { name: 'CSAF', multi: true, schemes: ['https'] }
  };
  var MISSPELLED = { 'acknowledgements': 'Acknowledgments', 'preferred-language': 'Preferred-Languages' };

  var ARMOR_BEGIN = '-----BEGIN PGP SIGNED MESSAGE-----';
  var SIG_BEGIN = '-----BEGIN PGP SIGNATURE-----';
  var SIG_END = '-----END PGP SIGNATURE-----';
  var MAX_INPUT = 200000;

  // ---- Value checks ----
  function schemeOf(v) {
    var m = /^([A-Za-z][A-Za-z0-9+.-]*):/.exec(v);
    return m ? m[1].toLowerCase() : null;
  }
  function validEmail(a) {
    return /^[^\s@<>,;:"]+@[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)+$/.test(a);
  }
  // Returns {level, text} problems for a URI-valued field, [] when fine.
  function checkUriValue(key, value) {
    var f = FIELDS[key], out = [];
    var sc = schemeOf(value);
    if (!sc) {
      if (validEmail(value)) out.push({ level: 'fail', text: f.name + ': "' + value + '" is a bare email address; it must be a URI, write mailto:' + value + '.' });
      else out.push({ level: 'fail', text: f.name + ': "' + value + '" is not a URI (no scheme such as https: or mailto:).' });
      return out;
    }
    if (f.schemes.indexOf(sc) < 0) {
      var why = sc === 'http' ? ' Web URIs must use https:, not http:.' : '';
      if (key === 'encryption' && sc === 'mailto') why = ' An Encryption value must point to a key, not be an email address.';
      out.push({ level: 'fail', text: f.name + ': scheme "' + sc + ':" is not allowed; use ' + f.schemes.map(function (s) { return s + ':'; }).join(', ') + '.' + why });
      return out;
    }
    if (sc === 'mailto') {
      var addr = value.slice(7).split('?')[0];
      try { addr = decodeURIComponent(addr); } catch (e) { /* keep raw */ }
      if (!validEmail(addr)) out.push({ level: 'fail', text: f.name + ': "' + value + '" does not hold a valid email address.' });
    } else if (sc === 'tel') {
      if (!/^tel:\+?[0-9][0-9().\-;=a-zA-Z]*$/.test(value) || value.replace(/\D/g, '').length < 5) out.push({ level: 'fail', text: f.name + ': "' + value + '" is not a valid tel: URI (expected like tel:+1-201-555-0123).' });
      else if (value.charAt(4) !== '+') out.push({ level: 'warn', text: f.name + ': tel: numbers should be in international format starting with +.' });
    } else if (sc === 'https') {
      var u;
      try { u = new URL(value); } catch (e2) { u = null; }
      if (!u || !u.hostname) out.push({ level: 'fail', text: f.name + ': "' + value + '" is not a valid https URL.' });
      else if (u.username || u.password) out.push({ level: 'warn', text: f.name + ': the URL embeds credentials; remove them.' });
    } else if (sc === 'dns') {
      if (!/^dns:[^\s]+$/.test(value)) out.push({ level: 'fail', text: f.name + ': "' + value + '" is not a valid dns: URI.' });
    } else if (sc === 'openpgp4fpr') {
      if (!/^openpgp4fpr:[0-9A-Fa-f]{40,64}$/.test(value)) out.push({ level: 'fail', text: f.name + ': "' + value + '" is not a valid openpgp4fpr: URI (a hex fingerprint is expected).' });
    }
    if (key === 'csaf' && sc === 'https' && !/provider-metadata\.json$/i.test(value.split(/[?#]/)[0])) out.push({ level: 'warn', text: 'CSAF: the URL should point to a provider-metadata.json file.' });
    return out;
  }

  function parseExpires(v) {
    var m = /^(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})(\.\d+)?([Zz]|[+-]\d{2}:\d{2})$/.exec(v);
    if (!m) return null;
    var Y = +m[1], M = +m[2], D = +m[3], h = +m[4], mi = +m[5], s = +m[6];
    if (M < 1 || M > 12 || D < 1 || h > 23 || mi > 59 || s > 60) return null;
    var dim = new Date(Date.UTC(Y, M, 0)).getUTCDate();
    if (D > dim) return null;
    var off = 0;
    if (m[8].toUpperCase() !== 'Z') {
      var oh = +m[8].slice(1, 3), om = +m[8].slice(4, 6);
      if (oh > 23 || om > 59) return null;
      off = (m[8].charAt(0) === '-' ? -1 : 1) * (oh * 60 + om) * 60000;
    }
    return new Date(Date.UTC(Y, M - 1, D, h, mi, Math.min(s, 59)) - off);
  }

  function validLangTag(t) {
    return /^[A-Za-z]{2,3}(-[A-Za-z0-9]{1,8})*$/.test(t) && !/-[A-Za-z0-9]{9,}/.test(t);
  }

  // ---- Parser + validator ----
  // opts: {domain, now}. Returns {rows, checks, signed, fields}.
  function validate(text, opts) {
    opts = opts || {};
    var now = opts.now || new Date();
    var checks = [];
    var add = function (level, t) { checks.push({ level: level, text: t }); };
    var rows = [];
    var fields = {};

    if (text.charCodeAt(0) === 0xFEFF) { add('warn', 'The text starts with a byte order mark (BOM). Save the file as UTF-8 without BOM.'); text = text.slice(1); }
    if (text.indexOf('�') >= 0) add('fail', 'The text contains replacement characters (U+FFFD): the file is not valid UTF-8 (RFC 9116 requires UTF-8).');
    if (/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/.test(text)) add('warn', 'The text contains control characters; remove them.');
    var lines = text.replace(/\r\n/g, '\n').replace(/\r/g, '\n').split('\n');
    if (lines.length && lines[lines.length - 1] === '') lines.pop();

    // OpenPGP clearsign wrapper
    var firstIdx = -1;
    for (var i = 0; i < lines.length; i++) { if (lines[i].trim() !== '') { firstIdx = i; break; } }
    var signed = firstIdx >= 0 && lines[firstIdx].trim() === ARMOR_BEGIN;
    var bodyStart = 0, bodyEnd = lines.length;
    if (signed) {
      var j = firstIdx + 1;
      while (j < lines.length && lines[j].trim() !== '') j++;   // armor headers (Hash: ...)
      bodyStart = j + 1;
      var sigAt = -1;
      for (var k = bodyStart; k < lines.length; k++) { if (lines[k].trim() === SIG_BEGIN) { sigAt = k; break; } }
      if (sigAt < 0) { add('fail', 'The clearsign wrapper has no "' + SIG_BEGIN + '" block.'); bodyEnd = lines.length; }
      else {
        bodyEnd = sigAt;
        var hasEnd = lines.slice(sigAt).some(function (l) { return l.trim() === SIG_END; });
        if (!hasEnd) add('fail', 'The signature block is not closed with "' + SIG_END + '".');
      }
      add('info', 'Signed with an OpenPGP clearsign wrapper (recommended by RFC 9116). The signature is NOT verified here: a browser page cannot check it without a key. Verify it with: gpg --verify security.txt');
      for (var p = 0; p < bodyStart; p++) rows.push({ n: p + 1, kind: 'armor', raw: lines[p] });
    } else if (text.indexOf(ARMOR_BEGIN) >= 0) {
      add('fail', 'The OpenPGP header "' + ARMOR_BEGIN + '" is not on the first line; the file must start with it.');
    }
    if (!signed) add('info', 'The file is not signed. RFC 9116 recommends an OpenPGP clearsign signature (gpg --clearsign).');

    var badLines = 0;
    for (var n = bodyStart; n < bodyEnd; n++) {
      var raw = lines[n];
      if (signed) raw = raw.replace(/^- /, '');                  // dash-escaping inside clearsigned text
      var t = raw.replace(/[ \t]+$/, '');
      if (t.trim() === '') { rows.push({ n: n + 1, kind: 'blank', raw: raw }); continue; }
      if (/^[ \t]*#/.test(t)) { rows.push({ n: n + 1, kind: 'comment', raw: raw }); continue; }
      var m = /^([^\s:]+):(.*)$/.exec(t);
      if (!m || !/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(m[1])) {
        badLines++;
        rows.push({ n: n + 1, kind: 'bad', raw: raw, issues: [{ level: 'fail', text: 'Not a comment, blank line or "Field: value" line.' }] });
        add('fail', 'Line ' + (n + 1) + ' is not a comment, a blank line or a "Field: value" line: ' + short(t));
        continue;
      }
      var name = m[1], key = name.toLowerCase(), rest = m[2];
      var value = rest.replace(/^ /, '').trim();
      var row = { n: n + 1, kind: 'field', raw: raw, name: name, value: value, issues: [] };
      var issue = function (level, msg) { row.issues.push({ level: level, text: msg }); add(level, 'Line ' + (n + 1) + ': ' + msg); };
      if (rest.charAt(0) !== ' ') issue('warn', 'there must be a space after the colon ("' + name + ': value").');
      if (value === '') issue('fail', name + ' has an empty value.');
      if (/[ \t]/.test(name)) issue('fail', 'whitespace before the colon.');

      var f = FIELDS[key];
      if (!f) {
        if (MISSPELLED[key]) issue('warn', 'unknown field "' + name + '"; did you mean ' + MISSPELLED[key] + '?');
        else issue('info', 'unknown field "' + name + '": allowed as an extension, but ignored by consumers that do not know it.');
      } else {
        if (name !== f.name) issue('info', 'field names are case-insensitive, canonical spelling is "' + f.name + '".');
        fields[key] = fields[key] || [];
        fields[key].push({ n: n + 1, value: value });
        if (value !== '') {
          if (f.schemes) checkUriValue(key, value).forEach(function (x) { issue(x.level, x.text); });
          if (key === 'expires') {
            var d = parseExpires(value);
            if (!d) issue('fail', 'Expires must be an ISO 8601 / RFC 3339 date-time such as 2027-12-31T23:59:59Z.');
            else row.date = d;
          }
          if (key === 'preferred-languages') {
            var tags = value.split(',').map(function (s) { return s.trim(); });
            var bad = tags.filter(function (s) { return !validLangTag(s); });
            if (bad.length) issue('fail', 'invalid language tag(s): ' + bad.map(function (s) { return s === '' ? '(empty)' : s; }).join(', ') + ' (RFC 5646 tags such as en or fr-CA, separated by commas).');
            if (new Set(tags.map(function (s) { return s.toLowerCase(); })).size !== tags.length) issue('warn', 'duplicate language tags.');
          }
        }
      }
      rows.push(row);
    }

    // Presence and cardinality
    var contacts = fields.contact || [];
    if (!contacts.length) add('fail', 'Contact is missing. At least one Contact field is required.');
    else {
      var cbad = false;
      rows.forEach(function (r) { if (r.kind === 'field' && r.name.toLowerCase() === 'contact' && r.issues.some(function (x) { return x.level === 'fail'; })) cbad = true; });
      if (!cbad) add('pass', contacts.length + ' Contact field(s), all valid URIs.');
      if (contacts.length > 1) add('info', 'Several Contact fields: RFC 9116 asks for them to be listed in order of preference.');
    }
    var exp = fields.expires || [];
    if (!exp.length) add('fail', 'Expires is missing. Exactly one Expires field is required.');
    else {
      if (exp.length > 1) add('fail', 'Expires appears ' + exp.length + ' times (lines ' + exp.map(function (x) { return x.n; }).join(', ') + '); it must appear exactly once.');
      var ed = parseExpires(exp[0].value);
      if (ed) {
        var ms = ed.getTime() - now.getTime();
        var oneYear = new Date(now.getTime()); oneYear.setUTCFullYear(oneYear.getUTCFullYear() + 1);
        if (ms <= 0) add('fail', 'Expires (' + ed.toISOString() + ') is in the past: the file is stale and must be treated as invalid.');
        else {
          if (ed.getTime() > oneYear.getTime()) add('warn', 'Expires (' + ed.toISOString() + ') is more than a year ahead. RFC 9116 recommends less than a year so the contact details get reviewed.');
          else add('pass', 'Expires is valid and in the future (' + ed.toISOString() + ').');
          var days = Math.floor(ms / 86400000);
          if (days < 30) add('warn', 'Expires in ' + days + ' day(s): renew it soon.');
        }
      }
    }
    Object.keys(FIELDS).forEach(function (key) {
      if (!FIELDS[key].multi && (fields[key] || []).length > 1 && key !== 'expires') add('fail', FIELDS[key].name + ' appears ' + fields[key].length + ' times (lines ' + fields[key].map(function (x) { return x.n; }).join(', ') + '); it must appear at most once.');
    });
    if (!(fields.canonical || []).length) add('info', 'No Canonical field. RFC 9116 recommends it, and it is most useful when the file is signed.');
    else if (opts.domain) {
      var hosts = (fields.canonical).map(function (c) { try { return new URL(c.value).hostname.toLowerCase(); } catch (e) { return ''; } });
      var d0 = opts.domain.toLowerCase();
      var hit = hosts.some(function (h) { return h === d0 || h === 'www.' + d0 || d0 === 'www.' + h; });
      add(hit ? 'pass' : 'warn', hit ? 'A Canonical URL matches ' + opts.domain + '.' : 'No Canonical URL is on ' + opts.domain + ' (found: ' + hosts.filter(Boolean).join(', ') + '). Is this file for a different site?');
    }
    if (!(fields.encryption || []).length) add('info', 'No Encryption field. Add one if you want reports sent encrypted.');
    if (!(fields.policy || []).length) add('info', 'No Policy field. Linking your disclosure policy helps researchers.');
    return { rows: rows, checks: checks, signed: signed, fields: fields, badLines: badLines };
  }
  function short(s) { return s.length > 80 ? s.slice(0, 77) + '...' : s; }

  // ---- Rendering ----
  function worst(list) {
    return list.some(function (c) { return c.level === 'fail'; }) ? 'fail' : list.some(function (c) { return c.level === 'warn'; }) ? 'warn' : 'ok';
  }
  var LABELS = { pass: 'ok', warn: 'warn', fail: 'fail', info: 'note' };
  var ORDER = { fail: 0, warn: 1, info: 2, pass: 3 };

  var placeholder = $('placeholderState'), box = $('resultBox');

  function renderResult(res) {
    box.replaceChildren();
    var w = worst(res.checks);
    var state = el('div', 'state ' + w);
    state.append(el('h2', 'state-title', w === 'fail' ? 'Invalid security.txt' : w === 'warn' ? 'Valid, with warnings' : 'Valid security.txt'));
    var c = { fail: 0, warn: 0, info: 0, pass: 0 };
    res.checks.forEach(function (x) { c[x.level]++; });
    state.append(el('p', 'verdict-counts', c.fail + ' error(s), ' + c.warn + ' warning(s), ' + c.info + ' note(s), ' + c.pass + ' passed. Signature not verified.'));
    box.append(state);

    var ul = el('ul', 'checks');
    res.checks.slice().sort(function (a, b) { return ORDER[a.level] - ORDER[b.level]; }).forEach(function (x) {
      var li = el('li');
      li.append(el('span', 'chk ' + x.level, LABELS[x.level]));
      li.append(el('span', null, x.text));
      ul.append(li);
    });
    box.append(ul);

    var scroll = el('div', 'table-scroll');
    scroll.setAttribute('role', 'region');
    scroll.setAttribute('aria-label', 'Parsed lines');
    scroll.tabIndex = 0;
    var tb = el('table', 'ftable');
    var cap = el('caption', 'sr-only', 'Parsed lines of the file');
    tb.append(cap);
    var thead = el('thead'), hr = el('tr');
    ['Line', 'Field', 'Value', 'Status'].forEach(function (h) { var th = el('th', null, h); th.scope = 'col'; hr.append(th); });
    thead.append(hr); tb.append(thead);
    var tbody = el('tbody');
    res.rows.forEach(function (r) {
      if (r.kind === 'blank') return;
      var tr = el('tr', r.kind === 'comment' || r.kind === 'armor' ? 'cm' : '');
      tr.append(el('td', 'ln', String(r.n)));
      if (r.kind === 'field') {
        tr.append(el('td', 'fname', r.name));
        tr.append(el('td', null, r.value));
        var lv = r.issues.some(function (x) { return x.level === 'fail'; }) ? 'fail' : r.issues.some(function (x) { return x.level === 'warn'; }) ? 'warn' : 'pass';
        var td = el('td', 'st'); td.append(el('span', 'chk ' + lv, LABELS[lv])); tr.append(td);
      } else if (r.kind === 'bad') {
        tr.append(el('td', 'fname', '?'));
        tr.append(el('td', null, r.raw));
        var tdb = el('td', 'st'); tdb.append(el('span', 'chk fail', 'fail')); tr.append(tdb);
      } else {
        var cell = el('td', null, r.raw); cell.colSpan = 2; tr.append(cell);
        tr.append(el('td', 'st', r.kind === 'armor' ? 'PGP armor' : 'comment'));
      }
      tbody.append(tr);
    });
    tb.append(tbody); scroll.append(tb);
    box.append(scroll);
    placeholder.hidden = true; box.hidden = false;
  }

  function showMessage(msg) {
    box.replaceChildren();
    var s = el('div', 'state fail error-message');
    s.setAttribute('role', 'alert');
    s.append(el('h2', 'state-title', 'Nothing to validate'));
    s.append(el('p', null, msg));
    box.append(s);
    placeholder.hidden = true; box.hidden = false;
  }

  // ---- Domain helper ----
  function normalizeDomain(input) {
    return String(input || '').trim().toLowerCase().replace(/^[a-z]+:\/\//, '').replace(/^.*@/, '').replace(/[\/?#].*$/, '').replace(/:\d+$/, '').replace(/\.+$/, '');
  }
  function validDomain(d) {
    if (!d || d.length > 253 || d.indexOf('.') < 0) return false;
    return d.split('.').every(function (l) { return /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/.test(l); });
  }
  var domainInput = $('domainInput'), domainError = $('domainError');
  var curlOut = $('curlOut'), curlCmd = $('curlCmd'), curlLegacy = $('curlLegacy');
  function curlFor(domain, path) { return "curl -sSLi --max-time 10 'https://" + domain + path + "'"; }

  function buildCurl() {
    var d = normalizeDomain(domainInput.value);
    if (!validDomain(d)) {
      domainError.textContent = d ? 'That is not a valid domain name (for example example.com).' : 'Enter a domain name.';
      domainError.classList.add('visible');
      curlOut.hidden = true;
      return;
    }
    domainError.textContent = ''; domainError.classList.remove('visible');
    domainInput.value = d;
    curlCmd.textContent = curlFor(d, '/.well-known/security.txt');
    curlLegacy.textContent = curlFor(d, '/security.txt');
    var sib = $('curlSiblings');
    sib.replaceChildren('Also check ' + d + ': ');
    [['caa', 'CAA'], ['ssl', 'SSL'], ['rdap', 'RDAP'], ['dnssec', 'DNSSEC'], ['mx', 'MX'], ['spf', 'SPF'], ['dmarc', 'DMARC'], ['dkim', 'DKIM'], ['bimi', 'BIMI'], ['ip', 'IP']].forEach(function (t, i) {
      if (i) sib.append(' · ');
      var a = el('a', 'link', t[1]);
      a.href = 'https://' + t[0] + '.hbenali.ovh/?domain=' + encodeURIComponent(d);
      a.target = '_blank'; a.rel = 'noopener noreferrer';
      sib.append(a);
    });
    curlOut.hidden = false;
    return d;
  }
  $('curlBtn').addEventListener('click', buildCurl);
  domainInput.addEventListener('keydown', function (e) { if (e.key === 'Enter') buildCurl(); });
  function flash(btn, msg) {
    var old = btn.dataset.label || btn.textContent;
    btn.dataset.label = old;
    btn.textContent = msg;
    setTimeout(function () { btn.textContent = old; }, 1600);
  }
  function copyText(text, btn) {
    if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(text).then(function () { flash(btn, 'Copied'); }, function () { flash(btn, 'Copy failed'); });
    else flash(btn, 'Copy not available');
  }
  $('copyCurlBtn').addEventListener('click', function () { copyText(curlCmd.textContent, this); });

  // ---- Paste flow ----
  var pasteInput = $('pasteInput');
  function runValidation() {
    var text = pasteInput.value;
    if (text.trim() === '') { showMessage('Paste the contents of a security.txt first.'); return; }
    if (text.length > MAX_INPUT) { showMessage('The text is too large for a security.txt (over ' + MAX_INPUT + ' characters).'); return; }
    var d = normalizeDomain(domainInput.value);
    renderResult(validate(text, { domain: validDomain(d) ? d : null }));
  }
  $('validateBtn').addEventListener('click', runValidation);
  $('clearPasteBtn').addEventListener('click', function () {
    pasteInput.value = ''; box.hidden = true; box.replaceChildren(); placeholder.hidden = false; pasteInput.focus();
  });

  // ---- Generator ----
  var G = {
    contact: $('genContact'), expires: $('genExpires'), lang: $('genLang'), encryption: $('genEncryption'),
    acknowledgments: $('genAck'), policy: $('genPolicy'), hiring: $('genHiring'), canonical: $('genCanonical'), csaf: $('genCsaf')
  };
  var genOut = $('genOut'), genError = $('genError');
  function pad(n) { return (n < 10 ? '0' : '') + n; }
  function defaultExpires() {
    var d = new Date();
    d.setUTCFullYear(d.getUTCFullYear() + 1);
    d.setUTCDate(d.getUTCDate() - 1);
    return d.getUTCFullYear() + '-' + pad(d.getUTCMonth() + 1) + '-' + pad(d.getUTCDate()) + 'T' + pad(d.getUTCHours()) + ':' + pad(d.getUTCMinutes()) + ':00Z';
  }
  function linesOf(ta) { return ta.value.split('\n').map(function (s) { return s.trim(); }).filter(Boolean); }

  function generate() {
    var out = [], problems = [];
    linesOf(G.contact).forEach(function (v) {
      if (!schemeOf(v) && validEmail(v)) v = 'mailto:' + v;
      out.push('Contact: ' + v);
    });
    var ex = G.expires.value.trim();
    if (/^\d{4}-\d{2}-\d{2}$/.test(ex)) ex += 'T00:00:00Z';
    if (ex) out.push('Expires: ' + ex);
    var lang = G.lang.value.split(',').map(function (s) { return s.trim(); }).filter(Boolean);
    if (lang.length) out.push('Preferred-Languages: ' + lang.join(', '));
    ['encryption', 'acknowledgments', 'policy', 'hiring', 'canonical', 'csaf'].forEach(function (k) {
      linesOf(G[k]).forEach(function (v) { out.push(FIELDS[k].name + ': ' + v); });
    });
    var text = out.join('\n');
    var res = validate(text, {});
    // The generator warns only about what the user typed; "missing" notes about optional fields are noise here.
    res.checks.forEach(function (c) {
      if (c.level === 'fail' || c.level === 'warn') problems.push(c.text);
    });
    genOut.textContent = text ? text + '\n' : '';
    genError.textContent = problems.join(' ');
    genError.classList.toggle('visible', problems.length > 0);
    return { text: text ? text + '\n' : '', ok: !problems.length && !!text };
  }
  function resetGen() {
    Object.keys(G).forEach(function (k) { G[k].value = ''; });
    G.expires.value = defaultExpires();
    generate();
  }
  Object.keys(G).forEach(function (k) { G[k].addEventListener('input', generate); });
  $('copyGenBtn').addEventListener('click', function () { var g = generate(); if (g.text) copyText(g.text, this); });
  $('dlGenBtn').addEventListener('click', function () {
    var g = generate();
    if (!g.text) return;
    var url = URL.createObjectURL(new Blob([g.text], { type: 'text/plain;charset=utf-8' }));
    var a = document.createElement('a');
    a.href = url; a.download = 'security.txt';
    document.body.append(a); a.click(); a.remove();
    setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
  });
  $('valGenBtn').addEventListener('click', function () {
    var g = generate();
    if (!g.text) return;
    pasteInput.value = g.text;
    runValidation();
    $('valTitle').scrollIntoView();
  });
  $('resetGenBtn').addEventListener('click', resetGen);
  resetGen();

  // ---- ?domain= ----
  var param = new URLSearchParams(window.location.search).get('domain');
  if (param) { domainInput.value = param; buildCurl(); }

  if ('serviceWorker' in navigator) navigator.serviceWorker.register('/sw.js');
})();
