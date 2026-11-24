#!/usr/bin/env python3
"""Builds the static copy of the English Assessment Reports site (GitHub Pages)
from the artifact page and the assessment records.

Same approach as build_static.py: the report data never goes to the repository as plain text. Each
assessment gets one file in data/, named and encrypted from its personal link code
(PBKDF2-SHA256 -> AES-256-GCM). The page derives the same key in the browser from the code after
the "#" in the link, so only that link opens the report.

usage:
  build_assessment.py --page ARTIFACT_INDEX_HTML --seed DIR_WITH_RECORDS --codes CODES_JSON --out REPO_DIR

CODES_JSON stays outside the repository. The record id (the code the artifact shows) always opens
its report; "static" adds extra codes. Format:
  { "<record id>": { "static": "<code used in the link>" or ["<code>", ...], "file": "<record>.json" } }
Codes are matched lowercase; prefer letters and digits that cannot be mixed up (no 0/o, 1/l/i).
"""
import argparse
import base64
import hashlib
import json
import os
import re
import sys

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ITER = 200000
SALT = b'english-assessment-reports-v1'


def derive(code):
    raw = hashlib.pbkdf2_hmac('sha256', code.encode('utf-8'), SALT, ITER, dklen=48)
    return raw[:32], raw[32:48].hex()  # AES key, file id


def pack(code, doc):
    key, fid = derive(code)
    iv = os.urandom(12)
    ct = AESGCM(key).encrypt(iv, json.dumps(doc, ensure_ascii=False, separators=(',', ':')).encode('utf-8'), None)
    return fid, {'v': 1, 'iv': base64.b64encode(iv).decode(), 'ct': base64.b64encode(ct).decode()}


DATA_JS = r"""  /* ---------- data: one encrypted file per assessment ---------- */
  var ENC = new TextEncoder(), DEC = new TextDecoder(), ITER = 200000, SALT = 'english-assessment-reports-v1';
  function unb64(s) { var b = atob(s), a = new Uint8Array(b.length); for (var i = 0; i < b.length; i++) a[i] = b.charCodeAt(i); return a; }
  function hex(u8) { return Array.prototype.map.call(u8, function (x) { return ('0' + x.toString(16)).slice(-2); }).join(''); }
  async function openReport(code) {
    var base = await crypto.subtle.importKey('raw', ENC.encode(code), 'PBKDF2', false, ['deriveBits']);
    var bits = new Uint8Array(await crypto.subtle.deriveBits({ name: 'PBKDF2', salt: ENC.encode(SALT), iterations: ITER, hash: 'SHA-256' }, base, 384));
    var res = await fetch('data/' + hex(bits.slice(32, 48)) + '.json', { cache: 'no-cache' });
    if (!res.ok) throw new Error('missing');
    var pk = await res.json();
    var key = await crypto.subtle.importKey('raw', bits.slice(0, 32), 'AES-GCM', false, ['decrypt']);
    var plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(pk.iv) }, key, unb64(pk.ct));
    return JSON.parse(DEC.decode(plain));
  }
  /* codes are case-insensitive and ignore spaces, so a typed code still opens */
  function norm(s) { return decodeURIComponent(String(s || '')).replace(/^.*#/, '').replace(/\s+/g, '').toLowerCase(); }
  /* without a code in the link: let the reader paste the code or the full link */
  function askCode(bad) {
    $('msg').innerHTML = '<strong>Open your report</strong>' +
      '<p>Paste the code you received (or the full link) to open the report.</p>' +
      '<form id="code-form" style="display:flex;flex-wrap:wrap;gap:.5rem;justify-content:center;margin-top:1rem">' +
      '<label for="code-in" style="position:absolute;left:-9999px">Report code</label>' +
      '<input id="code-in" autocomplete="off" spellcheck="false" placeholder="e.g. cpto-xxxxxxxxxxxxxx" style="flex:1 1 16rem;max-width:22rem;padding:.5rem .7rem;border:1px solid var(--line);border-radius:.5rem;background:var(--card);color:var(--fg);font:inherit">' +
      '<button type="submit" style="border:0;border-radius:.5rem;padding:.5rem 1rem;background:var(--navy);color:var(--navy-fg);font:inherit;font-weight:600;cursor:pointer">Open</button></form>' +
      (bad ? '<p style="margin-top:.6rem;color:var(--muted);font-size:.85rem">That code is not complete. Check that you copied all of it.</p>' : '');
    show('msg');
    $('code-form').addEventListener('submit', function (e) {
      e.preventDefault();
      var v = norm($('code-in').value);
      if (/^[a-z0-9][a-z0-9-]{9,60}$/.test(v)) { if (norm(location.hash) === v) route(); else location.hash = '#' + v; }
      else { $('code-in').setAttribute('aria-invalid', 'true'); $('code-in').focus(); }
    });
  }
  function route() {
    var code = norm(location.hash);
    $('all-link').hidden = true;
    S.doc = null; S.ready = false; S.mode = 'report';
    if (!/^[a-z0-9][a-z0-9-]{9,60}$/i.test(code)) {
      askCode(code);
      return;
    }
    if (!(window.crypto && window.crypto.subtle)) {
      message('This browser cannot open the report', 'Try again in an up-to-date browser, using the https link.');
      return;
    }
    message('Loading the assessment', 'This takes a few seconds.');
    openReport(code).then(function (doc) {
      if (code !== norm(location.hash)) return;
      S.doc = Object.assign({}, doc, { _id: code });
      S.ready = true;
      paintReport();
    }, function () {
      message('We could not open this report', 'Check that you opened the full link you received. If it keeps happening, tell the assessor.');
    });
  }

"""


def cut(s, a, b):
    i = s.index(a)
    j = s.index(b, i)
    return s[:i] + s[j:]


def make_page(src):
    # edit mode, translation and the "new assessment" form only exist in the live artifact
    src = re.sub(r'/\* admin:start \*/.*?/\* admin:end \*/', '', src, flags=re.S)
    src = re.sub(r'<!-- admin:start -->.*?<!-- admin:end -->', '', src, flags=re.S)
    head_end = src.index('</style>') + len('</style>')
    head, body = src[:head_end], src[head_end:]
    head = re.sub(r'<meta name="claude:viewport-fit-sides"[^>]*>\n?', '', head)

    # no assessor index on the public copy
    body = cut(body, '  function paintIndex(', '  /* ---------- data ---------- */')
    # data loading
    i = body.index('  /* ---------- data ---------- */')
    j = body.index('  /* ---------- events ---------- */')
    body = body[:i] + DATA_JS + body[j:]
    # index buttons and form
    body = cut(body, "  $('index').addEventListener('click'", "  $('lang').addEventListener('click'")
    # start
    i = body.index('  (async function () {\n    try {\n      var c = window.claude;')
    j = body.rindex('})();\n</script>')
    body = body[:i] + '  /* ---------- start ---------- */\n  route();\n' + body[j:]

    return ('<!doctype html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n'
            '<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">\n'
            '<meta name="robots" content="noindex, nofollow">\n<link rel="icon" href="data:,">\n'
            + head + '\n</head>\n<body>\n' + body.strip() + '\n</body>\n</html>\n')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--page', required=True)
    ap.add_argument('--seed', required=True)
    ap.add_argument('--codes', required=True)
    ap.add_argument('--out', required=True)
    a = ap.parse_args()

    os.makedirs(a.out, exist_ok=True)
    page = make_page(open(a.page, encoding='utf-8').read())
    open(os.path.join(a.out, 'index.html'), 'w', encoding='utf-8').write(page)

    data_dir = os.path.join(a.out, 'data')
    os.makedirs(data_dir, exist_ok=True)
    codes = json.load(open(a.codes, encoding='utf-8'))
    keep = set()
    for rec_id, info in codes.items():
        doc = json.load(open(os.path.join(a.seed, info['file']), encoding='utf-8'))
        statics = info.get('static', [])
        statics = statics if isinstance(statics, list) else [statics]
        if rec_id not in statics:  # the code shown in the artifact always opens the report too
            statics = [rec_id] + statics
        for code in statics:
            fid, pk = pack(code.lower(), doc)
            keep.add(fid + '.json')
            json.dump(pk, open(os.path.join(data_dir, fid + '.json'), 'w'))
            print('wrote data/%s.json  (%s)' % (fid, rec_id))
    for f in os.listdir(data_dir):  # drop files of assessments that were removed
        if f.endswith('.json') and f not in keep:
            os.remove(os.path.join(data_dir, f))
            print('removed data/' + f)


if __name__ == '__main__':
    sys.exit(main())
