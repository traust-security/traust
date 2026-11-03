"""Trusted, offline exploration of exported LocDashboard JSON; portable reports stay script-free."""

# ruff: noqa: E501

from __future__ import annotations

import base64
import hashlib
from pathlib import Path

from traust.cli._doors import parser, run

_SCRIPT = r"""
'use strict';
const byId = id => document.getElementById(id);
const fmt = value => value.toLocaleString();
let model = null;
let direction = -1;
let sortKey = 'code';
const colors = ['#176b83','#8c4b16','#6253a4','#26744e','#9b3653','#536575'];
const languageColor = name => {
    let hash = 0;
    for (const char of name) hash = (hash * 31 + char.codePointAt(0)) >>> 0;
    return colors[hash % colors.length];
};
const buckets = ['Not measured','Empty','Under 1k','1k–10k','10k–100k','100k+'];
const bucket = r => r.unmeasured ? buckets[0] : r.code === 0 ? buckets[1] :
    r.code < 1000 ? buckets[2] : r.code < 10000 ? buckets[3] :
    r.code < 100000 ? buckets[4] : buckets[5];
const node = (tag, text, className) => {
    const el = document.createElement(tag);
    if (text !== undefined) el.textContent = text;
    if (className) el.className = className;
    return el;
};
function validate(data) {
    const count = n => Number.isSafeInteger(n) && n >= 0;
    if (!data || !Array.isArray(data.repositories) || !Array.isArray(data.languages) ||
        !count(data.code) || !count(data.total)) throw new Error('Expected a lines-of-code.json export.');
    const ids = new Set();
    for (const r of data.repositories) {
        if (!r || typeof r.repository_id !== 'string' || ids.has(r.repository_id) ||
            typeof r.repository_url !== 'string' ||
            (!r.unmeasured && (!count(r.code) || !count(r.total))) ||
            (r.unmeasured && !((r.code == null || count(r.code)) &&
                (r.total == null || count(r.total)))) ||
            (r.unmeasured != null && typeof r.unmeasured !== 'string') ||
            (r.corpus_trees != null && (!Array.isArray(r.corpus_trees) ||
                r.corpus_trees.some(t => typeof t !== 'string'))) ||
            !Array.isArray(r.languages) || r.languages.some(l => !l ||
                typeof l.name !== 'string' || !count(l.code))) {
            throw new Error('Invalid repository measurements; export the LoC view again.');
        }
        ids.add(r.repository_id);
    }
    return data;
}
function render() {
    if (!model) return;
    const query = byId('search').value.trim().toLowerCase();
    const language = byId('language').value;
    const tree = byId('tree').value;
    const size = byId('bucket').value;
    const rows = model.repositories.filter(r =>
        r.repository_url.toLowerCase().includes(query) &&
        (!language || r.languages.some(l => l.name === language)) &&
        (!size || bucket(r) === size) &&
        (!tree || (JSON.parse(tree) === null ? !(r.corpus_trees || []).length :
            (r.corpus_trees || []).includes(JSON.parse(tree)))));
    rows.sort((a,b) => {
        const av = a.unmeasured && sortKey !== 'repository_url' ? null : a[sortKey];
        const bv = b.unmeasured && sortKey !== 'repository_url' ? null : b[sortKey];
        if (av == null || bv == null) return av == null ? (bv == null ? 0 : 1) : -1;
        return direction * (typeof av === 'number' ? av-bv : String(av).localeCompare(String(bv))) ||
            a.repository_url.localeCompare(b.repository_url);
    });
    byId('count').textContent = `${fmt(rows.length)} of ${fmt(model.repositories.length)} repositories`;
    const body = byId('rows');
    body.replaceChildren();
    for (const r of rows) {
        const tr = node('tr');
        const name = node('td', r.repository_url, 'repo');
        if (r.unmeasured) name.append(node('small', r.unmeasured));
        tr.append(name, node('td', r.unmeasured ? 'Not measured' : fmt(r.code), 'number'),
            node('td', r.unmeasured ? '—' : fmt(r.total), 'number'),
            node('td', r.code_delta == null ? '—' : `${r.code_delta > 0 ? '+' : ''}${fmt(r.code_delta)}`, 'number'),
            node('td', bucket(r)));
        const cell = node('td');
        const strip = node('div', undefined, 'mix');
        strip.setAttribute('role','img');
        strip.setAttribute('aria-label', r.languages.map(l => `${l.name}: ${fmt(l.code)} lines`).join(', ') || 'No measured languages');
        r.languages.forEach(l => {
            const part = node('span');
            part.style.width = `${r.total ? 100*l.code/r.total : 0}%`;
            part.style.backgroundColor = languageColor(l.name);
            part.title = `${l.name}: ${fmt(l.code)} lines`;
            strip.append(part);
        });
        cell.append(strip, node('small', r.languages.map(l => `${l.name} ${fmt(l.code)}`).join(' · ') || '—'));
        tr.append(cell);
        body.append(tr);
    }
    byId('empty').hidden = rows.length !== 0;
    document.querySelectorAll('th[data-sort]').forEach(th => {
        th.setAttribute('aria-sort', th.dataset.sort === sortKey ?
            (direction === 1 ? 'ascending' : 'descending') : 'none');
    });
}
byId('file').addEventListener('change', async event => {
    const file = event.target.files[0];
    if (!file) return;
    byId('status').textContent = 'Reading local export…';
    try {
        if (file.size > 20 * 1024 * 1024) throw new Error('Export exceeds the 20 MiB local-file limit.');
        model = validate(JSON.parse(await file.text()));
        byId('language').replaceChildren(new Option('All languages',''));
        [...new Set(model.repositories.flatMap(r => r.languages.map(l => l.name)))].sort()
            .forEach(name => byId('language').add(new Option(name,name)));
        byId('tree').replaceChildren(new Option('All corpus trees',''));
        const corpus = byId('corpus');
        corpus.replaceChildren();
        if (model.corpus_buckets) {
            for (const group of model.corpus_buckets) {
                const value = JSON.stringify(group.tree);
                const name = group.tree === null ? 'Unassigned' : group.tree;
                byId('tree').add(new Option(name, value));
                const button = node('button', `${name} · ${fmt(group.repositories)} repos · ${fmt(group.code)} code lines`, 'bucket');
                button.type = 'button';
                const bar = node('span');
                bar.style.width = `${model.repositories.length ? 100*group.repositories/model.repositories.length : 0}%`;
                button.append(bar);
                button.addEventListener('click', () => {byId('tree').value = value; render();});
                corpus.append(button);
            }
        } else {
            corpus.append(node('p', 'Corpus buckets are unavailable in this older export. Republish the LoC view to include recorded corpus membership.'));
        }
        byId('tree').value = '';
        byId('search').value = '';
        byId('bucket').value = '';
        byId('controls').disabled = false;
        byId('content').hidden = false;
        const measured = model.repositories.filter(r => !r.unmeasured).length;
        byId('summary').textContent = `${fmt(model.code)} measured code lines · ${fmt(model.total)} including documentation · ${fmt(measured)} repositories measured`;
        byId('time').textContent = model.as_of ? `Recomputed as of ${model.as_of}` : 'Latest recorded measurements';
        byId('estimate').textContent = model.first_party_estimate == null ?
            'First-party estimate not requested; no calibration ratio is assumed.' :
            `First-party estimate ${model.first_party_estimate} (code ÷ ${model.first_party_divisor}; not measured).`;
        const comparison = model.comparison;
        byId('comparison').textContent = comparison ?
            `Compared with ${comparison.as_of}: ${comparison.code_delta > 0 ? '+' : ''}${fmt(comparison.code_delta)} code lines across ${fmt(comparison.comparable_repositories)} repositories measured at both points. Coverage changes are excluded from growth.` :
            'Export with --compare-as-of to inspect changes between recorded measurements.';
        const chart = byId('buckets');
        chart.replaceChildren();
        for (const size of buckets) {
            const count = model.repositories.filter(r => bucket(r) === size).length;
            const button = node('button', `${size} · ${fmt(count)}`, 'bucket');
            button.type = 'button';
            const bar = node('span');
            bar.style.width = `${model.repositories.length ? 100*count/model.repositories.length : 0}%`;
            button.append(bar);
            button.addEventListener('click', () => {byId('bucket').value = size; render();});
            chart.append(button);
        }
        byId('status').textContent = `${file.name} loaded locally. No data is sent or saved by this app.`;
        render();
    } catch (error) {
        model = null;
        byId('content').hidden = true;
        byId('controls').disabled = true;
        byId('status').textContent = `Could not open export: ${error.message}`;
    }
});
byId('search').addEventListener('input', render);
byId('language').addEventListener('change', render);
byId('bucket').addEventListener('change', render);
byId('tree').addEventListener('change', render);
byId('reset').addEventListener('click', () => {
    byId('search').value = ''; byId('language').value = '';
    byId('bucket').value = ''; byId('tree').value = ''; render();
});
document.querySelectorAll('th[data-sort] button').forEach(button => {
    button.addEventListener('click', () => {
        const key = button.parentElement.dataset.sort;
        direction = sortKey === key ? -direction : key === 'repository_url' ? 1 : -1;
        sortKey = key; render();
    });
});
"""

_HTML = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'sha256-SCRIPT_HASH'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>LoC explorer · Traust</title>
<style>
:root{font-family:system-ui,sans-serif;color:#172b38;background:#f6f8fa;font-size:16px;accent-color:#176b83;caret-color:#176b83}
*{box-sizing:border-box}body{margin:0}main{max-width:1440px;margin:auto;padding:2rem}
h1{font-size:2rem;margin:0 0 .5rem}h2{font-size:1.25rem;margin:2rem 0 1rem}
p{max-width:75ch;line-height:1.55}small{display:block;color:#465d6b;margin-top:.4rem;line-height:1.5}
header{border-bottom:1px solid #cbd5dd;padding-bottom:1.5rem}button,input,select{font:inherit}
button,select,input{border:1px solid #899da9;border-radius:4px;background:#fff;color:inherit;padding:.6rem .8rem}
button{cursor:pointer}button:hover{background:#e4edf1}button:active{background:#cfdee5}
:focus-visible{outline:3px solid #176b83;outline-offset:3px}::selection{background:#c4e5ee;color:#172b38}
input[type=file]{max-width:100%;margin:.5rem 0}fieldset{border:0;padding:0;margin:1.5rem 0;display:flex;flex-wrap:wrap;gap:1rem;align-items:end}
label{display:grid;gap:.4rem}label.search{flex:1;min-width:200px}fieldset:disabled{opacity:.6}
#status{min-height:1.5rem;color:#3a5363}#summary{font-size:1.125rem;font-weight:600}#buckets{display:grid;grid-template-columns:repeat(6,1fr);gap:.75rem}
.bucket{text-align:left;position:relative;padding-bottom:1rem;overflow:hidden;font-size:.875rem;min-height:3.5rem}
#corpus{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:.75rem}
.bucket span{position:absolute;bottom:0;left:0;height:5px;background:#176b83}.scroll{overflow-x:auto;border:1px solid #cbd5dd;background:#fff}
table{border-collapse:collapse;width:100%;font-size:.875rem}caption{text-align:left;padding:.8rem;font-weight:600}
th,td{text-align:left;border-bottom:1px solid #dae1e7;padding:.8rem;vertical-align:top}th{background:#edf2f5;white-space:nowrap}
th button{border:0;padding:.25rem;background:transparent;font-weight:600}th[aria-sort=ascending] button::after{content:' ↑'}th[aria-sort=descending] button::after{content:' ↓'}
.number{text-align:right;font-variant-numeric:tabular-nums}.repo{min-width:230px;overflow-wrap:anywhere}.mix{display:flex;height:9px;min-width:170px;background:#e5ebef}.mix span{height:100%}
#empty{padding:1rem}footer{border-top:1px solid #cbd5dd;margin-top:2rem;color:#465d6b;font-size:.875rem}
[hidden]{display:none!important}@media(max-width:760px){main{padding:1rem}#buckets{grid-template-columns:repeat(2,1fr)}fieldset{align-items:stretch}fieldset label{width:100%}h1{font-size:1.75rem}}
</style></head><body><main>
<header><h1>LoC explorer</h1><p>Inspect measured repository size, language mix and historical changes. Open a local <strong>lines-of-code.json</strong> export; portable report HTML remains script-free.</p>
<label for="file">Open LoC JSON<input id="file" type="file" accept=".json,application/json"></label>
<p id="status" role="status" aria-live="polite">Choose an export to begin. Files stay in this browser tab.</p></header>
<fieldset id="controls" disabled><legend>Filter repositories</legend>
<label class="search" for="search">Repository contains<input id="search" type="search" placeholder="Repository name or URL"></label>
<label for="language">Language<select id="language"><option value="">All languages</option></select></label>
<label for="tree">Corpus tree<select id="tree"><option value="">All corpus trees</option></select></label>
<label for="bucket">Measured code size<select id="bucket"><option value="">All sizes</option><option>Not measured</option><option>Empty</option><option>Under 1k</option><option>1k–10k</option><option>10k–100k</option><option>100k+</option></select></label>
<button id="reset" type="button">Clear filters</button></fieldset>
<section id="content" hidden aria-label="Measurements"><h2 id="time">Latest recorded measurements</h2><p id="summary"></p><p id="estimate"></p><p id="comparison"></p>
<h2>Corpus buckets</h2><p>Recorded corpus-tree memberships may overlap. Unassigned means no matching registry tree; it is not a guessed ownership category.</p><div id="corpus"></div>
<h2>Repository size distribution</h2><div id="buckets"></div>
<h2>Repositories</h2><p id="count" role="status" aria-live="polite"></p>
<div class="scroll" role="region" aria-label="Repository measurements" tabindex="0"><table><caption>Click a column heading to sort. A dash means no comparable measurement.</caption><thead><tr>
<th scope="col" data-sort="repository_url" aria-sort="none"><button type="button">Repository</button></th>
<th scope="col" data-sort="code" aria-sort="descending"><button type="button">Code lines</button></th>
<th scope="col" data-sort="total" aria-sort="none"><button type="button">All lines</button></th>
<th scope="col" data-sort="code_delta" aria-sort="none"><button type="button">Code change</button></th>
<th scope="col">Size bucket</th><th scope="col">Language mix (all lines)</th></tr></thead><tbody id="rows"></tbody></table>
<p id="empty" hidden>No repositories match. Clear filters to see the full population.</p></div></section>
<footer><p>Whole-repository measurements can include tests, fixtures and tooling. Historical views recompute recorded facts under current policy; they are not immutable as-reported snapshots. This trusted local app has no network access, external assets or browser storage.</p></footer>
</main><script>SCRIPT_BODY</script></body></html>
"""


def explorer_html() -> str:
    digest = base64.b64encode(hashlib.sha256(_SCRIPT.encode()).digest()).decode()
    return _HTML.replace("SCRIPT_HASH", digest).replace("SCRIPT_BODY", _SCRIPT)


def main(argv: list[str] | None = None) -> int:
    ap = parser("dashboard", "explore-loc", "Write the trusted offline LoC JSON explorer.")
    ap.add_argument("--out", type=Path, required=True, help="local explorer HTML file")
    args = ap.parse_args(argv)

    def call() -> dict[str, str]:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(explorer_html(), encoding="utf-8")
        return {"written": str(args.out), "open": args.out.resolve().as_uri()}

    return run(call)
