"""Web layer: one FastAPI app serving both the page and the API.

Deliberately a single service. The page and the API share an origin, so there
is no CORS, one deployment, one URL.

    uvicorn ghosts.web:app --host 0.0.0.0 --port $PORT
"""

from __future__ import annotations

import asyncio
import glob
import json
import os
from pathlib import Path
from typing import Any, Optional

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

from ghosts.ingest import IngestError, cleanup_repo, scan_repo
from ghosts.narrate import narrate
from ghosts.rules import run_all
from fastapi.staticfiles import StaticFiles
from ghosts.anomaly import find_anomalies

app = FastAPI(title="Ghosts in the Machine")

PROJECT_ROOT = Path(__file__).resolve().parent.parent
app.mount("/static", StaticFiles(directory=PROJECT_ROOT / "static"), name="static")
MAX_COMMITS = int(os.environ.get("GHOSTS_MAX_COMMITS", "500"))
SCAN_TIMEOUT = int(os.environ.get("GHOSTS_SCAN_TIMEOUT", "240"))


class ScanRequest(BaseModel):
    url: str


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------

def _scan(url: str) -> dict:
    """Run the whole pipeline. Synchronous and slow; called in a thread."""
    repo = None
    try:
        commits, meta, repo = scan_repo(url, MAX_COMMITS)
        findings = run_all(commits, repo)

        extra, _ = find_anomalies(commits, verbose=False)
        findings.extend(extra)
        findings.sort(key=lambda f: (f.date, f.rule_id, f.file_path))

        interpretation = narrate(findings, verbose=False)
        return {
            "repository": url,
            "scan": meta,
            "findings": [f.to_dict() for f in findings],
            "interpretation": interpretation,
        }
    finally:
        if repo is not None:
            cleanup_repo(repo)


@app.post("/scan")
async def scan(request: ScanRequest) -> JSONResponse:
    url = (request.url or "").strip()
    if not url:
        return JSONResponse({"error": "Give me a public GitHub repository URL."}, 400)
    if "github.com" not in url:
        return JSONResponse({"error": "Only public GitHub repositories, for now."}, 400)

    try:
        result = await asyncio.wait_for(
            asyncio.to_thread(_scan, url), timeout=SCAN_TIMEOUT
        )
    except asyncio.TimeoutError:
        return JSONResponse(
            {"error": "That repository took too long to read. Try a smaller one."}, 504
        )
    except IngestError as exc:
        return JSONResponse({"error": str(exc)}, 400)
    except Exception as exc:  # noqa: BLE001 - never 500 silently at a demo
        return JSONResponse({"error": f"Something went wrong reading that repository: {exc}"}, 500)

    return JSONResponse(result)


@app.get("/featured")
async def featured() -> JSONResponse:
    """Pre-generated exhibits. Frozen artifacts -- the audio matches this text."""
    out = []
    for path in sorted(glob.glob(str(PROJECT_ROOT / "featured-*.json"))):
        try:
            with open(path, encoding="utf-8") as fh:
                out.append(json.load(fh))
        except Exception:
            continue
    return JSONResponse({"exhibits": out})


@app.get("/healthz")
async def healthz() -> dict:
    return {"ok": True}


# ---------------------------------------------------------------------------
# Page
# ---------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
async def index() -> HTMLResponse:
    return HTMLResponse(PAGE)


PAGE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Ghosts in the Machine</title>
<style>
  :root {
    --bg: #0c0c0e;
    --panel: #141417;
    --line: #26262c;
    --ink: #e8e6e1;
    --dim: #8a8780;
    --fainter: #5c5a56;
    --accent: #c9a227;
    --alarm: #c4604a;
    --mono: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
    --serif: Georgia, "Iowan Old Style", "Times New Roman", serif;
  }
  * { box-sizing: border-box; }
  html, body { margin: 0; padding: 0; background: var(--bg); color: var(--ink); }
  body {
    font-family: var(--serif);
    line-height: 1.6;
    -webkit-font-smoothing: antialiased;
  }
  .wrap { max-width: 820px; margin: 0 auto; padding: 0 20px 120px; }

  header { padding: 90px 0 50px; border-bottom: 1px solid var(--line); }
  h1 {
    font-size: clamp(2rem, 6vw, 3.1rem);
    line-height: 1.1; margin: 0 0 18px; font-weight: 400; letter-spacing: -0.02em;
  }
  .lede { color: var(--dim); font-size: 1.05rem; max-width: 60ch; margin: 0; }
  .lede + .lede { margin-top: 14px; }

  form { display: flex; gap: 10px; margin: 44px 0 0; flex-wrap: wrap; }
  input[type=url] {
    flex: 1 1 320px; min-width: 0;
    background: var(--panel); border: 1px solid var(--line); color: var(--ink);
    padding: 13px 15px; font-family: var(--mono); font-size: 0.85rem; border-radius: 2px;
  }
  input[type=url]:focus { outline: none; border-color: var(--fainter); }
  button {
    background: transparent; border: 1px solid var(--accent); color: var(--accent);
    padding: 13px 24px; font-family: var(--mono); font-size: 0.78rem;
    letter-spacing: 0.1em; text-transform: uppercase; cursor: pointer;
    border-radius: 2px; transition: background .25s, color .25s;
  }
  button:hover:not(:disabled) { background: var(--accent); color: var(--bg); }
  button:disabled { opacity: .4; cursor: default; }

  /* progress: revealed one line at a time, as though uncovered */
  #progress { margin-top: 30px; font-family: var(--mono); font-size: 0.8rem; color: var(--dim); }
  #progress div { opacity: 0; animation: surface .9s ease forwards; }
  @keyframes surface { from { opacity: 0; transform: translateY(3px); } to { opacity: 1; } }

  .err {
    margin-top: 28px; padding: 16px 18px; border-left: 2px solid var(--alarm);
    background: var(--panel); color: var(--ink); font-size: 0.95rem;
  }

  /* each exhibit opens with a rule and its repository; the gap between exhibits
     must beat the largest gap inside one (.dismissed, 80px) */
  section.result { margin-top: 70px; padding-top: 30px; border-top: 2px solid var(--fainter); }
  section.result + section.result { margin-top: 150px; }
  .exhibit-title {
    font-size: clamp(1.7rem, 5vw, 2.2rem); line-height: 1.2; font-weight: 700;
    letter-spacing: -0.01em; margin: 0 0 8px; overflow-wrap: anywhere;
  }
  .scanned { font-family: var(--mono); font-size: 0.75rem; color: var(--dim); letter-spacing: 0.06em; }

  article.ghost {
    margin: 54px 0 0; opacity: 0;
    animation: rise 1.1s cubic-bezier(.2,.7,.3,1) forwards;
  }
  @keyframes rise { from { opacity: 0; transform: translateY(14px); } to { opacity: 1; transform: none; } }

  .label {
    font-family: var(--mono); font-size: 0.7rem; letter-spacing: 0.22em;
    text-transform: uppercase; color: var(--accent); margin-bottom: 10px;
  }
  .ghost h2 { font-size: 1.5rem; font-weight: 400; margin: 0 0 6px; letter-spacing: -0.01em; }
  .severity { font-family: var(--mono); font-size: 0.72rem; color: var(--dim); letter-spacing: 0.08em; }
  .reason { color: var(--dim); font-style: italic; margin: 14px 0 0; }

  .pane { margin-top: 26px; border: 1px solid var(--line); border-radius: 2px; }
  .pane > h3 {
    margin: 0; padding: 11px 16px; border-bottom: 1px solid var(--line);
    font-family: var(--mono); font-size: 0.68rem; letter-spacing: 0.16em;
    text-transform: uppercase; color: var(--fainter); font-weight: 400;
  }
  .pane .body { padding: 18px 16px; }
  .pane.said .body p { margin: 0 0 14px; }
  .pane.said .body p:last-child { margin-bottom: 0; }
  .pane.recorded { background: var(--panel); }
  .pane.recorded .body { padding: 10px 16px; }

  .fact { padding: 14px 0; border-bottom: 1px solid var(--line); font-family: var(--mono); font-size: 0.78rem; }
  .fact:last-child { border-bottom: none; }
  .fact .meta { color: var(--fainter); font-size: 0.72rem; letter-spacing: 0.04em; }
  .fact .what { color: var(--ink); margin: 6px 0 0; font-family: var(--serif); font-size: 0.95rem; }
  .fact .evidence {
    margin-top: 9px; padding: 9px 11px; background: #0a0a0c;
    border-left: 2px solid var(--alarm); color: var(--dim);
    overflow-x: auto; white-space: pre; font-size: 0.75rem;
  }

  audio { width: 100%; margin-top: 20px; filter: invert(.88) hue-rotate(180deg); }

  .audio-controls { display: flex; gap: 18px; flex-wrap: wrap; margin-top: 22px; }
  .audio-controls .ac-btn {
    border: none; background: none; color: var(--fainter);
    font-family: var(--mono); font-size: .72rem; padding: 0;
    cursor: pointer; letter-spacing: .1em;
  }
  .audio-controls .ac-btn:hover { color: var(--accent); }

  .dismissed { margin-top: 80px; padding-top: 26px; border-top: 1px solid var(--line); }
  .dismissed > h3 {
    font-family: var(--mono); font-size: 0.68rem; letter-spacing: 0.16em;
    text-transform: uppercase; color: var(--fainter); font-weight: 400; margin: 0 0 18px;
  }
  .dismissed .item { color: var(--fainter); margin-bottom: 15px; font-size: 0.92rem; }
  .dismissed .item strong { color: var(--dim); font-weight: 400; }

  .quiet { margin-top: 56px; padding: 26px; border: 1px solid var(--line); background: var(--panel); }
  .quiet p { margin: 0 0 12px; color: var(--dim); }
  .quiet p:last-child { margin-bottom: 0; }

  footer {
    margin-top: 110px; padding-top: 26px; border-top: 1px solid var(--line);
    font-family: var(--mono); font-size: 0.72rem; color: var(--fainter); line-height: 1.9;
  }
  footer a { color: var(--dim); }
</style>
</head>
<body>
<div class="wrap">

  <header>
    <h1>Ghosts in the Machine</h1>
    <p class="lede">Some things break loudly. Others are committed, forgotten, and
    sit in a repository's history for months without ever raising an error.</p>
    <p class="lede">Point this at a public repository and it reads the history
    looking for failures that nobody noticed at the time, because nothing failed.</p>
    
    <p class="lede" style="font-size:.85rem; color:var(--fainter)">Large
    repositories take a while to read. Small and medium ones return in
    under a minute.</p>

    <form id="f">
      <input id="u" type="url" placeholder="https://github.com/owner/repository" required>
      <button id="b" type="submit">Summon</button>
    </form>
    <div id="progress"></div>
    <div id="err"></div>
  </header>

  <div class="audio-controls">
    <audio id="intro" preload="none" src="/static/intro.mp3"></audio>
    <button type="button" data-audio="intro" onclick="playIntro()"
            class="ac-btn">▸ listen</button>

    <audio id="ambient" preload="none" src="/static/ambient.mp3" loop></audio>
    <button type="button" data-audio="ambient" onclick="toggleAmbient()"
            class="ac-btn">▸ sound on</button>
  </div>

  <div id="out"></div>

  <footer>
    Detection is deterministic: git history, read by rules.<br>
    Interpretation is a language model (Gemma, open weights) reading that evidence.<br>
    Both are shown, separately, so you can check one against the other.
  </footer>

</div>

<script>
const $ = s => document.querySelector(s);
const out = $('#out'), prog = $('#progress'), err = $('#err');

const STEPS = [
  'cloning the repository…',
  'walking the commit history…',
  'looking for what broke quietly…',
  'asking the model what it makes of this…'
];

let timer = null;
function startProgress() {
  prog.innerHTML = ''; err.innerHTML = '';
  let i = 0;
  const tick = () => {
    if (i >= STEPS.length) return;
    const d = document.createElement('div');
    d.textContent = STEPS[i++];
    prog.appendChild(d);
    timer = setTimeout(tick, i === 1 ? 2600 : 12000);
  };
  tick();
}
function stopProgress() { clearTimeout(timer); prog.innerHTML = ''; }

function esc(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g,
    c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}

// owner/repo from a GitHub URL; anything unrecognised is shown as given.
function repoName(url) {
  const m = String(url || '').match(/github\.com[/:]([^/\s]+)\/([^/\s?#]+)/);
  return m ? `${m[1]}/${m[2].replace(/\.git$/, '')}` : String(url || '');
}

function paragraphs(text) {
  return String(text || '').split(/\n\s*\n/).filter(p => p.trim())
    .map(p => `<p>${esc(p.trim())}</p>`).join('');
}

function factBlock(f) {
  const ev = f.evidence || {};
  const line = ev.redacted_line
    ? `<div class="evidence">${esc(ev.redacted_line)}</div>` : '';
  const msg = ev.commit_message ? ` · “${esc(ev.commit_message)}”` : '';
  return `<div class="fact">
    <div class="meta">${esc(f.rule_id)} · ${esc((f.commit_sha||'').slice(0,8))} · ${esc(f.date)} · ${esc(f.file_path)}${msg}</div>
    <div class="what">${esc(f.summary)}</div>
    ${line}
  </div>`;
}

function ghostBlock(group, n, audioSrc) {
  const said = group.narration
    ? `<div class="pane said">
         <h3>What the model made of it</h3>
         <div class="body">${paragraphs(group.narration)}</div>
       </div>` : '';
  const audio = audioSrc
    ? `<audio controls preload="none" src="${esc(audioSrc)}"></audio>` : '';
  return `<article class="ghost" style="animation-delay:${n * 140}ms">
    <div class="label">Ghost No. ${n}</div>
    <h2>${esc(group.title)}</h2>
    <div class="severity">severity ${esc(group.significance)} / 10</div>
    <p class="reason">${esc(group.reason)}</p>
    ${said}
    ${audio}
    <div class="pane recorded">
      <h3>What git actually recorded</h3>
      <div class="body">${(group.findings || []).map(factBlock).join('')}</div>
    </div>
  </article>`;
}

function render(data, audioMap) {
  const interp = data.interpretation || {};
  const groups = interp.groups || [];
  const shown = groups.filter(g => g.narration);
  const dismissed = groups.filter(g => !g.narration);
  const scanned = data.scan || {};

  let html = `<section class="result">
    <h2 class="exhibit-title">${esc(repoName(data.repository))}</h2>
    <div class="scanned">${esc(scanned.commits_scanned || 0)} commits read${scanned.capped ? ' · history capped' : ''}</div>`;

  if (!groups.length) {
    html += `<div class="quiet">
      <p><strong>Nothing found.</strong> This history is quiet — or I am not yet
      looking for the right things.</p>
      <p>I currently recognise two kinds of silent failure: files committed empty,
      and credentials entering the tree. Both of these I met personally, in my own
      repositories. There are certainly more.</p>
    </div>`;
  }

  shown.forEach((g, i) => {
    const key = (g.group_id || '') + '';
    html += ghostBlock(g, i + 1, (audioMap || {})[key] || (audioMap || {})[String(i + 1)]);
  });

  if (dismissed.length) {
    html += `<div class="dismissed"><h3>Also examined, and judged unremarkable</h3>`;
    dismissed.forEach(g => {
      html += `<div class="item"><strong>${esc(g.title)}</strong> — ${esc(g.significance)}/10.
        ${esc(g.reason)} ${g.narration_skipped ? esc(g.narration_skipped) : ''}</div>`;
    });
    html += `</div>`;
  }

  if (interp.warning) {
    html += `<div class="dismissed"><h3>Note</h3><div class="item">${esc(interp.warning)}</div></div>`;
  }

  html += `</section>`;
  return html;
}

$('#f').addEventListener('submit', async e => {
  e.preventDefault();
  const url = $('#u').value.trim();
  if (!url) return;
  $('#b').disabled = true;
  out.innerHTML = '';
  startProgress();
  try {
    const r = await fetch('/scan', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({url})
    });
    const data = await r.json();
    stopProgress();
    if (!r.ok) {
      err.innerHTML = `<div class="err">${esc(data.error || 'That did not work.')}</div>`;
    } else {
      out.innerHTML = render(data, null);
    }
  } catch (e) {
    stopProgress();
    err.innerHTML = `<div class="err">Could not reach the server. It may be waking up — try once more.</div>`;
  } finally {
    $('#b').disabled = false;
  }
});

// Featured exhibits, shown on arrival so the page is never empty.
// Map a group_id to an audio file here once the mp3s exist, e.g. {"g1": "/static/ghost-1.mp3"}
const AUDIO = {};

fetch('/featured').then(r => r.json()).then(d => {
  if (!d.exhibits || !d.exhibits.length) return;
  out.innerHTML = d.exhibits.map(e => render(e, AUDIO)).join('');
}).catch(() => {});

// Quiet audio controls in the header. No autoplay — browsers block it.
const introEl = $('#intro'), ambientEl = $('#ambient');
ambientEl.volume = 0.25;

function playIntro() {
  introEl.currentTime = 0;          // restart from the beginning every time
  introEl.play().catch(() => {});
}

function toggleAmbient() {
  const btn = document.querySelector('[data-audio="ambient"]');
  if (ambientEl.paused) {
    ambientEl.play().then(() => {
      btn.textContent = '■ sound off';
    }).catch(() => {});
  } else {
    ambientEl.pause();
    btn.textContent = '▸ sound on';
  }
}
</script>
</body>
</html>
"""