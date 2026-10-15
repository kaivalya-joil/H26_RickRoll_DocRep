"""DocRep standalone, proof-carrying HTML report generator.

Generates a 100% self-contained, offline-compatible HTML report with the same
luxury gold theme as the main GUI. Zero external CDN dependencies, zero build
steps, 100% standard library.
"""

from __future__ import annotations

import html
import json
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .models import DependencyExitCapsule

# ── Shared CSS (mirrors the luxury gold theme from static/index.html) ──────────
_CSS = """
  :root {
    --bg:        #f9f8f6;
    --surface:   #ffffff;
    --surface2:  #f4f3f0;
    --border:    #e8e6e1;
    --text:      #1a1814;
    --text2:     #6b6760;
    --text3:     #b0aea8;
    --gold:      #c9a84c;
    --gold-dim:  rgba(201,168,76,.10);
    --green:     #3d9970;
    --green-dim: rgba(61,153,112,.10);
    --red:       #c0392b;
    --red-dim:   rgba(192,57,43,.10);
    --amber:     #d4860a;
    --amber-dim: rgba(212,134,10,.10);
    --teal:      #1a7a8a;
    --teal-dim:  rgba(26,122,138,.10);
    --font: "Georgia","Times New Roman",serif;
    --sans: -apple-system,BlinkMacSystemFont,"Inter","Segoe UI",Helvetica,Arial,sans-serif;
    --mono: ui-monospace,"SFMono-Regular",Menlo,Consolas,monospace;
    --r: 4px; --r-lg: 8px;
  }
  [data-theme="dark"] {
    --bg:        #111009;
    --surface:   #19180f;
    --surface2:  #211f14;
    --border:    #2e2c1e;
    --text:      #f0ece2;
    --text2:     #9a9580;
    --text3:     #5a5648;
    --gold:      #d4a847;
    --gold-dim:  rgba(212,168,71,.12);
    --green:     #4aab82;
    --green-dim: rgba(74,171,130,.12);
    --red:       #e05a4a;
    --red-dim:   rgba(224,90,74,.12);
    --amber:     #e8a030;
    --amber-dim: rgba(232,160,48,.12);
    --teal:      #30a0b0;
    --teal-dim:  rgba(48,160,176,.12);
  }
  *,*::before,*::after{box-sizing:border-box;margin:0;padding:0;}
  html{overflow-x:hidden;}
  body{
    font-family:var(--sans);font-size:13.5px;line-height:1.6;
    background:var(--bg);color:var(--text);
    -webkit-font-smoothing:antialiased;overflow-x:hidden;
    transition:background .25s,color .25s;
  }
  .wrap{max-width:1100px;width:100%;margin:0 auto;padding:0 24px;}

  /* Header */
  header{position:sticky;top:0;z-index:100;background:var(--surface);border-bottom:1px solid var(--border);}
  .nav{display:flex;align-items:center;justify-content:space-between;height:52px;gap:16px;}
  .brand{display:flex;align-items:center;gap:10px;text-decoration:none;}
  .brand-mark{width:26px;height:26px;background:var(--text);color:var(--surface);border-radius:3px;
    display:flex;align-items:center;justify-content:center;font-weight:800;font-size:11px;letter-spacing:.5px;}
  .brand-name{font-size:14px;font-weight:700;letter-spacing:-.02em;color:var(--text);}
  .brand-sep{width:1px;height:14px;background:var(--border);}
  .brand-repo{font-size:12px;color:var(--gold);font-weight:500;}
  .nav-right{display:flex;align-items:center;gap:6px;flex-shrink:0;}

  /* Buttons */
  .btn{display:inline-flex;align-items:center;justify-content:center;gap:5px;
    font-family:var(--sans);font-size:12.5px;font-weight:500;padding:6px 14px;
    border-radius:var(--r);cursor:pointer;border:1px solid transparent;
    text-decoration:none;white-space:nowrap;transition:all .15s;}
  .btn-primary{background:var(--gold);color:#fff;border-color:var(--gold);}
  .btn-primary:hover{opacity:.88;}
  .btn-outline{background:transparent;color:var(--text2);border-color:var(--border);}
  .btn-outline:hover{background:var(--surface2);color:var(--text);}
  .btn-sm{padding:4px 10px;font-size:11.5px;}
  .theme-btn{background:none;border:1px solid var(--border);color:var(--text3);
    border-radius:var(--r);padding:5px 9px;font-size:13px;cursor:pointer;transition:all .15s;}
  .theme-btn:hover{background:var(--surface2);color:var(--text);}

  /* Dropdown */
  .dropdown{position:relative;}
  .dropdown-menu{display:none;position:absolute;right:0;top:calc(100% + 6px);min-width:200px;
    background:var(--surface);border:1px solid var(--border);border-radius:var(--r-lg);
    box-shadow:0 12px 32px rgba(0,0,0,.12);z-index:999;overflow:hidden;padding:4px;}
  .dropdown:hover .dropdown-menu,.dropdown:focus-within .dropdown-menu{display:block;}
  .d-item{display:flex;align-items:center;gap:9px;padding:8px 12px;font-size:12.5px;
    color:var(--text2);text-decoration:none;cursor:pointer;border-radius:var(--r);
    transition:background .1s,color .1s;}
  .d-item:hover{background:var(--surface2);color:var(--text);}

  /* Main layout */
  main{padding:28px 0 72px;}

  /* Report header block */
  .report-header{
    padding:32px 0 24px;
    border-bottom:1px solid var(--border);
    margin-bottom:28px;
  }
  .report-eyebrow{
    font-size:10.5px;font-weight:700;text-transform:uppercase;
    letter-spacing:.12em;color:var(--gold);margin-bottom:10px;
  }
  .report-title{
    font-family:var(--font);font-size:26px;font-weight:400;
    color:var(--text);letter-spacing:-.01em;margin-bottom:8px;
  }
  .report-title span{color:var(--gold);}
  .report-meta-row{
    display:flex;flex-wrap:wrap;gap:20px;
    font-size:12px;color:var(--text3);
  }
  .report-meta-item strong{color:var(--text2);}
  .gold-rule{height:1px;background:linear-gradient(to right,var(--gold),transparent);
    margin-bottom:28px;opacity:.4;}

  /* KPI strip */
  .kpi-strip{
    display:grid;grid-template-columns:repeat(4,1fr);
    border:1px solid var(--border);border-radius:var(--r-lg);
    overflow:hidden;background:var(--border);gap:1px;margin-bottom:28px;
  }
  .kpi{background:var(--surface);padding:18px 20px;}
  .kpi-lbl{font-size:10px;font-weight:700;text-transform:uppercase;
    letter-spacing:.1em;color:var(--text3);margin-bottom:8px;}
  .kpi-val{font-family:var(--font);font-size:24px;font-weight:400;
    color:var(--text);letter-spacing:-.02em;line-height:1;margin-bottom:5px;}
  .kpi-sub{font-size:11px;color:var(--text3);}

  /* Tabs */
  .tab-bar{display:flex;border-bottom:1px solid var(--border);
    margin-bottom:20px;gap:0;overflow-x:auto;scrollbar-width:none;}
  .tab-bar::-webkit-scrollbar{display:none;}
  .tab-btn{background:none;border:none;border-bottom:2px solid transparent;
    padding:8px 14px;font-family:var(--sans);font-size:12.5px;font-weight:500;
    color:var(--text3);cursor:pointer;white-space:nowrap;margin-bottom:-1px;
    transition:color .15s,border-color .15s;display:inline-flex;align-items:center;gap:6px;}
  .tab-btn:hover{color:var(--text2);}
  .tab-btn.active{color:var(--gold);border-bottom-color:var(--gold);font-weight:600;}
  .count-chip{font-size:10px;font-weight:700;background:var(--gold-dim);color:var(--gold);
    padding:1px 6px;border-radius:99px;border:1px solid rgba(201,168,76,.25);}
  .tab-pane{display:none;}
  .tab-pane.active{display:block;animation:fadeUp .15s ease;}
  @keyframes fadeUp{from{opacity:0;transform:translateY(3px)}to{opacity:1;transform:translateY(0)}}

  /* Toolbar */
  .toolbar{display:flex;align-items:center;justify-content:space-between;
    gap:10px;flex-wrap:wrap;margin-bottom:14px;}
  .search-box{padding:6px 11px;font-size:12.5px;border:1px solid var(--border);
    border-radius:var(--r);background:var(--surface);color:var(--text);
    outline:none;flex:1;min-width:160px;max-width:260px;transition:border-color .15s;}
  .search-box:focus{border-color:var(--gold);}
  .filter-row{display:flex;gap:6px;flex-wrap:wrap;}
  .sel{padding:6px 9px;font-size:11.5px;border:1px solid var(--border);
    border-radius:var(--r);background:var(--surface);color:var(--text2);
    outline:none;cursor:pointer;}

  /* Cards */
  .card-list{display:flex;flex-direction:column;gap:10px;}
  .card{background:var(--surface);border:1px solid var(--border);
    border-radius:var(--r-lg);padding:16px 18px;transition:border-color .15s;}
  .card:hover{border-color:var(--gold);}
  .card-top{display:flex;align-items:flex-start;justify-content:space-between;
    gap:10px;margin-bottom:6px;}
  .card-meta{display:flex;align-items:center;gap:6px;flex-wrap:wrap;}
  .card-title{font-size:13.5px;font-weight:600;color:var(--text);}
  .card-id{font-family:var(--mono);font-size:10.5px;color:var(--text3);white-space:nowrap;}
  .card-body{font-size:12.5px;color:var(--text2);line-height:1.65;margin-bottom:10px;}

  /* Badges */
  .badge{display:inline-flex;align-items:center;padding:2px 7px;border-radius:3px;
    font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.05em;}
  .badge-critical,.badge-high{background:var(--red-dim);color:var(--red);}
  .badge-medium{background:var(--amber-dim);color:var(--amber);}
  .badge-low{background:var(--teal-dim);color:var(--teal);}
  .badge-cat{background:var(--surface2);color:var(--text3);border:1px solid var(--border);
    text-transform:none;font-weight:500;font-size:10.5px;border-radius:3px;}
  .badge-ok{background:var(--green-dim);color:var(--green);}
  .badge-err{background:var(--red-dim);color:var(--red);}
  .badge-warn{background:var(--amber-dim);color:var(--amber);}
  .badge-info{background:var(--teal-dim);color:var(--teal);}

  /* Evidence */
  .ev{background:var(--surface2);border:1px solid var(--border);
    border-radius:var(--r);padding:10px 13px;margin-top:8px;
    font-family:var(--mono);font-size:11.5px;overflow-x:auto;}
  .ev-header{display:flex;justify-content:space-between;
    font-family:var(--sans);font-size:10.5px;color:var(--text3);margin-bottom:5px;}

  /* AI chip */
  .ai-chip{border-left:2px solid var(--gold);background:var(--gold-dim);
    border-radius:0 var(--r) var(--r) 0;padding:9px 13px;margin-top:10px;
    font-size:12px;color:var(--text2);line-height:1.55;}
  .ai-chip strong{color:var(--text);}
  code{font-family:var(--mono);font-size:.88em;background:var(--surface2);
    border:1px solid var(--border);border-radius:2px;padding:1px 5px;word-break:break-all;}

  /* Challenge sections */
  .chal-section{background:var(--surface2);border-radius:var(--r);
    padding:11px 14px;margin-top:10px;font-size:12.5px;}
  .chal-section h4{font-size:10px;font-weight:700;text-transform:uppercase;
    letter-spacing:.1em;color:var(--text3);margin-bottom:5px;}
  .chal-section ul{padding-left:16px;color:var(--text2);line-height:1.65;}
  .chal-section p{color:var(--text2);margin-top:2px;}

  /* Callout */
  .callout{background:var(--gold-dim);border:1px solid rgba(201,168,76,.22);
    border-radius:var(--r);padding:12px 15px;font-size:12.5px;
    color:var(--text2);margin-bottom:16px;line-height:1.6;}

  /* Table */
  .table-wrap{background:var(--surface);border:1px solid var(--border);
    border-radius:var(--r-lg);overflow-x:auto;}
  table{width:100%;border-collapse:collapse;text-align:left;font-size:12.5px;}
  th{padding:10px 16px;font-size:10px;font-weight:700;text-transform:uppercase;
    letter-spacing:.1em;color:var(--text3);background:var(--surface2);
    border-bottom:1px solid var(--border);white-space:nowrap;}
  td{padding:11px 16px;border-bottom:1px solid var(--border);
    color:var(--text2);vertical-align:middle;}
  td strong{color:var(--text);}
  tr:last-child td{border-bottom:none;}
  tbody tr:hover td{background:var(--surface2);}

  /* Raw JSON pre */
  .raw-pre{background:var(--surface2);border:1px solid var(--border);
    border-radius:var(--r);padding:14px;font-family:var(--mono);font-size:11.5px;
    max-height:520px;overflow-y:auto;color:var(--text2);line-height:1.65;}

  /* Limits card */
  .section-head{font-size:10px;font-weight:700;text-transform:uppercase;
    letter-spacing:.1em;color:var(--text3);margin-bottom:10px;}
  .limits-ul{padding-left:16px;font-size:12.5px;color:var(--text2);line-height:1.85;}

  /* Footer */
  footer{border-top:1px solid var(--border);padding:20px 0;
    font-size:11.5px;color:var(--text3);text-align:center;}
  footer span{color:var(--gold);}

  @media(max-width:860px){
    .kpi-strip{grid-template-columns:repeat(2,1fr);}
    .wrap{padding:0 14px;}
  }
  @media(max-width:520px){
    .kpi-strip{grid-template-columns:1fr 1fr;}
    .report-title{font-size:20px;}
  }
"""


def render_html_report(capsule: "DependencyExitCapsule") -> str:
    """Render a fully self-contained luxury HTML report from a DependencyExitCapsule."""
    raw_json = json.dumps(capsule.model_dump(), indent=2)
    escaped_json = html.escape(raw_json)

    c = capsule
    meta = c.metadata
    findings = c.findings
    recs = c.recommendations
    challenges = c.recommendation_challenges
    verifs = c.verifications
    blast = c.blast_radii
    debt = c.verification_debt_details
    limits = c.limitations

    total_findings = len(findings)
    crit_count = sum(1 for f in findings if f.severity.value == "critical")
    high_count = sum(1 for f in findings if f.severity.value == "high")
    med_count  = sum(1 for f in findings if f.severity.value == "medium")

    verif_pass  = sum(1 for v in verifs if v.status.value == "verified")
    verif_total = len(verifs)
    debt_count  = len(debt)

    model_display = (c.model_info.get("model_name", "qwen2.5-coder:1.5b")
                     if c.model_info else "qwen2.5-coder:1.5b")
    model_mode    = (c.model_info.get("mode", "local_ollama_qwen")
                     if c.model_info else "local_ollama_qwen")

    gen_ts = getattr(meta, "generated_at", "")
    tool_ver = getattr(c, "tool_version", "0.2.0")

    # ── Findings HTML ───────────────────────────────────────────────────
    findings_parts = []
    for f in findings:
        sev = f.severity.value
        ev_html = "".join(f"""
          <div class="ev">
            <div class="ev-header">
              <span><strong>{html.escape(ev.file_path)}</strong> &middot; Line {ev.line_start or 1}</span>
              <span>{html.escape(ev.source_type)}</span>
            </div>
            <pre><code>{html.escape(ev.content_snippet or "")}</code></pre>
          </div>""" for ev in f.evidence)

        mr = next((r for r in recs if r.finding_id == f.id), None)
        rec_html = ""
        if mr:
            repl = (f" &rarr; <code>{html.escape(mr.target_replacement)}</code>"
                    if mr.target_replacement else "")
            rec_html = f"""
          <div class="ai-chip">
            <strong>AI:</strong> {html.escape(mr.suggested_action.upper())}{repl}
            <div style="margin-top:3px;color:var(--text3)">{html.escape(mr.rationale)}</div>
          </div>"""

        findings_parts.append(f"""
        <div class="card finding-item"
          data-severity="{sev}"
          data-category="{html.escape(f.category)}"
          data-search="{html.escape(f.package_name or '')} {html.escape(f.title)} {html.escape(f.explanation)}">
          <div class="card-top">
            <div class="card-meta">
              <span class="badge badge-{sev}">{sev}</span>
              <span class="badge badge-cat">{html.escape(f.category)}</span>
              <span class="card-title">{html.escape(f.package_name or f.id)}: {html.escape(f.title)}</span>
            </div>
            <span class="card-id">{html.escape(f.id)}</span>
          </div>
          <div class="card-body">{html.escape(f.explanation)}</div>
          {ev_html}{rec_html}
        </div>""")
    findings_body = "".join(findings_parts)

    # ── Challenges HTML ─────────────────────────────────────────────────
    chal_parts = []
    for ch in challenges:
        ass_li  = "".join(f"<li>{html.escape(a)}</li>" for a in ch.assumptions)
        cnt_li  = "".join(f"<li>{html.escape(ci)}</li>" for ci in ch.counterarguments)
        badge   = ('<span class="badge badge-ok">Verified</span>'
                   if ch.check_result == "VERIFIED"
                   else f'<span class="badge badge-warn">{html.escape(ch.check_result)}</span>')
        chal_parts.append(f"""
        <div class="card">
          <div class="card-top">
            <div class="card-meta">
              <span class="card-title">Challenge &mdash; {html.escape(ch.package_name)}</span>
              <span class="badge badge-cat">{html.escape(ch.recommendation_id)}</span>
            </div>
            {badge}
          </div>
          <div class="chal-section"><h4>Assumptions</h4>
            <ul>{ass_li or "<li>Standard API parity assumed.</li>"}</ul></div>
          <div class="chal-section"><h4>Counterarguments &amp; Risks</h4>
            <ul>{cnt_li or "<li>Migration requires testing.</li>"}</ul></div>
          <div class="chal-section"><h4>Disproving Evidence</h4>
            <p>{html.escape(ch.disproving_evidence)}</p></div>
          <div class="chal-section"><h4>Required Check</h4>
            <p><code>{html.escape(ch.verification_check_needed)}</code></p></div>
        </div>""")
    challenges_body = "".join(chal_parts)

    # ── Blast radius rows ───────────────────────────────────────────────
    blast_rows = []
    for b in blast:
        lvl = b.risk_level.value
        cls = ("badge-err" if lvl in ("critical", "high")
               else "badge-warn" if lvl == "medium" else "badge-info")
        blast_rows.append(f"""
        <tr>
          <td><strong>{html.escape(b.dependency_name)}</strong></td>
          <td><span class="badge {cls}">{lvl}</span></td>
          <td>{html.escape(", ".join(b.importing_files) or "None (Ghost)")}</td>
          <td>{html.escape(", ".join(b.affected_tests) or "None")}</td>
          <td>{html.escape(b.summary)}</td>
        </tr>""")
    blast_body = "".join(blast_rows) or (
        '<tr><td colspan="5" style="text-align:center;padding:32px;'
        'color:var(--text3)">No blast radius data.</td></tr>')

    # ── Verification rows ───────────────────────────────────────────────
    verif_rows = []
    for v in verifs:
        stat = v.status.value
        cls  = ("badge-ok" if stat == "verified"
                else "badge-err" if stat == "failed" else "badge-warn")
        verif_rows.append(f"""
        <tr>
          <td><code>{html.escape(v.id)}</code></td>
          <td>{html.escape(v.target)}</td>
          <td><span class="badge {cls}">{stat.upper()}</span></td>
          <td style="text-align:center">{v.exit_code if v.exit_code is not None else "—"}</td>
          <td style="text-align:right">{v.duration_ms}ms</td>
          <td style="text-align:center">{"Yes" if v.sandbox_used else "No"}</td>
        </tr>""")
    verif_body = "".join(verif_rows) or (
        '<tr><td colspan="6" style="text-align:center;padding:32px;'
        'color:var(--text3)">No verification results.</td></tr>')

    # ── Debt items ──────────────────────────────────────────────────────
    if not debt:
        debt_body = """
        <div class="card" style="text-align:center;padding:28px;">
          <div style="font-size:20px;color:var(--green);margin-bottom:6px;">&#10003;</div>
          <strong style="color:var(--green)">Zero Verification Debt</strong>
          <p style="font-size:12px;color:var(--text3);margin-top:4px;">
            All recommendations proven in isolated sandbox.</p>
        </div>"""
    else:
        debt_parts = []
        for d in debt:
            debt_parts.append(f"""
            <div class="card">
              <div class="card-top">
                <span class="card-title">{html.escape(d.id)}: {html.escape(d.title)}</span>
                <span class="badge badge-warn">{html.escape(d.status)}</span>
              </div>
              <p style="font-size:12.5px;margin-bottom:5px;color:var(--text2)">
                <strong>Why unverified:</strong> {html.escape(d.unverified_reason)}</p>
              <p style="font-size:12px;color:var(--text3)">
                <strong>Next action:</strong> {html.escape(d.recommended_maintainer_action)}</p>
            </div>""")
        debt_body = "".join(debt_parts)

    limits_li = "".join(f"<li>{html.escape(lim)}</li>" for lim in limits)

    # ── Assemble ────────────────────────────────────────────────────────
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>DocRep Report &mdash; {html.escape(meta.repo_name)}</title>
  <style>{_CSS}</style>
</head>
<body>

  <header>
    <div class="wrap">
      <nav class="nav">
        <div class="brand">
          <div class="brand-mark">DR</div>
          <span class="brand-name">DocRep</span>
          <div class="brand-sep"></div>
          <span class="brand-repo">{html.escape(meta.repo_name)}</span>
        </div>
        <div class="nav-right">
          <div class="dropdown">
            <button class="btn btn-outline btn-sm">&#8595; Export</button>
            <div class="dropdown-menu">
              <a class="d-item" onclick="downloadJSON()" style="cursor:pointer">
                <span>{{}}</span> Machine JSON
              </a>
              <a class="d-item" onclick="downloadMD()" style="cursor:pointer">
                <span>&#8801;</span> Markdown Summary
              </a>
              <a class="d-item" onclick="window.print()" style="cursor:pointer">
                <span>&#9113;</span> Print / Save PDF
              </a>
            </div>
          </div>
          <button class="theme-btn" onclick="toggleTheme()" title="Toggle theme">&#9680;</button>
        </div>
      </nav>
    </div>
  </header>

  <main>
    <div class="wrap">

      <!-- Report identity block -->
      <div class="report-header">
        <div class="report-eyebrow">Dependency Exit Capsule &mdash; Proof-Carrying Artifact</div>
        <h1 class="report-title">
          {html.escape(meta.repo_name)} <span>Resilience Report</span>
        </h1>
        <div class="report-meta-row">
          <span><strong>Generated:</strong> {html.escape(str(gen_ts)[:19].replace("T", " "))}</span>
          <span><strong>Tool:</strong> DocRep v{html.escape(str(tool_ver))}</span>
          <span><strong>Model:</strong> {html.escape(model_display)} via {html.escape(model_mode)}</span>
          <span><strong>Python:</strong> {html.escape(str(meta.python_version_detected))}</span>
          <span><strong>Files:</strong> {meta.source_files_count}</span>
        </div>
      </div>
      <div class="gold-rule"></div>

      <!-- KPI strip -->
      <div class="kpi-strip">
        <div class="kpi">
          <div class="kpi-lbl">Repository</div>
          <div class="kpi-val">{html.escape(meta.repo_name)}</div>
          <div class="kpi-sub">{meta.source_files_count} files &middot; {len(meta.manifests_found)} manifests</div>
        </div>
        <div class="kpi">
          <div class="kpi-lbl">Findings</div>
          <div class="kpi-val">{total_findings}</div>
          <div class="kpi-sub" style="color:var(--red)">{crit_count} Critical &middot; {high_count} High &middot; {med_count} Med</div>
        </div>
        <div class="kpi">
          <div class="kpi-lbl">Sandbox Checks</div>
          <div class="kpi-val" style="color:var(--green)">{verif_pass} / {verif_total}</div>
          <div class="kpi-sub">Passed in isolated sandbox</div>
        </div>
        <div class="kpi">
          <div class="kpi-lbl">Verification Debt</div>
          <div class="kpi-val">{debt_count}</div>
          <div class="kpi-sub">{"No unverified items" if debt_count == 0 else "Items need maintainer test"}</div>
        </div>
      </div>

      <!-- Tabs -->
      <div class="tab-bar">
        <button class="tab-btn active" onclick="switchTab('tab-findings')">
          Findings <span class="count-chip">{total_findings}</span>
        </button>
        <button class="tab-btn" onclick="switchTab('tab-ai')">
          AI Challenges <span class="count-chip">{len(challenges)}</span>
        </button>
        <button class="tab-btn" onclick="switchTab('tab-blast')">
          Blast Radius <span class="count-chip">{len(blast)}</span>
        </button>
        <button class="tab-btn" onclick="switchTab('tab-verif')">
          Verification <span class="count-chip">{verif_total}</span>
        </button>
        <button class="tab-btn" onclick="switchTab('tab-debt')">Debt &amp; Limits</button>
        <button class="tab-btn" onclick="switchTab('tab-raw')">Raw JSON</button>
      </div>

      <!-- TAB 1: FINDINGS -->
      <div class="tab-pane active" id="tab-findings">
        <div class="toolbar">
          <input type="text" class="search-box" id="findingSearch"
            placeholder="Search packages, files, categories&hellip;"
            oninput="filterFindings()">
          <div class="filter-row">
            <select id="severityFilter" class="sel" onchange="filterFindings()">
              <option value="ALL">All Severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
            <select id="categoryFilter" class="sel" onchange="filterFindings()">
              <option value="ALL">All Categories</option>
              <option value="migration_tripwire">Migration Tripwires</option>
              <option value="ghost_dependency">Ghost Dependencies</option>
              <option value="manifest_conflict">Manifest Conflicts</option>
              <option value="private_api">Private APIs</option>
            </select>
          </div>
        </div>
        <div class="card-list" id="findingsList">
          {findings_body if findings_body else
           '<div style="text-align:center;padding:48px;color:var(--text3)">No findings identified.</div>'}
        </div>
      </div>

      <!-- TAB 2: AI CHALLENGES -->
      <div class="tab-pane" id="tab-ai">
        <div class="callout">
          <strong>Model:</strong>&nbsp;<code>{html.escape(model_display)}</code>
          &mdash; All suggestions are probabilistic AI outputs challenged by
          assumptions, counterarguments and sandbox checks. Not deterministic.
        </div>
        <div class="card-list">
          {challenges_body if challenges_body else
           '<div style="text-align:center;padding:48px;color:var(--text3)">No AI challenges available.</div>'}
        </div>
      </div>

      <!-- TAB 3: BLAST RADIUS -->
      <div class="tab-pane" id="tab-blast">
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Dependency</th><th>Risk</th>
                <th>Direct Imports</th><th>Affected Tests</th><th>Summary</th>
              </tr>
            </thead>
            <tbody>{blast_body}</tbody>
          </table>
        </div>
      </div>

      <!-- TAB 4: VERIFICATION -->
      <div class="tab-pane" id="tab-verif">
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Check ID</th><th>Target</th><th>Status</th>
                <th style="text-align:center">Exit</th>
                <th style="text-align:right">Duration</th>
                <th style="text-align:center">Sandbox</th>
              </tr>
            </thead>
            <tbody>{verif_body}</tbody>
          </table>
        </div>
      </div>

      <!-- TAB 5: DEBT & LIMITS -->
      <div class="tab-pane" id="tab-debt">
        <div class="card-list" style="margin-bottom:14px;">
          {debt_body}
        </div>
        <div class="card">
          <div class="section-head">Scanner &amp; Environment Limitations</div>
          <ul class="limits-ul">
            {limits_li if limits_li else
             "<li>No scanner limitations reported for this run.</li>"}
          </ul>
        </div>
      </div>

      <!-- TAB 6: RAW JSON -->
      <div class="tab-pane" id="tab-raw">
        <div class="card">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;">
            <span style="font-size:13px;font-weight:600;color:var(--text)">
              Complete Signed Machine JSON
            </span>
            <button class="btn btn-outline btn-sm" onclick="copyJSON()">Copy</button>
          </div>
          <pre class="raw-pre"><code id="rawJsonBlock">{escaped_json}</code></pre>
        </div>
      </div>

    </div><!-- /.wrap -->
  </main>

  <footer>
    <div class="wrap">
      Generated by <span>DocRep v{html.escape(str(tool_ver))}</span>
      &mdash; local AI via <span>{html.escape(model_mode)}</span>
      &mdash; all findings are evidence-backed, AI output is probabilistic.
    </div>
  </footer>

  <script id="capsule-data" type="application/json">
    {escaped_json}
  </script>

  <script>
    /* Theme */
    function toggleTheme() {{
      const c = document.documentElement.getAttribute('data-theme') || 'light';
      const n = c === 'dark' ? 'light' : 'dark';
      document.documentElement.setAttribute('data-theme', n);
      localStorage.setItem('docrep-theme', n);
    }}
    const _t = localStorage.getItem('docrep-theme');
    if (_t) document.documentElement.setAttribute('data-theme', _t);
    else if (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches)
      document.documentElement.setAttribute('data-theme', 'dark');

    /* Tabs */
    function switchTab(id) {{
      document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
      document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
      const t = document.getElementById(id); if (t) t.classList.add('active');
      const b = Array.from(document.querySelectorAll('.tab-btn'))
        .find(x => x.getAttribute('onclick')?.includes(id));
      if (b) b.classList.add('active');
    }}

    /* Filter */
    function filterFindings() {{
      const q   = document.getElementById('findingSearch').value.toLowerCase();
      const sev = document.getElementById('severityFilter').value;
      const cat = document.getElementById('categoryFilter').value;
      document.querySelectorAll('.finding-item').forEach(el => {{
        const ok = (!q || el.getAttribute('data-search').toLowerCase().includes(q))
          && (sev === 'ALL' || el.getAttribute('data-severity') === sev)
          && (cat === 'ALL' || el.getAttribute('data-category') === cat);
        el.style.display = ok ? 'block' : 'none';
      }});
    }}

    /* Downloads */
    function downloadJSON() {{
      const d = document.getElementById('capsule-data').textContent.trim();
      _dl(d, 'capsule.json', 'application/json');
    }}
    function downloadMD() {{
      const data = JSON.parse(document.getElementById('capsule-data').textContent.trim());
      let md = `# DocRep Dependency Exit Capsule\\n`;
      md += `> Repository: ${{data.metadata.repo_name}} | Python: ${{data.metadata.python_version_detected}}\\n\\n`;
      md += `## Findings (${{data.findings.length}})\\n`;
      data.findings.forEach(f => {{
        md += `- **[${{f.severity.toUpperCase()}}] ${{f.id}}**: ${{f.title}}\\n  ${{f.explanation}}\\n`;
      }});
      md += `\\n## Verifications (${{data.verifications.length}})\\n`;
      data.verifications.forEach(v => {{
        md += `- **${{v.id}}**: ${{v.target}} (${{v.status.toUpperCase()}}, exit: ${{v.exit_code}})\\n`;
      }});
      _dl(md, 'capsule.md', 'text/markdown');
    }}
    function _dl(content, name, type) {{
      const a = Object.assign(document.createElement('a'), {{
        href: URL.createObjectURL(new Blob([content], {{type}})),
        download: name
      }});
      a.click(); URL.revokeObjectURL(a.href);
    }}
    function copyJSON() {{
      navigator.clipboard.writeText(document.getElementById('rawJsonBlock').textContent)
        .then(() => alert('Copied JSON to clipboard!'));
    }}
  </script>
</body>
</html>
"""
