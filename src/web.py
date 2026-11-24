#!/usr/bin/env python3
"""The review page: what exodon filtered, what it let through, and what it was
unsure of, one compact row per message that opens to correct it (not spam /
spam) or to always allow / block the sender; and a lists page (/lists) to
view, filter, test, add to and remove from the allow and block lists.

    python3 src/web.py        # serves on :8799 (EXODON_WEB_PORT)

Runs in its own container with no mail token: it reads the decision log,
writes the owner's marks to it, and appends validated lines to the list
files (src/listedit.py). On a live mailbox a correction also asks for the
message to be moved (the `moves` table); the watcher, which holds the token,
makes the move (shadow.Shadow.maybe_moves). The page never touches the mailbox.

One machine-readable route: GET /api/readout (src/readout.py), for another
agent to summarize the filtering. It needs a bearer token
(EXODON_READOUT_TOKEN, plus one EXODON_READOUT_TOKEN_<READER> per extra
reader; none set = route off) and is the only route the containers named in
EXODON_WEB_READERS may reach.

No password (tailnet only, by the owner's choice), so it defends itself
against other web pages instead: a fixed Host allowlist (DNS rebinding),
JSON-only POSTs from its own Origin (forged requests), no framing
(clickjacking), and every logged field escaped (senders and subjects are
written by strangers).
"""

from __future__ import annotations

import datetime as dt
import hmac
import html
import json
import logging
import math
import os
import pathlib
import re
import socket
import sqlite3
import sys
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import config  # noqa: E402
import grade as G  # noqa: E402
import listedit as E  # noqa: E402
import lists as L  # noqa: E402
import readout as R  # noqa: E402
import shadow as S  # noqa: E402

log = logging.getLogger("exodon.web")

PORT = int(os.environ.get("EXODON_WEB_PORT", "8799"))
# The public name lives in .env (EXODON_WEB_HOSTS / EXODON_WEB_ORIGIN).
HOSTS = {h.strip().lower() for h in os.environ.get(
    "EXODON_WEB_HOSTS", "localhost:8799,exodon-web:8799").split(",") if h.strip()}
ORIGIN = os.environ.get("EXODON_WEB_ORIGIN", "http://localhost:8799")
# Other containers share the proxy's network (and could forge any header), so
# only the proxy itself -- and local probes -- may talk to the page. Empty
# means no peer check (running outside Docker).
PROXY = os.environ.get("EXODON_WEB_PROXY", "")
LOCAL_PEERS = {"127.0.0.1", "::1"}
# Containers allowed to call /api/readout directly (and nothing else).
READERS = [r.strip() for r in os.environ.get("EXODON_WEB_READERS", "").split(",") if r.strip()]
# One token per reader (e.g. EXODON_READOUT_TOKEN_AGENT), so each
# revokes alone.
READOUT_TOKEN = [v for k, v in sorted(os.environ.items())
                 if (k == "EXODON_READOUT_TOKEN" or k.startswith("EXODON_READOUT_TOKEN_")) and v]
STALE_S = 600
ROW_CAP = 500
SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; "
                               "script-src 'unsafe-inline'; connect-src 'self'; "
                               "frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "Cache-Control": "no-store",
}
BIDI = dict.fromkeys(map(ord, "‪‫‬‭‮⁦⁧⁨⁩‎‏"))


class Bad(Exception):
    """A request we refuse with 400 and a reason."""


# ------------------------------------------------------------------ helpers


def esc(v) -> str:
    return html.escape(str(v if v is not None else "").translate(BIDI), quote=True)


def has_col(store: S.Store, col: str) -> bool:
    return col in store.cols


def has_table(store: S.Store, name: str) -> bool:
    return store.db.execute("select 1 from sqlite_master where type='table' and name=?",
                            (name,)).fetchone() is not None


def label_expr(store: S.Store) -> str:
    return G.LABEL if has_col(store, "feedback") else "outcome"


def load_lists(lists_dir: pathlib.Path) -> list:
    return L.load(lists_dir / "allow.txt", "allow") + L.load(lists_dir / "block.txt", "block")


def agreement(would: str, label: str | None) -> str:
    """✓ agrees with the owner, ✗ disagrees, ? possible miss, '' no signal."""
    if label == "spam":
        return {"screen": "✓", "inbox": "✗"}.get(would, "")
    if label == "real":
        return {"inbox": "✓", "screen": "✗"}.get(would, "")
    if label == "fastmail_spam":
        return {"screen": "✓", "inbox": "?"}.get(would, "")
    return ""


def why(r: dict) -> str:
    if r["source"] == "block":
        return f"blocked by {r['list_entry']}"
    if r["source"] == "allow":
        return f"allowed by {r['list_entry']}"
    if r["source"] == "rule":
        return f"rule: {r['list_entry']}"
    if r["would"] == "error":
        return "model error"
    out = f"model {r['p_spam']:.2f}" if r["p_spam"] is not None else "model"
    if r.get("list_note"):
        out += f" · {r['list_note'].split(' (')[0]}"
    return out


def did(r: dict) -> str:
    """Live mode: what exodon actually did, shown under the reason."""
    a = r.get("action") or ""
    return " · moved to Spam" if a == "moved" else f" · {a}" if a else ""


def where_now(r: dict) -> str:
    if r["outcome_folder"]:
        return r["outcome_folder"]
    if r["graded_at"]:
        return "Inbox"
    return f"arrived in {r['arrived_in'] or '?'}"


def cutoff(days: float) -> str:
    return (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=days)).strftime(
        "%Y-%m-%dT%H:%M:%SZ")


# --------------------------------------------------------------------- page

VIEWS = {
    # name: (tab label, one-line hint)
    "filtered": ("Filtered", "Moved to Spam, or would have been. Open one to put it back."),
    "through": ("Let through", "Left in your Inbox. Open one to send it to Spam."),
    "unsure": ("Unsure", "The ones exodon was not certain about, either way."),
}
DAYS = 7
MORE_DAYS = 30
HITS_DAYS = 30

CSS = """
:root{--bg:#f6f5f1;--fg:#1c1c1a;--mute:#6b6a64;--faint:#a3a29b;--line:#e6e4dd;--card:#fff;
--sunk:#eeece6;--hover:#faf9f6;--accent:#2b4fc7;--accent-fg:#fff;
--red:#b42318;--red-bg:#fdecea;--amber:#9a6700;--green:#26703a;--green-bg:#e7f3ea;
--mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
--sans:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
@media (prefers-color-scheme:dark){:root{--bg:#121211;--fg:#ebeae6;--mute:#a09f99;--faint:#6c6b66;
--line:#272725;--card:#1a1a19;--sunk:#222220;--hover:#1f1f1d;--accent:#8aa6ff;--accent-fg:#0f1530;
--red:#ff8f84;--red-bg:#3a1d1a;--amber:#e8b44a;--green:#8fd6a0;--green-bg:#16301d}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.45 var(--sans);
-webkit-font-smoothing:antialiased}
a{color:inherit}
.mono{font-family:var(--mono);font-size:12.5px}
button,input{font:inherit;color:inherit}
:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
header.top{border-bottom:1px solid var(--line)}
.bar,main{max-width:900px;margin:0 auto;padding-left:16px;padding-right:16px}
.bar{display:flex;align-items:center;gap:22px;height:52px}
.brand{font-weight:700;letter-spacing:-.02em;font-size:16px;display:flex;align-items:center;gap:8px;
text-decoration:none}
.brand i{width:9px;height:9px;border-radius:2px;background:var(--accent);transform:rotate(45deg)}
nav.views{display:flex;gap:18px}
nav.views a{text-decoration:none;color:var(--mute);padding:15px 0;border-bottom:2px solid transparent}
nav.views a.on{color:var(--fg);border-color:var(--fg)}
.status{margin-left:auto;display:flex;align-items:center;gap:7px;color:var(--mute);font-size:12.5px}
.dot{width:7px;height:7px;border-radius:50%;background:var(--green);flex:none}
.status.bad{color:var(--red)}.status.bad .dot{background:var(--red)}
main{padding-top:22px;padding-bottom:64px}
/* toolbar */
.toolbar{display:flex;align-items:center;gap:12px;flex-wrap:wrap;margin-bottom:6px}
.tabs{display:flex;gap:4px}
.tabs a{text-decoration:none;padding:6px 12px;border-radius:8px;color:var(--mute);font-weight:500}
.tabs a:hover{color:var(--fg)}
.tabs a.on{background:var(--fg);color:var(--bg)}
.tabs .n{font-variant-numeric:tabular-nums;font-weight:400;margin-left:5px;opacity:.65}
.right{margin-left:auto;display:flex;align-items:center;gap:10px}
.boxes{display:flex;gap:2px;font-size:13px}
.boxes a{text-decoration:none;color:var(--mute);padding:4px 8px;border-radius:6px}
.boxes a.on{color:var(--fg);background:var(--sunk)}
input[type=search],input[type=text]{background:var(--card);border:1px solid var(--line);
border-radius:8px;padding:5px 10px;min-height:32px}
form.find input{width:150px;transition:width .15s}
form.find input:focus,form.find input:not(:placeholder-shown){width:220px}
.hint{color:var(--mute);margin:0 0 18px;font-size:13px}
/* message list */
.day{margin:0 0 18px}
.day h3{font-size:12px;font-weight:600;color:var(--mute);margin:0 0 6px;padding-left:14px}
.list{background:var(--card);border:1px solid var(--line);border-radius:12px;overflow:hidden}
details.msg+details.msg{border-top:1px solid var(--line)}
details.msg summary{list-style:none;cursor:pointer;display:grid;align-items:center;
grid-template-columns:10px minmax(0,190px) minmax(0,1fr) auto;grid-template-areas:"f w l e";
gap:12px;padding:10px 14px}
summary>:nth-child(1){grid-area:f}summary .who{grid-area:w}summary .line{grid-area:l}
summary .end{grid-area:e}
details.msg summary::-webkit-details-marker{display:none}
details.msg summary:hover{background:var(--hover)}
details.msg[open] summary{background:var(--hover)}
.flag{width:6px;height:6px;border-radius:50%}
.flag.x{background:var(--red)}.flag.q{background:var(--amber)}
.who{font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.line{white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.line .pv{color:var(--faint)}
.end{display:flex;align-items:center;gap:10px;color:var(--faint);font-size:12.5px;
font-variant-numeric:tabular-nums;white-space:nowrap}
.acct{border:1px solid var(--line);border-radius:5px;padding:0 6px;font-size:11.5px}
.tag{display:none;color:var(--green);font-weight:500}
details.marked .tag{display:inline}
details.marked .who,details.marked .line{color:var(--mute);font-weight:400}
.more{padding:2px 14px 14px 36px}
.meta{color:var(--mute);font-size:12.5px;display:flex;flex-wrap:wrap;gap:4px 14px;margin-bottom:8px}
.preview{margin:0 0 12px;color:var(--mute);font-size:13px;max-width:68ch;overflow-wrap:anywhere}
.acts{display:flex;flex-wrap:wrap;align-items:center;gap:8px}
.btn{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:5px 12px;
cursor:pointer;font-size:13px}
.btn:hover{background:var(--sunk)}
.btn.primary{background:var(--fg);color:var(--bg);border-color:var(--fg)}
.btn.primary:hover{opacity:.88}
.link{background:none;border:0;color:var(--mute);cursor:pointer;padding:0;font-size:12.5px;
text-decoration:underline;text-underline-offset:2px}
.link:hover{color:var(--fg)}
details.marked .acts .primary,details.listed .acts .lst{display:none}
.state{font-size:13px;margin-top:10px;display:flex;flex-wrap:wrap;gap:4px 12px;align-items:baseline}
.state:empty{display:none}
.state .bad{color:var(--red)}
.empty{color:var(--mute);padding:48px 0;text-align:center}
.older{text-align:center;margin:6px 0 30px;font-size:13px}
.older a{color:var(--mute)}
.how{border-top:1px solid var(--line);padding-top:14px;color:var(--mute);font-size:13px}
.how b{color:var(--fg);font-weight:600}
.how p{margin:0 0 4px}
/* lists */
.lhead{display:flex;align-items:center;gap:12px;flex-wrap:wrap;margin-bottom:6px}
.lhead .right input{width:260px}
.verdict{min-height:20px;font-size:13px;margin:0 0 12px;color:var(--mute)}
.verdict b{color:var(--fg)}
form.add{display:grid;grid-template-columns:minmax(0,1.3fr) minmax(0,1fr) auto;gap:8px;padding:10px 14px;
border-bottom:1px solid var(--line);background:var(--hover)}
.ent{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1.2fr) 60px 28px;gap:12px;
align-items:center;padding:8px 14px;border-top:1px solid var(--line)}
form.add+.ent{border-top:0}
.ent .p{overflow-wrap:anywhere}
.ent .note{color:var(--mute);font-size:12.5px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.ent .h{color:var(--faint);font-size:12px;text-align:right;font-variant-numeric:tabular-nums}
.rm{background:none;border:0;color:var(--faint);cursor:pointer;font-size:17px;line-height:1;
padding:2px 6px;border-radius:6px;opacity:0}
.ent:hover .rm,.rm:focus-visible{opacity:1}
@media (hover:none){.rm{opacity:1}}
.rm:hover{color:var(--red);background:var(--red-bg)}
details.log{margin-top:22px;color:var(--mute);font-size:13px}
details.log summary{cursor:pointer}
details.log ul{margin:10px 0 0;padding:0}
details.log li{list-style:none;padding:6px 0;border-top:1px solid var(--line);display:flex;gap:10px;
flex-wrap:wrap;align-items:baseline}
.broken{background:var(--red-bg);color:var(--red);padding:10px 14px;border-radius:10px;margin:0 0 14px}
/* dialog + toast */
dialog{border:1px solid var(--line);border-radius:12px;background:var(--card);color:var(--fg);
padding:18px;max-width:440px;width:calc(100% - 32px);box-shadow:0 20px 50px rgb(0 0 0/.25)}
dialog::backdrop{background:rgb(0 0 0/.35)}
dialog p{margin:0 0 10px}dialog pre{white-space:pre-wrap;overflow-wrap:anywhere;background:var(--sunk);
padding:8px 10px;border-radius:8px;margin:0 0 14px}
dialog .btns{display:flex;justify-content:flex-end;gap:8px}
#toast{position:fixed;bottom:18px;left:50%;transform:translateX(-50%);background:var(--fg);
color:var(--bg);padding:9px 14px;border-radius:9px;font-size:13px;opacity:0;pointer-events:none;
transition:opacity .2s;max-width:calc(100% - 32px)}
#toast.on{opacity:1}
@media (max-width:700px){
.bar{gap:16px}.right{margin-left:0;width:100%;justify-content:space-between}
form.find input,form.find input:focus,form.find input:not(:placeholder-shown){width:160px}
details.msg summary{grid-template-columns:10px minmax(0,1fr) auto;
grid-template-areas:"f w e" "f l l";gap:2px 10px}
.more{padding-left:36px}
.lhead .right input{width:100%}.lhead .right{flex:1}
form.add{grid-template-columns:1fr auto}form.add input[name=note]{grid-column:1/2;grid-row:2}
.ent{grid-template-columns:minmax(0,1fr) auto 28px}.ent .note{grid-column:1/2;grid-row:2}}
"""

JS = """
const post=(u,b)=>fetch(u,{method:'POST',headers:{'Content-Type':'application/json'},
  body:JSON.stringify(b)}).then(async r=>{const j=await r.json().catch(()=>({error:r.statusText}));
  if(!r.ok) throw new Error(j.error||r.statusText); return j;});
const toastEl=document.getElementById('toast');let tt;
const toast=m=>{toastEl.textContent=m;toastEl.classList.add('on');clearTimeout(tt);
  tt=setTimeout(()=>toastEl.classList.remove('on'),3200);};
const fail=e=>toast(e.message);
const dlg=document.getElementById('confirm');
const ask=(msg,line,ok)=>new Promise(res=>{dlg.querySelector('p').textContent=msg;
  const pre=dlg.querySelector('pre');pre.textContent=line||'';pre.hidden=!line;
  dlg.querySelector('[value=ok]').textContent=ok||'Confirm';
  dlg.onclose=()=>res(dlg.returnValue==='ok');dlg.returnValue='';dlg.showModal();});
const el=(tag,cls,text)=>{const e=document.createElement(tag);if(cls)e.className=cls;
  if(text!=null)e.textContent=text;return e;};
const reload=()=>{sessionStorage.setItem('y',scrollY);location.reload();};
try{const y=sessionStorage.getItem('y');if(y){sessionStorage.removeItem('y');scrollTo(0,+y);}}catch(e){}

/* mail */
const msgs=[...document.querySelectorAll('details.msg')];
function render(d){
  const s=d.dataset, fb=s.feedback, st=d.querySelector('.state');
  d.classList.toggle('marked',!!fb);d.classList.toggle('listed',!!s.change);
  const tag=d.querySelector('.tag');if(tag)tag.textContent=fb==='real'?'✓ Not spam':fb==='spam'?'✓ Spam':'';
  st.textContent='';
  if(fb){
    let t=fb==='real'?'You marked this not spam.':'You marked this spam.';
    const ms=s.ms||'';
    let bad=false;
    if(ms==='pending') t+=s.dir==='inbox'?' Moving it back to your Inbox…':' Moving it to Spam…';
    else if(ms==='done') t+=s.dir==='inbox'?' It is back in your Inbox.':' It is in Spam now.';
    else if(/^(refused|failed)/.test(ms)){t+=' Could not move it: '+ms.replace(/^\\w+: /,'')+'.';bad=true;}
    else if(s.mode!=='live') t+=' This mailbox is in shadow mode, so nothing moved.';
    st.append(el('span',bad?'bad':'',t));
    const u=el('button','link','Undo');u.onclick=()=>mark(d,null);st.append(u);
  }
  if(s.change){
    st.append(el('span','','On the '+s.list+' list as '+s.pattern+'.'));
    const u=el('button','link','Take it off');u.onclick=()=>post('/api/list/undo',{change_id:+s.change})
      .then(()=>{delete s.change;render(d);toast('Taken off the '+s.list+' list');}).catch(fail);
    st.append(u);
  }
}
function mark(d,label){
  return post('/api/mark',{account:d.dataset.account,email_id:d.dataset.id,label})
    .then(j=>{const s=d.dataset;s.feedback=label||'';
      if(j.move){s.dir=j.move;s.ms='pending';}else if(s.ms==='pending'){s.ms='';}
      render(d);poll();}).catch(fail);
}
async function list(d,b){
  const s=d.dataset,req={account:s.account,email_id:s.id,list:b.dataset.list,scope:b.dataset.scope};
  try{
    const v=await post('/api/list/preview',req);
    if(v.status!=='ok'){toast(v.message);return;}
    if(!await ask(v.message,v.line,'Add to '+req.list+' list')) return;
    const r=await post('/api/list/add',req);
    s.change=r.change_id;s.list=req.list;s.pattern=v.pattern;render(d);
    const want=req.list==='allow'?'real':'spam';
    if(s.feedback!==want&&(want==='real')===(s.would==='screen')) await mark(d,want);
  }catch(e){fail(e);}
}
msgs.forEach(d=>{render(d);
  d.querySelectorAll('[data-label]').forEach(b=>b.onclick=()=>mark(d,b.dataset.label));
  d.querySelectorAll('[data-list]').forEach(b=>b.onclick=()=>list(d,b));});
let polls=0,timer=null;
function poll(){
  if(timer||!msgs.some(d=>d.dataset.ms==='pending')) return;
  timer=setTimeout(()=>{timer=null;if(++polls>40) return;
    fetch('/api/moves').then(r=>r.json()).then(j=>{
      const by=new Map(msgs.map(d=>[d.dataset.account+'\\n'+d.dataset.id,d]));
      for(const m of j.moves){const d=by.get(m.account+'\\n'+m.email_id);
        if(d&&d.dataset.ms==='pending'&&m.dir===d.dataset.dir&&m.state!=='pending'){
          d.dataset.ms=m.state==='cancelled'?'':m.state;render(d);}}
      poll();}).catch(()=>poll());},6000);
}
poll();

/* lists */
document.querySelectorAll('button.rm').forEach(b=>b.onclick=async()=>{
  if(!await ask('Remove this from the '+b.dataset.list+' list? Senders it decided go to the next matching entry, or the model.',
    b.dataset.line,'Remove')) return;
  post('/api/list/remove',{list:b.dataset.list,line:b.dataset.line}).then(reload).catch(fail);});
document.querySelectorAll('button.undo').forEach(b=>b.onclick=()=>
  post('/api/list/undo',{change_id:+b.dataset.change}).then(reload).catch(fail));
const af=document.querySelector('form.add');
if(af) af.onsubmit=e=>{e.preventDefault();
  post('/api/list/new',{list:af.dataset.list,pattern:af.pattern.value,note:af.note.value})
    .then(v=>{toast(v.message);setTimeout(reload,700);}).catch(fail);};
const lf=document.querySelector('input.lfind');
if(lf){const out=document.querySelector('.verdict');let ct;
  lf.oninput=()=>{const q=lf.value.trim().toLowerCase();
    document.querySelectorAll('.ent').forEach(r=>r.hidden=q&&!r.dataset.text.includes(q));
    clearTimeout(ct);out.textContent='';
    if(/^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$/.test(q)) ct=setTimeout(()=>
      post('/api/list/check',{address:q}).then(v=>{out.textContent='';
        out.append(el('b','',q),' would be '+v.message.charAt(0).toLowerCase()+v.message.slice(1));})
        .catch(()=>{}),250);};}
"""


def _href(path: str, **q) -> str:
    keep = {k: v for k, v in q.items() if v not in (None, "", "all")}
    return path + ("?" + urllib.parse.urlencode(keep) if keep else "")


def view_where(view: str, store: S.Store) -> str:
    if view == "filtered":
        return "would = 'screen'"
    if view == "through":
        return "would in ('inbox','review','error')"
    if "action" in store.cols:  # unsure: what the daily digest lists
        return (f"(would = 'review' or (action = 'moved' and (source = 'rule' or "
                f"(source = 'model' and p_spam < {float(config.SURE_AT)}))))")
    return "would = 'review'"


def filters_from(params: dict, accounts: list[str]) -> dict:
    view = params.get("view", "filtered")
    account = params.get("account", "all")
    try:
        days = float(params.get("days", DAYS))
    except ValueError:
        days = DAYS
    days = min(max(days, 1), 60) if math.isfinite(days) else DAYS
    return {"view": view if view in VIEWS else "filtered",
            "account": account if account in accounts else "all",
            "days": days, "q": (params.get("q") or "").strip()[:100]}


def _where(f: dict, store: S.Store, view: str | None = None) -> tuple[list[str], list]:
    where, args = ["received_at >= ?", view_where(view or f["view"], store)], [cutoff(f["days"])]
    if f["account"] != "all":
        where.append("account = ?")
        args.append(f["account"])
    if f["q"]:
        needle = "%" + f["q"].lower().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        where.append("lower(coalesce(from_email,'') || ' ' || coalesce(from_name,'') || ' ' || "
                     "coalesce(subject,'')) like ? escape '\\'")
        args.append(needle)
    return where, args


def _status(store: S.Store, accts: list[str]) -> str:
    _, h = health(store, accts)
    bad = [a for a, v in h["accounts"].items() if not v["ok"]]
    detail = "; ".join(f"{a}: " + ("no heartbeat" if v["age_s"] is None else f"heartbeat {v['age_s']}s ago")
                       for a, v in h["accounts"].items())
    text = (", ".join(bad) + " stalled") if bad else "Watching"
    return (f'<span class="status{" bad" if bad else ""}" title="{esc(detail)}">'
            f'<span class="dot"></span>{esc(text)}</span>')


def _shell(view: str, inner: str, status: str, title: str) -> str:
    tabs = "".join(f'<a href="{href}" class="{"on" if v == view else ""}"'
                   f'{" aria-current=page" if v == view else ""}>{name}</a>'
                   for v, name, href in (("mail", "Mail", "/"), ("lists", "Allow &amp; block", "/lists")))
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        f'<title>{esc(title)} · exodon</title><style>{CSS}</style></head><body>'
        '<header class="top"><div class="bar"><a class="brand" href="/"><i></i>exodon</a>'
        f'<nav class="views">{tabs}</nav>{status}</div></header>'
        f'<main>{inner}</main>'
        '<dialog id="confirm"><form method="dialog"><p></p><pre class="mono"></pre>'
        '<div class="btns"><button class="btn" value="cancel">Cancel</button>'
        '<button class="btn primary" value="ok">Confirm</button></div></form></dialog>'
        f'<div id="toast" role="status" aria-live="polite"></div><script>{JS}</script></body></html>')


def plain(text: str | None) -> str:
    """A body preview as plain words: tags (HTML-only mail), entities and runs
    of whitespace removed, including a tag cut off at the end."""
    t = re.sub(r"<!--.*?(-->|$)|<(style|script|head)\b.*?(</\2\s*>|$)", " ", text or "",
               flags=re.S | re.I)
    t = re.sub(r"<[^>]*>|<[^>]*$", " ", t)
    return " ".join(html.unescape(t).split())


def _local(ts: str | None) -> dt.datetime | None:
    import zoneinfo
    try:
        t = dt.datetime.fromisoformat((ts or "").replace("Z", "+00:00"))
    except ValueError:
        return None
    if t.tzinfo is None:
        t = t.replace(tzinfo=dt.timezone.utc)
    return t.astimezone(zoneinfo.ZoneInfo(config.TZ))


def _day(t: dt.datetime | None, today: dt.date) -> str:
    if t is None:
        return "Undated"
    d = t.date()
    if d == today:
        return "Today"
    if d == today - dt.timedelta(days=1):
        return "Yesterday"
    return t.strftime("%A, %b %-d")


def _clock(t: dt.datetime | None) -> str:
    return t.strftime("%-I:%M %p").lower() if t else ""


def _how(store: S.Store, accounts: list[str], days: float) -> str:
    """Plain words: of the mail you filed, how much spam it caught and how
    much real mail it junked."""
    label = label_expr(store)
    lines = []
    for a in accounts:
        s = G.summary(store, a, days, label=label)
        lines.append(f'<p><b>{esc(a)}</b>: caught {s["spam_caught"]} of {s["spam"]} spam, '
                     f'junked {s["real_screened"]} of {s["real"]} real messages.</p>')
    span = f"last {days:g} day{'s' if days != 1 else ''}"
    return (f'<section class="how"><p>How it is doing, going by where you filed mail ({span}):</p>'
            + "".join(lines) + "</section>")


def latest_moves(store: S.Store, since: str | None = None) -> dict:
    """The newest move asked for each message: (account, email_id) -> (dir, state)."""
    if not has_table(store, "moves"):
        return {}
    where, args = ("where at >= ?", [since]) if since else ("", [])
    rows = store.db.execute(
        "select account, email_id, dir, state from moves where id in "
        f"(select max(id) from moves {where} group by account, email_id)", args)
    return {(a, i): (d, s) for a, i, d, s in rows}


def render_page(store: S.Store, params: dict, lists_dir: pathlib.Path,
                modes: dict | None = None, accts: list[str] | None = None) -> str:
    import zoneinfo
    modes = modes or {}
    accounts = [r[0] for r in store.db.execute(
        "select distinct account from decisions order by account")]
    f = filters_from(params, accounts)
    label = label_expr(store)

    counts = {}
    for v in VIEWS:
        w, a = _where(f, store, v)
        counts[v] = store.db.execute(f"select count(*) from decisions where {' and '.join(w)}",
                                     a).fetchone()[0]
    keep = {"account": f["account"], "q": f["q"],
            "days": None if f["days"] == DAYS else f"{f['days']:g}"}
    tabs = "".join(
        f'<a href="{esc(_href("/", view=None if v == "filtered" else v, **keep))}"'
        f' class="{"on" if f["view"] == v else ""}">{name}<span class="n">{counts[v]}</span></a>'
        for v, (name, _) in VIEWS.items())
    boxes = ""
    if len(accounts) > 1:
        boxes = '<nav class="boxes" aria-label="mailbox">' + "".join(
            f'<a href="{esc(_href("/", view=None if f["view"] == "filtered" else f["view"], account=v, q=f["q"], days=keep["days"]))}"'
            f' class="{"on" if f["account"] == v else ""}">{esc(t)}</a>'
            for v, t in [("all", "Both" if len(accounts) == 2 else "All")]
            + [(x, x) for x in accounts]) + "</nav>"
    hidden = "".join(f'<input type="hidden" name="{k}" value="{esc(v)}">'
                     for k, v in (("view", f["view"]), ("account", f["account"]),
                                  ("days", keep["days"]))
                     if v and v not in ("all", "filtered"))
    find = (f'<form class="find" method="get" action="/">{hidden}'
            f'<input type="search" name="q" value="{esc(f["q"])}" placeholder="Search"'
            ' aria-label="search sender or subject"></form>')

    where, args = _where(f, store)
    opt = lambda col: col if col in store.cols else "null"
    store.db.row_factory = sqlite3.Row
    rows = [dict(r) for r in store.db.execute(
        f"select account, email_id, received_at, from_name, from_email, subject, arrived_in, "
        f"would, source, list_entry, list_note, p_spam, outcome, outcome_folder, graded_at, "
        f"{opt('feedback')} as feedback, {opt('action')} as action, {opt('preview')} as preview, "
        f"{label} as label from decisions where {' and '.join(where)} "
        f"order by received_at desc limit {ROW_CAP}", args)]
    store.db.row_factory = None
    added = {}
    if has_table(store, "list_changes"):
        for cid, lst, line, acc, i in store.db.execute(
                "select id, list, line, account, email_id from list_changes "
                "where action='add' and undone_at is null and email_id is not null"):
            added[(acc, i)] = (cid, lst, line.split("  #")[0])
    moves = latest_moves(store)

    today = dt.datetime.now(zoneinfo.ZoneInfo(config.TZ)).date()
    groups: dict[str, list[str]] = {}
    for r in rows:
        t = _local(r["received_at"])
        addr = r["from_email"] or ""
        flag = {"✗": ("x", "You filed it the other way"),
                "?": ("q", "Fastmail put it in Spam; exodon would deliver it")}.get(
            agreement(r["would"], r["label"]))
        flag_html = (f'<span class="flag {flag[0]}" title="{esc(flag[1])}"></span>' if flag
                     else "<span></span>")
        acct = f'<span class="acct">{esc(r["account"])}</span>' if f["account"] == "all" and len(accounts) > 1 else ""
        preview = plain(r["preview"])
        line = (f'{esc(r["subject"] or "(no subject)")}'
                + (f' <span class="pv">— {esc(preview[:160])}</span>' if preview else ""))
        meta = [f'<span class="mono">{esc(addr)}</span>', esc(why(r) + did(r))]
        if r["outcome_folder"] or r["graded_at"]:
            meta.append(f"now in {esc(where_now(r))}")
        filtered = r["would"] == "screen"
        which = "allow" if filtered else "block"
        try:
            dom = E.candidate(addr, "domain") if not E.is_platform(addr) else None
        except E.Refused:
            dom = None
        acts = [f'<button class="btn primary" data-label="{"real" if filtered else "spam"}">'
                f'{"Not spam" if filtered else "Spam"}</button>']
        if addr:
            verb = "Always allow" if filtered else "Always block"
            if dom:
                acts.append(f'<button class="btn lst" data-list="{which}" data-scope="domain">'
                            f'{verb} {esc(dom)}</button>'
                            f'<button class="link lst" data-list="{which}" data-scope="address">'
                            'just this address</button>')
            else:
                acts.append(f'<button class="btn lst" data-list="{which}" data-scope="address">'
                            f'{verb} this address</button>')
        data = {"account": r["account"], "id": r["email_id"], "would": r["would"],
                "feedback": r["feedback"] or "", "mode": modes.get(r["account"], "shadow")}
        if (r["account"], r["email_id"]) in moves:
            d, s = moves[(r["account"], r["email_id"])]
            if s != "cancelled":
                data.update(dir=d, ms=s)
        if (r["account"], r["email_id"]) in added:
            cid, lst, pat = added[(r["account"], r["email_id"])]
            data.update(change=cid, list=lst, pattern=pat)
        attrs = " ".join(f'data-{k}="{esc(v)}"' for k, v in data.items())
        groups.setdefault(_day(t, today), []).append(
            f'<details class="msg" {attrs}><summary>{flag_html}'
            f'<span class="who">{esc(r["from_name"] or addr)}</span>'
            f'<span class="line">{line}</span>'
            f'<span class="end"><span class="tag"></span>{acct}'
            f'<time>{esc(_clock(t))}</time></span></summary>'
            f'<div class="more"><div class="meta">{"".join(f"<span>{m}</span>" for m in meta)}</div>'
            + (f'<p class="preview">{esc(preview)}</p>' if preview else "")
            + f'<div class="acts">{"".join(acts)}</div><div class="state" aria-live="polite"></div>'
            '</div></details>')

    body = "".join(f'<section class="day"><h3>{esc(day)}</h3><div class="list">{"".join(items)}</div>'
                   '</section>' for day, items in groups.items())
    if not body:
        body = ('<p class="empty">Nothing here' + (" matches that search" if f["q"] else "")
                + f' in the last {f["days"]:g} days.</p>')
    older = ""
    if f["days"] < MORE_DAYS:
        older = (f'<p class="older"><a href="{esc(_href("/", view=None if f["view"] == "filtered" else f["view"], account=f["account"], q=f["q"], days=MORE_DAYS))}">'
                 f'Show the last {MORE_DAYS} days</a></p>')
    elif len(rows) == ROW_CAP:
        older = f'<p class="older">Showing the newest {ROW_CAP}. Search to find older ones.</p>'
    inner = (f'<div class="toolbar"><nav class="tabs" aria-label="view">{tabs}</nav>'
             f'<div class="right">{boxes}{find}</div></div>'
             f'<p class="hint">{esc(VIEWS[f["view"]][1])}</p>{body}{older}'
             + _how(store, accounts if f["account"] == "all" else [f["account"]], f["days"]))
    return _shell("mail", inner, _status(store, accts or accounts), "Mail")


def _read_list(path: pathlib.Path, which: str) -> tuple[list[tuple[str, L.Entry]], str | None]:
    """(line, entry) for every pattern in the file, and a parse error if any."""
    try:
        text = path.read_text()
    except FileNotFoundError:
        return [], None
    out, err = [], None
    for i, line in enumerate(text.splitlines(), 1):
        try:
            e = L.parse_line(line, which, i)
        except Exception as x:  # noqa: BLE001 -- show it, keep rendering
            err = err or f"{path.name} line {i}: {x}"
            continue
        if e:
            out.append((line, e))
    return out, err


LIST_HINT = {"allow": "Never screened, whatever the model says (only for mail that proves "
                      "it came from that domain).",
             "block": "Always screened, without asking the model."}


def render_lists(store: S.Store, lists_dir: pathlib.Path, modes: dict | None = None,
                 accts: list[str] | None = None, params: dict | None = None) -> str:
    accounts = [r[0] for r in store.db.execute(
        "select distinct account from decisions order by account")]
    which = (params or {}).get("list", "allow")
    which = which if which in ("allow", "block") else "allow"
    hits = {(src, e): n for src, e, n in store.db.execute(
        "select source, list_entry, count(*) from decisions where source in ('allow','block') "
        "and received_at >= ? group by 1, 2", (cutoff(HITS_DAYS),))}
    loaded = {w: _read_list(lists_dir / f"{w}.txt", w) for w in ("allow", "block")}
    errs = [err for _, err in loaded.values() if err]
    ents = loaded[which][0]
    tabs = "".join(f'<a href="{"/lists" if w == "allow" else "/lists?list=block"}"'
                   f' class="{"on" if w == which else ""}">{w.capitalize()}'
                   f'<span class="n">{len(loaded[w][0])}</span></a>' for w in ("allow", "block"))
    rows = []
    for line, e in sorted(ents, key=lambda t: t[1].raw.lstrip("@*")):
        n = hits.get((which, e.raw), 0)
        rows.append(
            f'<div class="ent" data-text="{esc((e.raw + " " + e.note).lower())}">'
            f'<span class="p mono">{esc(e.raw)}</span><span class="note">{esc(e.note)}</span>'
            f'<span class="h" title="messages it decided in the last {HITS_DAYS} days">'
            f'{n or ""}</span>'
            f'<button class="rm" title="Remove" aria-label="remove {esc(e.raw)}" '
            f'data-list="{which}" data-line="{esc(line)}">×</button></div>')
    add = (f'<form class="add" data-list="{which}">'
           f'<input type="text" name="pattern" required maxlength="{E.PATTERN_LEN}" class="mono" '
           f'placeholder="Add @domain.com, name@domain.com, name:*Funding*" aria-label="pattern">'
           '<input type="text" name="note" maxlength="40" placeholder="Note (optional)" aria-label="note">'
           f'<button class="btn">Add</button></form>')

    log_html = ""
    if has_table(store, "list_changes"):
        lis = []
        for cid, at, action, lst, line, acc, undone in store.db.execute(
                "select id, at, action, list, line, account, undone_at from list_changes "
                "order by id desc limit 25"):
            verb = "Added to" if action == "add" else "Removed from"
            ctl = ("<span>undone</span>" if undone else
                   f'<button class="link undo" data-change="{cid}">'
                   f'{"undo" if action == "add" else "restore"}</button>')
            t = _local(at)
            lis.append(f'<li><span>{esc(t.strftime("%b %-d, %-I:%M %p").lower() if t else at)}</span>'
                       f'<span>{verb} {esc(lst)}</span><span class="mono">{esc(line.split("  #")[0])}</span>'
                       f'{ctl}</li>')
        if lis:
            log_html = (f'<details class="log"><summary>Recent changes from this page</summary>'
                        f'<ul>{"".join(lis)}</ul></details>')

    inner = (
        "".join(f'<div class="broken">{esc(e)} — the watcher cannot load this file; fix it by hand.</div>'
                for e in errs)
        + f'<div class="lhead"><nav class="tabs" aria-label="list">{tabs}</nav>'
        f'<div class="right"><input type="search" class="lfind" placeholder="Filter, or test an address"'
        f' aria-label="filter the list, or test an address"></div></div>'
        f'<p class="hint">{esc(LIST_HINT[which])}</p><div class="verdict" aria-live="polite"></div>'
        f'<div class="list">{add}{"".join(rows)}</div>'
        + ("" if ents else '<p class="empty">No entries yet.</p>') + log_html)
    return _shell("lists", inner, _status(store, accts or accounts), "Allow & block")


def health(store: S.Store, accts: list[str]) -> tuple[int, dict]:
    """Every configured mailbox must have a fresh heartbeat."""
    now = dt.datetime.now(dt.timezone.utc)
    out, ok = {}, bool(accts)
    for a in accts:
        alive = store.get(f"{a}:alive")
        age = None
        if alive:
            age = round((now - dt.datetime.fromisoformat(alive)).total_seconds())
        fresh = age is not None and age <= STALE_S
        ok = ok and fresh
        out[a] = {"alive": alive, "age_s": age, "ok": fresh}
    return (200 if ok else 503), {"ok": ok, "accounts": out}


# ------------------------------------------------------------------ actions


def _decision(store: S.Store, body: dict) -> dict:
    account, email_id = body.get("account"), body.get("email_id")
    if not isinstance(account, str) or not isinstance(email_id, str):
        raise Bad("account and email_id are required")
    store.db.row_factory = sqlite3.Row
    r = store.db.execute("select * from decisions where account=? and email_id=?",
                         (account, email_id)).fetchone()
    store.db.row_factory = None
    if r is None:
        raise Bad("no such decision")
    return dict(r)


def act_mark(store: S.Store, body: dict, modes: dict | None = None, **_) -> dict:
    """Record the owner's call. On a live mailbox, also ask the watcher to put
    the message where that call says it belongs (and, on undo, back where
    exodon left it). A move not yet made is cancelled by the next mark."""
    if not has_col(store, "feedback"):
        raise Bad("the log has not been upgraded yet; restart the watcher")
    r = _decision(store, body)
    label = body.get("label")
    if label not in ("spam", "real", None):
        raise Bad("label must be spam, real or null")
    key = (r["account"], r["email_id"])
    store.db.execute("update decisions set feedback=?, feedback_at=? where account=? and email_id=?",
                     (label, S.now() if label else None, *key))
    move = None
    if has_table(store, "moves"):
        store.db.execute("update moves set state='cancelled', done_at=? where account=? and "
                         "email_id=? and state='pending'", (S.now(), *key))
        if (modes or {}).get(r["account"]) == "live":
            left = "spam" if r.get("action") == "moved" else "inbox"  # where exodon left it
            last = store.db.execute("select dir from moves where account=? and email_id=? and "
                                    "state='done' order by id desc limit 1", key).fetchone()
            now_in = last[0] if last else left
            want = {"real": "inbox", "spam": "spam", None: left}[label]
            if want != now_in:
                store.db.execute("insert into moves (at, account, email_id, dir, state) "
                                 "values (?, ?, ?, ?, 'pending')", (S.now(), *key, want))
                move = want
    store.db.commit()
    return {"ok": True, "label": label, "move": move}


def _plan(store: S.Store, body: dict, lists_dir: pathlib.Path):
    r = _decision(store, body)
    which, scope = body.get("list"), body.get("scope")
    if which not in ("allow", "block"):
        raise Bad("list must be allow or block")
    if scope not in ("domain", "address"):
        raise Bad("scope must be domain or address")
    try:
        pattern = E.candidate(r["from_email"], scope)
    except E.Refused as e:
        raise Bad(str(e)) from None
    v = E.verdict(load_lists(lists_dir), r["from_email"], r.get("from_name") or "", which,
                  pattern, r.get("list_note"))
    line = E.line_for(pattern, r.get("subject") or "", dt.date.today().isoformat())
    return r, which, v, line


def act_preview(store, body, lists_dir, **_) -> dict:
    _, _, v, line = _plan(store, body, lists_dir)
    return {"status": v.status, "pattern": v.pattern, "message": v.message, "line": line}


def act_add(store, body, lists_dir, lock, **_) -> dict:
    if not has_table(store, "list_changes"):
        raise Bad("the log has not been upgraded yet; restart the watcher")
    with lock:
        r, which, v, line = _plan(store, body, lists_dir)
        if v.status != "ok":
            raise Bad(v.message)
        try:
            E.append(lists_dir / f"{which}.txt", which, line)
        except E.Refused as e:
            raise Bad(str(e)) from None
        cur = store.db.execute(
            "insert into list_changes (at, action, list, line, account, email_id) "
            "values (?, 'add', ?, ?, ?, ?)", (S.now(), which, line, r["account"], r["email_id"]))
        store.db.commit()
    log.info("added to %s: %s", which, line)
    return {"ok": True, "change_id": cur.lastrowid, "line": line}


def _need_changes(store: S.Store) -> None:
    if not has_table(store, "list_changes"):
        raise Bad("the log has not been upgraded yet; restart the watcher")


def _log_change(store: S.Store, action: str, which: str, line: str,
                account: str | None = None, email_id: str | None = None) -> int:
    cur = store.db.execute(
        "insert into list_changes (at, action, list, line, account, email_id) "
        "values (?, ?, ?, ?, ?, ?)", (S.now(), action, which, line, account, email_id))
    return cur.lastrowid


def act_undo(store, body, lists_dir, lock, **_) -> dict:
    """Undo a page change: an add is removed again, a remove is put back."""
    _need_changes(store)
    cid = body.get("change_id")
    if not isinstance(cid, int):
        raise Bad("change_id is required")
    with lock:
        row = store.db.execute("select action, list, line, account, email_id from list_changes "
                               "where id=? and action in ('add','remove') and undone_at is null",
                               (cid,)).fetchone()
        if row is None:
            raise Bad("no such change, or it was already undone")
        action, which, line, account, email_id = row
        try:
            if action == "add":
                E.remove(lists_dir / f"{which}.txt", which, line)
            else:
                E.append(lists_dir / f"{which}.txt", which, line)
        except E.Refused as e:
            raise Bad(str(e)) from None
        store.db.execute("update list_changes set undone_at=? where id=?", (S.now(), cid))
        _log_change(store, "remove" if action == "add" else "add", which, line, account, email_id)
        store.db.commit()
    log.info("undid %s on %s: %s", action, which, line)
    return {"ok": True}


def _which(body: dict) -> str:
    which = body.get("list")
    if which not in ("allow", "block"):
        raise Bad("list must be allow or block")
    return which


def act_new(store, body, lists_dir, lock, **_) -> dict:
    """Add a pattern the owner typed on the lists page."""
    _need_changes(store)
    which = _which(body)
    pattern, why_ = body.get("pattern"), body.get("note") or ""
    if not isinstance(pattern, str) or not isinstance(why_, str):
        raise Bad("pattern and note must be text")
    with lock:
        try:
            line = E.manual_line(pattern, which, why_, dt.date.today().isoformat())
        except E.Refused as e:
            raise Bad(str(e)) from None
        raw = L.parse_line(line, which).raw
        entries = load_lists(lists_dir)
        same = [e for e in entries if e.raw == raw]
        if any(e.list == which for e in same):
            raise Bad(f"{raw} is already on the {which} list")
        try:
            E.append(lists_dir / f"{which}.txt", which, line)
        except E.Refused as e:
            raise Bad(str(e)) from None
        cid = _log_change(store, "add", which, line)
        store.db.commit()
    log.info("added to %s by hand: %s", which, line)
    msg = f"Added {raw} to the {which} list"
    if same:
        msg += f"; it is also on the {same[0].list} list, and allow wins a tie"
    return {"ok": True, "change_id": cid, "line": line, "message": msg}


def act_remove(store, body, lists_dir, lock, **_) -> dict:
    """Remove one line, by its exact text, from a list file."""
    _need_changes(store)
    which = _which(body)
    line = body.get("line")
    if not isinstance(line, str) or not line.strip() or len(line) > 1000:
        raise Bad("line is required")
    with lock:
        try:
            if L.parse_line(line, which) is None:
                raise Bad("that is not a list entry")
        except ValueError as e:
            raise Bad(str(e)) from None
        try:
            E.remove(lists_dir / f"{which}.txt", which, line)
        except E.Refused as e:
            raise Bad(str(e)) from None
        cid = _log_change(store, "remove", which, line)
        store.db.commit()
    log.info("removed from %s: %s", which, line)
    return {"ok": True, "change_id": cid}


def act_check(store, body, lists_dir, **_) -> dict:
    """Which entry decides this sender, if any: the watcher's own rule."""
    addr, name = body.get("address"), body.get("name") or ""
    if not isinstance(addr, str) or not isinstance(name, str) or not 0 < len(addr) <= 320:
        raise Bad("an address is required")
    e = L.decide(load_lists(lists_dir), addr, name[:200])
    if e is None:
        return {"would": "model", "entry": None,
                "message": "No entry matches; the model decides."}
    verb = "allowed" if e.list == "allow" else "screened"
    extra = " (only if the message is authenticated for its domain)" if e.list == "allow" else ""
    return {"would": "inbox" if e.list == "allow" else "screen", "entry": e.raw, "list": e.list,
            "message": f"{verb} by {e.list} {e.raw}{extra}."}


ACTIONS = {"/api/mark": act_mark, "/api/list/preview": act_preview,
           "/api/list/add": act_add, "/api/list/undo": act_undo,
           "/api/list/new": act_new, "/api/list/remove": act_remove,
           "/api/list/check": act_check}


# ------------------------------------------------------------------- server


class Handler(BaseHTTPRequestHandler):
    server_version = "exodon-web"
    sys_version = ""
    timeout = 10  # a slow client cannot hold a thread

    def log_message(self, fmt, *args):  # quieter than stderr per request
        log.debug("%s " + fmt, self.address_string(), *args)

    def send(self, code: int, body: str | bytes, ctype: str) -> None:
        data = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        for k, v in SECURITY_HEADERS.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def json(self, code: int, obj: dict) -> None:
        self.send(code, json.dumps(obj), "application/json")

    def host_ok(self, readers: bool = False) -> bool:
        if not self.peer_ok(self.server.readers if readers else []):
            self.json(403, {"error": "refused: only through the proxy"})
            return False
        if (self.headers.get("Host") or "").lower() in self.server.hosts:
            return True
        self.json(421, {"error": "unknown host"})
        return False

    def peer_ok(self, also: list[str] = ()) -> bool:
        if not self.server.proxy:
            return True
        peer = self.client_address[0]
        if peer in LOCAL_PEERS:
            return True
        # resolved per request: a container's address changes when it is recreated
        for name in (self.server.proxy, *also):
            try:
                if peer in {a[4][0] for a in socket.getaddrinfo(name, None)}:
                    return True
            except OSError:
                pass
        return False

    def get_readout(self, params: dict) -> None:
        token = self.server.readout_token
        tokens = [t for t in ([token] if isinstance(token, str) else token) if t]
        given = (self.headers.get("Authorization") or "").removeprefix("Bearer ").strip()
        if not tokens:
            return self.json(404, {"error": "not found"})
        # every token is compared, so timing doesn't say which one nearly matched
        if not given or not sum(hmac.compare_digest(given.encode(), t.encode()) for t in tokens):
            return self.json(401, {"error": "bad or missing token"})
        try:
            hours = float(params.get("hours", 24))
        except ValueError:
            return self.json(400, {"error": "hours must be a number"})
        st = self.store()
        try:
            self.json(200, R.readout(st, self.server.acct_objs, hours))
        except Exception as e:  # noqa: BLE001 -- keep serving
            log.exception("readout failed")
            self.json(500, {"error": type(e).__name__})
        finally:
            st.db.close()

    def store(self) -> S.Store:
        return S.Store(self.server.db_path, migrate=False)

    def do_GET(self):
        url = urllib.parse.urlsplit(self.path)
        params = {k: v[-1] for k, v in urllib.parse.parse_qs(url.query).items()}
        if url.path == "/api/readout":
            if self.host_ok(readers=True):
                self.get_readout(params)
            return
        if not self.host_ok():
            return
        st = self.store()
        try:
            if url.path == "/":
                self.send(200, render_page(st, params, self.server.lists_dir, self.server.modes,
                                           self.server.accounts), "text/html; charset=utf-8")
            elif url.path == "/lists":
                self.send(200, render_lists(st, self.server.lists_dir, self.server.modes,
                                            self.server.accounts, params), "text/html; charset=utf-8")
            elif url.path == "/api/moves":
                since = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=2)).isoformat(
                    timespec="seconds")
                self.json(200, {"moves": [
                    {"account": a, "email_id": i, "dir": d, "state": s}
                    for (a, i), (d, s) in latest_moves(st, since).items()]})
            elif url.path == "/health":
                self.json(*health(st, self.server.accounts))
            else:
                self.json(404, {"error": "not found"})
        except Exception as e:  # noqa: BLE001 -- keep serving
            log.exception("GET %s failed", url.path)
            self.json(500, {"error": type(e).__name__})
        finally:
            st.db.close()

    def do_POST(self):
        if not self.host_ok():
            return
        ctype = (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()
        if ctype != "application/json" or self.headers.get("Origin") != self.server.origin:
            return self.json(403, {"error": "refused: not a request from this page"})
        action = ACTIONS.get(urllib.parse.urlsplit(self.path).path)
        if action is None:
            return self.json(404, {"error": "not found"})
        try:
            n = int(self.headers.get("Content-Length") or 0)
            if not 0 < n <= 10_000:
                raise Bad("bad request size")
            body = json.loads(self.rfile.read(n))
            if not isinstance(body, dict):
                raise Bad("expected a JSON object")
        except (Bad, ValueError) as e:
            return self.json(400, {"error": str(e)})
        st = self.store()
        try:
            self.json(200, action(st, body, lists_dir=self.server.lists_dir,
                                  lock=self.server.lock, modes=self.server.modes))
        except Bad as e:
            self.json(400, {"error": str(e)})
        except Exception as e:  # noqa: BLE001 -- keep serving
            log.exception("POST %s failed", self.path)
            self.json(500, {"error": type(e).__name__})
        finally:
            st.db.close()


def make_server(port: int, db_path: pathlib.Path, lists_dir: pathlib.Path,
                hosts: set[str] = HOSTS, origin: str = ORIGIN, proxy: str = PROXY,
                accounts: list[str] | None = None, readers: list[str] = READERS,
                readout_token: str | list[str] = READOUT_TOKEN,
                modes: dict | None = None) -> ThreadingHTTPServer:
    srv = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    srv.daemon_threads = True
    srv.db_path, srv.lists_dir = db_path, lists_dir
    srv.hosts, srv.origin, srv.proxy, srv.lock = hosts, origin, proxy, threading.Lock()
    configured = {a.name: a for a in config.accounts()}
    if accounts is None:
        accounts = list(configured)
        modes = {n: a.mode for n, a in configured.items()}
    srv.accounts, srv.modes = accounts, modes or {}
    srv.acct_objs = [configured.get(n) or config.Account(n, config.TRAINING_FOLDER)
                     for n in srv.accounts]
    srv.readers, srv.readout_token = readers, readout_token
    return srv


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s",
                        stream=sys.stdout)
    srv = make_server(PORT, config.STATE / "shadow.db", config.LISTS)
    log.info("serving on :%d for %s", PORT, ", ".join(sorted(HOSTS)))
    srv.serve_forever()


if __name__ == "__main__":
    main()
