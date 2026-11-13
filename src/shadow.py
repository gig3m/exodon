#!/usr/bin/env python3
"""The watcher: decide each new message, log it, and -- only for a mailbox in
live mode -- move screened mail from the Inbox to Spam and send a daily digest
of the unsure ones. A shadow-mode mailbox is never touched.
Design: docs/shadow-mode.md.

    keys exec MY_RO_JMAP_TOKEN -- python3 src/shadow.py run      # daemon
    keys exec MY_RO_JMAP_TOKEN -- python3 src/shadow.py once     # one sync
    python3 src/shadow.py status                                      # the log
"""

from __future__ import annotations

import datetime as dt
import logging
import html
import re
import pathlib
import sqlite3
import sys
import time

import httpx

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import backends as B  # noqa: E402
import config  # noqa: E402
import lists as L  # noqa: E402

log = logging.getLogger("exodon.shadow")

# ------------------------------------------------------------ authentication


def _registrable(domain: str) -> str:
    """acme.com for mail.acme.com; three labels for co.uk-style suffixes.
    Relaxed DMARC-style alignment compares these."""
    parts = domain.lower().strip(".").split(".")
    if len(parts) >= 3 and len(parts[-1]) == 2 and parts[-2] in ("co", "com", "org", "net", "gov"):
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _clauses(result: str) -> tuple[str, list[dict]]:
    """Split one Authentication-Results header into its authserv-id and
    method clauses: [{'method': 'dkim', 'result': 'pass', 'header.d': ...}]."""
    head, *rest = re.sub(r"=\s+", "=", result).split(";")
    out = []
    for clause in rest:
        tokens = clause.replace("(", " (").split()
        if not tokens or "=" not in tokens[0]:
            continue
        method, _, res = tokens[0].partition("=")
        c = {"method": method.lower(), "result": res.lower()}
        for tok in tokens[1:]:
            if "=" in tok and not tok.startswith("("):
                k, _, v = tok.partition("=")
                c[k.lower()] = v.strip().strip(")").strip('"').lower()
        out.append(c)
    return head.strip().lower(), out


def authenticated(results: list[str], from_email: str,
                  trusted: str | None = None) -> tuple[bool, str]:
    """Is this message really from its From domain, per the provider's own
    checks? DMARC pass for the From domain, or a DKIM or SPF pass whose domain
    aligns with it (SPF: the envelope sender's domain -- small senders often
    publish SPF and nothing else). Results from any other server are ignored:
    a sender can write an Authentication-Results header into their own message."""
    trusted = (trusted or config.AUTHSERV_SUFFIX).lower()
    dom = from_email.lower().rsplit("@", 1)[-1]
    org = _registrable(dom)
    seen_foreign = False
    for res in results or []:
        authserv, clauses = _clauses(res)
        if not (authserv == trusted or authserv.endswith("." + trusted)):
            seen_foreign = True
            continue
        for c in clauses:
            if c["result"] != "pass":
                continue
            if c["method"] == "dmarc" and _registrable(c.get("header.from", "")) == org:
                return True, "dmarc=pass"
            if c["method"] == "dkim" and c.get("header.d") and _registrable(c["header.d"]) == org:
                return True, f"dkim=pass d={c['header.d']}"
            mfrom = c.get("smtp.mailfrom", "").rsplit("@", 1)[-1]
            if c["method"] == "spf" and mfrom and _registrable(mfrom) == org:
                return True, f"spf=pass mailfrom={mfrom}"
    if not results:
        return False, "no authentication results"
    return False, "no aligned dmarc/dkim/spf pass" + (" (ignored untrusted results)" if seen_foreign else "")


# ------------------------------------------------------------------ decision

# Phishing dressed as a receipt or notice, sent from a free webmail account.
# The model is told receipts and account notices are not spam, so it lets these
# through (2026-10-26: "Thank you! Payment received for order" from a gmail
# address scored 0.000). No real company sends its receipts from gmail; real
# people do write from gmail about an order or an invoice, hence the reply
# exemption and the Sent-folder check in decide().
FREEMAIL = {
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com", "msn.com",
    "yahoo.com", "ymail.com", "aol.com", "icloud.com", "me.com", "mac.com",
    "proton.me", "protonmail.com", "gmx.com", "gmx.net", "mail.com", "zoho.com",
    "yandex.com", "yandex.ru",
}
TRANSACTIONAL = re.compile(
    r"\b(receipt|invoice|payment|purchase|transaction|refund|billing|subscription|parcel|"
    r"shipment|your\s+order|order\s*(#|no\b|number|\d)|doc\s*[:#\d])", re.I)
# Re: / Fwd: anywhere in the leading run of markers: "[EXT] RE:", "Re[2]:".
REPLY = re.compile(r"^\s*(\[[^\]]*\]\s*)*(re|fwd?|aw|sv)(\[\d+\])?\s*:", re.I)
# Cyrillic look-alikes that spammers swap in to dodge keyword matches ("fоr").
CONFUSABLES = str.maketrans("аеорсухіАЕОРСХІԁ", "aeopcyxiAEOPCXId")


def phish_rule(msg: dict) -> str | None:
    """The rule's name if this is webmail posing as a receipt or notice."""
    dom = (msg.get("from_email") or "").rsplit("@", 1)[-1]
    subject = (msg.get("subject") or "").translate(CONFUSABLES)
    if dom in FREEMAIL and not REPLY.match(subject) and TRANSACTIONAL.search(subject):
        return "webmail receipt/notice"
    return None


# Drip-sequence cold sales: "Re:" on a thread the owner never joined, quoting
# only the sender's own earlier messages. The quoted history reads as a real
# back-and-forth and the model lets it through (one real drip
# follow-up scored 0.0002; the same text cut before the quote, 0.9997).
# decide() spares anyone the owner has written to, like the webmail rule.
WROTE = re.compile(r"\bwrote\s*:", re.I)
ATTRIBUTION_ON = re.compile(r"\bOn\s")  # capital "On", as mail clients write it
EMAIL = re.compile(r"[\w.+'-]+@[\w-]+(?:\.[\w-]+)+")
# History quoted without a "wrote:" line (Outlook's header block, a forward).
# Its author can't be checked, so each one counts as somebody else.
HEADER_QUOTE = re.compile(
    r"-{2,}\s*(?:original\s+message|forwarded\s+message)\s*-{2,}|begin\s+forwarded\s+message|_{10,}"
    r"|\bFrom:\s.{0,300}?\b(?:Sent|Date|Subject|To):"
    r"|\b(?:Von|De|Da|Van|Från|Fra):\s.{0,200}?\b(?:Gesendet|Envoyé|Inviato|Verzonden|Skickat|Sendt|Enviado):"
    # Attribution lines in other languages ("Am ... schrieb X:", "Le ... a écrit :").
    r"|\b(?:schrieb|a\s+écrit|escribió|ha\s+scritto|skrev|schreef|napisał|escreveu)\b", re.I)
# The author's address(es) as an attribution ends: "<a@b> [a@b] wrote:".
AUTHOR_TAIL = re.compile(r"((?:[<\[(][^<>\[\]()]*[>\])]\s*)*)wrote:$")
# An attribution starts "On <date>": a digit before any sentence ends.
DATED_ON = re.compile(r"On\s[^.!?]{0,60}?\d")


def attributions(body: str) -> list[str]:
    """Each "On <date>, <who> wrote:" line of a body's quoted history, with
    quote markers and line wrapping undone. A "wrote:" with no "On" before it
    comes back empty, which the rule reads as someone it can't name, and so
    does each header-style quote (HEADER_QUOTE)."""
    body = html.unescape(body or "")  # HTML-only parts keep "&lt;a@b&gt;" after strip_html
    text = " ".join(re.sub(r"(?m)^[ \t>]+", " ", body).split())
    text = re.sub(r"\]\s*>(?=\s*wrote\b)", "] ", text, flags=re.I)  # "[a@b]> wrote:"
    out, prev = [], 0
    for w in WROTE.finditer(text):
        # Look back no further than the previous attribution, so one never
        # borrows another's "On" or the sender's own signature.
        window = text[max(prev, w.start() - 300):w.start()]
        prev = w.end()
        starts = [m.start() for m in ATTRIBUTION_ON.finditer(window)]
        seg = window[starts[-1]:].strip() if starts else ""
        out.append(seg + " wrote:" if DATED_ON.match(seg) else "")
    return out + [""] * len(HEADER_QUOTE.findall(text))


def self_quote_rule(msg: dict) -> str | None:
    """The rule's name if this reply quotes nobody but its own sender: every
    attribution carries the sender's address or their full display name (the
    name follows a campaign that moves to a new domain)."""
    quoted = msg.get("attributions") or []
    subject = (msg.get("subject") or "").translate(CONFUSABLES)
    if not quoted or not REPLY.match(subject):
        return None
    addr = (msg.get("from_email") or "").lower()
    name = " ".join((msg.get("from_name") or "").lower().split())
    # The name must be the whole author: after the date (a comma, a digit or
    # am/pm), straight before the address brackets and "wrote:".
    named = (re.compile(r"(?:,|\d|\b[ap]\.?m\.?)\s*\"?" + re.escape(name) + r"\"?\s*"
                        + AUTHOR_TAIL.pattern) if len(name.split()) >= 2 else None)
    for a in quoted:
        low = " ".join(a.lower().split())
        tail = AUTHOR_TAIL.search(low)
        if not tail:
            return None
        bare = re.search(r"(\S+?)[\s>]*$", low[:tail.start()])  # "a@b > wrote:"
        own = {e for e in EMAIL.findall(tail.group(1) + " " + (bare.group(1) if bare else ""))}
        if addr not in own and not (named and named.search(low)):
            return None
    return "self-quoted follow-up"


def decide(msg: dict, entries: list, model, screen_at: float | None = None,
           review_at: float | None = None, wrote_to=None) -> dict:
    """Lists first (allow only when authenticated), then the webmail-receipt
    and self-quoted follow-up rules, the model for the rest. The model still scores rule hits, for the record.
    `wrote_to(address)` -> has the owner ever sent mail there; the rule spares
    those senders. Without it the rule spares nobody."""
    screen_at = config.SCREEN_AT if screen_at is None else screen_at
    review_at = config.REVIEW_AT if review_at is None else review_at
    ok, why = authenticated(msg.get("auth_results", []), msg["from_email"])
    d = {"authenticated": int(ok), "auth_reason": why, "list_entry": None,
         "list_note": None, "p_spam": None, "error": None}
    e = L.decide(entries, msg["from_email"], msg.get("from_name", ""))
    if e and e.list == "block":
        return {**d, "source": "block", "would": "screen", "list_entry": e.raw}
    if e and e.list == "allow":
        if ok:
            return {**d, "source": "allow", "would": "inbox", "list_entry": e.raw}
        d["list_note"] = f"allow {e.raw} ignored: not authenticated ({why})"
        d["list_entry"] = e.raw
    rule = phish_rule(msg) or self_quote_rule(msg)
    if rule and wrote_to and wrote_to(msg["from_email"]):
        rule = None
    if rule == "self-quoted follow-up" and d["list_note"] is None:
        # The attribution usually sits past the logged preview; say what fired.
        d["list_note"] = f"quotes only: {msg['attributions'][0][:160]}"
    v = model.score(msg)
    if rule:
        p = None if v.error is not None else v.p_spam
        return {**d, "source": "rule", "would": "screen", "list_entry": rule, "p_spam": p}
    if v.error is not None:
        return {**d, "source": "model", "would": "error", "error": v.error}
    would = "screen" if v.p_spam >= screen_at else "review" if v.p_spam >= review_at else "inbox"
    return {**d, "source": "model", "would": would, "p_spam": v.p_spam}


# ------------------------------------------------------------------- grading


def outcome(mailbox_ids: dict | None, boxes: dict, age_hours: float,
            inbox_grace_hours: float = 24 * 7, training: str | None = None,
            arrived_junk: bool = False) -> str | None:
    """Where the owner filed it -> spam / real / deleted / fastmail_spam /
    unknown, or None if it is still in the inbox and may yet be filed.

    `deleted` (Trash, or gone) is reported but NOT scored: it usually means
    read-and-done, but sometimes spam binned instead of filed, so it is not a
    reliable label either way. Nor is it a keep signal -- list seeding counts
    only Archive as kept."""
    if not mailbox_ids:
        # Gone. The owner deleted it -- unless the provider filed it in its
        # own Spam and purged it later, which is nobody's verdict.
        return "unknown" if arrived_junk else "deleted"
    kinds = set()
    for mid in mailbox_ids:
        b = boxes.get(mid, {})
        if b.get("name") == (training or config.TRAINING_FOLDER):
            kinds.add("spam")
        elif b.get("role") == "junk":
            kinds.add("fastmail_spam")
        elif b.get("role") == "trash":
            kinds.add("trash")
        elif b.get("role") == "inbox":
            kinds.add("inbox")
        else:
            kinds.add("real")
    for k in ("spam", "fastmail_spam", "real"):
        if k in kinds:
            return k
    if "trash" in kinds:
        return "deleted"
    return "real" if age_hours >= inbox_grace_hours else None


# --------------------------------------------------------------------- store

SCHEMA = """
create table if not exists meta (key text primary key, value text);
create table if not exists decisions (
    account text not null default 'default',
    email_id text not null,
    received_at text, decided_at text,
    from_email text, from_name text, subject text, arrived_in text,
    authenticated integer, auth_reason text,
    source text, would text, list_entry text, list_note text,
    p_spam real, model text, error text, fastmail_score real,
    outcome text, outcome_folder text, graded_at text,
    primary key (account, email_id)
);
create table if not exists events (at text, kind text, detail text);
create table if not exists list_changes (
    id integer primary key, at text, action text, list text, line text,
    account text, email_id text, undone_at text
);
-- The review page asks, the watcher (which holds the token) moves: dir is
-- 'inbox' (Spam -> Inbox) or 'spam' (Inbox -> Spam); state is pending,
-- done, cancelled, or "refused: ..." / "failed: ...".
create table if not exists moves (
    id integer primary key, at text, account text, email_id text,
    dir text, state text, done_at text
);
"""
# Columns added after the first release; ADD COLUMN is safe to repeat.
_ADDED = (("feedback", "text"), ("feedback_at", "text"),
          # live mode: what exodon did to the message ("moved", or "move failed: ...")
          ("action", "text"), ("acted_at", "text"),
          # the start of the body, for the readout's second reader
          ("preview", "text"))
_PER_ACCOUNT_META = ("email_state", "last_sync", "last_grade")


class Store:
    """The decision log. One connection per thread (sqlite's rule); every
    watcher opens its own on the same file."""

    def __init__(self, path: pathlib.Path, legacy_account: str | None = None,
                 migrate: bool = True):
        """`migrate=False` is for readers (the review page): connect only,
        never change the schema -- the watcher owns that."""
        path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path, timeout=30)
        if migrate:
            self._migrate(legacy_account)
            self.db.executescript(SCHEMA)
            for col, kind in _ADDED:
                try:
                    self.db.execute(f"alter table decisions add column {col} {kind}")
                except sqlite3.OperationalError as e:
                    if "duplicate column" not in str(e):
                        raise
            # The watcher threads and the review page write concurrently.
            self.db.execute("pragma journal_mode=wal")
            self.db.commit()
        self.cols = {r[1] for r in self.db.execute("pragma table_info(decisions)")}

    def _migrate(self, legacy: str | None) -> None:
        """A log from before accounts existed: its rows and saved position
        belong to `legacy` (the first configured account), so upgrading does
        not restart that watcher from 'now' and skip mail."""
        old = {r[1] for r in self.db.execute("pragma table_info(decisions)")}
        if not old or "account" in old:
            return
        legacy = legacy or "default"
        self.db.execute("alter table decisions rename to decisions_v1")
        self.db.executescript(SCHEMA)
        cols = ",".join(sorted(old))
        self.db.execute(f"insert into decisions (account,{cols}) select ?,{cols} from decisions_v1",
                        (legacy,))
        self.db.execute("drop table decisions_v1")
        for k in _PER_ACCOUNT_META:
            self.db.execute("update meta set key=? where key=?", (f"{legacy}:{k}", k))
        self.db.commit()

    def get(self, key: str) -> str | None:
        r = self.db.execute("select value from meta where key=?", (key,)).fetchone()
        return r[0] if r else None

    def set(self, key: str, value: str) -> None:
        self.db.execute("insert or replace into meta values (?,?)", (key, value))
        self.db.commit()

    def event(self, kind: str, detail: str = "") -> None:
        self.db.execute("insert into events values (?,?,?)", (now(), kind, detail))
        self.db.commit()

    def record(self, row: dict) -> None:
        row = {k: v for k, v in row.items() if k in self.cols}
        cols = ",".join(row)
        self.db.execute(f"insert or ignore into decisions ({cols}) values "
                        f"({','.join('?' * len(row))})", tuple(row.values()))
        self.db.commit()


def now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


# ------------------------------------------------------------------- service

PROPS = ["id", "from", "to", "subject", "receivedAt", "mailboxIds", "preview",
         "textBody", "bodyValues", "header:Authentication-Results:asText:all",
         "header:X-Spam-score:asText", "header:X-Exodon:asText"]
DIGEST_HEADER = "X-Exodon"
# Body bytes fetched per message: HTML-only mail spends the first few KB on
# <head> and inline CSS before any text.
BODY_BYTES = 16000


def strip_html(text: str) -> str:
    """Visible text of an HTML part. JMAP's textBody falls back to the HTML
    part when a message has no text/plain one, and its first 600 characters
    were often nothing but styling -- the model saw no message at all."""
    text = re.sub(r"(?is)<head\b.*?(</head\s*>|(?=<body\b)|$)", " ", text)
    text = re.sub(r"(?is)<(style|script|title)\b.*?(</\1\s*>|$)", " ", text)
    text = re.sub(r"(?s)<!--.*?(-->|$)", " ", text)
    text = re.sub(r"(?i)<br\s*/?>|</(p|div|tr|li|h\d)\s*>", "\n", text)
    return re.sub(r"(?s)<[^>]*(>|$)", " ", text)


def extract(m: dict) -> dict:
    """A JMAP Email into the flat shape the lists, the model and the log use."""
    frm = (m.get("from") or [{}])[0]
    to = (m.get("to") or [{}])[0]
    values = m.get("bodyValues") or {}
    html_parts = {p.get("partId") for p in m.get("textBody") or [] if p.get("type") == "text/html"}
    body = " ".join(strip_html(v.get("value", "")) if k in html_parts else v.get("value", "")
                    for k, v in values.items())
    score = m.get("header:X-Spam-score:asText")
    try:
        score = float(score.strip()) if score else None
    except ValueError:
        score = None
    return {
        "id": m["id"],
        "from_email": (frm.get("email") or "").lower(),
        "from_name": frm.get("name") or "",
        "to": (to.get("email") or "").lower(),
        "subject": m.get("subject") or "",
        "received_at": m.get("receivedAt") or "",
        "preview": B.clean(body or m.get("preview") or "")[:600],
        # From the whole body: the quoted history usually starts past the preview.
        "attributions": attributions(body),
        "auth_results": m.get("header:Authentication-Results:asText:all") or [],
        "fastmail_score": score,
        "mailbox_ids": m.get("mailboxIds") or {},
        "exodon_digest": bool(m.get("header:X-Exodon:asText")),
    }


class ListFiles:
    """allow.txt + block.txt, reloaded whenever either file changes."""

    def __init__(self, root: pathlib.Path):
        self.paths = [(root / "allow.txt", "allow"), (root / "block.txt", "block")]
        self.stamp, self.entries = None, []

    def get(self) -> list:
        stamp = tuple(p.stat().st_mtime_ns if p.exists() else 0 for p, _ in self.paths)
        if stamp != self.stamp:
            self.entries = [e for p, w in self.paths for e in L.load(p, w)]
            if self.stamp is not None:
                log.info("lists reloaded: %d entries", len(self.entries))
            self.stamp = stamp
        return self.entries


class Shadow:
    """One watcher per mailbox. Saved state is namespaced by account name."""

    def __init__(self, jmap, store: Store, lists: ListFiles, model,
                 account: str = "default", training: str | None = None,
                 live: bool = False, address: str | None = None, writer=None):
        """`jmap` reads and listens (read-only token); `writer`, live mode
        only, is a separate writable client that never opens a push stream."""
        self.jmap, self.store, self.lists, self.model = jmap, store, lists, model
        self.writer = writer
        self.account, self.training = account, training or config.TRAINING_FOLDER
        self.live, self.address = live, address
        self.log = logging.getLogger(f"exodon.{account}")
        self.boxes = jmap.mailboxes()
        self.skip = {i for i, b in self.boxes.items() if b.get("role") in ("sent", "drafts")}
        role = {b.get("role"): i for i, b in self.boxes.items() if b.get("role")}
        self.inbox, self.junk = role.get("inbox"), role.get("junk")
        self.sent = role.get("sent")
        if live and not (self.inbox and self.junk and getattr(writer, "write", False)):
            raise SystemExit(f"[{account}] live mode needs a writable client and an Inbox "
                             "and a Spam (junk) mailbox")
        if live and store.get(self.key("digest_since")) is None:
            # First live start: the first digest covers live mail only, and
            # waits for tomorrow's DIGEST_AT rather than going out right now.
            import zoneinfo
            store.set(self.key("digest_day"),
                      dt.datetime.now(zoneinfo.ZoneInfo(config.TZ)).date().isoformat())
            store.set(self.key("digest_since"), now())
            store.event("live", f"[{account}] live mode started")

    def key(self, k: str) -> str:
        return f"{self.account}:{k}"

    def sync(self) -> int:
        import jmap as J
        since = self.store.get(self.key("email_state"))
        if since is None:
            state = self.jmap.email_state()
            self.store.set(self.key("email_state"), state)
            self.store.event("start", f"[{self.account}] no saved state; watching from {state}")
            self.log.info("first run: watching new mail from state %s", state)
            return 0
        try:
            created, state = self.jmap.changes(since)
        except J.JmapError as e:
            if e.type != "cannotCalculateChanges":
                raise
            state = self.jmap.email_state()
            self.store.event("gap", f"[{self.account}] cannot calculate changes since {since}; "
                                    f"resumed at {state}")
            self.log.warning("gap: changes since %s unavailable, resuming at %s", since, state)
            self.store.set(self.key("email_state"), state)
            return 0
        n = self.process(created)
        self.store.set(self.key("email_state"), state)
        self.store.set(self.key("last_sync"), now())
        return n

    def wrote_to(self, address: str) -> bool:
        """Is there mail to this address in Sent? A failed lookup answers yes,
        so the rules stand down and the model decides instead."""
        if not self.sent:
            return True
        who = {"operator": "OR", "conditions": [{"to": address}, {"cc": address},
                                                 {"bcc": address}]}
        try:
            got = self.jmap.call("Email/query", {"filter": {"operator": "AND", "conditions": [
                {"inMailbox": self.sent}, who]}, "limit": 1})
        except Exception as e:  # noqa: BLE001 -- any failure means: don't screen on the rule
            self.log.warning("Sent lookup for %s failed (%r); rule skipped", address, e)
            return True
        return bool(got.get("ids"))

    def process(self, ids: list[str]) -> int:
        n = 0
        entries = self.lists.get()
        for i in range(0, len(ids), 50):
            got = self.jmap.call("Email/get", {"ids": ids[i:i + 50], "properties": PROPS,
                                               "fetchTextBodyValues": True,
                                               "maxBodyValueBytes": BODY_BYTES})["list"]
            for m in got:
                msg = extract(m)
                if set(msg["mailbox_ids"]) & self.skip or msg["exodon_digest"]:
                    continue
                d = decide(msg, entries, self.model, wrote_to=self.wrote_to)
                arrived = ",".join(self.boxes.get(b, {}).get("name", b) for b in msg["mailbox_ids"])
                self.store.record({"account": self.account, "email_id": msg["id"],
                                   "received_at": msg["received_at"], "decided_at": now(),
                                   "from_email": msg["from_email"], "from_name": msg["from_name"],
                                   "subject": msg["subject"], "arrived_in": arrived,
                                   "fastmail_score": msg["fastmail_score"],
                                   "preview": msg["preview"][:300],
                                   "model": getattr(self.model, "model", None), **d})
                self.log.info("%-6s %-6s %-28s %s", d["would"], d["source"],
                              msg["from_email"][:28], msg["subject"][:60])
                if self.live and d["would"] == "screen":
                    self.act(msg)
                n += 1
        return n

    def act(self, msg: dict) -> None:
        """Live mode: move a screened message to Spam -- only if it is in the
        Inbox and nowhere else, so mail a rule already filed is left alone.
        A failed move is logged on the row and leaves the message where it is."""
        if set(msg["mailbox_ids"]) != {self.inbox}:
            return
        try:
            self.writer.move(msg["id"], self.inbox, self.junk)
            action = "moved"
        except Exception as e:  # noqa: BLE001 -- one failed move must not stop the watcher
            action = f"move failed: {e}"[:300]
            self.log.warning("could not move %s to Spam: %s", msg["id"], e)
            self.store.event("error", f"[{self.account}] move {msg['id']}: {e!r}"[:500])
        self.store.db.execute("update decisions set action=?, acted_at=? where account=? "
                              "and email_id=?", (action, now(), self.account, msg["id"]))
        self.store.db.commit()

    MOVE_MAX_AGE_S = 3600

    def maybe_moves(self) -> None:
        """Make the moves the owner asked for on the review page. Only on a
        live mailbox, only between Inbox and Spam, only for a message exodon
        decided, and only while it is still where the page saw it -- anything
        else is refused and the reason shown on the page."""
        rows = self.store.db.execute(
            "select id, at, email_id, dir from moves where account=? and state='pending' "
            "order by id", (self.account,)).fetchall()
        for mid, at, email_id, to in rows:
            try:
                state = self._owner_move(at, email_id, to)
            except Exception as e:  # noqa: BLE001 -- one failed move must not stop the watcher
                state = f"failed: {e}"[:300]
                self.log.warning("could not move %s to %s: %s", email_id, to, e)
                self.store.event("error", f"[{self.account}] owner move {email_id}: {e!r}"[:500])
            self.store.db.execute("update moves set state=?, done_at=? where id=?",
                                  (state, now(), mid))
            self.store.db.commit()
            self.log.info("owner move %s -> %s: %s", email_id, to, state)

    def _owner_move(self, at: str, email_id: str, to: str) -> str:
        if not self.live:
            return "refused: this mailbox is in shadow mode"
        if to not in ("inbox", "spam"):
            return "refused: unknown destination"
        age = (dt.datetime.now(dt.timezone.utc) - dt.datetime.fromisoformat(at)).total_seconds()
        if age > self.MOVE_MAX_AGE_S:
            return "refused: asked too long ago"
        if self.store.db.execute("select 1 from decisions where account=? and email_id=?",
                                 (self.account, email_id)).fetchone() is None:
            return "refused: not a message exodon decided"
        src, dst = (self.junk, self.inbox) if to == "inbox" else (self.inbox, self.junk)
        got = self.jmap.call("Email/get", {"ids": [email_id], "properties": ["mailboxIds"]})["list"]
        if not got:
            return "refused: no longer in the mailbox"
        if set(got[0].get("mailboxIds") or {}) != {src}:
            return f"refused: no longer only in {'Spam' if to == 'inbox' else 'the Inbox'}"
        self.writer.move(email_id, src, dst)
        return "done"

    def maybe_digest(self) -> None:
        """Live mode, once a day after DIGEST_AT local time: put a digest of
        the unsure mail since the last one in the Inbox. Skipped (but still
        stamped) when there is nothing to list. EXODON_DIGEST_AT=off sends
        none, but keeps stamping so turning it back on starts from that day."""
        if not self.live:
            return
        import zoneinfo
        local = dt.datetime.now(zoneinfo.ZoneInfo(config.TZ))
        today = local.date().isoformat()
        if self.store.get(self.key("digest_day")) == today:
            return
        if config.DIGEST_AT.strip().lower() in ("", "off"):
            self.store.set(self.key("digest_day"), today)
            self.store.set(self.key("digest_since"), now())
            return
        if local.strftime("%H:%M") < config.DIGEST_AT:
            return
        since = self.store.get(self.key("digest_since")) or (
            dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=1)).isoformat(timespec="seconds")
        stamp = now()
        subject, text = digest(self.store, self.account, since, local)
        if text:
            try:
                self.writer.create(self.inbox, self.address, self.address, subject, text,
                                 {DIGEST_HEADER: "digest"})
            except Exception as e:  # noqa: BLE001 -- retried on the next event
                self.log.warning("digest failed (%s); will retry", e)
                self.store.event("error", f"[{self.account}] digest: {e!r}"[:500])
                return
            self.log.info("digest sent: %s", subject)
        self.store.set(self.key("digest_day"), today)
        self.store.set(self.key("digest_since"), stamp)

    def alive(self) -> None:
        """Heartbeat for the review page's /health: set on every push event
        and ping (Fastmail pings once a minute)."""
        self.store.set(self.key("alive"), now())

    def maybe_grade(self, every_h: float = 1.0) -> None:
        """Hourly, re-grade this account's recent decisions and rewrite the
        plain-language report (all accounts) at var/report.txt."""
        last = self.store.get(self.key("last_grade"))
        if last and (dt.datetime.now(dt.timezone.utc)
                     - dt.datetime.fromisoformat(last)).total_seconds() < every_h * 3600:
            return
        import grade as G
        # Stamp the attempt first: a failing grade must not retry on every
        # ping, nor tear down the push stream -- it waits for the next hour.
        self.store.set(self.key("last_grade"), now())
        try:
            n = G.grade(self.store, self.jmap, self.account, self.training)
            G.write_report(self.store, config.STATE / "report.txt")
        except Exception as e:  # noqa: BLE001
            self.store.db.rollback()
            self.log.warning("grading failed (%s); next try in an hour", e)
            self.store.event("error", f"[{self.account}] grading: {e!r}"[:500])
            return
        self.log.info("changed %d grades; report in %s", n, config.STATE / "report.txt")

    def run(self) -> None:
        import jmap as J
        attempt = 0
        while True:
            try:
                self.sync()
                self.alive()
                self.maybe_grade()
                self.maybe_digest()
                self.maybe_moves()
                for ev in self.jmap.events():
                    self.alive()
                    if ev.get("type") != "ping":
                        self.sync()
                    self.maybe_grade()
                    self.maybe_digest()
                    self.maybe_moves()
                    attempt = 0
                self.log.info("push stream closed; reconnecting")
            except (httpx.RemoteProtocolError, httpx.ReadTimeout, httpx.ReadError) as e:
                # Routine: the provider drops long-lived push connections now
                # and then. Resync on reconnect means nothing is missed.
                self.log.info("push stream dropped (%s); reconnecting", type(e).__name__)
                time.sleep(2)
            except Exception as e:  # noqa: BLE001 -- stay up; log and back off
                attempt += 1
                wait = J.backoff(attempt)
                self.log.warning("error (%s); retrying in %.0fs", e, wait)
                self.store.event("error", f"[{self.account}] {e!r}"[:500])
                time.sleep(wait)


def digest(store: Store, account: str, since: str,
           local: dt.datetime | None = None) -> tuple[str, str]:
    """The daily digest for one live mailbox: (subject, text), text empty
    when nothing was unsure. Unsure = left in the Inbox on a review score, or
    moved to Spam on a model score below SURE_AT or by a rule (block-list moves
    are sure)."""
    q = lambda sql: store.db.execute(sql, (account, since)).fetchall()
    cols = "from_name, from_email, subject, p_spam, source, list_entry"
    unsure = f"(source='rule' or (source='model' and p_spam<{config.SURE_AT}))"
    kept = q(f"select {cols} from decisions where account=? and decided_at>? "
             "and would='review' order by p_spam desc")
    moved = q(f"select {cols} from decisions where account=? and decided_at>? "
              f"and action='moved' and {unsure} order by p_spam")
    (sure,) = q("select count(*) from decisions where account=? and decided_at>? "
                f"and action='moved' and not {unsure}")[0]
    if not kept and not moved:
        return "", ""

    def lines(rows):
        out = []
        for name, addr, subj, p, source, entry in rows:
            who = f"{name} <{addr}>" if name else addr
            tag = f"rule: {entry}" if source == "rule" else f"{p:.2f}"
            out.append(f"  {who}\n      {subj or '(no subject)'}   [{tag}]")
        return out

    day = (local or dt.datetime.now()).strftime("%b %-d")
    n = len(kept) + len(moved)
    text = [f"exodon: {n} email{'s' if n != 1 else ''} it was not sure about since the last digest."]
    if moved:
        text += ["", f"Moved to Spam, but not certain ({len(moved)}) -- pull back any that are real:"]
        text += lines(moved)
    if kept:
        text += ["", f"Left in your Inbox, possibly spam ({len(kept)}):"] + lines(kept)
    text += ["", f"Also moved {sure} to Spam that it was sure about."]
    if config.WEB_ORIGIN:
        text += ["", f"Mark any of these, or always allow / block a sender: {config.WEB_ORIGIN}"]
    text += ["", "[n.nn] is the model's spam score, 0 to 1."]
    return f"exodon: {n} unsure email{'s' if n != 1 else ''} ({day})", "\n".join(text) + "\n"


def status(store: Store) -> None:
    q = lambda sql, *a: store.db.execute(sql, a).fetchall()
    accts = [r[0] for r in q("select distinct substr(key,1,instr(key,':')-1) from meta "
                             "where key like '%:email_state'")]
    for a in accts or ["-"]:
        n = q("select count(*) from decisions where account=?", a)[0][0]
        live = next((c.live for c in config.accounts() if c.name == a), False)
        print(f"[{a}] {'LIVE' if live else 'shadow'} | last sync {store.get(a + ':last_sync') or '-'} | "
              f"{n} decisions logged")
        for would, source, c in q("select would, source, count(*) from decisions where "
                                  "account=? group by would, source order by would, source", a):
            print(f"    would {would:6} via {source:5}  {c}")
    print("latest:")
    for r in q("select decided_at, account, would, source, from_email, subject from decisions "
               "order by decided_at desc limit 10"):
        print(f"  {r[0][5:16]}  {r[1][:8]:8} {r[2]:6} {r[3]:5}  {r[4][:28]:28} {r[5][:44]}")
    for at, kind, detail in q("select * from events where kind in ('gap','error') "
                              "order by at desc limit 3"):
        print(f"  !{kind} {at}: {detail[:100]}")


def main() -> None:
    import threading

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s",
                        stream=sys.stdout)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    accounts = config.accounts()
    db = config.STATE / "shadow.db"
    store = Store(db, legacy_account=accounts[0].name)  # migrates an old log once
    if cmd == "status":
        return status(store)
    if cmd not in ("run", "once"):
        sys.exit(__doc__)
    import jmap as J

    def watcher(acct):
        client = J.Jmap(acct.token())  # reads and push; never writes
        if not client.read_only:
            log.info("[%s] the read token can write; the reading client never will",
                     acct.name)
        writer = None
        if acct.live:
            writer = J.Jmap(acct.write_token(), write=True)
            if writer.read_only:
                raise SystemExit(f"[{acct.name}] live mode, but the write token is read-only")
            if writer.account != client.account:
                raise SystemExit(f"[{acct.name}] the read and write tokens are for different "
                                 "mailboxes")
        return Shadow(client, Store(db), ListFiles(config.LISTS),
                      B.OllamaLogprobBackend(config.OLLAMA_URL, config.MODEL),
                      account=acct.name, training=acct.training_folder, live=acct.live,
                      address=config.imap_user(acct.name) if acct.live else None,
                      writer=writer)

    # An account whose token is missing is skipped loudly, not fatally: one
    # unconfigured mailbox must not take the others down with it.
    watchers = []
    for acct in accounts:
        try:
            acct.token()
            if acct.live:
                acct.write_token()
        except SystemExit as e:
            log.error("[%s] SKIPPED: %s", acct.name, e)
            store.event("skipped", f"[{acct.name}] {e}")
            continue
        watchers.append(acct)
    if not watchers:
        sys.exit("no account has a JMAP token; nothing to watch")
    if cmd == "once":
        for acct in watchers:
            print(f"[{acct.name}] processed {watcher(acct).sync()} new messages")
        return
    # Each watcher is built inside its own thread: sqlite connections may
    # only be used by the thread that opened them.
    threads = []
    for acct in watchers:
        t = threading.Thread(target=lambda a=acct: watcher(a).run(), name=acct.name, daemon=True)
        t.start()
        threads.append(t)
    while all(t.is_alive() for t in threads):
        time.sleep(30)
    sys.exit("a watcher thread died; exiting so the container restarts")


if __name__ == "__main__":
    main()
