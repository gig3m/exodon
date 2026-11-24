"""List edits from the review page: one validated line at a time.

From a message row the page adds a line derived from the logged address,
never from the request. On the lists page the owner may also type a pattern
(manual_line validates it as the watcher will parse it) or remove any single
line by its exact text. Every write is checked to parse to exactly the old
entries plus (or minus) that one -- a list file that fails to parse would stop every
decision, and a stray newline in a subject must not become a live pattern.
"""

from __future__ import annotations

import os
import pathlib
import re
import unicodedata
from dataclasses import dataclass

import context as C
import lists as L

ADDR_RE = re.compile(r"^[a-z0-9._%+-]+@[a-z0-9-]+(\.[a-z0-9-]+)+$")
LABEL_RE = re.compile(r"^[a-z0-9-]+$")
NOTE_LEN = 40
# Shared hosting where one domain holds many unrelated senders (a Microsoft 365
# tenant, a Heroku app): like free-mail, only the single address may be listed.
SHARED_HOSTING = {
    "onmicrosoft.com", "herokuapp.com", "github.io", "firebaseapp.com", "web.app",
    "appspot.com", "azurewebsites.net", "cloudfront.net", "amazonaws.com", "netlify.app",
    "vercel.app", "pages.dev", "workers.dev", "wordpress.com", "blogspot.com",
    "wixsite.com", "godaddysites.com", "myshopify.com", "square.site", "weebly.com",
    "sharepoint.com", "google.com", "googlegroups.com", "zendesk.com", "freshdesk.com",
}


class Refused(Exception):
    """A request the page will not carry out; the message says why."""


def is_platform(addr: str) -> bool:
    """Free-mail, bulk-sending and relay senders: their domain vouches for
    nobody, so only the single address may be listed."""
    addr = (addr or "").lower().strip()
    if "@" not in addr:
        return False
    dom = addr.rsplit("@", 1)[1]
    if any(dom == d or dom.endswith("." + d) for d in SHARED_HOSTING):
        return True
    return C.org(addr) == addr


def default_scope(addr: str) -> str:
    return "address" if is_platform(addr) else "domain"


def candidate(addr: str, scope: str) -> str:
    """The list pattern for this sender at this scope, or Refused."""
    addr = (addr or "").lower().strip()
    if not ADDR_RE.match(addr):
        raise Refused(f"not a plain email address: {addr!r}")
    if scope == "address":
        e = L.parse_line(addr, "allow")
        if e is None or e.kind != "exact":
            raise Refused(f"not a plain email address: {addr!r}")
        return addr
    if scope == "domain":
        if is_platform(addr):
            raise Refused(f"{addr.split('@')[1]} is a shared mail service; "
                          "list the address, not the whole domain")
        dom = C.org(addr)
        if not all(LABEL_RE.match(p) for p in dom.split(".")):
            raise Refused(f"unusual domain: {dom!r}")
        return "@" + dom
    raise Refused(f"unknown scope {scope!r}")


@dataclass
class Verdict:
    status: str   # covered | ok | blocked
    pattern: str
    message: str


def verdict(entries: list, addr: str, name: str, which: str, pattern: str,
            list_note: str | None = None) -> Verdict:
    """Would adding `pattern` to `which` decide this sender? Uses the same
    precedence as the watcher (lists.decide), so the answer is the truth."""
    before = L.decide(entries, addr, name)
    if before is not None and before.list == which:
        msg = f"already on the {which} list as {before.raw}"
        if which == "allow" and list_note and "not authenticated" in list_note:
            msg += (" -- but this message did not prove it came from that domain, "
                    "so the entry was ignored for it")
        return Verdict("covered", pattern, msg)
    cand = L.parse_line(pattern, which)
    after = L.decide(entries + [cand], addr, name)
    if after is cand:
        msg = f"adds {pattern} to the {which} list"
        if before is not None:
            msg += f" (overrides {before.list} {before.raw})"
        return Verdict("ok", pattern, msg)
    return Verdict("blocked", pattern,
                   f"{after.list} {after.raw} would still decide this sender; "
                   f"change it by hand in lists/{after.list}.txt")


def note(subject: str) -> str:
    """The subject, safe inside a list comment: no line breaks of any kind
    (str.splitlines splits on more than \\n), no control characters, no `#`
    or quotes."""
    out = []
    for ch in subject or "":
        if len(("a" + ch + "b").splitlines()) > 1 or unicodedata.category(ch).startswith("C"):
            out.append(" ")
        elif ch not in '#"':
            out.append(ch)
    return " ".join("".join(out).split())[:NOTE_LEN]


def line_for(pattern: str, subject: str, today: str) -> str:
    return f'{pattern}  # exodon page {today}: "{note(subject)}"'


PATTERN_LEN = 200


def manual_line(pattern: str, which: str, why: str, today: str) -> str:
    """A line the owner typed on the lists page: any pattern the list syntax
    accepts (address, @domain, glob, name:, re:), validated the same way the
    watcher will parse it, plus a cleaned note."""
    if which not in ("allow", "block"):
        raise Refused("list must be allow or block")
    pat = (pattern or "").strip()
    if not pat or len(pat) > PATTERN_LEN:
        raise Refused(f"a pattern is 1 to {PATTERN_LEN} characters")
    if any(len(("a" + ch + "b").splitlines()) > 1 or unicodedata.category(ch).startswith("C")
           or ch == "#" for ch in pat):
        raise Refused("a pattern cannot hold line breaks, control characters or #")
    try:
        e = L.parse_line(pat, which)
    except (ValueError, re.error) as err:
        raise Refused(str(err).split(": ", 1)[-1]) from None
    if e is None:
        raise Refused("empty pattern")
    if e.kind == "domain" and is_platform("x" + e.raw):
        raise Refused(f"{e.raw[1:]} is a shared mail service; list single addresses on it")
    extra = note(why)
    return f'{e.raw}  # exodon page {today}' + (f': "{extra}"' if extra else "")


# ---------------------------------------------------------------- writing


def _read(path: pathlib.Path) -> tuple[str, int, int]:
    """(text, mtime_ns, mode); an absent file reads as empty."""
    try:
        st = path.stat()
    except FileNotFoundError:
        return "", 0, 0o644
    return path.read_text(), st.st_mtime_ns, st.st_mode & 0o777


def _mtime_check(path: pathlib.Path, mtime: int) -> bool:
    try:
        return path.stat().st_mtime_ns == mtime
    except FileNotFoundError:
        return mtime == 0


def _replace(path: pathlib.Path, which: str, change) -> None:
    """Read, apply `change(text) -> (new_text, expected_raws)`, validate,
    and rename into place -- retrying once if the file was edited meanwhile.
    The mtime check narrows, but cannot close, the window against an editor
    saving at the same instant; the page's writes are rare and logged."""
    for _ in range(2):
        text, mtime, mode = _read(path)
        new, want = change(text)
        if [e.raw for e in L.load_text(new, which)] != want:
            raise Refused("the edit would change more than one entry; nothing written")
        tmp = path.with_name(f".{path.name}.exodon-tmp")
        tmp.write_text(new)
        os.chmod(tmp, mode)
        if not _mtime_check(path, mtime):
            tmp.unlink()
            continue  # a hand edit landed: start again from the new file
        os.replace(tmp, path)
        return
    raise Refused(f"{path.name} kept changing while writing; try again")


def append(path: pathlib.Path, which: str, line: str) -> None:
    new_entries = L.load_text(line, which)
    if len(new_entries) != 1 or "\n" in line or len(line.splitlines()) != 1:
        raise Refused("not exactly one list entry")

    def change(text):
        old = [e.raw for e in L.load_text(text, which)]
        sep = "" if not text or text.endswith("\n") else "\n"
        return text + sep + line + "\n", old + [new_entries[0].raw]

    _replace(path, which, change)


def remove(path: pathlib.Path, which: str, line: str) -> None:
    def change(text):
        lines = text.splitlines(keepends=True)
        hits = [i for i, x in enumerate(lines) if x.rstrip("\r\n") == line]
        if len(hits) != 1:
            raise Refused("that line is no longer in the list exactly once; "
                          "leaving the file alone")
        old = [e.raw for e in L.load_text(text, which)]
        gone = L.load_text(line, which)[0].raw
        want = old.copy()
        want.remove(gone)
        return "".join(lines[:hits[0]] + lines[hits[0] + 1:]), want

    _replace(path, which, change)
