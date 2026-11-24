#!/usr/bin/env python3
"""Allow / block lists: explicit, owned by Kyle. Changed only by him: by hand,
or by a click on the review page (src/listedit.py), never by the service.

    python3 src/lists.py seed             # write proposals to spike/proposed/
    python3 src/lists.py check ADDR [NAME]   # which entry decides this sender
    python3 src/lists.py lint             # overlaps and dead entries

Pattern syntax, one per line, case-insensitive, `#` starts a note:

    bob@acme.com                exact address
    @acme.com                   acme.com and every subdomain (mail.acme.com)
    *@acme.com                  glob on the full address: only acme.com itself
    invoices-*@acme.com         glob; * and ? work anywhere in the address
    no-reply@*                  glob; that local part on any domain
    name:*Hello Funding*        glob on the display name
    re:@.*nassau.*\\.info$      regular expression searched in the address

Precedence: the most specific matching entry wins, across both lists.
    exact address > address glob (more literal characters first)
    > domain (more labels first: @business.amazon.com beats @amazon.com)
    > name: > re:
An allow and a block at the same specificity -> allow (never lose real mail);
`lint` reports those.

Allow entries are meant to count only when the message is authenticated for
the sender's domain (DKIM/SPF), otherwise a forged From: walks straight
through -- a spam folder can hold mail forging your own company address. That check belongs to the service, which sees the headers; the
matcher only decides which entry applies.
"""

from __future__ import annotations

import fnmatch
import json
import pathlib
import re
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
import config  # noqa: E402

LISTS = config.LISTS
PROPOSED = config.DATA / "proposed"


@dataclass(frozen=True)
class Entry:
    raw: str
    kind: str        # exact | glob | domain | name | re
    list: str        # allow | block
    note: str = ""
    line: int = 0

    @property
    def rank(self) -> tuple:
        """Lower sorts first = more specific."""
        tier = {"exact": 0, "glob": 1, "domain": 2, "name": 3, "re": 4}[self.kind]
        if self.kind == "glob":
            return (tier, -len(self.raw.replace("*", "").replace("?", "")))
        if self.kind == "domain":
            return (tier, -self.raw.count("."))
        return (tier, 0)

    def matches(self, addr: str, name: str) -> bool:
        if self.kind == "exact":
            return addr == self.raw
        if self.kind == "glob":
            return fnmatch.fnmatchcase(addr, self.raw)
        if self.kind == "domain":
            dom = addr.rsplit("@", 1)[-1]
            d = self.raw[1:]
            return dom == d or dom.endswith("." + d)
        if self.kind == "name":
            return fnmatch.fnmatchcase(name, self.raw[5:])
        return re.search(self.raw[3:], addr) is not None


def parse_line(text: str, which: str, lineno: int = 0) -> Entry | None:
    body, _, note = text.partition("#")
    pat = body.strip().lower()
    if not pat:
        return None
    if pat.startswith("name:"):
        kind = "name"
    elif pat.startswith("re:"):
        re.compile(pat[3:])  # fail loudly on a bad regex
        kind = "re"
    elif "*" in pat or "?" in pat:
        kind = "glob"
    elif pat.startswith("@"):
        kind = "domain"
    elif "@" in pat:
        kind = "exact"
    else:
        raise ValueError(f"{which}:{lineno}: not an address, @domain, glob, "
                         f"name: or re: pattern: {text.strip()!r}")
    return Entry(pat, kind, which, note.strip(), lineno)


def load(path: pathlib.Path, which: str) -> list[Entry]:
    if not path.exists():
        return []
    return load_text(path.read_text(), which)


def load_text(text: str, which: str) -> list[Entry]:
    out = []
    for i, line in enumerate(text.splitlines(), 1):
        e = parse_line(line, which, i)
        if e:
            out.append(e)
    return out


def decide(entries: list[Entry], addr: str, name: str = "") -> Entry | None:
    """The single entry that governs this sender, or None (-> ask the model)."""
    addr, name = (addr or "").lower().strip(), (name or "").lower().strip()
    hits = [e for e in entries if e.matches(addr, name)]
    if not hits:
        return None
    # allow sorts before block at equal rank
    return min(hits, key=lambda e: (e.rank, e.list != "allow"))


# --------------------------------------------------------------------- seed

def _load_indexes(C) -> tuple[dict, Counter, list[dict], list[str]]:
    """Merge the per-account mailbox indexes (src/context.py index --account)
    into one view: who you have emailed from ANY account, how much you kept,
    and who you filed as spam. With no per-account index, fall back to the
    single legacy index plus the spike's spam-folder download."""
    names = [a.name for a in config.accounts()]
    paths = [C.index_path(n) for n in names if C.index_path(n).exists()]
    missing = [n for n in names if not C.index_path(n).exists()]
    if not paths:
        paths, missing = [C.index_path()], []
    sent: dict = {}
    kept: Counter = Counter()
    spam_rows: list[dict] = []
    used = []
    for path in paths:
        idx = json.loads(path.read_text())
        used.append(idx.get("account", path.name))
        for k, t in idx["sent"].items():
            sent[k] = min(sent.get(k, t), t)
        kept.update({k: len(v) for k, v in idx["kept"].items()})
        if "spam" in idx:
            spam_rows += [{"from_email": a, "from_name": n, "account": idx.get("account")}
                          for _, a, n in idx["spam"]]
        else:  # legacy index: spam senders came from the spike download
            spam_rows += [json.loads(l) for l in (config.DATA / "corpus" / "work_all.jsonl").open()
                          if json.loads(l)["source"] == "Identified Spam"]
    if missing:
        print(f"note: no index yet for {', '.join(missing)} -- run "
              f"`src/context.py index --account NAME`", file=sys.stderr)
    return sent, kept, spam_rows, used


def seed() -> None:
    """Propose lists from mailbox history. Writes to <data>/proposed/ only;
    nothing is live until Kyle reviews and moves the files up a level.
    new-allow.txt / new-block.txt hold just what the live lists lack."""
    import datetime as dt
    sys.path.insert(0, str(ROOT / "src"))
    import context as C

    sent, kept, spam_rows, used = _load_indexes(C)
    spam = Counter(C.org(r["from_email"]) for r in spam_rows)
    today = dt.date.today().isoformat()

    def pattern(k: str) -> str:
        # org() returns an address for free-mail and bulk platforms, where the
        # domain vouches for nobody; a company domain otherwise.
        return k if "@" in k else "@" + k

    # Kyle's explicit rulings win over anything derived below, and a pattern
    # he has ruled on is never offered in decide.txt again.
    decided: dict[str, tuple[str, str]] = {}
    dpath = LISTS / "decisions.txt"
    if dpath.exists():
        for i, line in enumerate(dpath.read_text().splitlines(), 1):
            body, _, note = line.partition("#")
            parts = body.split()
            if not parts:
                continue
            if len(parts) != 2 or parts[0] not in ("allow", "block"):
                sys.exit(f"decisions.txt:{i}: expected 'allow|block <pattern>': {line!r}")
            parse_line(parts[1], parts[0], i)  # validate the pattern
            decided[parts[1].lower()] = (parts[0], note.strip())

    allow, block, mixed = [], [], []
    for pat, (which, note) in decided.items():
        (allow if which == "allow" else block).append((pat, f"owner: {note}", 10**9))
    for k in sent:
        if pattern(k) in decided:
            continue
        if spam.get(k):
            mixed.append(k)
        else:
            allow.append((pattern(k), f"you emailed them; {kept.get(k, 0)} archived", kept.get(k, 0)))
    for k, n in spam.items():
        if k in sent or pattern(k) in decided:
            continue
        if kept.get(k):
            mixed.append(k)
        elif n >= 2:
            block.append((pattern(k), f"{n} in Identified Spam, never archived or emailed", n))

    def covered(k: str) -> bool:
        dom = k.rsplit("@", 1)[-1]
        return any(p.startswith("@") and (dom == p[1:] or dom.endswith("." + p[1:]))
                   for p in decided)
    mixed = [k for k in mixed if not covered(k)]
    block = [b for b in block if b[2] == 10**9 or not covered(b[0].lstrip("@"))]
    allow = [a for a in allow if a[2] == 10**9 or not covered(a[0].lstrip("@"))]

    # Rotating-domain families: one display name ("X from Hello Funding")
    # across several domains. A domain entry cannot catch the next one.
    fam = defaultdict(set)
    for r in spam_rows:
        m = re.search(r"\bfrom\s+(.+)$", r["from_name"] or "", re.I)
        brand = (m.group(1) if m else "").strip().lower()
        if len(brand) >= 5:
            fam[brand].add(r["from_email"].split("@")[-1])
    families = [(f"name:*{b}*", f"display name across {len(d)} domains: {', '.join(sorted(d)[:3])}")
                for b, d in fam.items() if len(d) >= 2]

    # Domains that relay mail on behalf of many people (notifications, messages
    # from strangers). Emailing someone there once should not vouch for all of it.
    relays = {"linkedin.com", "facebookmail.com", "google.com", "microsoft.com",
              "apple.com", "zoom.us", "docusign.net", "dropbox.com", "slack.com"}
    flagged = [pattern(k) for k in sent if k in relays and not spam.get(k)]
    allow = [a for a in allow if a[0] not in flagged]

    out = PROPOSED
    out.mkdir(parents=True, exist_ok=True)
    head = ("# PROPOSED -- generated {when} by src/lists.py seed from mailbox history.\n"
            "# Nothing here is live. Review, edit, then move to lists/{name}.\n"
            "# Syntax: see the docstring of src/lists.py.\n# From mailboxes: " + ", ".join(used) + "\n\n")
    (out / "allow.txt").write_text(
        head.format(when=today, name="allow.txt")
        + "\n".join(f"{p:44} # {n}" for p, n, _ in sorted(allow, key=lambda x: -x[2])) + "\n")
    (out / "block.txt").write_text(
        head.format(when=today, name="block.txt")
        + "\n".join(f"{p:44} # {n}" for p, n, _ in sorted(block, key=lambda x: -x[2]))
        + "\n\n# --- suggested patterns for rotating-domain senders\n"
        + "\n".join(f"{p:44} # {n}" for p, n in families) + "\n")
    lines = ["# Senders in BOTH your spam folder and your archive/sent mail.",
             "# Not seeded into either list. Decide each; an address- or subdomain-",
             "# level entry can split a company (allow the company, block one sender).",
             ""]
    for k in sorted(set(mixed), key=lambda k: -(spam.get(k, 0) + kept.get(k, 0))):
        who = sorted({r["from_email"] for r in spam_rows if C.org(r["from_email"]) == k})
        lines.append(f"{pattern(k):40} spam {spam.get(k,0):>3} | archived {kept.get(k,0):>4} | "
                     f"{'emailed' if k in sent else 'never emailed'}")
        lines.append(f"    spam came from: {', '.join(who)}")
    if flagged:
        lines += ["", "# Relay/notification domains you have emailed someone at. Held out of",
                  "# allow.txt because the domain also carries mail from strangers",
                  "# (e.g. LinkedIn messages). Allow the specific people instead, or",
                  "# the whole domain if you really mean it."]
        lines += [f"{p:40} {kept.get(p.lstrip('@'), 0)} archived" for p in sorted(flagged)]
    (out / "decide.txt").write_text("\n".join(lines) + "\n")

    # What the live lists do not have yet -- the only part that needs review
    # once the lists are live.
    live = {e.raw for e in load(LISTS / "allow.txt", "allow") + load(LISTS / "block.txt", "block")}
    fresh = {}
    for name, rows in (("allow", allow), ("block", block + [(p, n, 0) for p, n in families])):
        new = [(p, n) for p, n, _ in sorted(rows, key=lambda x: -x[2]) if p.lower() not in live]
        fresh[name] = len(new)
        (out / f"new-{name}.txt").write_text(
            f"# NEW {name} entries: proposed from mailbox history on {today}, not yet in "
            f"lists/{name}.txt.\n# Review, then append the ones you want to lists/{name}.txt.\n\n"
            + "\n".join(f"{p:44} # {n}" for p, n in new) + "\n")
    print(f"proposed from {', '.join(used)}: allow {len(allow)}, block {len(block)} + "
          f"{len(families)} name patterns, to decide {len(set(mixed))} -> {out}")
    print(f"not yet in your live lists: {fresh['allow']} allow, {fresh['block']} block "
          f"(new-allow.txt, new-block.txt)")


def lint() -> None:
    allow = load(LISTS / "allow.txt", "allow")
    block = load(LISTS / "block.txt", "block")
    print(f"allow {len(allow)} entries, block {len(block)}")
    for a in allow:
        for b in block:
            if a.rank == b.rank and a.raw == b.raw:
                print(f"  CONFLICT same pattern in both lists: {a.raw} "
                      f"(allow:{a.line}, block:{b.line}) -> allow wins")


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd == "seed":
        seed()
    elif cmd == "lint":
        lint()
    elif cmd == "check" and len(sys.argv) >= 3:
        entries = (load(LISTS / "allow.txt", "allow") + load(LISTS / "block.txt", "block")
                   or load(PROPOSED / "allow.txt", "allow")
                   + load(PROPOSED / "block.txt", "block"))
        e = decide(entries, sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else "")
        print(f"{e.list.upper()} via {e.raw!r} ({e.kind}) # {e.note}" if e else "no entry -> model decides")
    else:
        sys.exit(__doc__)
