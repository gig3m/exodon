#!/usr/bin/env python3
"""Mailbox context: what the mailbox already knew about a sender before an
email arrived. Gives a model the one fact it cannot read off the email --
whether Kyle has a relationship with the company.

    keys exec MY_IMAP_SECRET -- python3 src/context.py index   # see .env.example
    keys exec <that account's IMAP secret> -- python3 src/context.py index --account personal
    python3 src/context.py annotate corpus/work.jsonl corpus/curated.jsonl

`index` scans the whole mailbox read-only -- Sent recipients, and sender +
date for every archived message and every message in the hand-trained spam
folder -- into corpus/mailbox_index.json, or mailbox_index.<account>.json with
--account (login from EXODON_<ACCOUNT>_IMAP_*).
`annotate` adds a `context` block to each row and writes <name>_ctx.jsonl.

LEAKAGE WARNING. work_pinned's negatives were *selected* by "Kyle emailed
this address", so any sender-history feature trivially separates that set.
Evaluate context on a set drawn without that filter (the random draw in
work.jsonl), and read curated's correspondence row with the same caution.
Only messages received strictly *before* the one being scored are counted.
"""

from __future__ import annotations

import datetime as dt
import email
import email.policy
import email.utils
import imaplib
import json
import os
import pathlib
import re
import ssl
import sys
from collections import defaultdict

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
import config  # noqa: E402

INDEX = config.DATA / "corpus" / "mailbox_index.json"

# For these the domain says nothing about a relationship, so fall back to the
# individual address.
FREEMAIL = {
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com",
    "msn.com", "yahoo.com", "icloud.com", "me.com", "aol.com", "duck.com",
    "proton.me", "protonmail.com", "gmx.com", "mail.com",
    # Bulk-sending platforms: thousands of unrelated senders share these
    # domains, so having once emailed someone at beehiiv.com must not vouch
    # for every newsletter sent through it.
    "beehiiv.com", "ccsend.com", "constantcontact.com", "list-manage.com",
    "mailchimpapp.com", "mcsv.net", "mcdlv.net", "hubspotemail.net",
    "hubspotlinks.com", "sendgrid.net", "sendinblue.com", "sendibm3.com",
    "brevo.com", "substack.com", "mailgun.org", "amazonses.com",
    "sparkpostmail.com", "klaviyomail.com", "govdelivery.com", "mlsend.com",
    "convertkit-mail.com", "createsend.com", "cmail19.com", "cmail20.com",
    # Internet-provider mailboxes: a customer base, not a company.
    "att.net", "sbcglobal.net", "bellsouth.net", "comcast.net", "cox.net",
    "charter.net", "earthlink.net", "windstream.net", "suddenlink.net", "suddenlinkmail.com",
    "verizon.net", "optonline.net", "frontier.com", "centurylink.net",
    "embarqmail.com", "q.com", "rocketmail.com", "ymail.com", "tds.net", "valornet.com",
    # Hosting relays and marketing/inbound-processing platforms: reply-to
    # plumbing shared by thousands of unrelated senders.
    "secureserver.net", "maropost.com", "customer.io", "mindbox.cloud",
    "emailinboundprocessing.com", "emailinboundprocessing.eu",
}


# Addresses that are not a person or a company you corresponded with: one-off
# tracking/bounce addresses (VERP "kyle=example.com@...", long random tokens)
# and unsubscribe/opt-out mailboxes. Emailing one of these says nothing about
# a relationship -- and an unsubscribe to a normal-looking
# unsubscribe@vendor.com must not vouch for all of @vendor.com.
_UNSUB = re.compile(r"^(unsub|unsubscribe|optout|opt-out|opt_out|remove|leave|list-unsubscribe)"
                    r"([+._-]|$)")
_BOUNCE = re.compile(r"^(bounce|bounces|return|reply|msprvs\d)[+._-]")


def is_tracking_address(addr: str) -> bool:
    local = (addr or "").lower().split("@", 1)[0]
    if not local:
        return False
    if "=" in local or _UNSUB.match(local) or _BOUNCE.match(local):
        return True
    if "+" in local and len(local.split("+", 1)[1]) >= 12:
        return True
    return (len(local) >= 24 and sum(c.isdigit() for c in local) >= 5
            and not re.search(r"[._]", local))


def parse_date(s: str) -> float:
    try:
        return dt.datetime.strptime(s, "%d-%b-%Y %H:%M:%S %z").timestamp()
    except (ValueError, TypeError):
        return 0.0


def org(addr: str) -> str:
    """The relationship key: registrable-ish domain, or the full address for
    free-mail providers. Subdomains collapse (mail.x.com, e.x.com -> x.com) so
    a company's marketing sender matches its people."""
    addr = (addr or "").lower().strip()
    if "@" not in addr:
        return addr
    dom = addr.split("@", 1)[1]
    # match subdomains too: mail.beehiiv.com is still beehiiv
    if any(dom == d or dom.endswith("." + d) for d in FREEMAIL):
        return addr
    parts = dom.split(".")
    # US locality domains (ci.jacksonville.tx.us): tx.us is a suffix, not an
    # organisation; keep the city/county, and one more label for k12/ci/co.
    if len(parts) >= 3 and parts[-1] == "us" and len(parts[-2]) == 2:
        keep = 4 if len(parts) >= 4 and parts[-3] in ("k12", "ci", "co", "cc", "lib", "state") else 3
        return ".".join(parts[-keep:])
    # keep two labels, three for things like co.uk / com.au
    if len(parts) >= 3 and len(parts[-1]) == 2 and parts[-2] in ("co", "com", "org", "net", "gov"):
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def index_path(account: str | None = None) -> pathlib.Path:
    return INDEX if not account else INDEX.with_name(f"mailbox_index.{account}.json")


def build_index(account: str | None = None) -> None:
    pw = config.imap_password(account)
    M = imaplib.IMAP4_SSL(config.IMAP_HOST, 993, ssl_context=ssl.create_default_context())
    M.login(config.imap_user(account), pw)
    training = next((a.training_folder for a in config.accounts() if a.name == account),
                    config.TRAINING_FOLDER)

    def scan(folder: str, fields: str, want_date: bool):
        ok, _ = M.select(f'"{folder}"', readonly=True)
        ok, data = M.uid("SEARCH", None, "ALL")
        uids = data[0].split()
        for i in range(0, len(uids), 500):
            ok, resp = M.uid("FETCH", b",".join(uids[i:i + 500]).decode(),
                             f"(INTERNALDATE BODY.PEEK[HEADER.FIELDS ({fields})])")
            for item in resp:
                if isinstance(item, tuple):
                    m = re.search(rb'INTERNALDATE "([^"]+)"', item[0])
                    yield (m.group(1).decode() if m else ""), \
                        email.message_from_bytes(item[1], policy=email.policy.compat32)
            print(f"  {folder}: {min(i + 500, len(uids))}/{len(uids)}", file=sys.stderr, end="\r")
        print(file=sys.stderr)

    sent: dict[str, float] = {}  # org -> earliest time Kyle wrote to it
    for when, msg in scan("Sent", "TO CC BCC", True):
        t = parse_date(when)
        vals = [str(v) for f in ("To", "Cc", "Bcc") for v in msg.get_all(f, [])]
        for _, a in email.utils.getaddresses(vals):
            if a and not is_tracking_address(a):
                k = org(a)
                sent[k] = min(sent.get(k, t), t)

    kept: dict[str, list[float]] = defaultdict(list)  # org -> times of archived mail
    for when, msg in scan("Archive", "FROM", True):
        _, a = email.utils.parseaddr(str(msg.get("From", "")))
        if a:
            kept[org(a)].append(parse_date(when))

    # The owner's hand-trained spam folder: who filed there, with the display
    # name (rotating-domain senders keep their name) and when.
    spam: list[list] = []
    for when, msg in scan(training, "FROM", True):
        name, a = email.utils.parseaddr(str(msg.get("From", "")))
        if a:
            spam.append([parse_date(when), a.strip().lower(), name.strip()])
    M.logout()

    out = index_path(account)
    out.write_text(json.dumps({"account": account or "default", "sent": sent,
                               "kept": {k: sorted(v) for k, v in kept.items()}, "spam": spam}))
    print(f"indexed {account or 'mailbox'}: {len(sent)} orgs written to, "
          f"{sum(map(len, kept.values()))} archived from {len(kept)} orgs, "
          f"{len(spam)} in {training} -> {out}", file=sys.stderr)


def describe(row: dict, idx: dict) -> str:
    """Plain-language context, as a person glancing at their inbox would know it."""
    t = parse_date(row.get("received_at", ""))
    k = org(row.get("from_email", ""))
    who = k if "@" not in k else "this sender"
    wrote = idx["sent"].get(k)
    wrote_before = wrote is not None and (t == 0 or wrote < t)
    prior = sum(1 for x in idx["kept"].get(k, []) if t == 0 or x < t)
    lines = [
        f"The recipient has emailed {who} before." if wrote_before
        else f"The recipient has never emailed {who}.",
        f"The recipient kept {prior} earlier email{'s' if prior != 1 else ''} from {who}."
        if prior else f"The recipient has not kept any earlier email from {who}.",
    ]
    return "Mailbox context: " + " ".join(lines)


def annotate(paths: list[str]) -> None:
    idx = json.loads(INDEX.read_text())
    for p in map(pathlib.Path, paths):
        rows = [json.loads(l) for l in p.read_text().splitlines() if l.strip()]
        for r in rows:
            r["context"] = describe(r, idx)
        out = p.with_name(p.stem + "_ctx.jsonl")
        out.write_text("\n".join(json.dumps(r) for r in rows))
        print(f"{p.name} -> {out.name} ({len(rows)} rows)", file=sys.stderr)


if __name__ == "__main__":
    if len(sys.argv) >= 2 and sys.argv[1] == "index":
        acct = sys.argv[sys.argv.index("--account") + 1] if "--account" in sys.argv else None
        build_index(acct)
    elif len(sys.argv) >= 3 and sys.argv[1] == "annotate":
        annotate(sys.argv[2:])
    else:
        sys.exit(__doc__)
