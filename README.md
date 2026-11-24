# exodon

Screen unsolicited mail with explicit allow/block lists and a local language
model, instead of trusting a provider's spam filter or a hosted model.

The spam that gets through a modern filter is not pills and princes. It is
polite, personalised cold outreach ("Re: quick question about Acme Co") that
reads like real correspondence. Deciding whether it is unwanted is a judgment
about **your relationship with the sender**, which no model can read off the
email. exodon keeps that judgment in lists you own and uses a model only for
senders you have no history with.

## Status

A working spike, not yet a service. What exists:

- an evaluation harness that scores any backend against labeled mail from
  your own mailbox (`src/run.py`, `src/metrics.py`, `src/backends.py`)
- a pattern-based allow/block list matcher with a seeding tool that proposes
  lists from mailbox history (`src/lists.py`)
- read-only IMAP tools to build labeled samples and a sender-history index

- **shadow mode** (`src/shadow.py`, `src/grade.py`): watches new mail over
  JMAP push, decides what it *would* do with each message, logs it, and
  touches nothing. Every hour it grades those decisions against where the
  owner actually filed each message. Design: [docs/shadow-mode.md](docs/shadow-mode.md).
- **live mode**, per mailbox (`EXODON_<NAME>_MODE=live`): the same watcher
  also moves screened mail from the Inbox to the provider's Spam folder, and
  once a day puts a digest of the mail it was unsure about in the Inbox
  (unless `EXODON_DIGEST_AT=off`).

## What the spike found

Tested on a real business mailbox, using the owner's hand-trained spam folder
as ground truth and treating the provider's own spam score as the baseline:

- **A 12B local model (gemma4:12b via ollama) recognises cold outreach and
  phishing well**, far better than the provider's score. Two ~400M
  "decision model" encoders built to imitate TypeSafe's jev (jeff, laya)
  performed near chance: a cold pitch has the surface form of correspondence.
- **The model's remaining mistakes are relationship questions**:
  newsletters you signed up for, marketing from companies you buy from, and
  first emails from real people. Putting sender history in the prompt helped
  less than enforcing it as a rule in code.
- **Explicit lists beat inferred ones.** Rules re-derived from mailbox
  behaviour let one misfiled email silently change how a sender is treated
  forever. Lists are seeded from history once, then change only by the
  owner's hand.
- **Thinking models must have thinking off** for classification
  (`think: false` in ollama): with it on, a verdict takes ~10 s and its
  probability is pinned near 0 or 1; with it off, ~0.1-0.2 s and usable.

## Layout

    src/            shadow service, harness, backends, metrics, list matcher,
                    mailbox tools
    tests/          python3 -m unittest discover -s tests
    docker/         shadow-mode container (docker/up.sh)
    docs/           design notes
    lists/          *.example stubs (tracked); your live lists (gitignored)
    fixtures/       synthetic mail for plumbing checks (fake, trivially easy)
    spike/          built from real mail -- samples, results, proposals,
                    findings. Gitignored; created by the tools.
    var/            shadow mode's decision log and report. Gitignored.

## Setup

Python 3.10+ and `httpx`. A mailbox reachable over IMAP (read-only is
enough). For the local model, [ollama](https://ollama.com) with a model such
as `gemma4:12b`.

    cp .env.example .env          # mailbox, ollama URL
    cp lists/allow.txt.example lists/allow.txt      # or seed them, below
    cp lists/block.txt.example lists/block.txt
    cp lists/decisions.txt.example lists/decisions.txt

## Usage

    # plumbing check -- no mail, no model
    python3 src/run.py --backend mock --corpus fixtures/synthetic.jsonl

    # build a labeled sample and a sender-history index from your mailbox
    python3 src/build_work_corpus.py
    python3 src/context.py index
    python3 src/context.py annotate spike/corpus/work.jsonl

    # score the provider's own spam header, then the local model
    python3 src/run.py --backend fastmail --corpus spike/corpus/work_ctx.jsonl
    python3 src/run.py --backend local --model gemma4:12b --corpus spike/corpus/work_ctx.jsonl

    # propose allow/block lists from mailbox history, then check a sender
    python3 src/lists.py seed          # -> spike/proposed/{allow,block,decide}.txt
    python3 src/lists.py check someone@example.com

If a secrets manager injects the IMAP password, set `EXODON_IMAP_PASSWORD_ENV`
to the variable's name and wrap the command, e.g.
`keys exec MY_IMAP_SECRET -- python3 src/context.py index`.

Reports land in `spike/results/`. Results are phrased as "spam caught at a
given rate of real mail junked", because a filter that loses one real email
in a hundred is worse than one that catches no spam at all.

## Shadow mode

Needs a **read-only** JMAP token (`EXODON_JMAP_TOKEN` or
`EXODON_JMAP_TOKEN_ENV` in `.env`); the client also refuses any write method
itself.

**Live mode** (`EXODON_<NAME>_MODE=live`) needs a second, writable token for
that mailbox (`EXODON_<NAME>_JMAP_WRITE_TOKEN_ENV`); reads and push stay on the
read-only one. The writing client then allows exactly two writes: moving one
message between the Inbox and Spam, and creating the daily digest in the Inbox (`EXODON_DIGEST_AT`, local time in
`EXODON_TZ`; skipped when nothing was unsure; `off` turns it off). Moves happen only when exodon
screens a message that is in the Inbox and nowhere else, or when you correct a
call on the review page (below). Nothing is ever sent, flagged
or deleted. Unsure means the review band, or moved to Spam on a model score
below `EXODON_SURE_AT` (0.999); block-list moves count as sure.

    python3 src/shadow.py once       # one sync (first run: start watching from now)
    python3 src/shadow.py run        # daemon: push, decide, log, grade hourly
    python3 src/shadow.py status     # what has been logged
    python3 src/grade.py             # grade now and print the report
    python3 src/grade.py report      # report only, no network

    docker/up.sh                     # as a container; tokens go in
                                     # docker/docker-compose.override.yml, and a
                                     # secrets-manager wrapper in docker/up.local.sh

The report lands in `var/report.txt`, rewritten hourly: spam caught, real mail
that would have been screened (by sender and subject, so each can be checked),
what other screen thresholds would have done, and what the provider's own
filter did.

### Review page

    python3 src/web.py               # :8799; in Docker, the exodon-web service

Three views of the last week: **Filtered** (moved to Spam, or would have
been), **Let through**, and **Unsure** (what the digest lists). One row per
message, grouped by day; open one to see why, a short preview, and the fix:
**Not spam** / **Spam** (your mark beats the folder when scoring), or always
allow / block the sender (one checked line at a time, with undo). **Allow &
block** shows one list at a time, with a box that filters it or, given an
address, says which entry decides it.

On a live mailbox a correction also moves the message (Spam -> Inbox for Not
spam, Inbox -> Spam for Spam; Undo moves it back). The page holds no mail
token: it adds a row to the log's `moves` table, and the watcher makes the
move on its next push ping (about a minute), only for a message it decided,
only if it is still where the page saw it, and only within an hour of asking;
anything else is refused and the reason shown on the row. It has no password: put it behind a private network, and
set `EXODON_WEB_HOSTS` / `EXODON_WEB_ORIGIN` to the name it is served under --
it refuses any other Host, and any button press not sent from its own page.
Design: `docs/superpowers/specs/2026-09-27-review-page-design.md`.

### Readout

`GET /api/readout?hours=24` on the review page returns the window's decisions
as JSON, per mailbox: counts, everything screened (with a short body preview),
the unsure ones, where your filing disagreed, and model errors
(`src/readout.py`). It is for another agent to summarize the filtering and
point out what deserves a second look; it changes nothing. Off unless
a readout token is set, and every call needs one as a bearer token: one per
reader, `EXODON_READOUT_TOKEN_<READER>`, so each can be revoked alone. The
containers named in `EXODON_WEB_READERS` may call it directly; they still cannot
reach the page or its buttons.

For example, an agent container named `agent` on the proxy network, with
`EXODON_WEB_READERS=agent` and its own `EXODON_READOUT_TOKEN_AGENT`, calls
`http://exodon-web:8799/api/readout` with that token.

## Lists

Syntax and precedence are documented in `lists/allow.txt.example` and at the
top of `src/lists.py`. In short: exact address, `@domain` (with subdomains),
globs, `name:` display-name globs and `re:` regexes; the most specific match
wins; an exact tie goes to allow; allow only counts for authenticated mail.
Rulings on senders that appear in both your spam folder and your archive go in
`lists/decisions.txt`, which the seeding tool applies first and never re-asks.
