# Shadow mode

Watch new mail, decide what exodon *would* do with each message, and log it
-- without touching the mailbox. Later, grade every logged decision against
where the owner actually filed the message. The result is the number the spike
could not give: accuracy on fresh mail, with the real lists.

## Guarantees

- **Read-only** (shadow-mode mailboxes; see Live mode below). A read-only JMAP token, and a client that refuses any method
  outside `Session`, `Mailbox/get`, `Email/get`, `Email/changes`,
  `Email/query`. Nothing is moved, flagged, labelled or marked read.
- **Nothing is sent anywhere else.** The model runs on the local ollama.
- **Losing the log loses history, nothing more.** It is a record, not a
  source of truth; the mailbox and the list files are.

## Flow

```
Fastmail --push (EventSource, types=Email)--> state changed
  -> Email/changes since the last saved state -> new message ids
  -> Email/get headers, authentication results, first ~4 KB of text
  -> decide (below) -> append to var/shadow.db, save the new state
```

On first start there is no saved state: record the current one and begin from
now (no backfill). If Fastmail cannot compute changes from an old state (after
long downtime), record the gap in the log and resume from the current state.
Sent and Drafts are skipped; everything else is decided, including mail that
Fastmail filed straight into its own Spam folder.

## Decision

1. **Lists** (`lists/allow.txt`, `lists/block.txt`, reloaded when the files
   change). Most specific entry wins, as in `src/lists.py`.
   - An **allow** entry counts only if the message is **authenticated** for
     its From domain: `dmarc=pass` for that domain in Fastmail's
     `Authentication-Results`, or an aligned `dkim=pass`. An unauthenticated
     message that matches an allow entry falls through to the model and is
     logged as such -- that is the forged-own-address case.
   - A **block** entry needs no authentication (forging a blocked sender only
     gets you screened).
2. **Model** for everyone else: the spike's winning setup, gemma4:12b with
   thinking off and our prompt, no mailbox context in the prompt. The raw
   probability is stored.
3. **Would-do**, for display only -- the raw probability is what gets graded,
   so any threshold can be evaluated after the fact:
   - `screen` -- blocked, or model >= `EXODON_SCREEN_AT` (default 0.99)
   - `review` -- model >= `EXODON_REVIEW_AT` (default 0.5)
   - `inbox`  -- allowed, or below review

## Grading

`src/grade.py`, hourly from the watcher (or on demand). Every decision from the
last 7 days, and any older one never graded, is looked up again, so a message
is graded as soon as it leaves the inbox and a later re-filing wins; after a
week the grade is final. The owner's mark on the review page (spam / real)
overrides the folder. Where the message is now counts as:

| where it is now | counts as |
|---|---|
| Identified Spam (the owner's hand-trained folder) | spam |
| Archive, Inbox after 7 days, any other folder | real mail -- generally reliable (spam does get bulk-archived) |
| Fastmail's Spam, left there | **moderate** spam signal -- reported in its own section, not in the score |
| Trash, or gone | deleted -- listed, **not scored**: usually read-and-done, sometimes spam binned instead of filed |
| gone after the provider filed it in its own Spam | unknown -- excluded (auto-purge, nobody's verdict) |

Signal strength, per the owner: the training folder is a strong spam label,
Archive a generally reliable not-spam label, Fastmail's Spam a moderate spam
label, and deletion no label at all. Only the strong/general labels are scored.

Deleting is **not a keep signal**: list seeding counts only Archive as kept,
so deleting a sender's mail never makes them look trusted.

The report is plain language: spam caught, real mail that would have been
screened (by name, so each one can be checked), and what the provider's own
spam score would have done on the same messages.

## Deployment

`docker/docker-compose.yml` in this repo: one small Python container, the
repo mounted read-only, `var/` for the log. Tokens are passed in as
environment variables at start; `docker/up.sh` runs `docker/up.local.sh`
instead when it exists, so a secrets-manager wrapper can live there. Mail
tokens go only to the watcher (override file), never in `.env`, which the
review page also loads.

## Code rules

Two patterns the model reliably gets wrong are screened in code
(`shadow.decide`), after the lists and before the model's verdict counts. The
model still scores them, for the record. Both stand down for any sender the
owner has written to (a Sent-folder query; a failed lookup also stands down).

- **webmail receipt/notice**: a free-webmail sender, a subject that isn't a reply,
  and a transactional subject (receipt, invoice, order #...).
- **self-quoted follow-up** (2026-11-13): a `Re:`/`Fwd:` subject whose quoted
  history (`On <date>, <who> wrote:` lines, read from the whole body, not
  the 600-char preview) names only the sender, by address or full display
  name, each on a dated `On ...` line. Header-style quotes (Outlook's `From:/Sent:`,
  forwards) and non-English attributions make it abstain, since their author
  can't be checked. Drip-sequence cold sales quote their own earlier pitches,
  and the model reads that as a real conversation. Backtest over every logged
  reply (both mailboxes, 2026-11-13): 88 would screen, all filed as spam or
  deleted by the owner, 14 of them mail the model had left in the Inbox or
  review band. One real message matched (a travel agent quoting her own
  email) and was spared because the owner had written to her. The known gap:
  a genuine stranger bumping their own unanswered email is screened.

## Live mode

Per mailbox, `EXODON_<NAME>_MODE=live` (run a mailbox in shadow first, then switch it
to live once the report looks right). Same watcher, same decision, same log and grading, plus:

- **The move.** A `screen` decision (block list, a code rule, or model >=
  `EXODON_SCREEN_AT`, 0.95 since 2026-10-04) on a message that is in the Inbox and nowhere else is
  moved to the provider's Spam folder (role `junk`). Mail a rule already
  filed elsewhere is left alone. The row records `action` = `moved` (or
  `move failed: ...`, message untouched) and `acted_at`.
- **The digest.** Once a day after `EXODON_DIGEST_AT` (07:00 `EXODON_TZ`), the
  unsure mail since the last digest -- the review band left in the Inbox, and
  anything moved on a model score below `EXODON_SURE_AT` (0.999) -- is listed
  by name, address and subject in a plain-text message *created* in the Inbox
  (JMAP `Email/set` create, header `X-Exodon: digest`, which the watcher
  skips). Nothing is sent. No digest on a day with nothing unsure. The first
  live start waits for the next day's digest time, so shadow-era mail is
  never listed.
- **The guard.** `jmap.Jmap(write=True)` adds exactly `move` and `create`;
  `call` still refuses every non-read method, and a shadow mailbox's client
  is built read-only whatever its token can do.
- **Two tokens.** Reads and the push stream stay on the read-only token; the
  writable one (`EXODON_<NAME>_JMAP_WRITE_TOKEN_ENV`) is a separate client
  that never opens a push stream. Fastmail allows one push stream per token
  and the newest kicks the others off: sharing a token whose push another
  app holds (Wilco, on the personal full-access token) made the two kick
  each other off about once a minute (found 2026-10-04).
- **Grading** carries on: mail pulled back out of Spam grades as real (a
  wrong screen), filed into the training folder as spam, and left in Spam as
  the moderate "left in Fastmail's Spam" signal. If Spam's auto-purge removes
  a moved message it is `unknown`, not `deleted`.
- **Authentication** now also accepts an aligned SPF pass (the envelope
  sender's domain matches From) -- small senders often have SPF only.

The review page (`src/web.py`, separate
container, no mail token) is the one part that writes anything the watcher
reads: the list files, one validated line per click.
Its one machine-readable route, `GET /api/readout` (`src/readout.py`), is
read-only and token-guarded; it is how an outside agent reports on
the filtering without being able to change it. Since the readout needs the
body, each decision row keeps the first 300 characters of the message
(`preview`).
