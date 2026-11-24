# Review page: exodon.example.net

Status: approved in conversation 2026-09-27 (feedback: option C; access:
tailnet only, no password; build: separate container). Revised after a
review pass the same day.

> **Amended 2026-10-16 (redesign):** the page now also filters by mailbox,
> result, agreement, deciding source and sender/subject text, and has a
> lists view (`/lists`) that shows both lists with per-entry hit counts,
> tests a sender, adds a typed pattern, and removes any single line by its
> exact text. Every change is still one validated line, logged in
> `list_changes`, and reversible (undo an add, restore a remove). This lifts
> the earlier "never removes a line it did not add" guarantee.

> **Amended 2026-10-16 (compact page):** the mail view is three tabs --
> Filtered, Let through, Unsure -- of one-line rows grouped by day that open
> to the reason, a preview and the fix; the score tiles and filter dropdowns
> are gone (a plain "caught X of Y, junked Z" line stays at the foot). On a
> live mailbox Not spam / Spam also moves the message: the page queues it in
> `moves` and the watcher, which holds the token, makes it. The page still
> holds no mail token. This lifts the earlier "never touches the mailbox".

## Why

The daily text report answers "how is it doing" once a day, two days late,
and offers no way to act on a bad call. The owner wants a page that shows
recent decisions next to where the mail actually went, and lets him correct
a call or make a permanent ruling on a sender in one click.

## Scope

In:
1. A read-mostly web page listing recent decisions with the owner's filing.
2. Feedback: mark a call spam/real; add a sender to allow/block.
3. Faster grading: hourly, as soon as mail leaves the inbox, re-checked
   for 7 days; the owner's mark overrides the folder.
4. A liveness signal the page exposes for Gatus.

Out: moving mail, message bodies/previews, a password, editing or deleting
hand-written list lines, the Jason/SPF authentication change (separate
decision, not approved yet), writing `lists/decisions.txt` (page-added
lines live in the list files; `seed` already diffs proposals against the
live lists, so it will not re-propose them).

## Guarantees

- The mailbox is never written. The web container holds no mail token.
- A list changes only on the owner's click, one validated line at a time,
  every change is logged, and the page never removes a line it did not add.
- A list file the page writes always parses: a bad file would stop every
  decision, so the page validates the whole new file before replacing.

## Components

| unit | job |
|---|---|
| `src/jmap.py` (changed) | `events()` also yields pings, as `{"type": "ping"}` |
| `src/shadow.py` (changed) | heartbeat on every event/ping; hourly grading; `Store` gains columns/table, WAL, idempotent migration, `migrate=False` for readers |
| `src/grade.py` (changed) | hourly grading with re-checks; one `LABEL` expression used everywhere |
| `src/listedit.py` (new) | pure functions: candidate pattern for a sender, verdict, safe append, undo |
| `src/web.py` (new) | stdlib `ThreadingHTTPServer`: page, JSON actions, `/health` |
| `docker/docker-compose.yml` | second service `exodon-web` |

## Data

- `decisions` gains `feedback` (`spam` | `real` | null) and `feedback_at`.
- New table `list_changes (id integer primary key, at, action, list, line,
  account, email_id)`, `action` in `add` | `remove`.
- `meta` gains `<account>:alive` (UTC ISO), written by the watcher on every
  push event and ping (Fastmail pings every 60 s).
- WAL journal mode (`pragma journal_mode=wal`), set by the watcher. Both
  containers use the same host file on local disk, so WAL's shared memory
  works across them.
- Migration (adding columns/table) is idempotent: `ALTER TABLE ... ADD
  COLUMN` tolerates "duplicate column". Only the watcher migrates; the web
  server opens a plain connection per request (`Store(..., migrate=False)`,
  `timeout=30`) and never runs DDL.

## Grading changes

- Per account, hourly, from both push events and pings (so quiet periods
  still grade). `GRADE_AFTER_H` and `EXODON_GRADE_AFTER` are removed.
- Each pass looks up every decision received in the last 7 days plus any
  older one never graded, and stores the current `outcome()` result,
  overwriting the previous one. `None` (back in, or still in, the inbox)
  clears `outcome` and `outcome_folder`. After 7 days a graded outcome is
  final.
- Commits after every batch of 100, so the write lock is never held across
  a network call.
- One effective label, defined once in `grade.py`:
  `LABEL = "coalesce(feedback, outcome)"`. Every report and page count uses
  it, including "graded" (`LABEL is not null`): a marked message still in
  the inbox counts as graded.
- `report.txt` is rewritten at the end of each hourly pass.

## The page

`GET /` renders server-side HTML: no framework, no external assets, small
inline CSS/JS, light/dark via `prefers-color-scheme`, usable on a phone.

- Query parameters: `account` (all|<name>), `call`
  (all|screen|review|inbox|error), `disagree=1`, `days` (default 7, max 60).
- Top: one score line per account over the window, plain words:
  "caught S of T spam you filed; screened R of K real emails you kept;
  Fastmail's Spam: F of G would be screened." Uses `LABEL`.
- Rows, newest first, capped at 500: time, account, sender (name +
  address), subject, the call and why (`blocked by @x`, `allowed by @y`,
  `model 0.99`, `allow @z ignored: not authenticated`), where it is now
  (labelled "as of <last grade time>"), agreement mark, the owner's mark,
  and any list line the page already added for this sender.
- Agreement mark from call vs `LABEL`:
  - `spam`: ✓ screen, ✗ inbox, none for review.
  - `real`: ✓ inbox, ✗ screen, none for review.
  - `fastmail_spam` (moderate): ✓ screen, "?" inbox (possible miss).
  - no label (deleted unmarked, in inbox, unknown): blank.
- `disagree=1` keeps only ✗ and "?" rows.

## Feedback actions

All are `POST`, JSON in and out; the page updates the row in place.

1. `POST /api/mark {account, email_id, label}`: `spam`, `real` or `null`
   (clear). Sets `feedback`, `feedback_at`.
2. `POST /api/list/preview {account, email_id, list, scope}` returns the
   candidate line and a verdict.
3. `POST /api/list/add` (same body) recomputes the verdict and writes only
   on `ok`.
4. `POST /api/list/undo {change_id}` removes that exact line if present
   exactly once and added by the page; records a `remove` row; otherwise
   refuses with the reason.

### Candidate pattern (derived from the logged sender, never the request)

- `address` scope: the lowercased address, only if it matches
  `^[a-z0-9._%+-]+@[a-z0-9-]+(\.[a-z0-9-]+)+$` and
  `parse_line(addr).kind == "exact"`. Otherwise refused.
- `domain` scope: `@` + `context.org(addr)`'s domain, only if every label
  matches `[a-z0-9-]+`. **Refused for free-mail / bulk-platform senders**
  (where `org()` returns the address), so `@gmail.com` is never one click
  away.
- Default scope: `address` for free-mail / bulk-platform senders, else
  `domain`.

### Verdict

Load both list files, add the candidate entry, run
`lists.decide(entries + [cand], from_email, from_name)` (name included, so
`name:` entries count):
- `covered`: the governing entry *before* adding is already on the chosen
  list. Nothing to add. For `allow`, if that decision was logged as
  "allow ... ignored: not authenticated", say so: the entry exists but
  this sender's mail does not prove itself.
- `ok`: after adding, the candidate is the governing entry. If it
  overrides an entry on the other list, name it ("overrides block @x.com").
- `blocked`: after adding, a different entry still governs (a more
  specific one on the other list, or the identical pattern already there,
  which wins ties if it is an allow). Show which, offer nothing.

### Safe write

Under one process-wide lock:
1. Read the file and its mtime.
2. Build the note `exodon page YYYY-MM-DD: "<subject>"`: the subject with
   every control character and every character `str.splitlines()` splits
   on removed, `#` and `"` removed, cut to 40 characters.
3. Write old text + the new line to a temp file in `lists/`, copying the
   original file's mode.
4. Validate: `lists.load(temp)` must equal the old entries plus exactly
   the candidate. Otherwise delete the temp file and refuse.
5. If the file's mtime changed since step 1 (a hand edit), delete the temp
   file and retry once from step 1.
6. `os.replace` onto the list file (same directory, so atomic; the
   watcher's mtime reload sees one complete file). Record `list_changes`.

Undo follows the same steps, with the line removed instead of added.

### Request safety (no password)

- **Host allowlist, on every request including GET:** `exodon.example.net`,
  plus `localhost:8799` and `exodon-web:8799` for probes and tests.
  Anything else gets 421. This defeats DNS rebinding.
- **POST:** `Content-Type` must be exactly `application/json` (parameters
  like charset allowed), and `Origin` must be exactly
  `https://exodon.example.net`. Otherwise 403. A cross-site page cannot send
  JSON without a CORS preflight, which the server never approves.
- **Headers on every response:**
  `Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline';
  script-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'`,
  `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`.
- **Input validation:** the account and email_id must name a logged
  decision; list in {allow, block}; scope in {domain, address}.
- **Output:** every logged field is escaped with `html.escape(quote=True)`,
  including attributes. JSON inside `<script>` is escaped for `<`.
  Bidi-override characters are stripped from displayed senders and
  subjects.

## `/health`

JSON: per watched account (those with a `<account>:email_state` key in
meta), the `alive` time and age in seconds, plus `ok`. 503 when any
heartbeat is older than 10 minutes, else 200. Gatus endpoint
`exodon` on `https://exodon.example.net/health`, condition
`[STATUS] == 200`, **dashboard-only** (no email) while exodon is in shadow
mode, per the alert policy.

## Deployment

- `exodon-web`: same image, `command: python3 src/web.py`, listening on
  8799 **with no host port**. It joins the external
  `nginx-proxy-manager_default` network, so it is reachable
  only through NPM, which is reachable only on the tailnet.
  `restart: unless-stopped`, `init: true`, no secrets. Mounts:
  `..:/app:ro`, `../var:/app/var`, `../lists:/app/lists` (the only
  writable view of the lists). The watcher is unchanged.
- The web service is started with `docker/up.sh` too; for a code change
  `docker restart exodon-web` is enough.
- A DNS record `exodon.example.net` → the host's private-network IP. NPM proxy
  host → `exodon-web:8799`, TLS, no access list.
- `lists.py` docstring: "never changed by the service" becomes "changed
  only by the owner, by hand or by a click on the review page".

## Error handling

- Web: any handler exception → 500 JSON with a short message; the server
  keeps running. A failed list write leaves the old file intact and
  records nothing.
- Watcher: heartbeat and grading run inside the existing error handling;
  grading errors are logged as events and retried next hour.

## Testing

Unit (no network):
- listedit: default scope; refusal of `*`/`#`/odd addresses and of domain
  scope for free-mail; `covered` (plus the not-authenticated note), `ok`,
  `ok` with override, `blocked` (identical pattern on allow; more specific
  entry on the other list); a subject with `\r`, ` `, `#` and `"`
  writes one clean line; validation refuses a file that would change other
  entries; undo removes only its own line and refuses when it is missing
  or duplicated.
- grading: feedback overrides outcome; a re-check replaces an outcome
  within 7 days, clears it on return to inbox, and leaves older ones alone;
  a marked in-inbox message counts as graded.
- jmap: `events()` yields a ping.
- web: foreign Host → 421; POST without/with foreign Origin → 403; wrong
  content type → 403; unknown email_id → 400; a `<script>` subject and a
  `"` sender are escaped; security headers present.
- Store: columns and table added to an existing log twice without error;
  WAL on.

Live:
- `curl` the page and `/health` from inside the NPM network, then via
  `https://exodon.example.net`.
- Screenshot the page (cellgate-bridge Playwright image) at desktop and
  phone width before calling it done.
- One real add + undo round trip with a throwaway pattern, confirming the
  watcher logs "lists reloaded".
