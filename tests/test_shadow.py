"""Shadow-mode rules: authentication, decision, grading. No network.

    python3 -m unittest discover -s tests
"""

import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "src"))

import lists as L  # noqa: E402
import shadow as S  # noqa: E402

FM = "phl-mx-08.messagingengine.com"


def ar(*clauses, authserv=FM):
    return authserv + ";" + ";".join(f" {c}" for c in clauses)


class Authentication(unittest.TestCase):
    def test_dmarc_pass_for_from_domain(self):
        ok, why = S.authenticated([ar("dmarc=pass header.from=acme.com")], "jane@acme.com")
        self.assertTrue(ok, why)

    def test_aligned_dkim_pass(self):
        ok, _ = S.authenticated([ar("dkim=pass header.d=acme.com header.i=@acme.com")],
                                "someone@acme.com")
        self.assertTrue(ok)

    def test_dkim_for_parent_or_subdomain_is_aligned(self):
        self.assertTrue(S.authenticated([ar("dkim=pass header.d=acme.com")], "x@mail.acme.com")[0])
        self.assertTrue(S.authenticated([ar("dkim=pass header.d=em.acme.com")], "x@acme.com")[0])

    def test_dkim_for_a_different_domain_is_not_enough(self):
        # a relay's own signature (amazonses.com) says nothing about the From domain
        ok, _ = S.authenticated([ar("dkim=pass header.d=amazonses.com")], "x@acme.com")
        self.assertFalse(ok)

    def test_forged_result_from_a_foreign_server_is_ignored(self):
        forged = ar("dmarc=pass header.from=acme.com", authserv="evil.example.com")
        self.assertFalse(S.authenticated([forged], "ceo@acme.com")[0])

    def test_failures_and_missing_headers(self):
        self.assertFalse(S.authenticated([ar("dmarc=fail header.from=acme.com")], "x@acme.com")[0])
        self.assertFalse(S.authenticated([], "x@acme.com")[0])


class FakeModel:
    def __init__(self, p=0.2, error=None):
        self.p, self.error, self.calls = p, error, 0

    def score(self, msg):
        self.calls += 1
        from backends import Verdict
        return Verdict(p_spam=float("nan") if self.error else self.p, error=self.error)


def entries(*allow, block=()):
    return ([L.parse_line(a, "allow") for a in allow]
            + [L.parse_line(b, "block") for b in block])


def msg(addr, auth=True, name=""):
    return {"from_email": addr, "from_name": name, "subject": "s", "preview": "p",
            "auth_results": [ar(f"dmarc=pass header.from={addr.split('@')[1]}")] if auth else []}


class Decide(unittest.TestCase):
    def test_authenticated_allow_skips_the_model(self):
        m = FakeModel(p=0.999)
        d = S.decide(msg("a@acme.com"), entries("@acme.com"), m)
        self.assertEqual((d["source"], d["would"]), ("allow", "inbox"))
        self.assertEqual(m.calls, 0)

    def test_unauthenticated_allow_falls_through_to_the_model(self):
        m = FakeModel(p=0.999)
        d = S.decide(msg("boss@acme.com", auth=False), entries("@acme.com"), m)
        self.assertEqual(d["source"], "model")
        self.assertEqual(d["would"], "screen")
        self.assertIn("not authenticated", d["list_note"])
        self.assertEqual(m.calls, 1)

    def test_block_needs_no_authentication(self):
        d = S.decide(msg("x@spam.example", auth=False), entries(block=["@spam.example"]), FakeModel())
        self.assertEqual((d["source"], d["would"]), ("block", "screen"))

    def test_model_bands(self):
        for p, want in ((0.995, "screen"), (0.7, "review"), (0.1, "inbox")):
            self.assertEqual(S.decide(msg("x@new.example"), [], FakeModel(p))["would"], want)

    def test_webmail_receipt_is_screened_whatever_the_model_says(self):
        for subject in ("Thank you! Payment received for order", "Feedback on Invoice 290276?",
                        "[Doc: 2799656] Transit file", "еnabled sales batch — Transaction/2026/4036",
                        "Thank You for Your Order 4KEZNZ2J", "Order #55120 confirmed",
                        "Invоice attached"):  # the last two carry Cyrillic look-alikes
            m = FakeModel(p=0.0)
            d = S.decide({**msg("x@gmail.com"), "subject": subject}, [], m)
            self.assertEqual((d["source"], d["would"]), ("rule", "screen"), subject)
            self.assertEqual(d["p_spam"], 0.0)  # still scored, for the record
            self.assertEqual(m.calls, 1)

    def test_webmail_rule_spares_replies_companies_and_plain_subjects(self):
        cases = [("x@gmail.com", "Re: Invoice 52365"), ("x@gmail.com", "Fwd: your order"),
                 ("x@gmail.com", "[EXT] RE: payment"), ("x@gmail.com", "Re[2]: invoice"),
                 ("x@gmail.com", "Paid you back for dinner"), ("x@gmail.com", "Bank statement"),
                 ("x@gmail.com", "report"), ("x@gmail.com", "Ordering pizza"),
                 ("x@gmail.com", "Order of service Sunday"), ("x@gmail.com", "Doc for Sunday"),
                 ("billing@paddle.com", "Payment confirmed")]
        for addr, subject in cases:
            d = S.decide({**msg(addr), "subject": subject}, [], FakeModel(p=0.1))
            self.assertEqual(d["source"], "model", (addr, subject))

    def test_webmail_rule_spares_people_the_owner_has_written_to(self):
        m = {**msg("member@gmail.com"), "subject": "Invoice for lawn mowing"}
        d = S.decide(m, [], FakeModel(p=0.1), wrote_to=lambda a: a == "member@gmail.com")
        self.assertEqual((d["source"], d["would"]), ("model", "inbox"))
        d = S.decide(m, [], FakeModel(p=0.1), wrote_to=lambda a: False)
        self.assertEqual(d["source"], "rule")

    def test_authenticated_allow_beats_the_webmail_rule(self):
        d = S.decide({**msg("friend@gmail.com"), "subject": "Your order"},
                     entries("friend@gmail.com"), FakeModel())
        self.assertEqual(d["source"], "allow")

    def test_webmail_rule_still_screens_when_the_model_is_down(self):
        d = S.decide({**msg("x@gmail.com"), "subject": "Your receipt"}, [],
                     FakeModel(error="timeout"))
        self.assertEqual((d["source"], d["would"], d["p_spam"]), ("rule", "screen", None))

    def test_model_error_is_logged_not_guessed(self):
        d = S.decide(msg("x@new.example"), [], FakeModel(error="timeout"))
        self.assertEqual(d["would"], "error")
        self.assertEqual(d["error"], "timeout")


class Extract(unittest.TestCase):
    def email(self, value, kind):
        return {"id": "m1", "from": [{"email": "A@X.example"}], "subject": "s",
                "textBody": [{"partId": "1", "type": kind}], "bodyValues": {"1": {"value": value}}}

    def test_html_part_reaches_the_model_as_text(self):
        html = ('<html><head><style>p{font-family:"Times New Roman";}</style></head>'
                '<body><table style="WORD-SPACING:0px"><tr><td>Hello, there is a new '
                'Document in MyChart.<br>View MyDocument</td></tr></table></body></html>')
        got = S.extract(self.email(html, "text/html"))["preview"]
        self.assertEqual(got, "Hello, there is a new Document in MyChart. View MyDocument")

    def test_html_cut_off_mid_style_leaves_no_css(self):
        got = S.extract(self.email('<style>td{color:red;} .x{margin:0', "text/html"))["preview"]
        self.assertEqual(got, "")

    def test_head_without_its_closing_tag_ends_at_body(self):
        html = "<html><head><meta charset=utf-8><body><p>Your invoice is ready</p></body>"
        self.assertEqual(S.extract(self.email(html, "text/html"))["preview"], "Your invoice is ready")

    def test_plain_text_is_left_alone(self):
        got = S.extract(self.email("Price < cost > zero", "text/plain"))["preview"]
        self.assertEqual(got, "Price < cost > zero")


class Grading(unittest.TestCase):
    boxes = {"A": {"role": "archive", "name": "Archive"}, "I": {"role": "inbox", "name": "Inbox"},
             "S": {"role": None, "name": "Identified Spam"}, "J": {"role": "junk", "name": "Spam"},
             "T": {"role": "trash", "name": "Trash"}, "X": {"role": None, "name": "Customers"}}

    def test_outcomes(self):
        o = lambda ids, age=72: S.outcome({k: True for k in ids}, self.boxes, age)
        self.assertEqual(o(["S"]), "spam")
        self.assertEqual(o(["A"]), "real")
        self.assertEqual(o(["X"]), "real")
        self.assertEqual(o(["J"]), "fastmail_spam")
        # Deleting means "read and done": not spam. (It is never a keep signal
        # for the lists -- only Archive counts as kept there.)
        self.assertEqual(o(["T"]), "deleted")
        self.assertIsNone(o(["I"]))              # not filed yet: grade later
        self.assertEqual(o(["I"], age=24 * 8), "real")  # left in inbox a week
        self.assertEqual(S.outcome(None, self.boxes, 72), "deleted")  # gone
        # ...unless the provider put it in its own Spam and then purged it:
        # nobody decided anything, so it is not evidence either way.
        self.assertEqual(S.outcome(None, self.boxes, 72, arrived_junk=True), "unknown")


    def test_per_account_training_folder(self):
        boxes = {"P": {"role": None, "name": "Junk I Trained"}, "S": {"role": None, "name": "Identified Spam"}}
        self.assertEqual(S.outcome({"P": True}, boxes, 72, training="Junk I Trained"), "spam")
        self.assertEqual(S.outcome({"S": True}, boxes, 72, training="Junk I Trained"), "real")


class Store(unittest.TestCase):
    def test_roundtrip_and_idempotent_insert(self):
        with tempfile.TemporaryDirectory() as d:
            st = S.Store(pathlib.Path(d) / "t.db")
            row = {"account": "work", "email_id": "E1", "from_email": "a@b.c",
                   "would": "inbox", "source": "allow"}
            st.record(row)
            st.record(row)  # a replayed push event must not duplicate
            st.record({**row, "account": "personal"})  # same id, other mailbox: distinct
            self.assertEqual(st.db.execute("select count(*) from decisions").fetchone()[0], 2)
            st.set("state", "J1")
            self.assertEqual(st.get("state"), "J1")

    def test_pre_account_log_migrates_to_first_account(self):
        import sqlite3
        with tempfile.TemporaryDirectory() as d:
            path = pathlib.Path(d) / "old.db"
            db = sqlite3.connect(path)
            db.executescript("""
                create table meta (key text primary key, value text);
                create table decisions (email_id text primary key, from_email text, would text,
                                        source text, outcome text);
                create table events (at text, kind text, detail text);
                insert into meta values ('email_state','J42'), ('last_sync','t');
                insert into decisions values ('E1','a@b.c','inbox','allow',null);""")
            db.commit(); db.close()
            st = S.Store(path, legacy_account="work")
            self.assertEqual(st.get("work:email_state"), "J42")   # position kept: no gap
            self.assertIsNone(st.get("email_state"))
            self.assertEqual(st.db.execute("select account, email_id, from_email from decisions")
                             .fetchall(), [("work", "E1", "a@b.c")])
            S.Store(path, legacy_account="work")  # idempotent on reopen

    def test_feedback_columns_list_changes_and_wal(self):
        with tempfile.TemporaryDirectory() as d:
            path = pathlib.Path(d) / "t.db"
            S.Store(path)
            st = S.Store(path)  # second open: no "duplicate column"
            self.assertTrue({"feedback", "feedback_at"} <= st.cols)
            st.db.execute("select id, at, action, list, line, account, email_id, undone_at "
                          "from list_changes").fetchall()
            self.assertEqual(st.db.execute("pragma journal_mode").fetchone()[0], "wal")

    def test_reader_mode_runs_no_ddl(self):
        with tempfile.TemporaryDirectory() as d:
            st = S.Store(pathlib.Path(d) / "t.db", migrate=False)
            self.assertEqual(st.db.execute("select count(*) from sqlite_master").fetchone()[0], 0)


class FakeClient:
    boxes = {"A": {"role": "archive", "name": "Archive"}, "I": {"role": "inbox", "name": "Inbox"},
             "S": {"role": None, "name": "Identified Spam"}, "T": {"role": "trash", "name": "Trash"}}

    def __init__(self, where):
        self.where = where  # email_id -> mailbox id, or None for gone

    def mailboxes(self):
        return self.boxes

    def call(self, method, args):
        return {"list": [{"id": i, "mailboxIds": {self.where[i]: True}}
                         for i in args["ids"] if self.where.get(i)]}


class Regrade(unittest.TestCase):
    def setUp(self):
        import datetime as dt
        import grade as G
        self.G = G
        self.tmp = tempfile.TemporaryDirectory()
        self.st = S.Store(pathlib.Path(self.tmp.name) / "t.db")
        self.ago = lambda h: (dt.datetime.now(dt.timezone.utc)
                              - dt.timedelta(hours=h)).strftime("%Y-%m-%dT%H:%M:%SZ")

    def tearDown(self):
        self.st.db.close()
        self.tmp.cleanup()

    def add(self, i, hours, would="screen", outcome=None, feedback=None):
        self.st.record({"account": "work", "email_id": i, "received_at": self.ago(hours),
                        "would": would, "source": "model", "p_spam": 0.5})
        self.st.db.execute("update decisions set outcome=?, feedback=? where email_id=?",
                           (outcome, feedback, i))
        self.st.db.commit()

    def outcome(self, i):
        return self.st.db.execute("select outcome from decisions where email_id=?", (i,)).fetchone()[0]

    def grade(self, where):
        self.G.grade(self.st, FakeClient(where), "work", "Identified Spam")

    def test_filed_mail_is_graded_without_waiting(self):
        self.add("E1", 1)
        self.grade({"E1": "S"})
        self.assertEqual(self.outcome("E1"), "spam")

    def test_recheck_within_a_week_follows_the_latest_filing(self):
        self.add("E1", 72, outcome="real")
        self.grade({"E1": "S"})
        self.assertEqual(self.outcome("E1"), "spam")

    def test_moved_back_to_inbox_clears_the_grade(self):
        self.add("E1", 72, outcome="real")
        self.grade({"E1": "I"})
        self.assertIsNone(self.outcome("E1"))

    def test_older_than_a_week_is_final(self):
        self.add("E1", 240, outcome="real")
        self.grade({"E1": "S"})
        self.assertEqual(self.outcome("E1"), "real")

    def test_owner_mark_overrides_the_folder(self):
        self.add("E1", 72, would="screen", outcome="deleted", feedback="spam")
        self.add("E2", 2, would="inbox", outcome=None, feedback="real")  # still in the inbox
        s = self.G.summary(self.st, "work")
        self.assertEqual((s["spam"], s["spam_caught"], s["real"], s["graded"], s["deleted"]),
                         (1, 1, 1, 2, 0))


class Accounts(unittest.TestCase):
    def test_parse(self):
        import os
        import config
        env = {"EXODON_ACCOUNTS": "Work, personal", "EXODON_PERSONAL_TRAINING_FOLDER": "Junk I Trained",
               "EXODON_WORK_JMAP_TOKEN": "tw", "EXODON_PERSONAL_JMAP_TOKEN_ENV": "PT", "PT": "tp"}
        old = {k: os.environ.get(k) for k in env}
        os.environ.update(env)
        try:
            a = config.accounts()
            self.assertEqual([x.name for x in a], ["work", "personal"])
            self.assertEqual(a[1].training_folder, "Junk I Trained")
            self.assertEqual((a[0].token(), a[1].token()), ("tw", "tp"))
        finally:
            for k, v in old.items():
                os.environ.pop(k) if v is None else os.environ.__setitem__(k, v)


if __name__ == "__main__":
    unittest.main()
