"""Live mode: SPF alignment, the move, the digest, the write guard. No network.

    python3 -m unittest discover -s tests
"""

import datetime as dt
import os
import pathlib
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "src"))

import config  # noqa: E402
import jmap as J  # noqa: E402
import shadow as S  # noqa: E402

FM = "phl-mx-08.messagingengine.com"

# Fastmail's own layout: whitespace after '=', the envelope sender quoted.
REAL_SPF = (FM + ";    dkim=pass (2048-bit rsa key sha256) header.d=crm-mailer.example      "
            "header.i=@crm-mailer.example;    dmarc=fail policy.published-domain-policy=none      "
            "header.from=smallcharity.example;    spf=pass      smtp.mailfrom=      "
            '"bounces+5315-you=example.com@mailman.crm-mailer.example"      '
            "smtp.helo=o3.mailman.crm-mailer.example")


class Spf(unittest.TestCase):
    def test_aligned_spf_pass_counts(self):
        res = FM + "; dmarc=none header.from=family-shop.example; spf=pass smtp.mailfrom=jo@family-shop.example"
        ok, why = S.authenticated([res], "jo@family-shop.example")
        self.assertTrue(ok, why)
        self.assertIn("spf=pass", why)

    def test_quoted_mailfrom_after_whitespace_is_parsed(self):
        # SPF passes for the relay's domain, not the From domain: not aligned
        ok, _ = S.authenticated([REAL_SPF], "jo@smallcharity.example")
        self.assertFalse(ok)
        self.assertTrue(S.authenticated([REAL_SPF], "x@crm-mailer.example")[0])

    def test_spf_fail_or_foreign_server_does_not_count(self):
        self.assertFalse(S.authenticated(
            [FM + "; spf=fail smtp.mailfrom=a@acme.com"], "a@acme.com")[0])
        self.assertFalse(S.authenticated(
            ["evil.example; spf=pass smtp.mailfrom=a@acme.com"], "a@acme.com")[0])


class WriteGuard(unittest.TestCase):
    def client(self, write):
        c = J.Jmap.__new__(J.Jmap)
        c.write, c.account = write, "A"
        c._post = mock.Mock(return_value={"updated": {"E1": None}})
        return c

    def test_read_only_client_refuses_moves_and_creates(self):
        c = self.client(write=False)
        with self.assertRaises(J.ReadOnlyViolation):
            c.move("E1", "I", "J")
        with self.assertRaises(J.ReadOnlyViolation):
            c.create("I", "a@b.c", "a@b.c", "s", "t")
        c._post.assert_not_called()

    def test_call_never_writes_even_when_writable(self):
        with self.assertRaises(J.ReadOnlyViolation):
            self.client(write=True).call("Email/set", {"destroy": ["E1"]})

    def test_move_patches_only_the_two_mailboxes(self):
        c = self.client(write=True)
        c.move("E1", "I", "J")
        c._post.assert_called_once_with(
            "Email/set", {"update": {"E1": {"mailboxIds/I": None, "mailboxIds/J": True}}})

    def test_a_refused_move_raises(self):
        c = self.client(write=True)
        c._post.return_value = {"notUpdated": {"E1": {"type": "forbidden"}}}
        with self.assertRaises(J.JmapError):
            c.move("E1", "I", "J")


class FakeModel:
    def __init__(self, p):
        self.p = p

    def score(self, msg):
        from backends import Verdict
        return Verdict(p_spam=self.p, error=None)


class FakeLive:
    """A writable client: three mailboxes, messages by id, records moves."""
    write = True

    def __init__(self, mails, sent_to=(), sent_fails=False):
        self.mails, self.moves, self.created = mails, [], []
        self.sent_to, self.sent_fails, self.queries = set(sent_to), sent_fails, []

    def mailboxes(self):
        return {"I": {"role": "inbox", "name": "Inbox"}, "J": {"role": "junk", "name": "Spam"},
                "A": {"role": "archive", "name": "Archive"}, "D": {"role": "drafts", "name": "Drafts"},
                "S": {"role": "sent", "name": "Sent"}}

    def call(self, method, args):
        if method == "Email/query":  # the Sent lookup: AND(inMailbox, OR(to, cc, bcc))
            self.queries.append(args)
            if self.sent_fails:
                raise RuntimeError("boom")
            inbox, who = args["filter"]["conditions"]
            addr = who["conditions"][0]["to"]
            hit = inbox["inMailbox"] == "S" and addr in self.sent_to
            return {"ids": ["S1"] if hit else []}
        return {"list": [self.mails[i] for i in args["ids"]]}

    def move(self, i, src, dst):
        self.moves.append((i, src, dst))

    def create(self, mailbox, sender, to, subject, text, headers=None):
        self.created.append((mailbox, subject, text, headers))
        return "D1"


def mail(i, box="I", frm="x@new.example", digest=False):
    m = {"id": i, "from": [{"email": frm, "name": "X"}], "subject": f"subj {i}",
         "receivedAt": "2026-10-04T12:00:00Z", "mailboxIds": {box: True}}
    if digest:
        m["header:X-Exodon:asText"] = "digest"
    return m


class LiveWatcher(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.st = S.Store(pathlib.Path(self.tmp.name) / "t.db")

    def tearDown(self):
        self.st.db.close()
        self.tmp.cleanup()

    def watcher(self, client, p, live=True):
        lists = mock.Mock(get=mock.Mock(return_value=[]))
        return S.Shadow(client, self.st, lists, FakeModel(p), account="personal",
                        live=live, address="me@example.com", writer=client)

    def action(self, i):
        return self.st.db.execute("select action from decisions where email_id=?", (i,)).fetchone()[0]

    def test_screened_inbox_mail_moves_to_spam(self):
        c = FakeLive({"E1": mail("E1")})
        self.watcher(c, 0.97).process(["E1"])
        self.assertEqual(c.moves, [("E1", "I", "J")])
        self.assertEqual(self.action("E1"), "moved")

    def test_review_and_inbox_mail_stay(self):
        c = FakeLive({"E1": mail("E1"), "E2": mail("E2")})
        w = self.watcher(c, 0.7)
        w.process(["E1"])
        w.model = FakeModel(0.1)
        w.process(["E2"])
        self.assertEqual(c.moves, [])

    def test_mail_already_filed_elsewhere_is_left_alone(self):
        c = FakeLive({"E1": mail("E1", box="A"), "E2": mail("E2", box="J")})
        self.watcher(c, 0.999).process(["E1", "E2"])
        self.assertEqual(c.moves, [])

    def test_shadow_mailbox_never_moves(self):
        c = FakeLive({"E1": mail("E1")})
        self.watcher(c, 0.999, live=False).process(["E1"])
        self.assertEqual(c.moves, [])
        self.assertIsNone(self.action("E1"))

    def test_failed_move_is_logged_and_the_watcher_goes_on(self):
        c = FakeLive({"E1": mail("E1"), "E2": mail("E2")})
        c.move = mock.Mock(side_effect=[RuntimeError("boom"), None])
        self.watcher(c, 0.99).process(["E1", "E2"])
        self.assertTrue(self.action("E1").startswith("move failed"))
        self.assertEqual(self.action("E2"), "moved")

    def receipt(self, frm):
        m = mail("E1", frm=frm)
        m["subject"] = "Thank you! Payment received for order"
        return m

    def test_webmail_receipt_from_a_stranger_moves_to_spam(self):
        c = FakeLive({"E1": self.receipt("x@gmail.com")})
        self.watcher(c, 0.0).process(["E1"])
        self.assertEqual(c.moves, [("E1", "I", "J")])
        self.assertEqual(len(c.queries), 1)

    def test_webmail_receipt_from_someone_written_to_stays(self):
        c = FakeLive({"E1": self.receipt("pal@gmail.com")}, sent_to={"pal@gmail.com"})
        self.watcher(c, 0.0).process(["E1"])
        self.assertEqual(c.moves, [])

    def test_failed_sent_lookup_leaves_it_to_the_model(self):
        c = FakeLive({"E1": self.receipt("x@gmail.com")}, sent_fails=True)
        self.watcher(c, 0.0).process(["E1"])
        self.assertEqual(c.moves, [])

    def test_no_sent_lookup_unless_the_rule_fires(self):
        c = FakeLive({"E1": mail("E1", frm="x@gmail.com")})
        self.watcher(c, 0.0).process(["E1"])
        self.assertEqual(c.queries, [])

    def test_own_digest_is_not_decided(self):
        c = FakeLive({"D1": mail("D1", digest=True)})
        self.assertEqual(self.watcher(c, 0.999).process(["D1"]), 0)

    def test_live_needs_a_writable_client(self):
        c = FakeLive({})
        c.write = False
        with self.assertRaises(SystemExit):
            self.watcher(c, 0.5)


class OwnerMoves(unittest.TestCase):
    """The review page queues a move; the watcher, which holds the token, makes it."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.st = S.Store(pathlib.Path(self.tmp.name) / "t.db")
        self.st.record({"account": "personal", "email_id": "E1", "would": "screen",
                        "source": "model", "p_spam": 0.97, "action": "moved"})

    def tearDown(self):
        self.st.db.close()
        self.tmp.cleanup()

    def watcher(self, client, live=True):
        lists = mock.Mock(get=mock.Mock(return_value=[]))
        return S.Shadow(client, self.st, lists, FakeModel(0.5), account="personal",
                        live=live, address="me@example.com", writer=client)

    def queue(self, email_id="E1", to="inbox", account="personal", at=None):
        self.st.db.execute("insert into moves (at, account, email_id, dir, state) "
                           "values (?, ?, ?, ?, 'pending')", (at or S.now(), account, email_id, to))
        self.st.db.commit()

    def state(self):
        return [r[0] for r in self.st.db.execute("select state from moves order by id")]

    def test_not_spam_moves_it_back_to_the_inbox(self):
        c = FakeLive({"E1": mail("E1", box="J")})
        self.queue()
        self.watcher(c).maybe_moves()
        self.assertEqual(c.moves, [("E1", "J", "I")])
        self.assertEqual(self.state(), ["done"])

    def test_spam_moves_it_out_of_the_inbox(self):
        c = FakeLive({"E1": mail("E1", box="I")})
        self.queue(to="spam")
        self.watcher(c).maybe_moves()
        self.assertEqual(c.moves, [("E1", "I", "J")])

    def test_only_from_where_the_page_expected(self):
        # filed in Archive since: the owner already dealt with it
        c = FakeLive({"E1": mail("E1", box="A")})
        self.queue()
        self.watcher(c).maybe_moves()
        self.assertEqual(c.moves, [])
        self.assertTrue(self.state()[0].startswith("refused"))

    def test_gone_unknown_foreign_stale_or_shadow_are_refused(self):
        c = FakeLive({"E1": mail("E1", box="J")})
        c.call = mock.Mock(return_value={"list": []})
        self.queue()                                  # gone from the mailbox
        self.queue(email_id="NOPE")                   # never decided
        self.queue(at="2020-01-01T00:00:00+00:00")    # too old to act on
        self.queue(account="work")                    # another watcher's
        self.watcher(c).maybe_moves()
        self.assertEqual(c.moves, [])
        st = self.state()
        self.assertTrue(all(x.startswith("refused") for x in st[:3]), st)
        self.assertEqual(st[3], "pending")
        c2 = FakeLive({"E1": mail("E1", box="J")})
        self.st.db.execute("update moves set state='pending'")
        self.st.db.commit()
        self.watcher(c2, live=False).maybe_moves()
        self.assertEqual(c2.moves, [])

    def test_a_failed_move_is_recorded(self):
        c = FakeLive({"E1": mail("E1", box="J")})
        c.move = mock.Mock(side_effect=RuntimeError("boom"))
        self.queue()
        self.watcher(c).maybe_moves()
        self.assertTrue(self.state()[0].startswith("failed"))


class Digest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.st = S.Store(pathlib.Path(self.tmp.name) / "t.db")

    def tearDown(self):
        self.st.db.close()
        self.tmp.cleanup()

    def add(self, i, would, source="model", p=0.5, action=None, at="2026-10-04T12:00:00+00:00"):
        self.st.record({"account": "personal", "email_id": i, "decided_at": at, "would": would,
                        "source": source, "p_spam": p, "from_email": f"{i}@x.example",
                        "from_name": f"Name {i}", "subject": f"Subject {i}", "action": action})

    def test_lists_the_unsure_and_counts_the_sure(self):
        self.add("review", "review", p=0.8)
        self.add("shaky", "screen", p=0.96, action="moved")
        self.add("sure", "screen", p=0.9995, action="moved")
        self.add("blocked", "screen", source="block", p=None, action="moved")
        self.add("fine", "inbox", p=0.1)
        self.add("old", "review", p=0.8, at="2026-10-01T00:00:00+00:00")
        subj, text = S.digest(self.st, "personal", "2026-10-03T12:00:00+00:00")
        self.assertIn("2 unsure emails", subj)
        self.assertIn("Name shaky <shaky@x.example>", text)
        self.assertIn("Subject review", text)
        self.assertIn("Also moved 2 to Spam", text)
        for absent in ("Subject sure", "Subject blocked", "Subject fine", "Subject old"):
            self.assertNotIn(absent, text)

    def test_rule_moves_are_listed_as_unsure(self):
        self.add("phish", "screen", source="rule", p=None, action="moved")
        self.add("sure", "screen", p=1.0, action="moved")
        subj, text = S.digest(self.st, "personal", "2026-10-03T00:00:00+00:00")
        self.assertIn("1 unsure email", subj)
        self.assertIn("Subject phish   [webmail receipt rule]", text)
        self.assertIn("Also moved 1 to Spam", text)

    def test_nothing_unsure_means_no_digest(self):
        self.add("sure", "screen", p=1.0, action="moved")
        self.assertEqual(S.digest(self.st, "personal", "2026-10-03T00:00:00+00:00"), ("", ""))

    def test_sent_once_a_day_after_the_hour(self):
        self.add("review", "review", p=0.8, at=S.now())
        c = FakeLive({})
        self.st.set("personal:digest_since", "2026-10-04T00:00:00+00:00")
        w = S.Shadow(c, self.st, mock.Mock(), FakeModel(0.5), account="personal",
                     live=True, address="me@example.com", writer=c)
        tz = dt.timezone(dt.timedelta(hours=-5))
        with mock.patch.object(config, "TZ", "America/Chicago"), \
             mock.patch.object(config, "DIGEST_AT", "07:00"), \
             mock.patch.object(S.dt, "datetime", wraps=dt.datetime) as fake:
            fake.now.side_effect = lambda z=None: dt.datetime(2026, 10, 5, 6, 59, tzinfo=tz)
            w.maybe_digest()
            self.assertEqual(c.created, [])           # before 07:00
            fake.now.side_effect = lambda z=None: dt.datetime(2026, 10, 5, 7, 1, tzinfo=tz)
            w.maybe_digest()
            w.maybe_digest()                          # same day: once
        self.assertEqual(len(c.created), 1)
        box, subj, _, headers = c.created[0]
        self.assertEqual((box, headers), ("I", {"X-Exodon": "digest"}))

    def test_off_sends_nothing_but_keeps_stamping(self):
        self.add("review", "review", p=0.8, at=S.now())
        c = FakeLive({})
        self.st.set("personal:digest_since", "2026-10-04T00:00:00+00:00")
        w = S.Shadow(c, self.st, mock.Mock(), FakeModel(0.5), account="personal",
                     live=True, address="me@example.com", writer=c)
        tz = dt.timezone(dt.timedelta(hours=-5))
        with mock.patch.object(config, "TZ", "America/Chicago"), \
             mock.patch.object(config, "DIGEST_AT", "off"), \
             mock.patch.object(S.dt, "datetime", wraps=dt.datetime) as fake:
            fake.now.side_effect = lambda z=None: dt.datetime(2026, 10, 5, 9, 0, tzinfo=tz)
            w.maybe_digest()
        self.assertEqual(c.created, [])
        self.assertEqual(self.st.get("personal:digest_day"), "2026-10-05")
        self.assertNotEqual(self.st.get("personal:digest_since"), "2026-10-04T00:00:00+00:00")

    def test_first_live_start_waits_for_tomorrow(self):
        self.add("review", "review", p=0.8, at="2026-10-04T12:00:00+00:00")  # shadow-era
        c = FakeLive({})
        w = S.Shadow(c, self.st, mock.Mock(), FakeModel(0.5), account="personal",
                     live=True, address="me@example.com", writer=c)
        w.maybe_digest()
        self.assertEqual(c.created, [])
        self.assertIsNotNone(self.st.get("personal:digest_since"))


class Modes(unittest.TestCase):
    def test_mode_per_account(self):
        env = {"EXODON_ACCOUNTS": "work,personal", "EXODON_PERSONAL_MODE": "live"}
        with mock.patch.dict(os.environ, env):
            os.environ.pop("EXODON_WORK_MODE", None)
            a = {x.name: x.live for x in config.accounts()}
        self.assertEqual(a, {"work": False, "personal": True})

    def test_bad_mode_refuses_to_start(self):
        with mock.patch.dict(os.environ, {"EXODON_ACCOUNTS": "work", "EXODON_WORK_MODE": "yes"}):
            with self.assertRaises(SystemExit):
                config.accounts()


if __name__ == "__main__":
    unittest.main()
