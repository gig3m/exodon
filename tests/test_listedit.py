"""Page-driven list edits: which pattern, whether it takes effect, and a
write that can only ever add or remove one clean line. No network.

    python3 -m unittest discover -s tests
"""

import os
import pathlib
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "src"))

import listedit as E  # noqa: E402
import lists as L  # noqa: E402


def entries(allow=(), block=()):
    return ([L.parse_line(a, "allow") for a in allow]
            + [L.parse_line(b, "block") for b in block])


class Candidate(unittest.TestCase):
    def test_default_scope(self):
        self.assertEqual(E.default_scope("a@gmail.com"), "address")
        self.assertEqual(E.default_scope("a@tenant.onmicrosoft.com"), "address")
        self.assertEqual(E.default_scope("a@mail.acme.com"), "domain")
        self.assertEqual(E.candidate("a@mail.acme.com", "domain"), "@acme.com")
        self.assertEqual(E.candidate("Bob.Smith+x@Acme.com", "address"), "bob.smith+x@acme.com")

    def test_refusals(self):
        for addr, scope in (("*@gmail.com", "address"), ("a#b@acme.com", "address"),
                            ("a@b@c.com", "address"), ("", "address"), ("", "domain"),
                            ("noatsign", "domain"), ("x@gmail.com", "domain"),
                            ("x@ac_me.com", "domain"), ("x@acme.com", "everything"),
                            ("x@tenant.onmicrosoft.com", "domain"), ("x@app.herokuapp.com", "domain")):
            with self.subTest(addr=addr, scope=scope), self.assertRaises(E.Refused):
                E.candidate(addr, scope)


class Verdicts(unittest.TestCase):
    def v(self, es, which, pattern, addr="bob@acme.com", note=None):
        return E.verdict(es, addr, "Bob", which, pattern, note)

    def test_nothing_governs_yet(self):
        self.assertEqual(self.v([], "block", "@acme.com").status, "ok")

    def test_covered(self):
        v = self.v(entries(allow=["@acme.com"]), "allow", "bob@acme.com")
        self.assertEqual(v.status, "covered")
        self.assertNotIn("did not prove", v.message)
        v = self.v(entries(allow=["@acme.com"]), "allow", "bob@acme.com",
                   note="allow @acme.com ignored: not authenticated (no aligned pass)")
        self.assertIn("did not prove", v.message)

    def test_more_specific_overrides_the_other_list(self):
        v = self.v(entries(block=["@acme.com"]), "allow", "bob@acme.com")
        self.assertEqual(v.status, "ok")
        self.assertIn("overrides block @acme.com", v.message)

    def test_blocked_by_a_more_specific_entry(self):
        v = self.v(entries(allow=["bob@acme.com"]), "block", "@acme.com")
        self.assertEqual(v.status, "blocked")
        self.assertIn("bob@acme.com", v.message)

    def test_blocked_by_an_identical_allow(self):
        # allow wins ties, so a block with the same pattern would never apply
        v = self.v(entries(allow=["@acme.com"]), "block", "@acme.com")
        self.assertEqual(v.status, "blocked")
        self.assertIn("allow @acme.com", v.message)

    def test_name_entries_count(self):
        v = self.v(entries(block=["name:*bob*"]), "block", "@acme.com")
        self.assertEqual(v.status, "covered")


class Write(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = pathlib.Path(self.tmp.name) / "block.txt"
        self.path.write_text("# my list\n@spam.example   # hand-written\n")
        os.chmod(self.path, 0o640)

    def tearDown(self):
        self.tmp.cleanup()

    def raws(self):
        return [e.raw for e in L.load(self.path, "block")]

    def test_note_is_one_clean_line(self):
        n = E.note('x\r\n@gmail.com y#z"q\x0bw\x85v')
        self.assertEqual(len(n.splitlines()), 1)
        for bad in "#\"\r\n \x0b\x85":
            self.assertNotIn(bad, n)
        line = E.line_for("@acme.com", 'evil\n@gmail.com', "2026-09-27")
        self.assertEqual([e.raw for e in L.load_text(line, "block")], ["@acme.com"])

    def test_append_adds_exactly_one_and_keeps_mode(self):
        E.append(self.path, "block", E.line_for("@acme.com", "Hi", "2026-09-27"))
        self.assertEqual(self.raws(), ["@spam.example", "@acme.com"])
        self.assertIn('@acme.com  # exodon page 2026-09-27: "Hi"', self.path.read_text())
        self.assertEqual(os.stat(self.path).st_mode & 0o777, 0o640)

    def test_append_refuses_a_line_that_is_not_exactly_one_entry(self):
        with self.assertRaises(E.Refused):
            E.append(self.path, "block", "@acme.com\n@gmail.com")
        self.assertEqual(self.raws(), ["@spam.example"])

    def test_hand_edit_during_write_is_kept(self):
        stale = E._read(self.path)  # we read the file...
        with open(self.path, "a") as f:  # ...then the owner saves a hand edit
            f.write("@hand.example\n")
        st = os.stat(self.path)
        os.utime(self.path, ns=(st.st_atime_ns, st.st_mtime_ns + 10**9))
        real, calls = E._read, []

        def reader(p):
            calls.append(1)
            return stale if len(calls) == 1 else real(p)

        with mock.patch.object(E, "_read", side_effect=reader):
            E.append(self.path, "block", E.line_for("@acme.com", "Hi", "2026-09-27"))
        self.assertEqual(self.raws(), ["@spam.example", "@hand.example", "@acme.com"])

    def test_remove_only_its_own_line(self):
        line = E.line_for("@acme.com", "Hi", "2026-09-27")
        E.append(self.path, "block", line)
        E.remove(self.path, "block", line)
        self.assertEqual(self.raws(), ["@spam.example"])
        with self.assertRaises(E.Refused):  # already gone
            E.remove(self.path, "block", line)
        self.path.write_text(self.path.read_text() + line + "\n" + line + "\n")
        with self.assertRaises(E.Refused):  # duplicated: ambiguous, leave it
            E.remove(self.path, "block", line)


if __name__ == "__main__":
    unittest.main()
