"""Privacy layer tests that need no optional dependency (detector off). Run: python3 -m unittest discover tests"""
import json
import os
import shutil
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from kasiru.privacy import Privacy, term_regex  # noqa: E402

_N = [0]


def fresh(persons=(), orgs=(), **opts):
    _N[0] += 1
    d = tempfile.mkdtemp(prefix="kasiru-t%d-" % _N[0])
    with open(os.path.join(d, "entities.json"), "w", encoding="utf-8") as f:
        json.dump({"persons": list(persons), "orgs": list(orgs), "pending": {"persons": [], "orgs": []}}, f, ensure_ascii=False)
    o = {"ner": "off"}
    o.update(opts)
    return Privacy(d, d, o, log=lambda *a: None)


class ScrubBasics(unittest.TestCase):
    def test_identifiers_and_dictionary_roundtrip(self):
        p = fresh(persons=["Jane Example"], orgs=["Example Robotics LLC"])
        src = "Mail jane@example.org, call Jane Example from Example Robotics LLC; card 4111 1111 1111 1111 and date 2024-05-04."
        out, rep = p.scrub(src, "personal", use_ner=False)
        self.assertNotIn("jane@example.org", out)
        self.assertNotIn("Jane Example", out)
        self.assertNotIn("4111 1111 1111 1111", out)
        self.assertIn("2024-05-04", out)
        self.assertEqual(rep["replaced"]["email"], 1)
        back = p.unscrub(out)
        self.assertIn("jane@example.org", back)
        self.assertIn("Jane Example", back)
        self.assertIn("Example Robotics LLC", back)
        self.assertEqual(p.leak_check(out), 0)

    def test_tokens_are_persistent(self):
        p = fresh(persons=["Jane Example"])
        a, _ = p.scrub("Jane Example wrote", "personal", use_ner=False)
        b, _ = p.scrub("then Jane Example called", "personal", use_ner=False)
        tok = [t for t in p.tokens["map"]][0]
        self.assertIn(tok, a)
        self.assertIn(tok, b)
        self.assertEqual(len(p.tokens["map"]), 1)

    def test_token_labels(self):
        p = fresh(persons=["Jane Example"], token_labels={"person": "персона"})
        out, _ = p.scrub("Jane Example wrote", "personal", use_ner=False)
        self.assertIn("[персона-1]", out)
        self.assertEqual(p.unscrub("Reply to [Персона-1] and [персона - 1]"), "Reply to Jane Example and Jane Example")

    def test_public_only_cuts_markup(self):
        p = fresh(persons=["Jane Example"])
        out, rep = p.scrub("Jane Example\n[secret] pin 1234\n<secret>x</secret> end", "public")
        self.assertIn("Jane Example", out)
        self.assertNotIn("1234", out)
        self.assertNotIn("<secret>", out)
        self.assertEqual(rep["secret_lines"], 1)
        self.assertEqual(rep["secret_blocks"], 1)

    def test_system_prompt_marker_is_instruction(self):
        p = fresh()
        clean, rep = p.scrub("keep lines marked [secret] untouched", "personal", use_ner=False, secret_markers=False)
        self.assertEqual(rep["secret"], [])
        self.assertIn("[secret]", clean)

    def test_custom_markers(self):
        p = fresh(secret_markers=["[private]"])
        out, rep = p.scrub("a\n[private] b\n[secret] c", "personal", use_ner=False)
        self.assertEqual(rep["secret_lines"], 1)
        self.assertIn("[secret] c", out)

    def test_keys_and_wallets(self):
        p = fresh()
        src = "key sk-or-v1-0123456789abcdef0123456789abcdef, wallet 0x742d35Cc6634C0532925a3b844Bc454e4438f44e, password: Qwe12345!, plain word Application."
        out, _ = p.scrub(src, "personal", use_ner=False)
        self.assertNotIn("sk-or-v1", out)
        self.assertNotIn("0x742d", out)
        self.assertNotIn("Qwe12345", out)
        self.assertIn("Application", out)


class Messages(unittest.TestCase):
    def test_scrub_messages_parts_and_tool_calls(self):
        p = fresh(persons=["Jane Example"])
        msgs = [{"role": "system", "content": "be brief"},
                {"role": "user", "content": [{"type": "text", "text": "ask Jane Example"}, {"type": "image_url", "image_url": {"url": "data:..."}}]},
                {"role": "assistant", "content": None, "tool_calls": [{"id": "1", "type": "function", "function": {"name": "f", "arguments": "{\"who\": \"Jane Example\"}"}}]},
                {"role": "tool", "tool_call_id": "1", "content": "Jane Example is out"}]
        out, rep, secret = p.scrub_messages(msgs, "personal", use_ner=False)
        dump = json.dumps(out, ensure_ascii=False)
        self.assertNotIn("Jane Example", dump)
        self.assertEqual(out[1]["content"][1]["type"], "image_url")
        self.assertEqual(rep["replaced"]["person"], 3)
        back = p.unscrub_message(out[2])
        self.assertIn("Jane Example", back["tool_calls"][0]["function"]["arguments"])


class LeakCheck(unittest.TestCase):
    def test_word_boundaries(self):
        p = fresh(persons=["Anton"])
        p._token("person", "Anton")
        self.assertEqual(p.leak_check("Antonov came"), 0)
        self.assertEqual(p.leak_check("Anton came"), 1)
        self.assertEqual(p.leak_check("anton, left"), 1)

    def test_stale_token_is_not_a_leak(self):
        p = fresh(persons=["Jane Example"])
        p._token("person", "Jane Example")
        p.entities["persons"] = []
        self.assertEqual(p.leak_check("Jane Example"), 0)
        self.assertEqual(p.purge_tokens(), 1)

    def test_yo_ye(self):
        rx = term_regex("Алене")
        self.assertTrue(rx.search("Написал Алёне вчера"))
        p = fresh(persons=["Алене"])
        out, rep = p.scrub("Передай Алёне, что Алене звонили.", "personal", use_ner=False)
        self.assertNotIn("Алёне", out)
        self.assertEqual(rep["replaced"]["person"], 2)
        self.assertEqual(p.leak_check(out), 0)


class TokenTableRace(unittest.TestCase):
    def test_concurrent_token_and_unscrub(self):
        p = fresh(persons=["Semyon Zarubin"])
        p._token("person", "Semyon Zarubin")
        errors, stop = [], threading.Event()

        def writer():
            try:
                for i in range(300):
                    p._token("person", "Person %d" % i, "Person %d" % i)
            except Exception as e:  # noqa: BLE001
                errors.append(e)
            finally:
                stop.set()

        def reader():
            try:
                while not stop.is_set():
                    p.unscrub("Reply: [person-1] and [person-2]")
                    p.leak_check("Semyon Zarubin wrote")
            except Exception as e:  # noqa: BLE001
                errors.append(e)

        ts = [threading.Thread(target=writer)] + [threading.Thread(target=reader) for _ in range(3)]
        for t in ts:
            t.start()
        for t in ts:
            t.join(timeout=30)
        self.assertEqual(errors, [])
        self.assertEqual(len(p.tokens["map"]), 301)


if __name__ == "__main__":
    unittest.main(verbosity=2)
