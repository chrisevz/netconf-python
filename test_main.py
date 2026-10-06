#!/usr/bin/env python3
"""Offline unit tests for main.py's pure/logic functions — no device needed.

Covers: text normalization/hashing (idempotency, blank-line insensitivity),
capability parsing (including the substring false-positive the old code was
vulnerable to), the XML-diff fallback producing an empty diff for a no-op
change, and preview_mode selection choosing "xml-diff" on an unsupported
render RPC rather than failing.
"""

import json
import unittest
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import lxml.etree as etree
from ncclient.operations.rpc import RPCError

import main

_NETCONF_NS = "urn:ietf:params:xml:ns:netconf:base:1.0"


def _make_rpc_error(tag="unknown-element"):
    """Build a real RPCError (not a mock) so getattr(e, 'tag', ...) — the
    same code path main.py relies on — actually works in tests."""
    root = etree.Element(f"{{{_NETCONF_NS}}}rpc-error")
    tag_el = etree.SubElement(root, f"{{{_NETCONF_NS}}}error-tag")
    tag_el.text = tag
    return RPCError(root)


class NormalizeAndHashTests(unittest.TestCase):
    def test_normalize_drops_blank_lines_and_trailing_whitespace(self):
        text = "interface Gi1  \n\n description test\n\n\n"
        self.assertEqual(main._normalize_text(text), "interface Gi1\n description test")

    def test_normalize_idempotent(self):
        text = "a\nb  \n\nc\n"
        once = main._normalize_text(text)
        twice = main._normalize_text(once)
        self.assertEqual(once, twice)

    def test_hash_identical_for_configs_differing_only_in_blank_lines(self):
        a = "interface Gi1\ndescription test\n"
        b = "interface Gi1\n\n\ndescription test\n\n"
        self.assertEqual(main._text_hash(a), main._text_hash(b))

    def test_hash_differs_for_real_content_change(self):
        a = "interface Gi1\ndescription test\n"
        b = "interface Gi1\ndescription other\n"
        self.assertNotEqual(main._text_hash(a), main._text_hash(b))

    def test_diff_lines_preserves_blank_lines(self):
        text = "a\n\nb\n"
        self.assertEqual(main._diff_lines(text), ["a", "", "b"])


class CapabilityParsingTests(unittest.TestCase):
    def _manager(self, capabilities):
        m = MagicMock()
        m.server_capabilities = capabilities
        return m

    def test_has_candidate_true(self):
        m = self._manager(["urn:ietf:params:netconf:capability:candidate:1.0"])
        self.assertTrue(main._has_candidate(m))

    def test_has_candidate_false_when_absent(self):
        m = self._manager(["urn:ietf:params:netconf:capability:writable-running:1.0"])
        self.assertFalse(main._has_candidate(m))

    def test_has_candidate_does_not_substring_false_positive(self):
        # A capability URI that merely *contains* ":candidate" as a substring
        # (not as the actual base capability) must not match. The old
        # implementation did `":candidate" in str(m.server_capabilities)`,
        # which this would have incorrectly matched.
        m = self._manager([
            "urn:cisco:params:netconf:capability:pre-candidate-extension:1.0",
        ])
        self.assertFalse(main._has_candidate(m))

    def test_has_validate_true_for_either_version(self):
        m10 = self._manager(["urn:ietf:params:netconf:capability:validate:1.0"])
        m11 = self._manager(["urn:ietf:params:netconf:capability:validate:1.1"])
        self.assertTrue(main._has_validate(m10))
        self.assertTrue(main._has_validate(m11))

    def test_has_validate_false_when_absent(self):
        m = self._manager(["urn:ietf:params:netconf:capability:candidate:1.0"])
        self.assertFalse(main._has_validate(m))


class PreviewRenderTests(unittest.TestCase):
    def test_device_rendered_mode_when_render_rpc_available(self):
        m = MagicMock()
        m.dispatch.side_effect = [
            self._fake_reply("running config text\n"),
            self._fake_reply("candidate config text\n"),
        ]
        result = main._preview_render(m, "<running/>", "<candidate/>")
        self.assertEqual(result["preview_mode"], "device-rendered")
        self.assertTrue(result["has_changes"])
        self.assertIn("running config text", result["running_config"])

    def test_xml_diff_fallback_on_unsupported_render_rpc(self):
        m = MagicMock()
        m.dispatch.side_effect = _make_rpc_error()
        result = main._preview_render(m, "<running/>", "<candidate/>")
        self.assertEqual(result["preview_mode"], "xml-diff")
        self.assertTrue(result["has_changes"])
        self.assertEqual(result["running_config"], "<running/>")

    def test_xml_diff_no_op_change_produces_empty_diff(self):
        m = MagicMock()
        m.dispatch.side_effect = _make_rpc_error()
        same_xml = "<config><a>1</a></config>"
        result = main._preview_render(m, same_xml, same_xml)
        self.assertEqual(result["preview_mode"], "xml-diff")
        self.assertEqual(result["diff"], "")
        self.assertFalse(result["has_changes"])

    def test_xml_diff_real_change_produces_nonempty_diff(self):
        m = MagicMock()
        m.dispatch.side_effect = _make_rpc_error()
        result = main._preview_render(m, "<config><a>1</a></config>", "<config><a>2</a></config>")
        self.assertEqual(result["preview_mode"], "xml-diff")
        self.assertTrue(result["has_changes"])
        self.assertNotEqual(result["diff"], "")

    @staticmethod
    def _fake_reply(cli_text):
        reply = MagicMock()
        reply.xml = (
            '<rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">'
            f"<result>{cli_text}</result>"
            "</rpc-reply>"
        )
        return reply


class SideBySideRowsTests(unittest.TestCase):
    """_side_by_side_rows: the diff as plain data (old left, new right) for the approval screen."""

    @staticmethod
    def _lines(n):
        return [f"line{i}" for i in range(n)]

    def test_identical_text_has_no_rows(self):
        rows, stats = main._side_by_side_rows("a\nb\nc", "a\nb\nc")
        self.assertEqual(rows, [])
        self.assertEqual(stats, {"added": 0, "removed": 0, "truncated": False})

    def test_one_change_keeps_three_lines_of_context_and_gaps_elsewhere(self):
        old = self._lines(20)
        new = list(old)
        new[10] = "CHANGED"
        rows, stats = main._side_by_side_rows("\n".join(old), "\n".join(new))
        self.assertEqual([r["kind"] for r in rows],
                         ["gap", "same", "same", "same", "change", "same", "same", "same", "gap"])
        self.assertEqual(rows[0]["hidden"], 7)
        self.assertEqual(rows[-1]["hidden"], 6)
        change = rows[4]
        self.assertEqual((change["old_no"], change["old"], change["old_mark"]), (11, "line10", "del"))
        self.assertEqual((change["new_no"], change["new"], change["new_mark"]), (11, "CHANGED", "add"))
        self.assertEqual((rows[1]["old_no"], rows[1]["new_no"]), (8, 8))
        self.assertEqual(stats, {"added": 1, "removed": 1, "truncated": False})

    def test_added_lines_sit_opposite_an_empty_old_side(self):
        rows, stats = main._side_by_side_rows("a\nb", "a\nX\nY\nb")
        added = [r for r in rows if r["kind"] == "change"]
        self.assertEqual([r["new"] for r in added], ["X", "Y"])
        for r in added:
            self.assertIsNone(r["old_no"])
            self.assertEqual((r["old"], r["old_mark"], r["new_mark"]), ("", "", "add"))
        self.assertEqual((added[0]["new_no"], added[1]["new_no"]), (2, 3))
        self.assertEqual(stats["added"], 2)
        self.assertEqual(stats["removed"], 0)

    def test_removed_lines_sit_opposite_an_empty_new_side(self):
        rows, stats = main._side_by_side_rows("a\nX\nb", "a\nb")
        removed = [r for r in rows if r["kind"] == "change"]
        self.assertEqual(len(removed), 1)
        self.assertEqual((removed[0]["old_no"], removed[0]["old"], removed[0]["old_mark"]), (2, "X", "del"))
        self.assertIsNone(removed[0]["new_no"])
        self.assertEqual(removed[0]["new_mark"], "")
        self.assertEqual((stats["added"], stats["removed"]), (0, 1))

    def test_replaced_block_is_paired_and_the_shorter_side_is_padded(self):
        rows, _ = main._side_by_side_rows("a\nb\nc\nd", "a\nX\nd")
        changes = [r for r in rows if r["kind"] == "change"]
        self.assertEqual([(r["old"], r["new"]) for r in changes], [("b", "X"), ("c", "")])
        self.assertEqual(changes[1]["new_mark"], "")
        self.assertIsNone(changes[1]["new_no"])

    def test_text_is_returned_raw_not_html_escaped(self):
        rows, _ = main._side_by_side_rows("a", "a\n<b>&amp;</b>")
        self.assertEqual([r["new"] for r in rows if r["kind"] == "change"], ["<b>&amp;</b>"])

    def test_trailing_whitespace_is_ignored_but_blank_lines_are_kept(self):
        rows, _ = main._side_by_side_rows("a  \n\nb", "a\n\nb\nc")
        self.assertEqual([r["new"] for r in rows if r["kind"] == "change"], ["c"])
        self.assertIn("", [r["old"] for r in rows if r["kind"] == "same"])

    def test_row_cap_truncates_and_says_so(self):
        old = self._lines(40)
        new = [f"changed{i}" for i in range(40)]
        rows, stats = main._side_by_side_rows("\n".join(old), "\n".join(new), max_rows=10)
        self.assertEqual(len(rows), 11)
        self.assertEqual(rows[-1], {"kind": "gap", "hidden": 30})
        self.assertTrue(stats["truncated"])

    def test_first_build_against_an_empty_config_is_all_additions(self):
        rows, stats = main._side_by_side_rows("", "hostname x\nntp server 1.2.3.4")
        self.assertEqual([r["kind"] for r in rows], ["change", "change"])
        self.assertEqual((stats["added"], stats["removed"]), (2, 0))


class ParallelRenderTests(unittest.TestCase):
    """The running-config render overlaps the staging work in a second session."""

    @staticmethod
    def _background(result="running text\n", error=None, exc=None, seconds=1.5):
        thread = MagicMock()
        return thread, {"result": result, "error": error, "exc": exc, "seconds": seconds}

    def test_uses_the_background_running_render_and_renders_only_candidate_here(self):
        m = MagicMock()
        m.dispatch.side_effect = [PreviewRenderTests._fake_reply("candidate text\n")]
        thread, box = self._background()
        result = main._preview_render(m, "<running/>", "<candidate/>", (thread, box))
        thread.join.assert_called_once()
        self.assertEqual(m.dispatch.call_count, 1)
        self.assertEqual(result["preview_mode"], "device-rendered")
        self.assertIn("running text", result["running_config"])
        self.assertIn("candidate text", result["candidate_config"])
        self.assertTrue(result["timings"]["parallel"])
        self.assertEqual(result["timings"]["running_render_s"], 1.5)
        self.assertIn("candidate_render_s", result["timings"])
        self.assertTrue(result["diff_rows"])

    def test_falls_back_to_rendering_running_here_when_the_second_session_failed(self):
        m = MagicMock()
        m.dispatch.side_effect = [PreviewRenderTests._fake_reply("candidate text\n"),
                                  PreviewRenderTests._fake_reply("running text\n")]
        thread, box = self._background(result=None, exc=RuntimeError("too many sessions"), seconds=0.1)
        result = main._preview_render(m, "<running/>", "<candidate/>", (thread, box))
        self.assertEqual(m.dispatch.call_count, 2)
        self.assertEqual(result["preview_mode"], "device-rendered")
        self.assertIn("running text", result["running_config"])
        self.assertFalse(result["timings"]["parallel"])

    def test_unsupported_render_rpc_still_ends_in_the_xml_diff(self):
        m = MagicMock()
        m.dispatch.side_effect = _make_rpc_error()
        thread, box = self._background(result=None, error="get-modelled-config-clis RPC not supported")
        result = main._preview_render(m, "<config><a>1</a></config>", "<config><a>2</a></config>", (thread, box))
        self.assertEqual(result["preview_mode"], "xml-diff")
        self.assertTrue(result["has_changes"])
        self.assertTrue(result["diff_rows"])

    def test_without_background_the_two_renders_run_one_after_the_other(self):
        m = MagicMock()
        m.dispatch.side_effect = [PreviewRenderTests._fake_reply("running text\n"),
                                  PreviewRenderTests._fake_reply("candidate text\n")]
        result = main._preview_render(m, "<running/>", "<candidate/>")
        self.assertFalse(result["timings"]["parallel"])
        self.assertIn("running text", result["running_config"])

    def test_background_render_uses_its_own_session_and_returns_the_text(self):
        m2 = MagicMock()
        m2.dispatch.return_value = PreviewRenderTests._fake_reply("running text\n")
        session = MagicMock()
        session.__enter__.return_value = m2
        conn = {"host": "10.0.0.1"}
        with patch.object(main, "_session", return_value=session) as opened:
            thread, box = main._start_background_render(conn, "running")
            thread.join(5)
        opened.assert_called_once_with(conn)
        self.assertIsNone(box["exc"])
        self.assertIn("running text", box["result"])
        self.assertIsNotNone(box["seconds"])
        self.assertTrue(thread.daemon)

    def test_background_render_reports_a_failed_session_instead_of_raising(self):
        with patch.object(main, "_session", side_effect=RuntimeError("no session")):
            thread, box = main._start_background_render({"host": "10.0.0.1"}, "running")
            thread.join(5)
        self.assertIsInstance(box["exc"], RuntimeError)
        self.assertIsNone(box["result"])


class PreviewConfigFlowTests(unittest.TestCase):
    """preview_config end to end with a mocked manager: ordering and result shape."""

    def _run(self, diff=True):
        m = MagicMock()
        m.server_capabilities = ["urn:ietf:params:netconf:capability:candidate:1.0"]
        m.dispatch.side_effect = [PreviewRenderTests._fake_reply("hostname a\ndescription new\n")]
        session = MagicMock()
        session.__enter__.return_value = m
        order = MagicMock()
        thread = MagicMock()
        box = {"result": "hostname a\ndescription old\n", "error": None, "exc": None, "seconds": 2.0}
        order.start.return_value = (thread, box)
        order.lock.return_value = 0.0
        conn = {"host": "10.0.0.1", "lock_timeout": 1, "lock_poll_interval": 0.1}
        args = MagicMock(config_xml="<config/>", force_discard=False, diff=diff)
        with patch.object(main, "_session", return_value=session), \
             patch.object(main, "_start_background_render", order.start), \
             patch.object(main, "_acquire_candidate_lock", order.lock), \
             patch.object(main, "_get_config_xml", side_effect=["<a>1</a>", "<a>1</a>", "<a>2</a>"]):
            result = main.preview_config(conn, args)
        return result, order, m

    def test_background_render_starts_before_the_candidate_lock(self):
        result, order, _ = self._run()
        self.assertTrue(result["success"])
        names = [c[0] for c in order.mock_calls if c[0] in ("start", "lock")]
        self.assertEqual(names, ["start", "lock"])
        order.start.assert_called_once_with({"host": "10.0.0.1", "lock_timeout": 1, "lock_poll_interval": 0.1},
                                            "running")

    def test_result_carries_side_by_side_rows_stats_and_timings(self):
        result, _, m = self._run()
        self.assertEqual(result["preview_mode"], "device-rendered")
        self.assertTrue(result["has_changes"])
        changes = [r for r in result["diff_rows"] if r["kind"] == "change"]
        self.assertEqual([(r["old"], r["new"]) for r in changes], [("description old", "description new")])
        self.assertEqual(result["diff_stats"]["added"], 1)
        self.assertTrue(result["timings"]["parallel"])
        self.assertFalse(result["committed"])
        m.discard_changes.assert_called()
        m.unlock.assert_called_once_with(target="candidate")

    def test_diff_false_drops_every_form_of_the_diff(self):
        result, _, _ = self._run(diff=False)
        self.assertIsNone(result["diff"])
        self.assertIsNone(result["diff_rows"])
        self.assertIsNone(result["diff_stats"])


class SendConfigXmlTests(unittest.TestCase):
    """send_command's push path, with a mocked ncclient manager."""

    CANDIDATE = "urn:ietf:params:netconf:capability:candidate:1.0"
    VALIDATE = "urn:ietf:params:netconf:capability:validate:1.1"
    CONFIRMED_1_0 = "urn:ietf:params:netconf:capability:confirmed-commit:1.0"
    CONFIRMED_1_1 = "urn:ietf:params:netconf:capability:confirmed-commit:1.1"

    def _run(self, capabilities, validate_error=None, confirm_timeout=None, commit_error=None):
        m = MagicMock()
        m.server_capabilities = capabilities
        if validate_error is not None:
            m.validate.side_effect = validate_error
        if commit_error is not None:
            m.commit.side_effect = commit_error
        session = MagicMock()
        session.__enter__.return_value = m
        conn = {"host": "10.0.0.1", "lock_timeout": 1, "lock_poll_interval": 0.1}
        args = MagicMock(config_xml="<config/>", expect_running_hash=None, confirm_timeout=confirm_timeout)
        with patch.object(main, "_session", return_value=session), \
             patch.object(main, "_acquire_candidate_lock", return_value=0.0):
            return main.send_command(conn, args), m

    def test_refuses_without_candidate_and_never_edits_running(self):
        result, m = self._run([])
        self.assertFalse(result["success"])
        self.assertEqual(result["error_type"], "NoCandidate")
        m.edit_config.assert_not_called()

    def test_commits_after_successful_validate(self):
        result, m = self._run([self.CANDIDATE, self.VALIDATE])
        self.assertTrue(result["success"])
        self.assertEqual(result["validate"], "valid")
        m.commit.assert_called_once()

    def test_validation_failure_discards_and_does_not_commit(self):
        result, m = self._run([self.CANDIDATE, self.VALIDATE], validate_error=_make_rpc_error("invalid-value"))
        self.assertFalse(result["success"])
        self.assertEqual(result["error_type"], "ValidationFailed")
        m.commit.assert_not_called()
        m.discard_changes.assert_called()
        m.unlock.assert_called_once_with(target="candidate")

    def test_commits_when_validate_unsupported(self):
        result, m = self._run([self.CANDIDATE])
        self.assertTrue(result["success"])
        self.assertEqual(result["validate"], "unsupported")
        m.commit.assert_called_once()

    def test_plain_commit_when_no_confirm_timeout(self):
        result, m = self._run([self.CANDIDATE, self.CONFIRMED_1_1])
        self.assertTrue(result["success"])
        self.assertFalse(result["confirmed_commit"])
        self.assertNotIn("persist_id", result)
        m.commit.assert_called_once_with()

    def test_confirmed_commit_uses_persist_and_returns_id_and_deadline(self):
        result, m = self._run([self.CANDIDATE, self.VALIDATE, self.CONFIRMED_1_1], confirm_timeout=600)
        self.assertTrue(result["success"])
        self.assertTrue(result["confirmed_commit"])
        self.assertEqual(result["confirm_timeout"], 600)
        self.assertTrue(result["persist_id"])
        m.commit.assert_called_once_with(confirmed=True, timeout="600", persist=result["persist_id"])
        # deadline is 'now + timeout' computed before the commit, never later than the device's own
        deadline = datetime.strptime(result["confirm_deadline_utc"], "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
        remaining = (deadline - datetime.now(timezone.utc)).total_seconds()
        self.assertTrue(590 <= remaining <= 600, remaining)
        m.unlock.assert_called_once_with(target="candidate")

    def test_confirmed_commit_persist_ids_are_unique(self):
        first, _ = self._run([self.CANDIDATE, self.CONFIRMED_1_1], confirm_timeout=60)
        second, _ = self._run([self.CANDIDATE, self.CONFIRMED_1_1], confirm_timeout=60)
        self.assertNotEqual(first["persist_id"], second["persist_id"])

    def test_confirm_timeout_refused_without_confirmed_commit_and_never_edits(self):
        result, m = self._run([self.CANDIDATE, self.VALIDATE], confirm_timeout=600)
        self.assertFalse(result["success"])
        self.assertEqual(result["error_type"], "NoConfirmedCommit")
        self.assertFalse(result["committed"])
        m.edit_config.assert_not_called()
        m.commit.assert_not_called()

    def test_confirmed_commit_1_0_is_not_enough(self):
        # 1.0's confirmed commit reverts as soon as the pushing session closes
        result, m = self._run([self.CANDIDATE, self.CONFIRMED_1_0], confirm_timeout=600)
        self.assertFalse(result["success"])
        self.assertEqual(result["error_type"], "NoConfirmedCommit")
        m.edit_config.assert_not_called()
        m.commit.assert_not_called()

    def test_commit_failure_in_confirm_mode_returns_persist_id_and_unknown_state(self):
        result, m = self._run([self.CANDIDATE, self.CONFIRMED_1_1], confirm_timeout=600,
                              commit_error=_make_rpc_error("operation-failed"))
        self.assertFalse(result["success"])
        self.assertTrue(result["persist_id"])
        self.assertEqual(result["confirmed_commit_state"], "unknown")
        m.discard_changes.assert_called()
        m.unlock.assert_called_once_with(target="candidate")


class ConfirmAndCancelCommitTests(unittest.TestCase):
    CONFIRMED_1_1 = "urn:ietf:params:netconf:capability:confirmed-commit:1.1"

    def _run(self, op, capabilities, persist_id="abc123", error=None):
        m = MagicMock()
        m.server_capabilities = capabilities
        if error is not None:
            m.commit.side_effect = error
            m.cancel_commit.side_effect = error
        session = MagicMock()
        session.__enter__.return_value = m
        args = MagicMock(persist_id=persist_id)
        with patch.object(main, "_session", return_value=session):
            return op({"host": "10.0.0.1"}, args), m

    def test_confirm_sends_confirming_commit_with_persist_id(self):
        result, m = self._run(main.confirm_commit, [self.CONFIRMED_1_1])
        self.assertTrue(result["success"])
        self.assertTrue(result["confirmed"])
        m.commit.assert_called_once_with(persist_id="abc123")

    def test_confirm_requires_persist_id(self):
        result, m = self._run(main.confirm_commit, [self.CONFIRMED_1_1], persist_id=None)
        self.assertFalse(result["success"])
        self.assertFalse(result["confirmed"])
        m.commit.assert_not_called()

    def test_confirm_refused_without_confirmed_commit_1_1(self):
        result, m = self._run(main.confirm_commit, [])
        self.assertFalse(result["success"])
        self.assertEqual(result["error_type"], "NoConfirmedCommit")
        m.commit.assert_not_called()

    def test_confirm_after_device_already_rolled_back_reports_not_confirmed(self):
        result, _ = self._run(main.confirm_commit, [self.CONFIRMED_1_1], error=_make_rpc_error("operation-failed"))
        self.assertFalse(result["success"])
        self.assertFalse(result["confirmed"])
        self.assertEqual(result["error_type"], "RPCError")
        self.assertEqual(result["rpc_tag"], "operation-failed")

    def test_cancel_sends_cancel_commit_with_persist_id(self):
        result, m = self._run(main.cancel_commit, [self.CONFIRMED_1_1])
        self.assertTrue(result["success"])
        self.assertTrue(result["rolled_back"])
        m.cancel_commit.assert_called_once_with(persist_id="abc123")

    def test_cancel_requires_persist_id(self):
        result, m = self._run(main.cancel_commit, [self.CONFIRMED_1_1], persist_id="")
        self.assertFalse(result["success"])
        self.assertFalse(result["rolled_back"])
        m.cancel_commit.assert_not_called()

    def test_cancel_failure_reports_not_rolled_back(self):
        result, _ = self._run(main.cancel_commit, [self.CONFIRMED_1_1], error=_make_rpc_error("operation-failed"))
        self.assertFalse(result["success"])
        self.assertFalse(result["rolled_back"])


class IsAliveCapabilityTests(unittest.TestCase):
    def _run(self, capabilities):
        m = MagicMock()
        m.server_capabilities = capabilities
        m.get.return_value.data_xml = (
            '<data><native xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-native"><version>17.15</version></native></data>')
        session = MagicMock()
        session.__enter__.return_value = m
        with patch.object(main, "_session", return_value=session):
            return main.is_alive({"host": "10.0.0.1"}, MagicMock())

    def test_reports_persistent_confirmed_commit_when_advertised(self):
        result = self._run(["urn:ietf:params:netconf:capability:confirmed-commit:1.1"])
        self.assertTrue(result["alive"])
        self.assertEqual(result["output"], "17.15")
        self.assertTrue(result["persist_confirmed_commit"])

    def test_reports_false_for_1_0_only_or_absent(self):
        self.assertFalse(self._run(["urn:ietf:params:netconf:capability:confirmed-commit:1.0"])["persist_confirmed_commit"])
        self.assertFalse(self._run([])["persist_confirmed_commit"])


class NormalizeArgsTests(unittest.TestCase):
    def _parse(self, *argv):
        args = main.build_parser().parse_args(["--op", "netconf-send-command", *argv])
        main._normalize_args(args)
        return args

    def test_confirm_timeout_unset_or_empty_is_none(self):
        self.assertIsNone(self._parse().confirm_timeout)
        self.assertIsNone(self._parse("--confirm_timeout", "").confirm_timeout)

    def test_confirm_timeout_parses_int(self):
        self.assertEqual(self._parse("--confirm-timeout", "600").confirm_timeout, 600)

    def test_confirm_timeout_must_be_positive(self):
        with self.assertRaises(SystemExit):
            self._parse("--confirm_timeout", "0")

    def test_persist_id_empty_string_is_none(self):
        self.assertIsNone(self._parse("--persist_id", "").persist_id)


class SaveConfigTests(unittest.TestCase):
    """save_config tries cisco-ia first, then falls back to Cisco-IOS-XE-rpc copy."""

    def _run(self, dispatch_side_effect):
        m = MagicMock()
        m.dispatch.side_effect = dispatch_side_effect
        session = MagicMock()
        session.__enter__.return_value = m
        with patch.object(main, "_session", return_value=session):
            return main.save_config({"host": "10.0.0.1"}, MagicMock()), m

    @staticmethod
    def _reply(text):
        r = MagicMock()
        r.xml = ('<rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">'
                 f'<result xmlns="http://cisco.com/yang/cisco-ia">{text}</result></rpc-reply>')
        return r

    def test_uses_cisco_ia_when_available(self):
        result, m = self._run([self._reply("Save running-config successful")])
        self.assertTrue(result["success"])
        self.assertEqual(result["method"], "cisco-ia:save-config")
        self.assertEqual(result["result"], "Save running-config successful")
        self.assertEqual(m.dispatch.call_count, 1)

    def test_falls_back_to_copy_rpc(self):
        result, m = self._run([_make_rpc_error("unknown-element"), self._reply("[OK]")])
        self.assertTrue(result["success"])
        self.assertEqual(result["method"], "Cisco-IOS-XE-rpc:copy")
        self.assertEqual(len(result["failed_attempts"]), 1)

    def test_reports_unsupported_when_both_fail(self):
        result, _ = self._run([_make_rpc_error("unknown-element"), _make_rpc_error("unknown-element")])
        self.assertFalse(result["success"])
        self.assertEqual(result["error_type"], "SaveUnsupported")
        self.assertEqual(len(result["failed_attempts"]), 2)


class FormatForHumansTests(unittest.TestCase):
    def test_is_alive_returns_full_json_including_version(self):
        result = {"success": True, "alive": True, "host": "10.0.0.1", "output": "17.15"}
        self.assertEqual(json.loads(main._format_for_humans(result, "netconf-is-alive")), result)


if __name__ == "__main__":
    unittest.main()
