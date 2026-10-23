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

    def test_candidate_xml_reader_is_not_called_when_the_device_renders(self):
        m = MagicMock()
        m.dispatch.side_effect = [
            self._fake_reply("running config text\n"),
            self._fake_reply("candidate config text\n"),
        ]
        reader = MagicMock(return_value="<candidate/>")
        result = main._preview_render(m, "<running/>", reader)
        self.assertEqual(result["preview_mode"], "device-rendered")
        reader.assert_not_called()

    def test_candidate_xml_reader_is_called_once_by_the_xml_diff_fallback(self):
        m = MagicMock()
        m.dispatch.side_effect = _make_rpc_error()
        reader = MagicMock(return_value="<config><a>2</a></config>")
        result = main._preview_render(m, "<config><a>1</a></config>", reader)
        reader.assert_called_once_with()
        self.assertEqual(result["preview_mode"], "xml-diff")
        self.assertEqual(result["candidate_config"], "<config><a>2</a></config>")
        self.assertTrue(result["has_changes"])

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

    def _run(self, diff=True, render_supported=True, reads=None, lock=None, force_discard=False,
             edit_error=None, version="17.15.4", validate_error=None, candidate_render="hostname a\ndescription new\n",
             caps=None):
        """version: what the mocked version read returns (an Exception instance makes the read fail); the
        default is on the allow-listed train, so the fast flow runs. reads: values for the mocked
        _get_config_xml; the default answers by source (running "<a>1</a>"; candidate "<a>1</a>" before the
        edit and "<a>2</a>" after it). lock: side_effect for _acquire_candidate_lock."""
        m = MagicMock()
        m.server_capabilities = caps if caps is not None else [
            "urn:ietf:params:netconf:capability:candidate:1.0", IOSXE_CAP,
            "urn:ietf:params:netconf:capability:validate:1.1"]
        if edit_error is not None:
            m.edit_config.side_effect = edit_error
        if validate_error is not None:
            m.validate.side_effect = validate_error
        order = MagicMock()
        thread = MagicMock()
        if render_supported:
            m.dispatch.side_effect = [PreviewRenderTests._fake_reply(candidate_render)]
            box = {"result": "hostname a\ndescription old\n", "error": None, "exc": None, "seconds": 2.0}
        else:
            m.dispatch.side_effect = _make_rpc_error()
            box = {"result": None, "error": "get-modelled-config-clis RPC not supported", "exc": None,
                   "seconds": 0.1}
        session = MagicMock()
        session.__enter__.return_value = m
        order.start.return_value = (thread, box)
        order.lock.return_value = 0.0
        if lock is not None:
            order.lock.side_effect = lock
        if reads is not None:
            order.read.side_effect = reads
        else:
            def read(mm, source, *a):
                if source == "running":
                    return "<a>1</a>"
                return "<a>2</a>" if m.edit_config.called else "<a>1</a>"
            order.read.side_effect = read
        conn = {"host": "10.0.0.1", "lock_timeout": 1, "lock_poll_interval": 0.1}
        args = MagicMock(config_xml="<config/>", force_discard=force_discard, diff=diff)
        version_read = MagicMock(side_effect=version if isinstance(version, Exception) else None,
                                 return_value=version)
        with patch.object(main, "_session", return_value=session), \
             patch.object(main, "_start_background_render", order.start), \
             patch.object(main, "_acquire_candidate_lock", order.lock), \
             patch.object(main, "_read_version", version_read), \
             patch.object(main, "_get_config_xml", order.read):
            result = main.preview_config(conn, args)
        return result, order, m

    def test_background_render_starts_before_the_candidate_lock(self):
        result, order, _ = self._run()
        self.assertTrue(result["success"])
        names = [c[0] for c in order.mock_calls if c[0] in ("start", "lock")]
        self.assertEqual(names, ["start", "lock"])
        order.start.assert_called_once_with({"host": "10.0.0.1", "lock_timeout": 1, "lock_poll_interval": 0.1},
                                            "running")

    def test_lock_ok_skips_both_pre_edit_xml_reads(self):
        # CHANGED on purpose (was: background render starts before the two slow XML reads): a granted lock
        # proves the candidate is clean (RFC 6241 section 7.5), so there are no pre-edit reads at all.
        result, order, m = self._run()
        self.assertTrue(result["success"], result)
        names = [c[0] for c in order.mock_calls if c[0] in ("start", "read", "lock")]
        self.assertEqual(names, ["start", "lock"])
        self.assertEqual(order.read.call_count, 0)
        self.assertEqual(result["preview_mode"], "device-rendered")

    def test_lock_ok_running_hash_is_the_cli_hash_of_the_running_render(self):
        result, order, _ = self._run()
        self.assertEqual(result["running_hash"], main._cli_hash("hostname a\ndescription old\n"))
        self.assertTrue(result["running_hash"].startswith("cli-sha256:"))
        self.assertEqual(order.read.call_count, 0)

    def test_device_rendered_mode_never_reads_any_xml(self):
        # CHANGED on purpose (was: reads running + candidate before the edit): now no XML read at all.
        result, order, _ = self._run()
        self.assertEqual(result["preview_mode"], "device-rendered")
        self.assertEqual(order.read.call_args_list, [])
        self.assertNotIn("get_candidate_xml_after_edit", result["timings"]["steps"])
        self.assertNotIn("get_running_xml_after_edit", result["timings"]["steps"])

    def test_xml_diff_fallback_reads_xml_only_after_the_edit_and_hashes_the_xml(self):
        # CHANGED on purpose (was: running, candidate, candidate): the pre-edit reads are gone.
        result, order, m = self._run(render_supported=False)
        self.assertTrue(result["success"])
        self.assertEqual(result["preview_mode"], "xml-diff")
        self.assertEqual([c.args[1] for c in order.read.call_args_list], ["running", "candidate"])
        self.assertIn("get_running_xml_after_edit", result["timings"]["steps"])
        self.assertIn("get_candidate_xml_after_edit", result["timings"]["steps"])
        self.assertEqual(result["running_hash"], main._text_hash("<a>1</a>"))
        self.assertFalse(result["running_hash"].startswith("cli-sha256:"))
        self.assertTrue(result["has_changes"])
        self.assertTrue(result["diff_rows"])
        m.discard_changes.assert_called()
        m.unlock.assert_called_once_with(target="candidate")

    def test_lock_refused_and_dirty_returns_the_dirty_candidate_result(self):
        result, order, m = self._run(lock=_make_rpc_error("operation-failed"), reads=["<a>1</a>", "<a>9</a>"])
        self.assertFalse(result["success"])
        self.assertEqual(result["error_type"], "DirtyCandidate")
        self.assertIn("-<a>1</a>", result["dirty_diff"])
        self.assertIn("+<a>9</a>", result["dirty_diff"])
        self.assertFalse(result["committed"])
        self.assertNotIn("lock_wait_seconds", result)
        self.assertEqual([c.args[1] for c in order.read.call_args_list], ["running", "candidate"])
        m.discard_changes.assert_not_called()
        m.edit_config.assert_not_called()

    def test_lock_refused_dirty_with_force_discard_discards_relocks_and_continues(self):
        result, order, m = self._run(lock=[_make_rpc_error("operation-failed"), 0.5],
                                     reads=["<a>1</a>", "<a>9</a>"], force_discard=True)
        self.assertTrue(result["success"], result)
        self.assertEqual(order.lock.call_count, 2)
        names = [c[0] for c in m.mock_calls if c[0] in ("discard_changes", "edit_config", "unlock")]
        self.assertEqual(names[:2], ["discard_changes", "edit_config"])
        self.assertEqual(result["lock_wait_seconds"], 0.5)
        self.assertEqual(result["preview_mode"], "device-rendered")
        self.assertTrue(result["running_hash"].startswith("cli-sha256:"))
        m.unlock.assert_called_once_with(target="candidate")
        self.assertFalse(result["committed"])

    def test_force_discard_but_relock_fails_returns_candidate_locked_and_edits_nothing(self):
        result, _, m = self._run(lock=[_make_rpc_error("operation-failed"), _make_rpc_error("lock-denied")],
                                 reads=["<a>1</a>", "<a>9</a>"], force_discard=True)
        self.assertEqual(result["error_type"], "CandidateLocked")
        m.edit_config.assert_not_called()

    def test_lock_refused_and_clean_returns_candidate_locked(self):
        result, order, m = self._run(lock=_make_rpc_error("operation-failed"), reads=["<a>1</a>", "<a>1</a>"])
        self.assertFalse(result["success"])
        self.assertEqual(result["error_type"], "CandidateLocked")
        self.assertEqual(result["rpc_tag"], "operation-failed")
        self.assertIn("lock_wait_seconds", result)
        self.assertFalse(result["committed"])
        m.edit_config.assert_not_called()
        m.discard_changes.assert_not_called()

    def test_lock_denied_returns_candidate_locked_without_any_read(self):
        result, order, m = self._run(lock=_make_rpc_error("lock-denied"))
        self.assertEqual(result["error_type"], "CandidateLocked")
        self.assertEqual(result["rpc_tag"], "lock-denied")
        self.assertEqual(order.read.call_count, 0)
        self.assertFalse(result["committed"])
        m.edit_config.assert_not_called()
        m.discard_changes.assert_not_called()

    def test_edit_failure_still_discards_and_unlocks(self):
        result, _, m = self._run(edit_error=_make_rpc_error("operation-failed"))
        self.assertFalse(result["success"])
        self.assertEqual(result["error_type"], "RPCError")
        m.discard_changes.assert_called()
        m.unlock.assert_called_once_with(target="candidate")
        m.commit.assert_not_called()

    def test_preview_and_push_hash_the_same_render_text_the_same_way(self):
        text = "hostname a\ndescription old\n"
        result, _, _ = self._run()
        self.assertEqual(result["running_hash"], main._cli_hash(text))
        # blank-line / trailing-space noise does not change it, a real change does
        self.assertEqual(main._cli_hash(text), main._cli_hash("hostname a  \n\ndescription old\n\n"))
        self.assertNotEqual(main._cli_hash(text), main._cli_hash("hostname b\ndescription old\n"))

    def test_result_carries_side_by_side_rows_stats_and_timings(self):
        result, _, m = self._run()
        self.assertEqual(result["preview_mode"], "device-rendered")
        self.assertTrue(result["has_changes"])
        changes = [r for r in result["diff_rows"] if r["kind"] == "change"]
        self.assertEqual([(r["old"], r["new"]) for r in changes], [("description old", "description new")])
        self.assertEqual(result["diff_stats"]["added"], 1)
        self.assertTrue(result["timings"]["parallel"])
        steps = result["timings"]["steps"]
        # CHANGED on purpose: get_running_xml / get_candidate_xml are gone from the lock-first (IOS XE) flow
        for name in ("connect", "lock", "edit_config", "validate", "render", "discard_unlock"):
            self.assertIn(name, steps)
        self.assertNotIn("get_running_xml", steps)
        self.assertNotIn("get_candidate_xml", steps)
        self.assertGreaterEqual(result["timings"]["driver_total_s"], 0)
        self.assertFalse(result["committed"])
        m.discard_changes.assert_called()
        m.unlock.assert_called_once_with(target="candidate")

    def test_diff_false_drops_every_form_of_the_diff(self):
        result, _, _ = self._run(diff=False)
        self.assertIsNone(result["diff"])
        self.assertIsNone(result["diff_rows"])
        self.assertIsNone(result["diff_stats"])


class FastPreviewGateTests(unittest.TestCase):
    """The lock-first preview runs only on IOS XE on an allow-listed train; everything else is today's flow."""

    @staticmethod
    def _names(order):
        return [c[0] for c in order.mock_calls if c[0] in ("start", "read", "lock")]

    def test_allow_list_is_exactly_the_proven_train(self):
        self.assertEqual(main.FAST_PREVIEW_IOSXE_TRAINS, ("17.15",))

    def test_gate_matches_major_minor_only(self):
        m = MagicMock()
        for version, expected in (("17.15.4", True), ("17.15.5a", True), ("17.15", True), ("17.12.4", False),
                                  ("17.150.1", False), ("117.15.1", False), ("", False), ("garbage", False),
                                  (None, False)):
            with patch.object(main, "_read_version", return_value=version):
                self.assertEqual(main._fast_preview_allowed(m, "iosxe"), expected, version)

    def test_gate_is_false_for_nxos_without_reading_the_version(self):
        for platform in ("nxos", "other"):
            with patch.object(main, "_read_version") as read:
                self.assertFalse(main._fast_preview_allowed(MagicMock(), platform))
            read.assert_not_called()

    def test_gate_for_unknown_platform_uses_the_iosxe_version_read(self):
        m = MagicMock()
        for version, expected in (("17.15.5", True), ("17.12.4", False), ("", False)):
            with patch.object(main, "_read_version", return_value=version) as read:
                self.assertEqual(main._fast_preview_allowed(m, "unknown"), expected, version)
            read.assert_called_once_with(m, "iosxe")
        with patch.object(main, "_read_version", side_effect=RuntimeError("unknown-namespace")):
            self.assertFalse(main._fast_preview_allowed(m, "unknown"))

    def test_gate_is_false_when_the_version_read_fails(self):
        with patch.object(main, "_read_version", side_effect=RuntimeError("boom")):
            self.assertFalse(main._fast_preview_allowed(MagicMock(), "iosxe"))

    def test_17_15_takes_the_fast_path(self):
        result, order, _ = PreviewConfigFlowTests()._run(version="17.15.4")
        self.assertEqual(self._names(order), ["start", "lock"])
        self.assertEqual(result["dirty_check"], "lock-first")
        self.assertEqual(result["fingerprint"], "cli")

    def test_another_train_runs_todays_flow_call_for_call(self):
        result, order, m = PreviewConfigFlowTests()._run(version="17.12.4")
        self.assertTrue(result["success"], result)
        self.assertEqual(self._names(order), ["start", "read", "read", "lock"])
        self.assertEqual([c.args[1] for c in order.read.call_args_list], ["running", "candidate"])
        self.assertEqual(result["dirty_check"], "full-read")
        self.assertEqual(result["fingerprint"], "xml")
        self.assertEqual(result["running_hash"], main._text_hash("<a>1</a>"))
        self.assertEqual(result["preview_mode"], "device-rendered")
        for name in ("get_running_xml", "get_candidate_xml"):
            self.assertIn(name, result["timings"]["steps"])

    def test_another_train_with_xml_diff_reads_three_times_as_before(self):
        result, order, _ = PreviewConfigFlowTests()._run(version="17.12.4", render_supported=False)
        self.assertEqual([c.args[1] for c in order.read.call_args_list], ["running", "candidate", "candidate"])
        self.assertEqual(result["running_hash"], main._text_hash("<a>1</a>"))

    def test_another_train_dirty_candidate_is_refused_before_the_lock(self):
        result, order, _ = PreviewConfigFlowTests()._run(version="17.12.4", reads=["<a>1</a>", "<a>9</a>"])
        self.assertEqual(result["error_type"], "DirtyCandidate")
        self.assertEqual(self._names(order), ["start", "read", "read"])
        order.lock.assert_not_called()

    def test_version_read_error_runs_todays_flow(self):
        result, order, _ = PreviewConfigFlowTests()._run(version=RuntimeError("read failed"))
        self.assertTrue(result["success"], result)
        self.assertEqual(self._names(order), ["start", "read", "read", "lock"])
        self.assertEqual(result["dirty_check"], "full-read")
        self.assertEqual(result["fingerprint"], "xml")

    def test_unparsable_version_runs_todays_flow(self):
        result, order, _ = PreviewConfigFlowTests()._run(version="")
        self.assertEqual(self._names(order), ["start", "read", "read", "lock"])

    # The lab C9500 stack (IOS XE 17.15) lists no YANG module in its hello, only yang-library: platform
    # "unknown" (seen live 10-23 via netconf-is-alive: platform unknown, output 17.15).
    HELLO_WITHOUT_MODULES = ["urn:ietf:params:netconf:base:1.1", "urn:ietf:params:netconf:capability:candidate:1.0",
                             "urn:ietf:params:netconf:capability:validate:1.1",
                             "urn:ietf:params:netconf:capability:confirmed-commit:1.1",
                             "urn:ietf:params:netconf:capability:yang-library:1.1?revision=2019-01-04&content-id=x"]

    def test_hello_without_modules_on_17_15_takes_the_fast_path(self):
        m = MagicMock()
        m.server_capabilities = self.HELLO_WITHOUT_MODULES
        self.assertEqual(main._detect_platform(m), "unknown")
        result, order, _ = PreviewConfigFlowTests()._run(version="17.15.5", caps=self.HELLO_WITHOUT_MODULES)
        self.assertTrue(result["success"], result)
        self.assertEqual(self._names(order), ["start", "lock"])
        self.assertEqual(result["dirty_check"], "lock-first")
        self.assertEqual(result["fingerprint"], "cli")
        self.assertIn("version_read", result["timings"]["steps"])

    def test_hello_without_modules_and_a_failed_version_read_runs_todays_flow(self):
        result, order, _ = PreviewConfigFlowTests()._run(version=RuntimeError("unknown-namespace"),
                                                         caps=self.HELLO_WITHOUT_MODULES)
        self.assertTrue(result["success"], result)
        self.assertEqual(self._names(order), ["start", "read", "read", "lock"])
        self.assertEqual(result["dirty_check"], "full-read")
        self.assertEqual(result["fingerprint"], "xml")

    def test_hello_without_modules_on_another_train_runs_todays_flow(self):
        result, order, _ = PreviewConfigFlowTests()._run(version="17.12.4", caps=self.HELLO_WITHOUT_MODULES)
        self.assertEqual(self._names(order), ["start", "read", "read", "lock"])
        self.assertEqual(result["dirty_check"], "full-read")

    def test_hello_without_modules_fast_and_todays_flow_agree_for_the_operator(self):
        fast, _, _ = PreviewConfigFlowTests()._run(version="17.15.5", caps=self.HELLO_WITHOUT_MODULES)
        slow, _, _ = PreviewConfigFlowTests()._run(version="17.12.4", caps=self.HELLO_WITHOUT_MODULES)
        for key in FastVersusTodaysFlowEquivalenceTests.SAME:
            self.assertEqual(fast.get(key), slow.get(key), key)

    def test_nxos_never_reads_the_version_and_runs_todays_flow(self):
        order = NxosPreviewOrderTests()
        with patch.object(main, "_read_version") as read:
            result, _ = order._run(["<a>1</a>", "<a>1</a>", "<a>2</a>"])
        read.assert_not_called()
        self.assertEqual(result["dirty_check"], "full-read")
        self.assertEqual(result["fingerprint"], "xml")


class FastVersusTodaysFlowEquivalenceTests(unittest.TestCase):
    """For the same mocked device and config_xml the fast flow and today's flow must agree on everything the
    operator sees; only running_hash, timings and the two path labels may differ."""

    SAME = ("success", "valid", "validate", "has_changes", "diff", "diff_rows", "diff_stats", "preview_mode",
            "candidate_config", "running_config", "warning", "committed")

    def _both(self, **kw):
        fast, _, mf = PreviewConfigFlowTests()._run(version="17.15.4", **kw)
        slow, _, ms = PreviewConfigFlowTests()._run(version="17.12.4", **kw)
        self.assertEqual(fast["dirty_check"], "lock-first")
        self.assertEqual(slow["dirty_check"], "full-read")
        for result, mm in ((fast, mf), (slow, ms)):
            mm.commit.assert_not_called()
            mm.unlock.assert_called_once_with(target="candidate")
            mm.discard_changes.assert_called()
        return fast, slow

    def _assert_equivalent(self, fast, slow, hash_differs=True):
        for key in self.SAME:
            self.assertEqual(fast[key], slow[key], key)
        self.assertEqual(set(fast) - {"timings"}, set(slow) - {"timings"})
        if hash_differs:
            self.assertNotEqual(fast["running_hash"], slow["running_hash"])

    def test_changes_present(self):
        fast, slow = self._both()
        self._assert_equivalent(fast, slow)
        self.assertTrue(fast["has_changes"])
        self.assertEqual(fast["validate"], "valid")

    def test_no_changes(self):
        fast, slow = self._both(candidate_render="hostname a\ndescription old\n")
        self._assert_equivalent(fast, slow)
        self.assertFalse(fast["has_changes"])
        self.assertEqual(fast["diff"], "")

    def test_validation_failure(self):
        fast, slow = self._both(validate_error=_make_rpc_error("invalid-value"))
        self._assert_equivalent(fast, slow)
        self.assertFalse(fast["valid"])

    def test_xml_diff_mode(self):
        fast, slow = self._both(render_supported=False)
        self._assert_equivalent(fast, slow, hash_differs=False)
        self.assertEqual(fast["preview_mode"], "xml-diff")
        # without a CLI render both flows fingerprint the running XML the same way
        self.assertEqual(fast["running_hash"], slow["running_hash"])


class GetConfigXmlPlatformFilterTests(unittest.TestCase):
    """An unfiltered read gets the NX-OS root filter on NX-OS only."""

    def _call(self, caps, filter_xml=None):
        m = MagicMock()
        m.server_capabilities = caps
        m.get_config.return_value.data_xml = "<data/>"
        main._get_config_xml(m, "running", filter_xml)
        return m.get_config.call_args.kwargs["filter"]

    def test_nxos_without_filter_uses_system_subtree(self):
        self.assertEqual(self._call([NXOS_CAP]), ("subtree", main._NXOS_ROOT_FILTER))
        self.assertEqual(main._NXOS_ROOT_FILTER,
                         '<System xmlns="http://cisco.com/ns/yang/cisco-nx-os-device"/>')

    def test_iosxe_without_filter_stays_unfiltered(self):
        self.assertIsNone(self._call([IOSXE_CAP]))

    def test_unknown_platform_without_filter_stays_unfiltered(self):
        self.assertIsNone(self._call(["urn:ietf:params:netconf:base:1.0"]))

    def test_explicit_filter_wins_on_nxos(self):
        self.assertEqual(self._call([NXOS_CAP], "<x/>"), ("subtree", "<x/>"))


class NxosPreviewFlowTests(unittest.TestCase):
    def test_nxos_preview_reads_with_filter_edits_and_falls_back_to_xml_diff(self):
        m = MagicMock()
        m.server_capabilities = ["urn:ietf:params:netconf:capability:candidate:1.0", NXOS_CAP]
        m.get_config.side_effect = [MagicMock(data_xml="<data><a>1</a></data>"),
                                    MagicMock(data_xml="<data><a>1</a></data>"),
                                    MagicMock(data_xml="<data><a>2</a></data>")]
        # a non-unknown-element error: if the render were attempted the preview would fail
        m.dispatch.side_effect = _make_rpc_error("operation-not-supported")
        session = MagicMock()
        session.__enter__.return_value = m
        conn = {"host": "10.0.0.1", "lock_timeout": 1, "lock_poll_interval": 0.1}
        args = MagicMock(config_xml="<config/>", force_discard=False, diff=True)
        with patch.object(main, "_session", return_value=session), \
             patch.object(main, "_start_background_render") as background, \
             patch.object(main, "_get_modelled_config_clis") as render, \
             patch.object(main, "_acquire_candidate_lock", return_value=0.0):
            result = main.preview_config(conn, args)
        background.assert_not_called()
        render.assert_not_called()
        m.dispatch.assert_not_called()
        self.assertTrue(result["success"], result)
        self.assertEqual(result["preview_mode"], "xml-diff")
        m.edit_config.assert_called_once()
        for c in m.get_config.call_args_list:
            self.assertEqual(c.kwargs["filter"], ("subtree", main._NXOS_ROOT_FILTER))


class NxosPreviewOrderTests(unittest.TestCase):
    """NX-OS keeps the old order: dirty check (XML reads) first, then lock; plain XML hash."""

    def _run(self, reads, lock=0.0, force_discard=False):
        order = MagicMock()
        m = order.m
        m.server_capabilities = ["urn:ietf:params:netconf:capability:candidate:1.0", NXOS_CAP]
        m.dispatch.side_effect = _make_rpc_error("operation-not-supported")
        order.read.side_effect = reads
        order.lock.side_effect = lock if isinstance(lock, (list, Exception)) else None
        if not isinstance(lock, (list, Exception)):
            order.lock.return_value = lock
        session = MagicMock()
        session.__enter__.return_value = m
        conn = {"host": "10.0.0.1", "lock_timeout": 1, "lock_poll_interval": 0.1}
        args = MagicMock(config_xml="<config/>", force_discard=force_discard, diff=True)
        with patch.object(main, "_session", return_value=session), \
             patch.object(main, "_start_background_render") as background, \
             patch.object(main, "_acquire_candidate_lock", order.lock), \
             patch.object(main, "_get_config_xml", order.read):
            result = main.preview_config(conn, args)
        background.assert_not_called()
        return result, order

    @staticmethod
    def _names(order):
        out = []
        for c in order.mock_calls:
            if c[0] == "read":
                out.append("read:" + c.args[1])
            elif c[0] in ("lock", "m.discard_changes", "m.edit_config", "m.unlock"):
                out.append(c[0].replace("m.", ""))
        return out

    def test_call_sequence_is_reads_then_lock_then_edit_then_one_more_read(self):
        result, order = self._run(["<a>1</a>", "<a>1</a>", "<a>2</a>"])
        self.assertTrue(result["success"], result)
        self.assertEqual(self._names(order), ["read:running", "read:candidate", "lock", "edit_config",
                                              "read:candidate", "discard_changes", "unlock"])
        self.assertEqual(result["running_hash"], main._text_hash("<a>1</a>"))
        self.assertIn("get_running_xml", result["timings"]["steps"])
        self.assertIn("get_candidate_xml", result["timings"]["steps"])

    def test_dirty_candidate_is_refused_before_any_lock(self):
        result, order = self._run(["<a>1</a>", "<a>9</a>"])
        self.assertEqual(result["error_type"], "DirtyCandidate")
        self.assertNotIn("lock_wait_seconds", result)
        self.assertEqual(self._names(order), ["read:running", "read:candidate"])

    def test_force_discard_discards_before_the_lock(self):
        result, order = self._run(["<a>1</a>", "<a>9</a>", "<a>2</a>"], force_discard=True)
        self.assertTrue(result["success"], result)
        self.assertEqual(self._names(order)[:5], ["read:running", "read:candidate", "discard_changes", "lock",
                                                  "edit_config"])

    def test_lock_failure_is_candidate_locked_after_the_reads(self):
        result, order = self._run(["<a>1</a>", "<a>1</a>"], lock=_make_rpc_error("lock-denied"))
        self.assertEqual(result["error_type"], "CandidateLocked")
        self.assertEqual(result["rpc_tag"], "lock-denied")
        self.assertFalse(result["committed"])
        self.assertEqual(self._names(order), ["read:running", "read:candidate", "lock"])


class PushDriftGuardTests(unittest.TestCase):
    """send_command's expect_running_hash guard and lock labelling, mocked manager."""

    RENDER = "hostname a\ndescription old\n"

    def _run(self, expect, render=None, render_exc=None, xml="<a>1</a>", lock=0.0, caps=None):
        order = MagicMock()
        m = order.m
        m.server_capabilities = ["urn:ietf:params:netconf:capability:candidate:1.0", IOSXE_CAP] + (caps or [])
        order.render.side_effect = render_exc
        if render_exc is None:
            order.render.return_value = render if render is not None else (self.RENDER, None)
        order.read.return_value = xml
        order.lock.side_effect = lock if isinstance(lock, Exception) else None
        if not isinstance(lock, Exception):
            order.lock.return_value = lock
        session = MagicMock()
        session.__enter__.return_value = m
        conn = {"host": "10.0.0.1", "lock_timeout": 1, "lock_poll_interval": 0.1}
        args = MagicMock(config_xml="<config/>", expect_running_hash=expect, confirm_timeout=None)
        with patch.object(main, "_session", return_value=session), \
             patch.object(main, "_get_modelled_config_clis", order.render), \
             patch.object(main, "_get_config_xml", order.read), \
             patch.object(main, "_acquire_candidate_lock", order.lock):
            return main.send_command(conn, args), order, m

    def test_drift_check_label(self):
        self.assertEqual(self._run(main._cli_hash(self.RENDER))[0]["drift_check"], "cli")
        self.assertEqual(self._run(main._text_hash("<a>1</a>"))[0]["drift_check"], "xml")
        self.assertEqual(self._run(None)[0]["drift_check"], "none")
        self.assertEqual(self._run("0123456789abcdef")[0]["drift_check"], "xml")
        self.assertEqual(self._run(main._cli_hash("x"))[0]["drift_check"], "cli")
        self.assertEqual(self._run(main._cli_hash(self.RENDER), render_exc=RuntimeError("x"))[0]["drift_check"], "cli")
        self.assertEqual(self._run(None, lock=_make_rpc_error("lock-denied"))[0]["drift_check"], "none")

    def test_matching_cli_hash_proceeds_and_commits(self):
        result, order, m = self._run(main._cli_hash(self.RENDER))
        self.assertTrue(result["success"], result)
        order.render.assert_called_once_with(m, "running")
        order.read.assert_not_called()
        m.commit.assert_called_once()

    def test_cli_hash_check_happens_before_the_lock(self):
        _, order, _ = self._run(main._cli_hash(self.RENDER))
        names = [c[0] for c in order.mock_calls if c[0] in ("render", "lock")]
        self.assertEqual(names, ["render", "lock"])

    def test_cli_hash_mismatch_is_config_drift_with_no_lock_or_edit(self):
        expected = main._cli_hash("hostname other\n")
        result, order, m = self._run(expected)
        self.assertFalse(result["success"])
        self.assertEqual(result["error_type"], "ConfigDrift")
        self.assertEqual(result["expected_running_hash"], expected)
        self.assertEqual(result["actual_running_hash"], main._cli_hash(self.RENDER))
        order.lock.assert_not_called()
        m.edit_config.assert_not_called()
        m.commit.assert_not_called()

    def test_render_exception_fails_closed(self):
        result, order, m = self._run(main._cli_hash(self.RENDER), render_exc=_make_rpc_error("operation-failed"))
        self.assertFalse(result["success"])
        self.assertEqual(result["error_type"], "DriftCheckUnavailable")
        self.assertFalse(result["committed"])
        order.lock.assert_not_called()
        m.edit_config.assert_not_called()
        m.commit.assert_not_called()

    def test_unsupported_or_empty_render_fails_closed(self):
        for render in ((None, "get-modelled-config-clis RPC not supported on this device"), (None, None)):
            result, order, m = self._run(main._cli_hash(self.RENDER), render=render)
            self.assertEqual(result["error_type"], "DriftCheckUnavailable")
            order.lock.assert_not_called()
            m.commit.assert_not_called()

    def test_render_with_a_warning_but_text_still_checks_the_hash(self):
        result, _, m = self._run(main._cli_hash(self.RENDER), render=(self.RENDER, "partial render"))
        self.assertTrue(result["success"], result)
        m.commit.assert_called_once()

    def test_unprefixed_hash_uses_the_xml_path_as_before(self):
        result, order, m = self._run(main._text_hash("<a>1</a>"))
        self.assertTrue(result["success"], result)
        order.render.assert_not_called()
        order.read.assert_called_once_with(m, "running")
        m.commit.assert_called_once()

    def test_unprefixed_hash_mismatch_is_config_drift(self):
        result, order, m = self._run("0123456789abcdef")
        self.assertEqual(result["error_type"], "ConfigDrift")
        order.render.assert_not_called()
        order.lock.assert_not_called()
        m.commit.assert_not_called()

    def test_no_expect_hash_reads_nothing_before_the_lock(self):
        result, order, m = self._run(None)
        self.assertTrue(result["success"], result)
        order.render.assert_not_called()
        order.read.assert_not_called()

    def test_nxos_push_with_unprefixed_hash_is_unchanged(self):
        result, order, m = self._run(main._text_hash("<a>1</a>"), caps=[NXOS_CAP])
        self.assertTrue(result["success"], result)
        order.render.assert_not_called()
        order.read.assert_called_once_with(m, "running")

    def test_lock_failure_is_candidate_locked_and_nothing_is_committed(self):
        for tag in ("lock-denied", "operation-failed"):
            result, _, m = self._run(None, lock=_make_rpc_error(tag))
            self.assertFalse(result["success"])
            self.assertEqual(result["error_type"], "CandidateLocked")
            self.assertEqual(result["rpc_tag"], tag)
            self.assertFalse(result["committed"])
            m.discard_changes.assert_not_called()
            m.edit_config.assert_not_called()
            m.commit.assert_not_called()


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


class UnresolvedSecretPlaceholderTests(unittest.TestCase):
    """The gateway swaps $GATEWAYSECRET_(name) for the real value before the driver runs. A placeholder that
    still reaches the driver was not swapped: it must never be sent on, where it would become the literal
    password or key on the device."""

    XML = "<config><key>$GATEWAYSECRET_(example-name)</key><other>keep-out-of-errors</other></config>"
    CONN = {"host": "10.0.0.1", "lock_timeout": 1, "lock_poll_interval": 0.1}

    def test_preview_refuses_before_opening_a_session(self):
        args = MagicMock(config_xml=self.XML, force_discard=False, diff=True)
        with patch.object(main, "_session") as session:
            result = main.preview_config(self.CONN, args)
        session.assert_not_called()
        self.assertFalse(result["success"])
        self.assertEqual(result["error_type"], "UnresolvedSecretPlaceholder")
        self.assertFalse(result["committed"])

    def test_push_refuses_before_opening_a_session(self):
        args = MagicMock(config_xml=self.XML, expect_running_hash=None, confirm_timeout=600)
        with patch.object(main, "_session") as session:
            result = main.send_command(self.CONN, args)
        session.assert_not_called()
        self.assertFalse(result["success"])
        self.assertEqual(result["error_type"], "UnresolvedSecretPlaceholder")
        self.assertFalse(result["committed"])

    def test_the_error_does_not_echo_the_config(self):
        args = MagicMock(config_xml=self.XML, force_discard=False, diff=True)
        with patch.object(main, "_session"):
            result = main.preview_config(self.CONN, args)
        text = json.dumps(result)
        self.assertNotIn("example-name", text)
        self.assertNotIn("keep-out-of-errors", text)

    def test_a_config_without_a_placeholder_is_not_refused(self):
        self.assertIsNone(main._unresolved_secret_placeholder("<config><a>1</a></config>", self.CONN, "dev"))


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


IOSXE_CAP = "http://cisco.com/ns/yang/Cisco-IOS-XE-native?module=Cisco-IOS-XE-native&revision=2024-01-01"
NXOS_CAP = "http://cisco.com/ns/yang/cisco-nx-os-device?module=cisco-nx-os-device&revision=2024-01-01"


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


class IsAlivePlatformTests(unittest.TestCase):
    NXOS_REPLY = ('<data><System xmlns="http://cisco.com/ns/yang/cisco-nx-os-device"><showversion-items>'
                  '<nxosVersion>10.5(5)</nxosVersion></showversion-items></System></data>')
    IOSXE_REPLY = ('<data><native xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-native">'
                   '<version>17.15</version></native></data>')

    def _run(self, capabilities, reply=None, error=None):
        m = MagicMock()
        m.server_capabilities = capabilities
        if error is not None:
            m.get.side_effect = error
        else:
            m.get.return_value.data_xml = reply
        session = MagicMock()
        session.__enter__.return_value = m
        with patch.object(main, "_session", return_value=session):
            return main.is_alive({"host": "10.0.0.1"}, MagicMock()), m

    def test_nxos_reads_version_from_showversion(self):
        result, m = self._run([NXOS_CAP], self.NXOS_REPLY)
        self.assertTrue(result["success"])
        self.assertEqual(result["platform"], "nxos")
        self.assertEqual(result["output"], "10.5(5)")
        self.assertNotIn("version_error", result)
        self.assertIn("nxosVersion", m.get.call_args.kwargs["filter"][1])

    def test_iosxe_platform_and_version(self):
        result, _ = self._run([IOSXE_CAP], self.IOSXE_REPLY)
        self.assertEqual(result["platform"], "iosxe")
        self.assertEqual(result["output"], "17.15")

    def test_unknown_platform_uses_iosxe_read(self):
        result, m = self._run(["urn:ietf:params:netconf:base:1.1"], self.IOSXE_REPLY)
        self.assertTrue(result["alive"])
        self.assertEqual(result["platform"], "unknown")
        self.assertEqual(result["output"], "17.15")
        self.assertIn("Cisco-IOS-XE-native", m.get.call_args.kwargs["filter"][1])

    def test_unknown_platform_read_failure_only_adds_version_error(self):
        result, _ = self._run([], error=_make_rpc_error("unknown-namespace"))
        self.assertTrue(result["alive"])
        self.assertEqual(result["platform"], "unknown")
        self.assertIn("version_error", result)

    def test_version_rpc_error_still_alive_on_both_platforms(self):
        for cap, platform in ((IOSXE_CAP, "iosxe"), (NXOS_CAP, "nxos")):
            result, _ = self._run([cap], error=_make_rpc_error("unknown-namespace"))
            self.assertTrue(result["success"])
            self.assertTrue(result["alive"])
            self.assertEqual(result["platform"], platform)
            self.assertEqual(result["output"], "")
            self.assertIn("version_error", result)

    def test_version_parse_error_still_alive(self):
        result, _ = self._run([NXOS_CAP], "not xml")
        self.assertTrue(result["alive"])
        self.assertIn("version_error", result)

    def test_capabilities_and_base_capabilities(self):
        base = "urn:ietf:params:netconf:base:1.1"
        caps = [NXOS_CAP, "urn:ietf:params:netconf:capability:validate:1.1",
                "urn:ietf:params:netconf:capability:candidate:1.0",
                "urn:ietf:params:netconf:capability:confirmed-commit:1.0",
                "urn:ietf:params:netconf:capability:startup:1.0", base]
        result, _ = self._run(caps, self.NXOS_REPLY)
        self.assertEqual(result["capabilities"], {
            "candidate": True, "validate": True,
            "confirmed_commit_1_0": True, "confirmed_commit_1_1": False,
            "writable_running": False, "rollback_on_error": False, "startup": True})
        self.assertFalse(result["persist_confirmed_commit"])
        self.assertEqual(result["base_capabilities"], sorted(c for c in caps if c.startswith("urn:")))
        self.assertNotIn(NXOS_CAP, result["base_capabilities"])

    def test_capabilities_confirmed_1_1_matches_persist(self):
        result, _ = self._run(["urn:ietf:params:netconf:capability:confirmed-commit:1.1"])
        self.assertTrue(result["capabilities"]["confirmed_commit_1_1"])
        self.assertTrue(result["persist_confirmed_commit"])
        self.assertFalse(result["capabilities"]["confirmed_commit_1_0"])


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

    def _run(self, dispatch_side_effect, capabilities=None):
        m = MagicMock()
        if capabilities is not None:
            m.server_capabilities = capabilities
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


    def test_iosxe_still_uses_cisco_ia_first(self):
        result, m = self._run([self._reply("Save running-config successful")], [IOSXE_CAP])
        self.assertEqual(result["method"], "cisco-ia:save-config")
        self.assertIn("cisco-ia", m.dispatch.call_args.args[0].tag)

    def test_nxos_uses_the_device_model_copy_rpc_only(self):
        ok = MagicMock()
        ok.xml = '<rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><ok/></rpc-reply>'
        result, m = self._run([ok], [NXOS_CAP])
        self.assertTrue(result["success"])
        self.assertEqual(result["method"], "cisco-nx-os-device:copy_running_config_src")
        self.assertIsNone(result["result"])
        self.assertEqual(m.dispatch.call_count, 1)
        sent = m.dispatch.call_args.args[0]
        self.assertEqual(sent.tag, "{http://cisco.com/ns/yang/cisco-nx-os-device}copy_running_config_src")
        self.assertEqual(sent[0].tag, "{http://cisco.com/ns/yang/cisco-nx-os-device}startup-config")

    def test_nxos_refusal_is_reported_without_trying_ios_xe_rpcs(self):
        result, m = self._run([_make_rpc_error("operation-not-supported")], [NXOS_CAP])
        self.assertFalse(result["success"])
        self.assertEqual(result["error_type"], "SaveUnsupported")
        self.assertEqual(m.dispatch.call_count, 1)


class SaveConfigBackupTests(unittest.TestCase):
    """backup_filesystem: copy running to <fs>:backup-<UTC stamp>, startup untouched."""

    def _run(self, backup_filesystem, dispatch_side_effect=None, capabilities=None):
        m = MagicMock()
        m.server_capabilities = capabilities if capabilities is not None else [IOSXE_CAP]
        reply = MagicMock()
        reply.xml = ('<rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">'
                     '<result xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-rpc">[OK]</result></rpc-reply>')
        m.dispatch.side_effect = dispatch_side_effect if dispatch_side_effect is not None else [reply]
        session = MagicMock()
        session.__enter__.return_value = m
        args = MagicMock()
        args.backup_filesystem = backup_filesystem
        with patch.object(main, "_session", return_value=session) as sess:
            return main.save_config({"host": "192.0.2.1"}, args), m, sess

    def test_flash_backup_destination_format_and_rpc(self):
        result, m, _ = self._run("flash")
        self.assertTrue(result["success"])
        self.assertRegex(result["destination"], r"^flash:backup-\d{8}-\d{6}$")
        self.assertEqual(m.dispatch.call_count, 1)
        sent = m.dispatch.call_args.args[0]
        self.assertEqual(sent.tag, "{http://cisco.com/ns/yang/Cisco-IOS-XE-rpc}copy")
        self.assertEqual(sent[0].text, "running-config")
        self.assertEqual(sent[1].text, result["destination"])

    def test_bootflash_backup_destination(self):
        result, _, _ = self._run("bootflash")
        self.assertRegex(result["destination"], r"^bootflash:backup-\d{8}-\d{6}$")

    def test_timestamp_is_utc(self):
        with patch.object(main, "datetime") as dt:
            dt.now.return_value = datetime(2026, 10, 23, 9, 5, 7, tzinfo=timezone.utc)
            result, _, _ = self._run("flash")
        self.assertEqual(result["destination"], "flash:backup-20261023-090507")
        dt.now.assert_called_with(timezone.utc)

    def test_other_value_refused_before_a_session_opens(self):
        for bad in ("usbflash0", "FLASH", "flash:", "nvram"):
            result, m, sess = self._run(bad)
            self.assertFalse(result["success"])
            self.assertEqual(result["error_type"], "InvalidBackupFilesystem")
            sess.assert_not_called()

    def test_empty_or_unset_is_the_normal_save(self):
        for unset in ("", None):
            ok = MagicMock()
            ok.xml = ('<rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">'
                      '<result xmlns="http://cisco.com/yang/cisco-ia">saved</result></rpc-reply>')
            result, m, _ = self._run(unset, [ok])
            self.assertEqual(result["method"], "cisco-ia:save-config")
            self.assertNotIn("destination", result)
            self.assertIn("cisco-ia", m.dispatch.call_args.args[0].tag)

    def _backup_with_result(self, text):
        r = MagicMock()
        r.xml = ('<rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">'
                 f'<result xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-rpc">{text}</result></rpc-reply>')
        return self._run("flash", [r])[0]

    def test_backup_result_text_with_error_or_fail_is_a_failure(self):
        for text in ("%Error opening flash:backup (No space left on device)", "Copy FAILED", "copy failure"):
            result = self._backup_with_result(text)
            self.assertFalse(result["success"])
            self.assertEqual(result["error_type"], "BackupFailed")
            self.assertEqual(result["error"], text)
            self.assertRegex(result["destination"], r"^flash:backup-")

    def test_backup_result_ok_text_is_a_success(self):
        for text in ("[OK]", "Copy in progress...", ""):
            self.assertTrue(self._backup_with_result(text)["success"])

    def test_nxos_backup_not_supported(self):
        result, m, _ = self._run("flash", capabilities=[NXOS_CAP])
        self.assertFalse(result["success"])
        self.assertEqual(result["error_type"], "NotSupported")
        m.dispatch.assert_not_called()

    def test_copy_failure_is_reported_without_fallback(self):
        result, m, _ = self._run("flash", [_make_rpc_error("operation-failed")])
        self.assertFalse(result["success"])
        self.assertEqual(result["error_type"], "RPCError")
        self.assertEqual(m.dispatch.call_count, 1)

    def test_parser_accepts_backup_filesystem(self):
        args = main.build_parser().parse_args(["--op", "netconf-save-config", "--backup_filesystem", "flash"])
        main._normalize_args(args)
        self.assertEqual(args.backup_filesystem, "flash")
        args = main.build_parser().parse_args(["--op", "netconf-save-config", "--backup_filesystem", ""])
        main._normalize_args(args)
        self.assertIsNone(args.backup_filesystem)


# Synthetic fixtures only: documentation addresses, invented names, a planted fake key.
FAKE_KEY = "FAKE-KEY-0123456789-DO-NOT-LEAK"
_NATIVE = "http://cisco.com/ns/yang/Cisco-IOS-XE-native"
_SW = "http://cisco.com/ns/yang/Cisco-IOS-XE-switch"


def _native(interfaces="", extra=""):
    return ('<data xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">'
            f'<native xmlns="{_NATIVE}"><interface>{interfaces}</interface>{extra}</native></data>')


_ETH = "http://cisco.com/ns/yang/Cisco-IOS-XE-ethernet"
_AAA = "http://cisco.com/ns/yang/Cisco-IOS-XE-aaa"


def _port(kind, num, switchport="", extra=""):
    sp = f'<switchport-config><switchport>{switchport}</switchport></switchport-config>' if switchport else ""
    return f"<{kind}><name>{num}</name>{sp}{extra}</{kind}>"


def _access(vlan):
    return (f'<access xmlns="{_SW}"><vlan><vlan>{vlan}</vlan></vlan></access>'
            f'<mode xmlns="{_SW}"><access/></mode>')


class ExistingConfigCheckTests(unittest.TestCase):
    def _check(self, data_xml, capabilities=None):
        m = MagicMock()
        m.server_capabilities = capabilities if capabilities is not None else [IOSXE_CAP]
        m.get_config.return_value = MagicMock(data_xml=data_xml)
        session = MagicMock()
        session.__enter__.return_value = m
        with patch.object(main, "_session", return_value=session):
            return main.existing_config_check({"host": "192.0.2.1", "device_name": "sw-test-01"}, MagicMock()), m

    def test_clean_device_not_found(self):
        mgmt = _port("GigabitEthernet", "0/0", extra='<vrf><forwarding>Mgmt-vrf</forwarding></vrf>')
        shut = _port("FortyGigabitEthernet", "1/0/1", extra="<description>spare</description>")
        result, m = self._check(_native(mgmt + shut))
        self.assertTrue(result["success"])
        self.assertFalse(result["found"])
        self.assertEqual(result["findings"], [])
        self.assertEqual(result["findings_total"], 0)

    def test_empty_native_not_found(self):
        result, _ = self._check('<data xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"/>')
        self.assertFalse(result["found"])

    def test_read_only_single_filtered_get_config_of_running(self):
        _, m = self._check(_native())
        self.assertEqual(m.get_config.call_count, 1)
        kwargs = m.get_config.call_args.kwargs
        self.assertEqual(kwargs["source"], "running")
        self.assertEqual(kwargs["filter"][0], "subtree")
        for name in ("lock", "edit_config", "commit", "discard_changes", "dispatch"):
            getattr(m, name).assert_not_called()
        etree.fromstring(kwargs["filter"][1])
        self.assertNotIn("<key", kwargs["filter"][1])
        self.assertNotIn("Vlan", kwargs["filter"][1])
        self.assertNotIn("Loopback", kwargs["filter"][1])

    def test_access_vlan_30_found(self):
        result, _ = self._check(_native(_port("FortyGigabitEthernet", "1/0/5", _access(30))))
        self.assertTrue(result["found"])
        self.assertIn("FortyGigabitEthernet1/0/5: access VLAN 30", result["findings"][0])

    def test_new_and_legacy_switchport_trees_give_one_finding(self):
        new = f'<switchport-config><switchport>{_access(999)}</switchport-config>'.replace("</switchport-config>", "</switchport></switchport-config>")
        legacy = f'<switchport><access xmlns="{_SW}"><vlan><vlan>999</vlan></vlan></access></switchport>'
        port = f"<FortyGigabitEthernet><name>1/0/7</name>{new}{legacy}<shutdown/></FortyGigabitEthernet>"
        result, _ = self._check(_native(port))
        self.assertEqual(result["findings"], ["FortyGigabitEthernet1/0/7: access VLAN 999, mode access"])

    def test_app_gigabit_port_counts(self):
        result, _ = self._check(_native(_port("AppGigabitEthernet", "1/0/1", _access(30))))
        self.assertTrue(result["found"])

    def test_vlan_1_only_not_found(self):
        sp = f'<access xmlns="{_SW}"><vlan><vlan>1</vlan></vlan></access>'
        result, _ = self._check(_native(_port("GigabitEthernet", "1/0/2", sp)))
        self.assertFalse(result["found"])

    def test_mode_access_alone_found(self):
        sp = f'<mode xmlns="{_SW}"><access/></mode>'
        result, _ = self._check(_native(_port("GigabitEthernet", "1/0/3", sp)))
        self.assertTrue(result["found"])
        self.assertIn("mode access", result["findings"][0])

    def test_trunk_found(self):
        sp = (f'<mode xmlns="{_SW}"><trunk/></mode>'
              f'<trunk xmlns="{_SW}"><allowed><vlan-v2><vlan-choices><vlans>10,20</vlans></vlan-choices></vlan-v2></allowed></trunk>')
        result, _ = self._check(_native(_port("TenGigabitEthernet", "1/1/1", sp)))
        self.assertTrue(result["found"])
        self.assertIn("mode trunk", result["findings"][0])
        self.assertIn("trunk allowed VLANs 10,20", result["findings"][0])

    def test_trunk_allowed_list_alone_found(self):
        sp = f'<trunk xmlns="{_SW}"><allowed><vlan><vlans>10</vlans></vlan></allowed></trunk>'
        result, _ = self._check(_native(_port("TenGigabitEthernet", "1/1/2", sp)))
        self.assertTrue(result["found"])

    def test_channel_group_found(self):
        cg = (f'<channel-group xmlns="{_ETH}">'
              "<number>5</number><mode>active</mode></channel-group>")
        result, _ = self._check(_native(_port("TenGigabitEthernet", "1/1/3", extra=cg)))
        self.assertTrue(result["found"])
        self.assertEqual(result["findings"], ["TenGigabitEthernet1/1/3: channel-group 5"])

    def test_port_channel_found(self):
        result, _ = self._check(_native(_port("Port-channel", "5")))
        self.assertTrue(result["found"])
        self.assertEqual(result["findings"], ["Port-channel5"])

    def test_mgmt_port_ignored_by_vrf_and_by_name(self):
        by_vrf = _port("GigabitEthernet", "1/0/9", _access(30),
                       extra='<vrf><forwarding>Mgmt-vrf</forwarding></vrf>')
        by_name = _port("GigabitEthernet", "0/0", _access(30))
        result, _ = self._check(_native(by_vrf + by_name))
        self.assertFalse(result["found"])

    def test_description_alone_does_not_count(self):
        result, _ = self._check(_native(_port("GigabitEthernet", "1/0/4", extra="<description>uplink</description>")))
        self.assertFalse(result["found"])

    def test_svi_and_loopback_ignored(self):
        extra = _port("Vlan", "10", _access(30)) + _port("Loopback", "0", _access(30))
        result, _ = self._check(_native(extra))
        self.assertFalse(result["found"])

    def test_aaa_new_model_found(self):
        aaa = '<aaa><new-model xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-aaa"/></aaa>'
        result, _ = self._check(_native(extra=aaa))
        self.assertTrue(result["found"])
        self.assertEqual(result["findings"], ["AAA: aaa new-model"])

    def test_aaa_entries_found(self):
        ns = "http://cisco.com/ns/yang/Cisco-IOS-XE-aaa"
        aaa = (f'<aaa><authentication xmlns="{ns}"><login><name>default</name></login></authentication>'
               f'<authorization xmlns="{ns}"><exec><name>default</name></exec></authorization>'
               f'<accounting xmlns="{ns}"><exec><name>default</name></exec></accounting>'
               f'<group xmlns="{ns}"><server><tacacs-plus><name>grp</name></tacacs-plus></server></group>'
               f'<session-id xmlns="{ns}">common</session-id></aaa>')
        result, _ = self._check(_native(extra=aaa))
        self.assertEqual(result["findings"], ["AAA: authentication", "AAA: authorization",
                                              "AAA: accounting", "AAA: group server"])

    def test_aaa_session_id_alone_not_found(self):
        aaa = '<aaa><session-id xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-aaa">common</session-id></aaa>'
        result, _ = self._check(_native(extra=aaa))
        self.assertFalse(result["found"])

    def test_tacacs_server_found_count_only(self):
        servers = "".join(f'<server xmlns="{_AAA}"><name>tac{i}</name></server>' for i in range(3))
        result, _ = self._check(_native(extra=f'<tacacs>{servers}</tacacs>'))
        self.assertTrue(result["found"])
        self.assertEqual(result["findings"], ["TACACS servers: 3"])
        self.assertNotIn("tac0", json.dumps(result))

    def test_output_never_contains_key_text(self):
        servers = (f'<server xmlns="{_AAA}"><name>tac1</name><address><ipv4>192.0.2.10</ipv4></address>'
                   f"<key><key>{FAKE_KEY}</key><key-type>7</key-type></key></server>")
        aaa = (f'<aaa><new-model xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-aaa"/>'
               f'<group xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-aaa"><server><tacacs-plus><name>g</name>'
               f'<key>{FAKE_KEY}</key></tacacs-plus></server></group></aaa>')
        port = _port("GigabitEthernet", "1/0/6", _access(30), extra=f"<description>{FAKE_KEY}</description>")
        result, _ = self._check(_native(port, f'<tacacs>{servers}</tacacs>{aaa}'))
        self.assertTrue(result["found"])
        out = json.dumps(result)
        self.assertNotIn(FAKE_KEY, out)
        self.assertNotIn("192.0.2.10", out)
        self.assertEqual(set(result), {"success", "host", "device_name", "found", "findings", "findings_total"})

    def test_findings_capped_with_full_total(self):
        ports = "".join(_port("GigabitEthernet", f"1/0/{i}", _access(30)) for i in range(1, 31))
        result, _ = self._check(_native(ports))
        self.assertEqual(len(result["findings"]), 20)
        self.assertEqual(result["findings_total"], 30)

    def test_cap_keeps_aaa_and_tacacs_first(self):
        ports = "".join(_port("GigabitEthernet", f"1/0/{i}", _access(30)) for i in range(1, 26))
        extra = ('<aaa><new-model xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-aaa"/></aaa>'
                 f'<tacacs><server xmlns="{_AAA}"><name>t1</name></server></tacacs>')
        result, _ = self._check(_native(_port("Port-channel", "5") + ports, extra))
        self.assertEqual(result["findings_total"], 28)
        self.assertEqual(len(result["findings"]), 20)
        self.assertEqual(result["findings"][:3], ["AAA: aaa new-model", "TACACS servers: 1", "Port-channel5"])
        self.assertTrue(result["found"])

    def test_natural_order(self):
        ports = "".join(_port("FortyGigabitEthernet", n, _access(30)) for n in ("1/0/10", "1/0/2", "1/0/1"))
        pcs = _port("Port-channel", "10") + _port("Port-channel", "5")
        result, _ = self._check(_native(ports + pcs))
        names = [f.split(":")[0] for f in result["findings"]]
        self.assertEqual(names, ["Port-channel5", "Port-channel10", "FortyGigabitEthernet1/0/1",
                                 "FortyGigabitEthernet1/0/2", "FortyGigabitEthernet1/0/10"])

    def test_nxos_not_supported(self):
        result, m = self._check(_native(), [NXOS_CAP])
        self.assertFalse(result["success"])
        self.assertEqual(result["error_type"], "NotSupported")
        m.get_config.assert_not_called()

    def test_rpc_error_fails_closed(self):
        m = MagicMock()
        m.server_capabilities = [IOSXE_CAP]
        m.get_config.side_effect = _make_rpc_error("operation-failed")
        session = MagicMock()
        session.__enter__.return_value = m
        with patch.object(main, "_session", return_value=session):
            result = main.existing_config_check({"host": "192.0.2.1"}, MagicMock())
        self.assertFalse(result["success"])
        self.assertNotIn("found", result)

    def test_unparsable_reply_fails_closed(self):
        result, _ = self._check("not xml")
        self.assertFalse(result["success"])
        self.assertNotIn("found", result)

    def test_filter_namespaces(self):
        root = etree.fromstring(main._EXISTING_CONFIG_FILTER)
        ns = lambda name: {etree.QName(e).namespace for e in root.iter() if etree.QName(e).localname == name}
        native = {_NATIVE}
        self.assertEqual(ns("channel-group"), {_ETH})
        self.assertEqual(ns("tacacs"), {_NATIVE})
        for name in ("native", "interface", "aaa", "switchport-config", "vrf", "Port-channel", "GigabitEthernet"):
            self.assertTrue(ns(name) <= native | {None} and ns(name), name)
        self.assertEqual(ns("server"), {_AAA})

    def test_registered_in_dispatch(self):
        self.assertIs(main._DISPATCH["netconf-existing-config-check"], main.existing_config_check)


class FormatForHumansTests(unittest.TestCase):
    def test_is_alive_returns_full_json_including_version(self):
        result = {"success": True, "alive": True, "host": "10.0.0.1", "output": "17.15"}
        self.assertEqual(json.loads(main._format_for_humans(result, "netconf-is-alive")), result)


if __name__ == "__main__":
    unittest.main()
