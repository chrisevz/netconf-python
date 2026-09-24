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


class SendConfigXmlTests(unittest.TestCase):
    """send_command's push path, with a mocked ncclient manager."""

    CANDIDATE = "urn:ietf:params:netconf:capability:candidate:1.0"
    VALIDATE = "urn:ietf:params:netconf:capability:validate:1.1"

    def _run(self, capabilities, validate_error=None):
        m = MagicMock()
        m.server_capabilities = capabilities
        if validate_error is not None:
            m.validate.side_effect = validate_error
        session = MagicMock()
        session.__enter__.return_value = m
        conn = {"host": "10.0.0.1", "lock_timeout": 1, "lock_poll_interval": 0.1}
        args = MagicMock(config_xml="<config/>", expect_running_hash=None)
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
