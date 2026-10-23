#!/usr/bin/env python3
"""Cisco IOS XE NETCONF service for IAG5 — single use case.

Pushes a pre-built NETCONF <config> XML payload to a Cisco IOS XE device,
rendered as CLI text (or, where unavailable, a structural XML diff) for
human approval before it is committed.

Fleet: Catalyst access (IE 3400, IE 3500, CAT 9300/9400) and Catalyst core
(CAT 9500), all IOS XE, all DMI netconf-yang on port 830. Trains: 17.15.5 (N)
and 17.12.4 (N-1). NX-OS is out of scope for this driver — see the
netconf-python git history for the removed dual-platform version if that
work resumes later.

Actions: netconf-is-alive, netconf-get-config, netconf-get-config-clis,
netconf-preview-config, netconf-send-command, netconf-discard,
netconf-save-config, netconf-confirm-commit, netconf-cancel-commit,
netconf-existing-config-check.

netconf-preview-config is the core feature: it stages a proposed config_xml
change into the candidate datastore, renders/diffs it against running, and
discards — all within one session, leaving zero state on the device. It
reports which rendering mode produced the diff via preview_mode:
  - "device-rendered" — CLI diff via get-modelled-config-clis
    (Cisco-IOS-XE-cli-rpc), available on 17.15.5-class images.
  - "xml-diff" — structural XML diff via plain get-config, used when
    get-modelled-config-clis is unsupported (expected on 17.12.4 — that
    train most likely carries the Cisco-IOS-XE-cli-rpc 2022-07-01 revision,
    which predates get-modelled-config-clis).
preview_mode is always present in the result — an operator approving a
change needs to know whether they're looking at the device's own rendering
or a structural diff, never a guess.

netconf-send-command pushes the same config_xml for real: lock candidate,
discard any stray staged content, edit, commit. Refuses to touch running
config with expect_running_hash set if running has drifted since a prior
netconf-preview-config call captured its hash.

netconf-send-command with confirm_timeout makes that commit a persistent
confirmed commit: the change is live, but the device reverts it by itself when
the timer runs out unless netconf-confirm-commit is called with the returned
persist_id first (netconf-cancel-commit rolls it back immediately). The timer
lives on the device, so it fires even if the caller dies. Devices without
:confirmed-commit:1.1 are refused, never pushed to with a plain commit.

netconf-save-config copies running-config to startup-config (write memory)
after a successful push, so the change survives a reload. With a confirmed
commit, save only after netconf-confirm-commit succeeds.

netconf-discard clears a dirty candidate out of band (e.g. after a refused
preview) — it does not pair with any staging mode, there isn't one.

Connection parameters are read from stdin as JSON in the gateway5
InventoryInfo format:

    {"inventory_nodes": [{"name": "...", "attributes": {
        "itential_host": "...", "itential_user": "...",
        "itential_password": "...",
        "itential_driver_options": {"netconf": {"port": 830, ...}}
    }}]}

CLI flags for connection params override stdin values — useful for local
testing.

Unverified for this fleet (fail loudly rather than guess if these turn out
to matter):
  - Whether Cisco-IOS-XE-cli-rpc is present on 17.12.4, and at which revision.
  - Whether get-modelled-config-clis exists on IE 3400 / IE 3500 at 17.15.5
    (confirmed on 17.15 generally, not on the IoT platforms).
  - Whether candidate-datastore is available/enabled across all four
    platform families on both trains.
  - What get-modelled-config-clis silently omits per platform.
  - Realistic render duration on a CAT 9500 core config (only ~17s on a
    CSR1000v lab device is measured, a different platform family entirely).
  - hostkey_verify=False — hardening item for production review.
"""

import argparse
import difflib
import hashlib
import json
import os
import re
import sys
import threading
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

import lxml.etree as _etree

from ncclient import manager
from ncclient.xml_ import to_ele
from ncclient.operations.rpc import RPCError
from ncclient.transport.errors import AuthenticationError, SSHError

# Cisco IOS XE get-modelled-config-clis RPC namespace (Cisco-IOS-XE-cli-rpc
# YANG module). RPC-only module — not advertised in the NETCONF hello
# capability list even when present, so don't gate on a capability check;
# just call it and handle unknown-element (see _get_modelled_config_clis).
_CLI_RPC_NS = "http://cisco.com/ns/yang/Cisco-IOS-XE-cli-rpc"

# NX-OS refuses an unfiltered <get-config> (operation-not-supported, "Request
# without namespace and filter is an unsupported operation"), so a read with
# no caller filter sends this whole-device subtree filter instead.
_NXOS_ROOT_FILTER = '<System xmlns="http://cisco.com/ns/yang/cisco-nx-os-device"/>'

# Single platform (IOS XE) — selects ncclient's generic IETF-style device
# handler.
_DEVICE_PARAMS = {"name": "iosxe"}


def _connect(conn):
    return manager.connect(
        host=conn["host"],
        port=conn["port"],
        username=conn["user"],
        password=conn["password"],
        hostkey_verify=False,
        device_params=_DEVICE_PARAMS,
        timeout=conn["timeout"],
        allow_agent=False,
        look_for_keys=False,
    )


@contextmanager
def _session(conn):
    """Wrap _connect() so a failure while gracefully closing the NETCONF session
    never clobbers a result already computed inside the `with` block. A device
    dropping the connection right after a commit is normal, not exceptional —
    but ncclient's Manager.__exit__() calls close_session() and lets any error
    from that RPC propagate, which would otherwise turn an operation that
    already succeeded on the device into a reported failure.
    """
    m = _connect(conn)
    try:
        yield m
    finally:
        try:
            # Bound the close-session wait so an unresponsive device doesn't
            # hold up the whole process for the full connect timeout.
            m.timeout = min(m.timeout, 5)
            if m.connected:
                m.close_session()
        except Exception:
            pass


def _has_capability(m, name: str) -> bool:
    """Return True if the server advertises IETF base capability `name`
    (e.g. "candidate", "validate") via its URN, not a naive substring match
    against the stringified capability blob — a substring match against
    ":candidate" or ":validate" can false-positive against any capability
    URI that merely contains that text."""
    prefix = f"urn:ietf:params:netconf:capability:{name}:1."
    return any(str(cap).startswith(prefix) for cap in m.server_capabilities)


def _has_candidate(m) -> bool:
    return _has_capability(m, "candidate")


def _has_validate(m) -> bool:
    return _has_capability(m, "validate")


def _has_persistent_confirmed_commit(m) -> bool:
    """True only for :confirmed-commit:1.1 (RFC 6241 §8.4). Version 1.0 is not
    enough: its confirmed commit is tied to the session that issued it and
    reverts as soon as that session closes, and every service call here is a
    fresh session. Only 1.1's persist / persist-id lets a later call confirm
    or cancel."""
    prefix = "urn:ietf:params:netconf:capability:confirmed-commit:1.1"
    return any(str(cap).startswith(prefix) for cap in m.server_capabilities)


def _get_config_xml(m, source: str, filter_xml: str = None) -> str:
    """Fetch a datastore's config as pretty-printed XML text, over an
    already-open session. Plain <get-config> — always available regardless
    of train/platform, unlike get-modelled-config-clis. An explicit filter_xml
    always wins; with none, NX-OS gets _NXOS_ROOT_FILTER and every other
    platform stays unfiltered."""
    if not filter_xml and _detect_platform(m) == "nxos":
        filter_xml = _NXOS_ROOT_FILTER
    reply = m.get_config(
        source=source,
        filter=("subtree", filter_xml) if filter_xml else None,
    )
    try:
        tree = _etree.fromstring(reply.data_xml.encode())
        return _etree.tostring(tree, pretty_print=True).decode().strip()
    except Exception:
        return reply.data_xml


def _get_modelled_config_clis(m, datastore: str = "running"):
    """Call get-modelled-config-clis and return (result_text, error_message).

    This is the RPC behind the operator CLI preview: it renders a whole
    datastore (running or candidate) as CLI text via the device's own
    modelled-config-to-CLI conversion. Not advertised in the NETCONF hello,
    so unsupported-RPC is detected by dispatching it and catching
    unknown-element — do not replace this with a capability check.

    error_message is a normal *output leaf* on a successful RPC reply (the
    device telling us it couldn't render something, e.g. wireless/
    app-hosting/telemetry per Cisco's own docs) — distinct from an
    RPCError, which means the RPC itself failed at the transport/protocol
    level (e.g. unsupported on this train/revision).
    """
    rpc_xml = (
        f'<get-modelled-config-clis xmlns="{_CLI_RPC_NS}">'
        f"<datastore>{datastore}</datastore>"
        f"</get-modelled-config-clis>"
    )
    try:
        reply = m.dispatch(to_ele(rpc_xml))
    except RPCError as e:
        tag = getattr(e, "tag", "") or ""
        if "unknown-element" in tag or "unknown-element" in str(e):
            return None, (
                "get-modelled-config-clis RPC not supported on this device — "
                "requires the Cisco-IOS-XE-cli-rpc YANG module (or a revision "
                "of it that includes get-modelled-config-clis)."
            )
        raise
    xml_str = reply.xml if hasattr(reply, "xml") else str(reply)
    tree = _etree.fromstring(xml_str.encode() if isinstance(xml_str, str) else xml_str)
    result_nodes = tree.xpath(".//*[local-name()='result']")
    error_nodes = tree.xpath(".//*[local-name()='error-message']")
    result = result_nodes[0].text if result_nodes and result_nodes[0].text else None
    error = error_nodes[0].text if error_nodes and error_nodes[0].text else None
    return result, error


def _detect_platform(m) -> str:
    """"nxos", "iosxe" or "unknown", from the YANG modules the server
    advertises. NX-OS is checked first; the two never overlap in practice."""
    caps = [str(cap) for cap in m.server_capabilities]
    if any("http://cisco.com/ns/yang/cisco-nx-os-device" in cap for cap in caps):
        return "nxos"
    if any("http://cisco.com/ns/yang/Cisco-IOS-XE-native" in cap for cap in caps):
        return "iosxe"
    return "unknown"


_VERSION_READS = {
    "iosxe": ("version",
              "<native xmlns=\"http://cisco.com/ns/yang/Cisco-IOS-XE-native\"><version/></native>"),
    "nxos": ("nxosVersion",
             "<System xmlns=\"http://cisco.com/ns/yang/cisco-nx-os-device\">"
             "<showversion-items><nxosVersion/></showversion-items></System>"),
}


def _read_version(m, platform: str) -> str:
    """Read the software version with the platform's own subtree filter.
    Raises on any failure; the caller decides that a failed read must not
    fail the liveness check."""
    local_name, filter_xml = _VERSION_READS[platform]
    reply = m.get(filter=("subtree", filter_xml))
    xml_str = reply.data_xml if hasattr(reply, "data_xml") else str(reply)
    tree = _etree.fromstring(xml_str.encode() if isinstance(xml_str, str) else xml_str)
    nodes = tree.xpath(f".//*[local-name()='{local_name}']")
    return nodes[0].text.strip() if nodes and nodes[0].text else ""


# Software trains (major.minor) on which the fast IOS XE preview (lock first, CLI-render fingerprint) has
# been proven live. Anything else, or a failed version read, gets the original flow.
FAST_PREVIEW_IOSXE_TRAINS = ("17.15",)


def _fast_preview_allowed(m, platform: str) -> bool:
    """True only for IOS XE on a train in FAST_PREVIEW_IOSXE_TRAINS, from the same small version read
    is-alive uses. An "unknown" platform gets the IOS XE read too (like is-alive's fallback): an IOS XE
    switch may list its YANG modules only through yang-library and not in the hello (the lab C9500 stack on
    17.15 does), so the version read decides. A failed or unparsable read, NX-OS or another train is
    False: the preview then runs the original flow (dirty check first with full XML reads, plain XML hash)."""
    if platform not in ("iosxe", "unknown"):
        return False
    try:
        version = _read_version(m, "iosxe")
    except Exception:
        return False
    found = re.match(r"\s*(\d+)\.(\d+)", version or "")
    return bool(found) and f"{found.group(1)}.{found.group(2)}" in FAST_PREVIEW_IOSXE_TRAINS


def is_alive(conn, args) -> dict:
    device_name = conn.get("device_name") or conn["host"]
    try:
        with _session(conn) as m:
            platform = _detect_platform(m)
            version = ""
            version_error = None
            # Opening the session is the liveness proof; a failed version read
            # (wrong model for this platform, RPCError, bad XML) is reported
            # but never turns the result into alive:false.
            # "unknown" falls back to the IOS XE read so a device that omits
            # its native module from the hello still reports a version.
            try:
                version = _read_version(m, platform if platform in _VERSION_READS else "iosxe")
            except Exception as e:
                version = ""
                version_error = str(e)[:200]
            confirmed_1_1 = _has_persistent_confirmed_commit(m)
            result = {
                "success": True,
                "alive": True,
                "host": conn["host"],
                "device_name": device_name,
                "output": version,
                # Lets a workflow refuse a device that cannot do a persistent
                # confirmed commit before any operator time is spent.
                "persist_confirmed_commit": confirmed_1_1,
                "platform": platform,
                "capabilities": {
                    "candidate": _has_capability(m, "candidate"),
                    "validate": _has_capability(m, "validate"),
                    "confirmed_commit_1_0": any(
                        str(cap).startswith("urn:ietf:params:netconf:capability:confirmed-commit:1.0")
                        for cap in m.server_capabilities),
                    "confirmed_commit_1_1": confirmed_1_1,
                    "writable_running": _has_capability(m, "writable-running"),
                    "rollback_on_error": _has_capability(m, "rollback-on-error"),
                    "startup": _has_capability(m, "startup"),
                },
                # Base protocol capabilities only; the YANG module list is huge on NX-OS.
                "base_capabilities": sorted(
                    str(cap) for cap in m.server_capabilities
                    if str(cap).startswith("urn:ietf:params:netconf:")),
            }
            if version_error is not None:
                result["version_error"] = version_error
            return result
    except (AuthenticationError, SSHError) as e:
        return {"success": False, "alive": False, "host": conn["host"], "device_name": device_name,
                "error": str(e), "error_type": type(e).__name__}
    except Exception as e:
        return {"success": False, "alive": False, "host": conn["host"], "device_name": device_name,
                "error": str(e), "error_type": type(e).__name__}


def get_config(conn, args) -> dict:
    try:
        with _session(conn) as m:
            config_xml = _get_config_xml(m, args.source, args.filter)
            return {"success": True, "host": conn["host"], "source": args.source, "config": config_xml}
    except Exception as e:
        return {"success": False, "host": conn["host"], "error": str(e), "error_type": type(e).__name__}


def get_config_clis(conn, args) -> dict:
    """Render a datastore as CLI text via get-modelled-config-clis."""
    datastore = args.source or "running"
    try:
        with _session(conn) as m:
            result, error = _get_modelled_config_clis(m, datastore)
            if error and result is None:
                return {
                    "success": False,
                    "host": conn["host"],
                    "datastore": datastore,
                    "error": error,
                    "error_type": "RPCError",
                }
            return {
                "success": True,
                "host": conn["host"],
                "datastore": datastore,
                "config": result or "",
                # Surfaced even on success — a non-empty error-message alongside a
                # result can mean partial render (e.g. an unsupported feature was
                # skipped rather than raising). Don't swallow it — whether
                # unsupported features error or silently omit is still unconfirmed
                # per-platform; this at least reports it when the device does tell us.
                "warning": error,
            }
    except Exception as e:
        return {"success": False, "host": conn["host"], "datastore": datastore,
                "error": str(e), "error_type": type(e).__name__}


def _acquire_candidate_lock(m, timeout: int, poll_interval: float) -> float:
    deadline = time.monotonic() + max(timeout, 0)
    start = time.monotonic()
    while True:
        try:
            m.lock(target="candidate")
            return time.monotonic() - start
        except RPCError as e:
            # Match on the tag only — string-sniffing messages like "in-use" or
            # "configuration database locked" was validated against exactly one
            # 17.15 device; a different DMI build (e.g. IE 3400 on 17.12.4) is
            # not guaranteed to phrase it the same way. An unrecognised error is
            # treated as fatal, not transient — retrying an error we didn't
            # parse is worse than failing.
            if getattr(e, "tag", None) != "lock-denied" or timeout == 0 or time.monotonic() >= deadline:
                raise
            time.sleep(poll_interval)


def _try_candidate_lock(m, conn):
    """Take the candidate lock with the usual retry rules. Returns
    (seconds, error): error is None when the lock is held, else the RPCError
    the device refused with, and seconds is then how long the attempt took
    (reported as lock_wait_seconds). Any non-RPCError exception propagates."""
    started = time.monotonic()
    try:
        return _acquire_candidate_lock(m, conn["lock_timeout"], conn["lock_poll_interval"]), None
    except RPCError as e:
        return time.monotonic() - started, e


def _candidate_locked_result(conn, device_name, error, waited) -> dict:
    """Failure result for a candidate lock that could not be taken: another
    session holds it, or the device refused it for another reason (error_type
    CandidateLocked, with the device's own message and tag). Nothing was edited
    or committed on this path."""
    return {"success": False, "host": conn["host"], "device_name": device_name,
            "error": f"could not take the candidate lock — nothing was edited or committed: {error}",
            "error_type": "CandidateLocked",
            "rpc_tag": getattr(error, "tag", None),
            "lock_wait_seconds": round(waited, 2),
            "committed": False}


def _normalize_text(text: str) -> str:
    """rstrip each line, drop blank lines, join with \\n. Used for hashing
    and for change-detection comparisons (dirty check, has_changes) so
    trailing whitespace / blank-line noise from a renderer doesn't produce
    false differences. Do NOT use this for operator-facing diffs — dropping
    blank lines merges unrelated config sections together in the diff
    output. Use _diff_lines for that instead."""
    if not text:
        return ""
    lines = (line.rstrip() for line in text.splitlines())
    return "\n".join(line for line in lines if line)


def _diff_lines(text: str) -> list:
    """rstrip each line but keep blank lines and line positions, for
    operator-facing unified diffs. Unlike _normalize_text, this doesn't
    merge sections separated by blank lines into one diff hunk."""
    if not text:
        return []
    return [line.rstrip() for line in text.splitlines()]


def _text_hash(text: str) -> str:
    """sha256 of normalized text, first 16 hex chars — the fingerprint of the
    running-config XML (via _get_config_xml). It is netconf-preview-config's
    running_hash only when the preview fell back to the XML diff (no CLI render),
    and the push's XML drift guard (unprefixed expect_running_hash) compares
    against it. See _cli_hash for the CLI-render fingerprint."""
    return hashlib.sha256(_normalize_text(text).encode("utf-8")).hexdigest()[:16]


_CLI_HASH_PREFIX = "cli-sha256:"


def _cli_hash(text: str) -> str:
    """Fingerprint of a running-config CLI render (get-modelled-config-clis):
    "cli-sha256:" + the full sha256 of the normalized text. The prefix tells the
    push which source to re-fingerprint, so a hash never gets compared against
    the other kind. The ONE helper both netconf-preview-config (running_hash)
    and netconf-send-command (expect_running_hash drift guard) use."""
    return _CLI_HASH_PREFIX + hashlib.sha256(_normalize_text(text).encode("utf-8")).hexdigest()


_SECRET_PLACEHOLDER = "GATEWAYSECRET_"


def _unresolved_secret_placeholder(config_xml, conn, device_name):
    """Failure result when config_xml still carries a $GATEWAYSECRET_(name) placeholder, else None.

    The gateway swaps each placeholder for the real secret before this process starts, and refuses the whole
    call when a name does not exist. A placeholder that still reaches the driver was therefore not swapped (a
    malformed one, for example), and sending it would set the literal text as the password or key on the
    device. Refuse before any session is opened. The error never echoes config_xml: it may hold other secrets."""
    if _SECRET_PLACEHOLDER not in config_xml:
        return None
    return {"success": False, "host": conn["host"], "device_name": device_name,
            "error": "config_xml still contains a $GATEWAYSECRET_ placeholder: the gateway did not substitute "
                     "it, so it would reach the device as literal text. Nothing was sent to the device.",
            "error_type": "UnresolvedSecretPlaceholder", "committed": False}


class _Steps:
    """Wall-clock laps of one preview, reported as timings.steps / timings.driver_total_s so a live
    run shows where the time goes (the 10-06 live run took ~222 s while the two CLI renders added up to
    only 22 s + 36 s)."""

    def __init__(self):
        self.start = self.last = time.monotonic()
        self.laps = {}

    def lap(self, name: str) -> None:
        now = time.monotonic()
        self.laps[name] = round(now - self.last, 2)
        self.last = now

    def record(self, name: str, seconds: float) -> None:
        """Add a phase that ran inside another lap (its time is part of that lap too)."""
        self.laps[name] = round(seconds, 2)

    def total(self) -> float:
        return round(time.monotonic() - self.start, 2)


_DIFF_CONTEXT_LINES = 3
_DIFF_MAX_ROWS = 5000


def _side_by_side_rows(old_text: str, new_text: str, context: int = _DIFF_CONTEXT_LINES,
                       max_rows: int = _DIFF_MAX_ROWS) -> tuple:
    """Build a side-by-side diff (old on the left, new on the right) as plain data.

    Returns (rows, stats). Each row is a dict:
      {"kind": "same"|"change", "old_no", "old", "old_mark", "new_no", "new", "new_mark"}
    where *_no is the 1-based line number on that side (None when that side has no
    line in this row), *_mark is "del" (line removed/changed on the old side), "add"
    (line added/changed on the new side) or "" (unchanged), or a gap row
      {"kind": "gap", "hidden": N}
    standing for N unchanged lines that are not shown. Only the changed lines plus
    `context` unchanged lines around them are returned, so a one-line change in a
    3000-line config stays small. Changed blocks are paired line by line; the longer
    side's extra lines sit opposite an empty cell. Presentation (HTML, colours) is the
    caller's job. Lines are compared like _diff_lines (rstripped, blank lines kept).
    stats = {"added", "removed", "truncated"}.
    """
    old = _diff_lines(old_text)
    new = _diff_lines(new_text)
    # default autojunk, like the unified diff above: autojunk=False took 7 s on a 4000-line config with
    # 100 scattered edits (very repetitive lines) against 0.04 s, and gave the same blocks
    ops = difflib.SequenceMatcher(None, old, new).get_opcodes()
    rows, added, removed, truncated = [], 0, 0, False

    def same_row(i, j):
        return {"kind": "same", "old_no": i + 1, "old": old[i], "old_mark": "",
                "new_no": j + 1, "new": new[j], "new_mark": ""}

    for n, (tag, i1, i2, j1, j2) in enumerate(ops):
        if tag == "equal":
            size = i2 - i1
            first, last = n == 0, n == len(ops) - 1
            if first and last:
                continue  # identical: no changes, no rows
            head = 0 if first else context      # lines kept after the previous change
            tail = 0 if last else context       # lines kept before the next change
            if size <= head + tail:
                rows += [same_row(i1 + k, j1 + k) for k in range(size)]
            else:
                rows += [same_row(i1 + k, j1 + k) for k in range(head)]
                rows.append({"kind": "gap", "hidden": size - head - tail})
                rows += [same_row(i2 - tail + k, j2 - tail + k) for k in range(tail)]
            continue
        removed += i2 - i1
        added += j2 - j1
        for k in range(max(i2 - i1, j2 - j1)):
            has_old, has_new = i1 + k < i2, j1 + k < j2
            rows.append({"kind": "change",
                         "old_no": i1 + k + 1 if has_old else None, "old": old[i1 + k] if has_old else "",
                         "old_mark": "del" if has_old else "",
                         "new_no": j1 + k + 1 if has_new else None, "new": new[j1 + k] if has_new else "",
                         "new_mark": "add" if has_new else ""})
    if len(rows) > max_rows:
        hidden = len(rows) - max_rows
        rows = rows[:max_rows] + [{"kind": "gap", "hidden": hidden}]
        truncated = True
    return rows, {"added": added, "removed": removed, "truncated": truncated}


def _start_background_render(conn, datastore: str = "running"):
    """Render a datastore as CLI text in a SECOND, read-only NETCONF session on a
    background thread, so the slow device-side render overlaps the staging work
    done in the main session (lock, edit, validate, candidate render) instead of
    running after it. get-modelled-config-clis on running needs no lock, so it
    cannot collide with the candidate lock held by the main session.

    Returns (thread, box). After thread.join(), box holds result/error (exactly
    what _get_modelled_config_clis returned), exc (the exception if the second
    session or the RPC failed; the caller then renders in its own session), and
    seconds (how long the render took). The thread is a daemon so a main flow that
    ends early never waits on it.
    """
    box = {"result": None, "error": None, "exc": None, "seconds": None}

    def work():
        started = time.monotonic()
        try:
            with _session(conn) as m2:
                box["result"], box["error"] = _get_modelled_config_clis(m2, datastore)
        except Exception as e:  # reported to the caller, which falls back to its own session
            box["exc"] = e
        box["seconds"] = round(time.monotonic() - started, 2)

    thread = threading.Thread(target=work, name=f"render-{datastore}", daemon=True)
    thread.start()
    return thread, box


def _preview_render(m, running_xml: str, candidate_after_xml: str, background=None, cli_render: bool = True) -> dict:
    """Produce the operator-facing diff, trying the device's own CLI
    renderer first and falling back to a structural XML diff of plain
    get-config output when get-modelled-config-clis isn't available.

    Returns preview_mode ("device-rendered" or "xml-diff") alongside diff,
    diff_rows / diff_stats (the same diff as side-by-side data), has_changes,
    candidate_config, running_config, render_warning and timings — always all
    present, so a caller never has to guess which rendering produced the result.

    With `background` (from _start_background_render: the running render already
    in flight in its own session) the candidate render starts now and the two
    overlap; without it they run one after the other in `m`. If the background
    session failed, running is rendered in `m` after all (timings.parallel False).

    `running_xml` and `candidate_after_xml` are the XML text, or a zero-argument
    callable that reads it (running is read lazily when the pre-edit reads were
    skipped). With cli_render=False no CLI render is attempted at all
    (straight to the XML diff). Only the XML-diff fallback needs it, and a plain
    get-config of a large stack config is slow (about 75 s on a two-member C9500
    stack), so the device-rendered path never calls the reader.
    """
    render_started = time.monotonic()
    timings = {"parallel": background is not None}
    if not cli_render:
        running_clis = candidate_clis = running_render_err = candidate_render_err = None
    elif background is not None:
        # The running render has been going since before the staging work. Start the candidate
        # render now; an unsupported RPC fails fast (unknown-element) and falls to the XML diff.
        candidate_started = time.monotonic()
        candidate_clis, candidate_render_err = _get_modelled_config_clis(m, "candidate")
        timings["candidate_render_s"] = round(time.monotonic() - candidate_started, 2)
        thread, box = background
        thread.join()
        timings["running_render_s"] = box["seconds"]
        if box["exc"] is None:
            running_clis, running_render_err = box["result"], box["error"]
        else:
            # the second session (or its RPC) failed: render running here, one after the other
            timings["parallel"] = False
            fallback_started = time.monotonic()
            running_clis, running_render_err = _get_modelled_config_clis(m, "running")
            timings["running_render_s"] = round(time.monotonic() - fallback_started, 2)
        if running_clis is None:
            candidate_clis = None
    else:
        running_started = time.monotonic()
        running_clis, running_render_err = _get_modelled_config_clis(m, "running")
        timings["running_render_s"] = round(time.monotonic() - running_started, 2)
        candidate_clis, candidate_render_err = None, None
        if running_clis is not None:
            candidate_started = time.monotonic()
            candidate_clis, candidate_render_err = _get_modelled_config_clis(m, "candidate")
            timings["candidate_render_s"] = round(time.monotonic() - candidate_started, 2)
    timings["render_wall_s"] = round(time.monotonic() - render_started, 2)
    if running_clis is not None and candidate_clis is not None:
        diff_text = "\n".join(difflib.unified_diff(
            _diff_lines(running_clis), _diff_lines(candidate_clis),
            fromfile="running", tofile="candidate", lineterm="",
        ))
        diff_rows, diff_stats = _side_by_side_rows(running_clis, candidate_clis)
        return {
            "preview_mode": "device-rendered",
            "diff": diff_text,
            "diff_rows": diff_rows,
            "diff_stats": diff_stats,
            "has_changes": _normalize_text(running_clis) != _normalize_text(candidate_clis),
            "candidate_config": candidate_clis or "",
            "running_config": running_clis or "",
            "render_warning": running_render_err or candidate_render_err,
            "timings": timings,
        }

    if callable(running_xml):
        running_xml = running_xml()
    if callable(candidate_after_xml):
        candidate_after_xml = candidate_after_xml()
    diff_text = "\n".join(difflib.unified_diff(
        _diff_lines(running_xml), _diff_lines(candidate_after_xml),
        fromfile="running", tofile="candidate", lineterm="",
    ))
    diff_rows, diff_stats = _side_by_side_rows(running_xml, candidate_after_xml)
    return {
        "preview_mode": "xml-diff",
        "diff": diff_text,
        "diff_rows": diff_rows,
        "diff_stats": diff_stats,
        "has_changes": _normalize_text(running_xml) != _normalize_text(candidate_after_xml),
        "candidate_config": candidate_after_xml or "",
        "running_config": running_xml or "",
        "render_warning": None,
        "timings": timings,
    }


def preview_config(conn, args) -> dict:
    """Stage a proposed config_xml change, diff it against running, and
    leave zero state on the device — all in one session.

    The sequence below is the "lock-first" flow. It runs only on IOS XE on a train in
    FAST_PREVIEW_IOSXE_TRAINS (see _fast_preview_allowed; an undetected platform counts when the IOS XE
    version read answers); NX-OS, another train or a failed version read run the original flow (dirty check first with
    full XML reads, plain XML hash, described last). Results carry dirty_check
    ("lock-first" | "full-read") and fingerprint ("cli" | "xml").

    Lock-first sequence: the CLI render of running starts in
    a second session -> lock candidate -> edit_config with the caller's
    config_xml -> validate (capability-gated, captured not raised) -> CLI render
    of candidate + diff against the running render -> discard_changes + unlock
    in a finally, discarding only if we actually edited. There are NO full
    get-config reads before the edit: a lock on the candidate is only granted
    when it has no uncommitted changes (RFC 6241 section 7.5; confirmed live on
    IOS XE 17.15: lock on a dirty candidate fails with operation-failed /
    "there are outstanding changes to the database"), so a granted lock proves
    the candidate is clean. running_hash is "cli-sha256:" + the hash of the
    running CLI render the diff used (_cli_hash), so no running XML read either.
    Only the XML-diff fallback (render unavailable) reads running and candidate
    as XML, after the edit, and then running_hash is the plain XML hash.

    If the lock is refused with a tag other than lock-denied (the dirty-candidate
    signature), the dirty check runs: plain get-config of running and candidate,
    compared. Dirty without force_discard -> DirtyCandidate with a dirty_diff
    (no lock held, so no lock_wait_seconds key). Dirty with force_discard ->
    discard_changes (needs no lock, RFC 6241 section 8.3.4.2), take the lock
    again and continue. Not dirty -> CandidateLocked. A lock-denied that outlasts
    lock_timeout (another session holds the lock) -> CandidateLocked straight
    away, no reads. Discarding stays gated on force_discard, never unconditional,
    or preview would silently destroy another session's pending work.

    Original flow (NX-OS, and IOS XE outside the gate; lock-on-dirty is not confirmed
    there): get-config(running) -> get-config(candidate) -> dirty check (same
    DirtyCandidate / force_discard rules) -> lock candidate -> edit -> validate
    -> XML diff (no CLI render RPC) -> discard + unlock. running_hash is the
    plain XML hash.

    A lock that cannot be taken ends in CandidateLocked on both platforms
    (nothing edited, nothing committed). The CLI render of running runs in the
    second session while the staging work happens (see timings in the result).
    If the call returns before the render is joined, that render is abandoned
    (daemon thread, ends with the process).

    Never commits (committed is always False in the result) and never
    leaves the candidate populated or locked on any exit path reached after
    the lock is taken. That guarantee depends on `edited` being set to True
    immediately before the edit_config call, not after — a raising
    edit_config (partial apply) still needs the finally's discard. Don't
    reorder it back.
    """
    device_name = conn.get("device_name") or conn["host"]
    config_xml = getattr(args, "config_xml", None)
    if not config_xml:
        return {"success": False, "host": conn["host"], "device_name": device_name,
                "error": "config_xml is required for action=netconf-preview-config"}
    unresolved = _unresolved_secret_placeholder(config_xml, conn, device_name)
    if unresolved:
        return unresolved

    force_discard = getattr(args, "force_discard", False)
    include_diff = getattr(args, "diff", True)
    steps = _Steps()

    try:
        with _session(conn) as m:
            steps.lap("connect")
            if not _has_candidate(m):
                return {"success": False, "host": conn["host"], "device_name": device_name,
                        "error": "device has no candidate datastore — netconf-preview-config requires it"}

            # The CLI render of RUNNING is the slowest device-side step and needs neither the lock nor the
            # edit, so it runs in a second read-only session from the start, hidden behind the staging work
            # (measured on a C9500 stack: ~36 s render).
            # get-modelled-config-clis is IOS XE only: on NX-OS skip the CLI render entirely
            # (no background session, no RPC) and go straight to the XML diff.
            platform = _detect_platform(m)
            cli_render = platform != "nxos"
            background = _start_background_render(conn, "running") if cli_render else None

            # IOS XE: lock first. A granted lock proves the candidate is clean (RFC 6241 section 7.5), which
            # skips the two full get-config reads (~64 s + ~74 s on the lab switch). NX-OS keeps the dirty
            # check first (lock-on-dirty is not confirmed there).
            # Only on a proven train (see FAST_PREVIEW_IOSXE_TRAINS); any other train, a failed version read
            # or NX-OS runs the original order below.
            lock_first = cli_render and _fast_preview_allowed(m, platform)
            if platform in ("iosxe", "unknown"):
                steps.lap("version_read")
            path = "lock-first" if lock_first else "full-read"
            running_xml = None
            lock_wait, lock_error = 0.0, None
            if lock_first:
                lock_wait, lock_error = _try_candidate_lock(m, conn)
                if lock_error is not None and getattr(lock_error, "tag", None) == "lock-denied":
                    # another session holds the lock and did not let go within lock_timeout
                    return dict(_candidate_locked_result(conn, device_name, lock_error, lock_wait), dirty_check=path)
                steps.lap("lock" if lock_error is None else "lock_refused")

            if not lock_first or lock_error is not None:
                running_xml = _get_config_xml(m, "running")
                steps.lap("get_running_xml")
                candidate_before_xml = _get_config_xml(m, "candidate")
                steps.lap("get_candidate_xml")

                if _normalize_text(running_xml) != _normalize_text(candidate_before_xml):
                    if not force_discard:
                        # Return the diff, not just the refusal — the caller needs to
                        # see what they'd be destroying before deciding. This may be
                        # real pending provisioning from another session, not noise.
                        dirty_diff = "\n".join(difflib.unified_diff(
                            _diff_lines(running_xml), _diff_lines(candidate_before_xml),
                            fromfile="running", tofile="candidate", lineterm="",
                        ))
                        return {
                            "success": False, "host": conn["host"], "device_name": device_name,
                            "error": "candidate datastore is dirty (differs from running) — another "
                                     "session may have uncommitted work staged there. Pass "
                                     "force_discard=true to discard it and proceed.",
                            "error_type": "DirtyCandidate",
                            "dirty_diff": dirty_diff,
                            "dirty_check": path,
                            "committed": False,
                        }
                    # force_discard=true: clear it now — discard-changes requires no lock
                    # (RFC 6241 section 8.3.4.2). Must stay gated on force_discard, never
                    # unconditional, or preview silently destroys another session's pending work.
                    m.discard_changes()
                    if lock_first:
                        # the refused lock is retried now that the candidate is clean
                        lock_wait, lock_error = _try_candidate_lock(m, conn)
                        if lock_error is not None:
                            return dict(_candidate_locked_result(conn, device_name, lock_error, lock_wait), dirty_check=path)
                        steps.lap("lock")
                elif lock_error is not None:
                    # candidate is clean, so the refusal had another cause: report it, edit nothing
                    return dict(_candidate_locked_result(conn, device_name, lock_error, lock_wait), dirty_check=path)

            if not lock_first:
                lock_wait, lock_error = _try_candidate_lock(m, conn)
                if lock_error is not None:
                    return dict(_candidate_locked_result(conn, device_name, lock_error, lock_wait), dirty_check=path)
                steps.lap("lock")

            edited = False
            result = None
            try:
                # Set before the call, not after: a raising edit_config may have
                # partially applied. The discard in the finally is most needed on
                # exactly that path.
                edited = True
                m.edit_config(target="candidate", config=config_xml)
                steps.lap("edit_config")

                if _has_validate(m):
                    try:
                        m.validate(source="candidate")
                        valid, validate_result = True, "valid"
                    except RPCError as e:
                        valid, validate_result = False, str(e)
                else:
                    # Distinct from both "valid" and an actual validation error —
                    # a device without :validate isn't invalid, it just can't tell us.
                    valid, validate_result = None, "unsupported"
                steps.lap("validate")

                def read_candidate_xml():
                    # only called by the XML-diff fallback; inside the render lap, so timed on its own
                    started = time.monotonic()
                    xml = _get_config_xml(m, "candidate")
                    steps.record("get_candidate_xml_after_edit", time.monotonic() - started)
                    return xml

                def read_running_xml():
                    # only called by the XML-diff fallback when the pre-edit reads were skipped (lock first)
                    started = time.monotonic()
                    xml = _get_config_xml(m, "running")
                    steps.record("get_running_xml_after_edit", time.monotonic() - started)
                    return xml

                render = _preview_render(m, running_xml if running_xml is not None else read_running_xml,
                                         read_candidate_xml, background, cli_render)
                steps.lap("render")
                # Fingerprint of the running config the diff was made against. With the CLI render it is the
                # hash of that render (the same helper the push re-checks with); with the XML-diff fallback it
                # is the plain XML hash. Either way it is of the text this preview diffed.
                if lock_first and render["preview_mode"] == "device-rendered":
                    running_hash = _cli_hash(render["running_config"])
                elif running_xml is not None:
                    running_hash = _text_hash(running_xml)
                else:
                    running_hash = _text_hash(render["running_config"])
                if not include_diff:
                    render["diff"] = None
                    render["diff_rows"] = None
                    render["diff_stats"] = None

                result = {
                    "success": True,
                    "host": conn["host"],
                    "device_name": device_name,
                    "lock_wait_seconds": round(lock_wait, 2),
                    "valid": valid,
                    "validate": validate_result,
                    "preview_mode": render["preview_mode"],
                    "diff": render["diff"],
                    # the same diff as plain data for a side-by-side view: changed lines + context
                    "diff_rows": render["diff_rows"],
                    "diff_stats": render["diff_stats"],
                    "has_changes": render["has_changes"],
                    "candidate_config": render["candidate_config"],
                    "running_config": render["running_config"],
                    "running_hash": running_hash,
                    # which path ran: "lock-first" (no pre-edit XML reads) or "full-read" (dirty check
                    # first); and what running_hash fingerprints: the CLI render or the running XML
                    "dirty_check": path,
                    "fingerprint": "cli" if running_hash.startswith(_CLI_HASH_PREFIX) else "xml",
                    "warning": render["render_warning"],
                    # how long each CLI render took and whether the two ran at the same time, plus where
                    # the whole call spent its time (steps) and the driver's own total in seconds
                    "timings": dict(render["timings"], steps=steps.laps, driver_total_s=steps.total()),
                    "committed": False,
                }
                return result
            finally:
                try:
                    if edited:
                        m.discard_changes()
                except Exception:
                    pass
                try:
                    m.unlock(target="candidate")
                except Exception:
                    pass
                if result is not None:
                    # the result dict is already on its way out; the cleanup lap is added to it here
                    steps.lap("discard_unlock")
                    result["timings"]["driver_total_s"] = steps.total()
    except RPCError as e:
        return {"success": False, "host": conn["host"], "device_name": device_name,
                "committed": False,
                "error": str(e), "error_type": "RPCError",
                "rpc_tag": getattr(e, "tag", None),
                "rpc_type": getattr(e, "type", None),
                "rpc_severity": getattr(e, "severity", None),
                "rpc_info": getattr(e, "info", None),
                "rpc_path": getattr(e, "path", None)}
    except Exception as e:
        return {"success": False, "host": conn["host"], "device_name": device_name,
                "error": str(e), "error_type": type(e).__name__,
                "committed": False}


def send_command(conn, args) -> dict:
    """Push config_xml for real: lock candidate, discard any stray staged
    content, edit, commit. The supported flow is netconf-preview-config
    (stage -> diff -> discard) followed by a separate call here — there is
    no do_commit=false staging mode. IOS XE's candidate is a single global
    datastore, not per-session: a second workflow run, or any other
    session, would merge into or clobber a candidate left staged across an
    operator review, so staging-then-later-finishing is not supported.

    With confirm_timeout set the commit is a persistent confirmed commit
    (RFC 6241 :confirmed-commit:1.1): the change goes live but the DEVICE
    reverts it on its own when the timer expires unless a later
    netconf-confirm-commit call presents the returned persist_id. So if the
    workflow, the gateway or this process dies mid-review, the device still
    rolls back. Fail closed: if the device does not advertise 1.1 nothing is
    edited or committed, and there is no fallback to a plain commit.

    expect_running_hash is the running_hash of a preview. "cli-sha256:..." is
    re-checked against a fresh CLI render of running (fail closed with
    DriftCheckUnavailable if it cannot be rendered); any other value against the
    plain XML hash, as before. A candidate lock that cannot be taken ends in
    CandidateLocked, with nothing edited or committed."""
    device_name = conn.get("device_name") or conn["host"]
    config_xml = getattr(args, "config_xml", None)
    if not config_xml:
        return {"success": False, "host": conn["host"], "device_name": device_name,
                "error": "config_xml is required for action=netconf-send-command"}
    unresolved = _unresolved_secret_placeholder(config_xml, conn, device_name)
    if unresolved:
        return unresolved
    expect_running_hash = getattr(args, "expect_running_hash", None)
    confirm_timeout = getattr(args, "confirm_timeout", None)
    persist_id = uuid.uuid4().hex if confirm_timeout else None

    try:
        with _session(conn) as m:
            drift_check = "none"
            if expect_running_hash:
                # Drift guard: caller captured running_hash from an earlier
                # netconf-preview-config call and wants to be sure nothing else
                # changed running config in between. Re-fingerprint before
                # touching candidate at all, and refuse to apply on a mismatch.
                # The prefix says what the preview hashed: "cli-sha256:" is a
                # running CLI render (the usual IOS XE preview), anything else is
                # the plain XML hash (XML-diff fallback, NX-OS, or a preview made
                # by an older driver).
                drift_check = "cli" if expect_running_hash.startswith(_CLI_HASH_PREFIX) else "xml"
                if drift_check == "cli":
                    try:
                        running_clis, render_error = _get_modelled_config_clis(m, "running")
                    except Exception as e:
                        running_clis, render_error = None, f"{type(e).__name__}: {e}"
                    if running_clis is None:
                        # Cannot re-fingerprint: fail closed, never push unchecked.
                        return {
                            "success": False,
                            "host": conn["host"],
                            "device_name": device_name,
                            "error": "could not render running config to check for drift "
                                     f"(expect_running_hash is a CLI-render hash) — refusing to apply: "
                                     f"{render_error or 'empty render'}",
                            "error_type": "DriftCheckUnavailable",
                            "drift_check": drift_check,
                            "committed": False,
                        }
                    actual_hash = _cli_hash(running_clis)
                else:
                    current_running_xml = _get_config_xml(m, "running")
                    actual_hash = _text_hash(current_running_xml)
                if actual_hash != expect_running_hash:
                    return {
                        "success": False,
                        "host": conn["host"],
                        "device_name": device_name,
                        "error": "running config has drifted since expect_running_hash was captured — refusing to apply",
                        "error_type": "ConfigDrift",
                        "drift_check": drift_check,
                        "expected_running_hash": expect_running_hash,
                        "actual_running_hash": actual_hash,
                    }

            # Fail closed, same as preview. Editing running directly would apply
            # the change live with no preview parity and no commit-level
            # rollback — the spec requires candidate + commit for every push.
            if not _has_candidate(m):
                return {"success": False, "host": conn["host"], "device_name": device_name,
                        "error": "device has no candidate datastore — netconf-send-config-xml requires it",
                        "error_type": "NoCandidate"}

            if confirm_timeout and not _has_persistent_confirmed_commit(m):
                return {"success": False, "host": conn["host"], "device_name": device_name,
                        "error": "device does not advertise :confirmed-commit:1.1 — refusing to push "
                                 "without a device-side rollback timer (no fallback to a plain commit)",
                        "error_type": "NoConfirmedCommit",
                        "committed": False}

            lock_wait, lock_error = _try_candidate_lock(m, conn)
            if lock_error is not None:
                return dict(_candidate_locked_result(conn, device_name, lock_error, lock_wait), drift_check=drift_check)
            try:
                # IOS XE's candidate is a single global datastore, not per-session.
                # The lock grants exclusive write access; it does NOT guarantee an
                # empty candidate. Without this, edit_config stacks on top of
                # whatever a prior or killed session left staged, and commit
                # pushes all of it.
                m.discard_changes()

                m.edit_config(target="candidate", config=config_xml)

                # Validate before commit when the device supports it. A failure
                # here refuses the commit; the except below discards the candidate.
                validate_result = "unsupported"
                if _has_validate(m):
                    try:
                        m.validate(source="candidate")
                        validate_result = "valid"
                    except RPCError as e:
                        m.discard_changes()
                        return {
                            "success": False,
                            "host": conn["host"],
                            "device_name": device_name,
                            "error": f"candidate failed validation — not committed: {e}",
                            "error_type": "ValidationFailed",
                            "drift_check": drift_check,
                            "rpc_tag": getattr(e, "tag", None),
                            "rpc_path": getattr(e, "path", None),
                            "committed": False,
                        }

                if confirm_timeout:
                    # Take the timestamp BEFORE the commit: the device starts its
                    # timer while processing the commit, so a deadline computed
                    # from before the call can only be earlier than the real one,
                    # never later.
                    started = datetime.now(timezone.utc)
                    commit_reply = m.commit(confirmed=True, timeout=str(confirm_timeout),
                                            persist=persist_id)
                    deadline = started + timedelta(seconds=confirm_timeout)
                else:
                    commit_reply = m.commit()

                result = {
                    "success": True,
                    "host": conn["host"],
                    "device_name": device_name,
                    "lock_wait_seconds": round(lock_wait, 2),
                    "datastore": "candidate",
                    "validate": validate_result,
                    "commit": getattr(commit_reply, "xml", str(commit_reply)),
                    "confirmed_commit": bool(confirm_timeout),
                    "drift_check": drift_check,
                }
                if confirm_timeout:
                    result.update({
                        "persist_id": persist_id,
                        "confirm_timeout": confirm_timeout,
                        "confirm_deadline_utc": deadline.strftime("%Y-%m-%d %H:%M:%S"),
                    })
                return result
            except Exception as inner:
                try:
                    m.discard_changes()
                except Exception:
                    pass
                failure = {
                    "success": False,
                    "host": conn["host"],
                    "device_name": device_name,
                    "error": str(inner),
                    "error_type": type(inner).__name__,
                    "drift_check": drift_check,
                }
                if confirm_timeout:
                    # If the commit reply was lost after the device applied it, the
                    # device state is unknown here. The persist_id lets a caller
                    # cancel it, and the device reverts it on its own at the timer.
                    failure["persist_id"] = persist_id
                    failure["confirmed_commit_state"] = "unknown"
                return failure
            finally:
                try:
                    m.unlock(target="candidate")
                except Exception:
                    pass

    except RPCError as e:
        return {"success": False, "host": conn["host"], "device_name": device_name,
                "error": str(e), "error_type": "RPCError",
                "rpc_tag": getattr(e, "tag", None),
                "rpc_type": getattr(e, "type", None),
                "rpc_severity": getattr(e, "severity", None),
                "rpc_info": getattr(e, "info", None),
                "rpc_path": getattr(e, "path", None)}
    except Exception as e:
        return {"success": False, "host": conn["host"], "device_name": device_name,
                "error": str(e), "error_type": type(e).__name__}


def discard(conn, args) -> dict:
    """Discard whatever is staged in the candidate datastore — e.g. to
    clear a dirty candidate flagged by netconf-preview-config
    (error_type=DirtyCandidate) without going through force_discard on the
    next preview call, or to recover from a partially-applied edit."""
    device_name = conn.get("device_name") or conn["host"]
    try:
        with _session(conn) as m:
            if not _has_candidate(m):
                return {"success": False, "host": conn["host"], "device_name": device_name,
                        "error": "device has no candidate datastore — nothing to discard"}
            lock_wait = _acquire_candidate_lock(m, conn["lock_timeout"], conn["lock_poll_interval"])
            try:
                m.discard_changes()
                return {
                    "success": True,
                    "host": conn["host"],
                    "device_name": device_name,
                    "lock_wait_seconds": round(lock_wait, 2),
                }
            finally:
                try:
                    m.unlock(target="candidate")
                except Exception:
                    pass
    except RPCError as e:
        return {"success": False, "host": conn["host"], "device_name": device_name,
                "error": str(e), "error_type": "RPCError",
                "rpc_tag": getattr(e, "tag", None),
                "rpc_type": getattr(e, "type", None),
                "rpc_severity": getattr(e, "severity", None),
                "rpc_info": getattr(e, "info", None),
                "rpc_path": getattr(e, "path", None)}
    except Exception as e:
        return {"success": False, "host": conn["host"], "device_name": device_name,
                "error": str(e), "error_type": type(e).__name__}


def _rpc_failure(conn, device_name, e) -> dict:
    return {"success": False, "host": conn["host"], "device_name": device_name,
            "error": str(e), "error_type": "RPCError",
            "rpc_tag": getattr(e, "tag", None),
            "rpc_type": getattr(e, "type", None),
            "rpc_severity": getattr(e, "severity", None),
            "rpc_info": getattr(e, "info", None),
            "rpc_path": getattr(e, "path", None)}


def confirm_commit(conn, args) -> dict:
    """Confirm a pending persistent confirmed commit started by
    netconf-send-command with confirm_timeout. Sends the confirming <commit>
    carrying the persist_id, which makes the change permanent in running. It
    does NOT save to startup — run netconf-save-config after this succeeds.

    Failure is expected and meaningful when the device's timer already ran out:
    the change was rolled back on its own and there is no pending confirmed
    commit left to confirm (a late click, or a device that lost management
    reachability after the push). success=False / confirmed=False means the
    change is NOT confirmed — treat the device as rolled back and verify."""
    device_name = conn.get("device_name") or conn["host"]
    persist_id = getattr(args, "persist_id", None)
    if not persist_id:
        return {"success": False, "confirmed": False, "host": conn["host"], "device_name": device_name,
                "error": "persist_id is required for action=netconf-confirm-commit"}
    try:
        with _session(conn) as m:
            if not _has_persistent_confirmed_commit(m):
                return {"success": False, "confirmed": False, "host": conn["host"],
                        "device_name": device_name,
                        "error": "device does not advertise :confirmed-commit:1.1",
                        "error_type": "NoConfirmedCommit"}
            m.commit(persist_id=persist_id)
            return {"success": True, "confirmed": True, "host": conn["host"],
                    "device_name": device_name, "persist_id": persist_id}
    except RPCError as e:
        return dict(_rpc_failure(conn, device_name, e), confirmed=False)
    except Exception as e:
        return {"success": False, "confirmed": False, "host": conn["host"], "device_name": device_name,
                "error": str(e), "error_type": type(e).__name__}


def cancel_commit(conn, args) -> dict:
    """Cancel a pending persistent confirmed commit now, rolling the device back
    to the config it had before the push instead of waiting for the timer."""
    device_name = conn.get("device_name") or conn["host"]
    persist_id = getattr(args, "persist_id", None)
    if not persist_id:
        return {"success": False, "rolled_back": False, "host": conn["host"], "device_name": device_name,
                "error": "persist_id is required for action=netconf-cancel-commit"}
    try:
        with _session(conn) as m:
            if not _has_persistent_confirmed_commit(m):
                return {"success": False, "rolled_back": False, "host": conn["host"],
                        "device_name": device_name,
                        "error": "device does not advertise :confirmed-commit:1.1",
                        "error_type": "NoConfirmedCommit"}
            m.cancel_commit(persist_id=persist_id)
            return {"success": True, "rolled_back": True, "host": conn["host"],
                    "device_name": device_name, "persist_id": persist_id}
    except RPCError as e:
        return dict(_rpc_failure(conn, device_name, e), rolled_back=False)
    except Exception as e:
        return {"success": False, "rolled_back": False, "host": conn["host"], "device_name": device_name,
                "error": str(e), "error_type": type(e).__name__}


# Two ways IOS XE exposes "write memory" over NETCONF. Which one a given
# image carries is not advertised reliably, so try them in order and report
# which one worked. (A lab switch was reported without cisco-ia on an earlier image —
# hence the fallback.)
_SAVE_CONFIG_RPCS = [
    ("cisco-ia:save-config", '<save-config xmlns="http://cisco.com/yang/cisco-ia"/>'),
    ("Cisco-IOS-XE-rpc:copy",
     '<copy xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-rpc">'
     "<source-drop-node-name>running-config</source-drop-node-name>"
     "<destination-drop-node-name>startup-config</destination-drop-node-name>"
     "</copy>"),
]

# NX-OS has no startup datastore over NETCONF and refuses the IOS XE RPCs;
# Cisco documents its own copy RPC in the device model (since 9.2(1)).
_NXOS_SAVE_CONFIG_RPCS = [
    ("cisco-nx-os-device:copy_running_config_src",
     '<copy_running_config_src xmlns="http://cisco.com/ns/yang/cisco-nx-os-device">'
     "<startup-config/>"
     "</copy_running_config_src>"),
]


_BACKUP_FILESYSTEMS = ("flash", "bootflash")


def _backup_filesystem(args):
    """The optional backup_filesystem argument, or None when unset/empty."""
    value = getattr(args, "backup_filesystem", None)
    return value if isinstance(value, str) and value != "" else None


def _backup_config(conn, device_name, filesystem) -> dict:
    """Copy running-config to <filesystem>:backup-<UTC YYYYMMDD-HHMMSS> with the
    Cisco-IOS-XE-rpc copy RPC (no cisco-ia path: it can only write startup).
    The startup-config is not touched."""
    destination = f"{filesystem}:backup-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"
    rpc_xml = ('<copy xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-rpc">'
               "<source-drop-node-name>running-config</source-drop-node-name>"
               f"<destination-drop-node-name>{destination}</destination-drop-node-name>"
               "</copy>")
    try:
        with _session(conn) as m:
            if _detect_platform(m) == "nxos":
                return {"success": False, "host": conn["host"], "device_name": device_name,
                        "error": "backup_filesystem is not supported on NX-OS",
                        "error_type": "NotSupported"}
            reply = m.dispatch(to_ele(rpc_xml))
            xml_str = reply.xml if hasattr(reply, "xml") else str(reply)
            tree = _etree.fromstring(xml_str.encode() if isinstance(xml_str, str) else xml_str)
            result_nodes = tree.xpath(".//*[local-name()='result']")
            return {
                "success": True,
                "host": conn["host"],
                "device_name": device_name,
                "method": "Cisco-IOS-XE-rpc:copy",
                "destination": destination,
                "result": result_nodes[0].text.strip() if result_nodes and result_nodes[0].text else None,
            }
    except RPCError as e:
        return dict(_rpc_failure(conn, device_name, e), destination=destination)
    except Exception as e:
        return {"success": False, "host": conn["host"], "device_name": device_name,
                "error": str(e), "error_type": type(e).__name__, "destination": destination}


def save_config(conn, args) -> dict:
    """Persist running-config to startup-config (NETCONF equivalent of
    `write memory`). A committed change only reaches running; without this a
    reload silently reverts it. Saves the WHOLE running config, not just the
    last change.

    With backup_filesystem (flash or bootflash) set it instead copies running
    to a timestamped file on that filesystem and leaves startup alone; the
    file URL comes back as `destination`."""
    device_name = conn.get("device_name") or conn["host"]
    backup_fs = _backup_filesystem(args)
    if backup_fs is not None:
        if backup_fs not in _BACKUP_FILESYSTEMS:
            return {"success": False, "host": conn["host"], "device_name": device_name,
                    "error": f"backup_filesystem must be one of {list(_BACKUP_FILESYSTEMS)}, got {backup_fs!r}",
                    "error_type": "InvalidBackupFilesystem"}
        return _backup_config(conn, device_name, backup_fs)
    attempts = []
    try:
        with _session(conn) as m:
            rpcs = _NXOS_SAVE_CONFIG_RPCS if _detect_platform(m) == "nxos" else _SAVE_CONFIG_RPCS
            for method, rpc_xml in rpcs:
                try:
                    reply = m.dispatch(to_ele(rpc_xml))
                except RPCError as e:
                    attempts.append({"method": method, "error": str(e),
                                     "rpc_tag": getattr(e, "tag", None)})
                    continue
                xml_str = reply.xml if hasattr(reply, "xml") else str(reply)
                tree = _etree.fromstring(xml_str.encode() if isinstance(xml_str, str) else xml_str)
                result_nodes = tree.xpath(".//*[local-name()='result']")
                return {
                    "success": True,
                    "host": conn["host"],
                    "device_name": device_name,
                    "method": method,
                    "result": result_nodes[0].text.strip() if result_nodes and result_nodes[0].text else None,
                    "failed_attempts": attempts,
                }
    except Exception as e:
        return {"success": False, "host": conn["host"], "device_name": device_name,
                "error": str(e), "error_type": type(e).__name__, "failed_attempts": attempts}
    return {"success": False, "host": conn["host"], "device_name": device_name,
            "error": "no supported save-config RPC on this device — running-config NOT saved to startup",
            "error_type": "SaveUnsupported", "failed_attempts": attempts}




# Interface types checked for leftover configuration: every physical type plus
# Port-channel. SVIs and Loopbacks are not part of the check.
_CHECK_PHYSICAL_TYPES = ("GigabitEthernet", "TwoGigabitEthernet", "FiveGigabitEthernet",
                         "TenGigabitEthernet", "TwentyFiveGigE", "FortyGigabitEthernet", "HundredGigE",
                         "AppGigabitEthernet")

_EXISTING_CONFIG_FILTER = (
    '<native xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-native">'
    "<interface>"
    + "".join(f"<{t}><name/><switchport-config/><channel-group/><vrf/></{t}>" for t in _CHECK_PHYSICAL_TYPES)
    + "<Port-channel><name/></Port-channel>"
    "</interface>"
    "<aaa/>"
    "<tacacs><server><name/></server></tacacs>"
    "</native>"
)

_FINDINGS_MAX = 20


def _ln(el) -> str:
    return _etree.QName(el).localname if isinstance(el.tag, str) else ""


def _kids(el, name):
    return [c for c in el if _ln(c) == name]


def _text(el) -> str:
    return (el.text or "").strip() if el is not None else ""


def _interface_findings(native) -> list:
    """One short line per physical port that carries access/trunk/channel-group
    configuration, plus one per Port-channel. The out-of-band management port
    (GigabitEthernet0/0, or whatever sits in Mgmt-vrf) is skipped. Only VLAN
    numbers, modes and the channel number are read, never anything else."""
    findings = []
    for interface in _kids(native, "interface"):
        for port in interface:
            kind = _ln(port)
            if kind not in _CHECK_PHYSICAL_TYPES and kind != "Port-channel":
                continue
            name = f"{kind}{_text((_kids(port, 'name') or [None])[0])}"
            if kind == "Port-channel":
                findings.append(name)
                continue
            vrfs = [_text(f) for v in _kids(port, "vrf") for f in _kids(v, "forwarding")]
            if name == "GigabitEthernet0/0" or "Mgmt-vrf" in vrfs:
                continue
            notes = []
            for sw in port.iter():
                if _ln(sw) != "switchport":
                    continue
                for vlan in sw.xpath("./*[local-name()='access']/*[local-name()='vlan']/*[local-name()='vlan']"):
                    if _text(vlan) and _text(vlan) != "1":
                        notes.append(f"access VLAN {_text(vlan)}")
                for mode in _kids(sw, "mode"):
                    for m_ in mode:
                        if _ln(m_) in ("access", "trunk"):
                            notes.append(f"mode {_ln(m_)}")
                for allowed in sw.xpath("./*[local-name()='trunk']/*[local-name()='allowed']"):
                    vlans = [_text(v) for v in allowed.iter() if _ln(v) == "vlans" and _text(v)]
                    notes.append(f"trunk allowed VLANs {','.join(vlans)}" if vlans else "trunk allowed VLANs")
            for group in _kids(port, "channel-group"):
                numbers = [_text(n) for n in _kids(group, "number")]
                notes.append(f"channel-group {numbers[0]}" if numbers and numbers[0] else "channel-group")
            notes = list(dict.fromkeys(notes))   # the device returns the new and the legacy switchport tree
            if notes:
                findings.append(f"{name}: {', '.join(notes)}")
    return findings


def _aaa_findings(native) -> list:
    findings = []
    for aaa in _kids(native, "aaa"):
        for child in aaa:
            kind = _ln(child)
            if kind == "new-model":
                findings.append("AAA: aaa new-model")
            elif kind in ("authentication", "authorization", "accounting"):
                findings.append(f"AAA: {kind}")
            elif kind == "group":
                findings.append("AAA: group server")
    return findings


def _tacacs_findings(native) -> list:
    servers = [s for t in _kids(native, "tacacs") for s in _kids(t, "server")]
    return [f"TACACS servers: {len(servers)}"] if servers else []


def existing_config_check(conn, args) -> dict:
    """Read-only check for configuration already on a staged device: a port with
    an access VLAN other than 1, a switchport mode, a trunk allowed list or a
    channel-group, any Port-channel, any AAA, any TACACS server. One get-config
    of running with a narrow subtree filter; no lock, no candidate. The config is
    evaluated here and only a short summary leaves: never the raw config, and
    never a key or secret value (the filter does not even ask for them).

    `found` is True when anything above exists; `findings` is capped, with the
    full count in `findings_total`. IOS XE only."""
    device_name = conn.get("device_name") or conn["host"]
    try:
        with _session(conn) as m:
            if _detect_platform(m) == "nxos":
                return {"success": False, "host": conn["host"], "device_name": device_name,
                        "error": "existing-config check is not supported on NX-OS",
                        "error_type": "NotSupported"}
            reply = m.get_config(source="running", filter=("subtree", _EXISTING_CONFIG_FILTER))
            tree = _etree.fromstring(reply.data_xml.encode())
    except RPCError as e:
        return _rpc_failure(conn, device_name, e)
    except Exception as e:
        return {"success": False, "host": conn["host"], "device_name": device_name,
                "error": str(e), "error_type": type(e).__name__}
    findings = []
    for native in tree.iter():
        if _ln(native) == "native":
            findings += _interface_findings(native) + _aaa_findings(native) + _tacacs_findings(native)
    return {"success": True, "host": conn["host"], "device_name": device_name,
            "found": bool(findings), "findings": findings[:_FINDINGS_MAX],
            "findings_total": len(findings)}


_DISPATCH = {
    "netconf-is-alive": is_alive,
    "netconf-get-config": get_config,
    "netconf-get-config-clis": get_config_clis,
    "netconf-preview-config": preview_config,
    "netconf-send-command": send_command,
    "netconf-discard": discard,
    "netconf-save-config": save_config,
    "netconf-existing-config-check": existing_config_check,
    "netconf-confirm-commit": confirm_commit,
    "netconf-cancel-commit": cancel_commit,
}


def _read_stdin_inventory():
    if sys.stdin.isatty():
        return None
    raw = sys.stdin.read()
    if not raw or not raw.strip():
        return None
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return None
    if not isinstance(data, dict) or "inventory_nodes" not in data:
        return None
    nodes = data.get("inventory_nodes") or []
    return nodes[0] if nodes else None


def _resolve_connection(args, node):
    attrs = (node or {}).get("attributes", {}) or {}

    def pick(cli_val, *attr_paths, default=None):
        if cli_val is not None:
            return cli_val
        for path in attr_paths:
            cursor = attrs
            for k in path:
                if not isinstance(cursor, dict):
                    cursor = None
                    break
                cursor = cursor.get(k)
            if cursor is not None:
                return cursor
        return default

    host = pick(args.host, ("itential_host",))
    user = pick(args.user, ("itential_user",))
    password = pick(args.password, ("itential_password",))
    port = pick(args.port, ("itential_driver_options", "netconf", "port"), default=830)
    timeout = pick(args.timeout, ("itential_driver_options", "netconf", "timeout"), default=90)
    lock_timeout = pick(args.lock_timeout, ("itential_driver_options", "netconf", "lock_timeout"), default=30)
    lock_poll_interval = pick(args.lock_poll_interval, ("itential_driver_options", "netconf", "lock_poll_interval"), default=2.0)

    missing = [name for name, val in [("host", host), ("user", user), ("password", password)] if not val]
    if missing:
        raise SystemExit(
            f"missing required connection field(s): {', '.join(missing)} "
            f"(provide via --{missing[0]} or inventory attribute itential_{missing[0]})"
        )

    return {
        "host": host,
        "port": int(port),
        "user": user,
        "password": password,
        "timeout": int(timeout),
        "lock_timeout": int(lock_timeout),
        "lock_poll_interval": float(lock_poll_interval),
        "device_name": (node or {}).get("name") or host,
    }


def _optional_int(value):
    """argparse type= for int flags that may arrive as '' — IAG5 forwards every
    decorator-declared key as a CLI flag even when the caller didn't set it,
    using '' as the unset sentinel. Plain type=int crashes on that; treat '' as
    unset so downstream default logic (_resolve_connection) applies."""
    if value is None or value == "":
        return None
    return int(value)


def _optional_float(value):
    if value is None or value == "":
        return None
    return float(value)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Cisco IOS XE NETCONF operations for IAG5")
    parser.add_argument("--op", default=os.environ.get("NETCONF_OP"),
                        choices=list(_DISPATCH.keys()),
                        help="Operation to perform. Defaults to NETCONF_OP env var.")
    parser.add_argument("--host", default=None)
    parser.add_argument("--port", type=_optional_int, default=None)
    parser.add_argument("--user", default=None)
    parser.add_argument("--password", default=None)
    parser.add_argument("--timeout", type=_optional_int, default=None)
    parser.add_argument("--lock_timeout", "--lock-timeout", dest="lock_timeout", type=_optional_int, default=None)
    parser.add_argument("--lock-poll-interval", type=_optional_float, default=None, dest="lock_poll_interval")
    parser.add_argument("--diff", nargs="?", const=True, default=None,
                        help="Default true. netconf-preview-config only — include a unified diff "
                             "(running vs candidate) in the result.")
    parser.add_argument("--force_discard", "--force-discard", dest="force_discard", nargs="?",
                        const=True, default=None,
                        help="Default false. netconf-preview-config only — if the candidate "
                             "datastore is dirty (differs from running), discard it and proceed "
                             "instead of returning error_type=DirtyCandidate.")
    parser.add_argument("--expect_running_hash", "--expect-running-hash", dest="expect_running_hash", default=None,
                        help="netconf-send-command only — optional drift guard. If set, running "
                             "config is re-fingerprinted before applying; a mismatch returns "
                             "error_type=ConfigDrift instead of applying.")
    parser.add_argument("--config_xml", "--config-xml", dest="config_xml", default=None,
                        help="A complete, pre-built NETCONF <config> XML payload — pushed as-is via "
                             "edit-config. Required for netconf-preview-config and "
                             "netconf-send-command.")
    parser.add_argument("--confirm_timeout", "--confirm-timeout", dest="confirm_timeout",
                        type=_optional_int, default=None,
                        help="netconf-send-command only — seconds. If set, the commit is a persistent "
                             "confirmed commit: the device rolls the change back on its own unless "
                             "netconf-confirm-commit is called with the returned persist_id in time. "
                             "Unset = plain commit.")
    parser.add_argument("--persist_id", "--persist-id", dest="persist_id", default=None,
                        help="netconf-confirm-commit / netconf-cancel-commit — the persist_id "
                             "returned by the netconf-send-command call that started the confirmed commit.")
    parser.add_argument("--backup_filesystem", "--backup-filesystem", dest="backup_filesystem", default=None,
                        help="netconf-save-config only — flash or bootflash. If set, copy running-config to "
                             "<filesystem>:backup-<UTC timestamp> instead of saving to startup.")
    parser.add_argument("--source", "--datastore", dest="source", default=None)
    parser.add_argument("--filter", default=None)
    return parser


def _normalize_args(args):
    for attr in ("source", "filter", "host", "user", "password", "config_xml", "expect_running_hash",
                 "persist_id", "backup_filesystem"):
        if getattr(args, attr, None) == "":
            setattr(args, attr, None)

    if getattr(args, "confirm_timeout", None) is not None and args.confirm_timeout <= 0:
        raise SystemExit(f"--confirm_timeout must be a positive number of seconds, got {args.confirm_timeout}")

    val = getattr(args, "force_discard", None)
    if val is None or val == "":
        args.force_discard = False
    elif isinstance(val, str):
        args.force_discard = val.lower() in ("true", "1", "yes")

    # diff defaults to True (netconf-preview-config includes the unified diff
    # unless explicitly turned off) — opposite polarity from force_discard,
    # kept as its own block rather than folded into that one.
    val = getattr(args, "diff", None)
    if val is None or val == "":
        args.diff = True
    elif isinstance(val, str):
        args.diff = val.lower() in ("true", "1", "yes")

    if args.source is None:
        args.source = "running"
    if args.source not in ("running", "candidate"):
        raise SystemExit(f"--source must be 'running' or 'candidate', got {args.source!r}")


def _format_for_humans(result, op):
    if op == "netconf-get-config":
        if not result.get("success"):
            return f"ERROR: {result.get('error', 'config retrieval failed')}"
        return result.get("config", "")

    if op == "netconf-get-config-clis":
        if not result.get("success"):
            return f"ERROR: {result.get('error', 'CLI render failed')}"
        text = result.get("config", "")
        if result.get("warning"):
            text = f"{text}\n\n# WARNING: {result['warning']}"
        return text

    return json.dumps(result, indent=2, default=str)


def main() -> int:
    args = build_parser().parse_args()
    if not args.op:
        raise SystemExit("--op flag or NETCONF_OP env var must be set")
    _normalize_args(args)
    node = _read_stdin_inventory()
    conn = _resolve_connection(args, node)
    result = _DISPATCH[args.op](conn, args)
    formatted = _format_for_humans(result, args.op)
    print(formatted)
    if not result.get("success"):
        print(formatted, file=sys.stderr)
    return 0 if result.get("success") else 1


if __name__ == "__main__":
    sys.exit(main())
