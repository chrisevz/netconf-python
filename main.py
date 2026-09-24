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
netconf-preview-config, netconf-send-command, netconf-discard.

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
import sys
import time
from contextlib import contextmanager

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


def _get_config_xml(m, source: str, filter_xml: str = None) -> str:
    """Fetch a datastore's config as pretty-printed XML text, over an
    already-open session. Plain <get-config> — always available regardless
    of train/platform, unlike get-modelled-config-clis."""
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


def is_alive(conn, args) -> dict:
    device_name = conn.get("device_name") or conn["host"]
    try:
        with _session(conn) as m:
            version = ""
            reply = m.get(filter=("subtree",
                "<native xmlns=\"http://cisco.com/ns/yang/Cisco-IOS-XE-native\"><version/></native>"
            ))
            try:
                xml_str = reply.data_xml if hasattr(reply, "data_xml") else str(reply)
                tree = _etree.fromstring(xml_str.encode() if isinstance(xml_str, str) else xml_str)
                nodes = tree.xpath(".//*[local-name()='version']")
                version = nodes[0].text.strip() if nodes and nodes[0].text else ""
            except Exception:
                pass
            return {
                "success": True,
                "alive": True,
                "host": conn["host"],
                "device_name": device_name,
                "output": version,
            }
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
    """sha256 of normalized text, first 16 hex chars — short fingerprint
    used for netconf-preview-config's running_hash and
    netconf-send-command's expect_running_hash drift guard. Always computed
    from the running-config XML (via _get_config_xml), never from a CLI
    render, so the drift guard works identically in both preview_mode
    outcomes."""
    return hashlib.sha256(_normalize_text(text).encode("utf-8")).hexdigest()[:16]


def _preview_render(m, running_xml: str, candidate_after_xml: str) -> dict:
    """Produce the operator-facing diff, trying the device's own CLI
    renderer first and falling back to a structural XML diff of plain
    get-config output when get-modelled-config-clis isn't available.

    Returns preview_mode ("device-rendered" or "xml-diff") alongside diff,
    has_changes, candidate_config, running_config, and render_warning —
    always all present, so a caller never has to guess which rendering
    produced the result.
    """
    running_clis, running_render_err = _get_modelled_config_clis(m, "running")
    if running_clis is not None:
        candidate_clis, candidate_render_err = _get_modelled_config_clis(m, "candidate")
        if candidate_clis is not None:
            diff_text = "\n".join(difflib.unified_diff(
                _diff_lines(running_clis), _diff_lines(candidate_clis),
                fromfile="running", tofile="candidate", lineterm="",
            ))
            return {
                "preview_mode": "device-rendered",
                "diff": diff_text,
                "has_changes": _normalize_text(running_clis) != _normalize_text(candidate_clis),
                "candidate_config": candidate_clis or "",
                "running_config": running_clis or "",
                "render_warning": running_render_err or candidate_render_err,
            }

    diff_text = "\n".join(difflib.unified_diff(
        _diff_lines(running_xml), _diff_lines(candidate_after_xml),
        fromfile="running", tofile="candidate", lineterm="",
    ))
    return {
        "preview_mode": "xml-diff",
        "diff": diff_text,
        "has_changes": _normalize_text(running_xml) != _normalize_text(candidate_after_xml),
        "candidate_config": candidate_after_xml or "",
        "running_config": running_xml or "",
        "render_warning": None,
    }


def preview_config(conn, args) -> dict:
    """Stage a proposed config_xml change, diff it against running, and
    leave zero state on the device — all in one session.

    Sequence: get-config(running) -> get-config(candidate) -> dirty check
    (if candidate already differs from running, another session has
    uncommitted work there — refuse with a dirty_diff unless force_discard,
    in which case discard it, no lock needed) -> lock candidate ->
    edit_config with the caller's config_xml -> validate (capability-gated,
    captured not raised) -> re-get-config(candidate) -> render/diff (device
    CLI render if available, else XML diff) -> discard_changes + unlock in
    a finally, discarding only if we actually edited.

    The dirty check runs BEFORE the lock, not after. A dirty candidate is
    exactly what makes lock(candidate) fail (operation-failed / "there are
    outstanding changes to the database" — confirmed live on IOS XE 17.15),
    so a dirty check placed after the lock is unreachable on the one input
    it exists to handle. This ordering only works because discard-changes
    requires no lock (RFC 6241 §8.3.4.2) — that's what makes a pre-lock
    discard possible at all. The dirty check itself uses plain get-config,
    not get-modelled-config-clis — it must work identically whether or not
    the render RPC is available on this train.

    Because of this, the DirtyCandidate return happens before any lock is
    taken, so it has no lock_wait_seconds key. That's expected — its
    absence itself signals the call never reached the lock.

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

    force_discard = getattr(args, "force_discard", False)
    include_diff = getattr(args, "diff", True)

    try:
        with _session(conn) as m:
            if not _has_candidate(m):
                return {"success": False, "host": conn["host"], "device_name": device_name,
                        "error": "device has no candidate datastore — netconf-preview-config requires it"}

            running_xml = _get_config_xml(m, "running")
            candidate_before_xml = _get_config_xml(m, "candidate")

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
                        "committed": False,
                    }
                # force_discard=true: clear it now, before locking — discard-changes
                # requires no lock (RFC 6241 §8.3.4.2). Must stay gated on
                # force_discard, never unconditional, or preview silently destroys
                # another session's pending work.
                m.discard_changes()

            running_hash = _text_hash(running_xml)

            lock_wait = _acquire_candidate_lock(m, conn["lock_timeout"], conn["lock_poll_interval"])
            edited = False
            try:
                # Set before the call, not after: a raising edit_config may have
                # partially applied. The discard in the finally is most needed on
                # exactly that path.
                edited = True
                m.edit_config(target="candidate", config=config_xml)

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

                candidate_after_xml = _get_config_xml(m, "candidate")
                render = _preview_render(m, running_xml, candidate_after_xml)
                if not include_diff:
                    render["diff"] = None

                return {
                    "success": True,
                    "host": conn["host"],
                    "device_name": device_name,
                    "lock_wait_seconds": round(lock_wait, 2),
                    "valid": valid,
                    "validate": validate_result,
                    "preview_mode": render["preview_mode"],
                    "diff": render["diff"],
                    "has_changes": render["has_changes"],
                    "candidate_config": render["candidate_config"],
                    "running_config": render["running_config"],
                    "running_hash": running_hash,
                    "warning": render["render_warning"],
                    "committed": False,
                }
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
    operator review, so staging-then-later-finishing is not supported."""
    device_name = conn.get("device_name") or conn["host"]
    config_xml = getattr(args, "config_xml", None)
    if not config_xml:
        return {"success": False, "host": conn["host"], "device_name": device_name,
                "error": "config_xml is required for action=netconf-send-command"}
    expect_running_hash = getattr(args, "expect_running_hash", None)

    try:
        with _session(conn) as m:
            if expect_running_hash:
                # Drift guard: caller captured running_hash from an earlier
                # netconf-preview-config call and wants to be sure nothing else
                # changed running config in between. Re-fingerprint before
                # touching candidate at all, and refuse to apply on a mismatch.
                current_running_xml = _get_config_xml(m, "running")
                actual_hash = _text_hash(current_running_xml)
                if actual_hash != expect_running_hash:
                    return {
                        "success": False,
                        "host": conn["host"],
                        "device_name": device_name,
                        "error": "running config has drifted since expect_running_hash was captured — refusing to apply",
                        "error_type": "ConfigDrift",
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

            lock_wait = _acquire_candidate_lock(m, conn["lock_timeout"], conn["lock_poll_interval"])
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
                            "rpc_tag": getattr(e, "tag", None),
                            "rpc_path": getattr(e, "path", None),
                            "committed": False,
                        }

                commit_reply = m.commit()

                return {
                    "success": True,
                    "host": conn["host"],
                    "device_name": device_name,
                    "lock_wait_seconds": round(lock_wait, 2),
                    "datastore": "candidate",
                    "validate": validate_result,
                    "commit": getattr(commit_reply, "xml", str(commit_reply)),
                }
            except Exception as inner:
                try:
                    m.discard_changes()
                except Exception:
                    pass
                return {
                    "success": False,
                    "host": conn["host"],
                    "device_name": device_name,
                    "error": str(inner),
                    "error_type": type(inner).__name__,
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


_DISPATCH = {
    "netconf-is-alive": is_alive,
    "netconf-get-config": get_config,
    "netconf-get-config-clis": get_config_clis,
    "netconf-preview-config": preview_config,
    "netconf-send-command": send_command,
    "netconf-discard": discard,
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
    parser.add_argument("--source", "--datastore", dest="source", default=None)
    parser.add_argument("--filter", default=None)
    return parser


def _normalize_args(args):
    for attr in ("source", "filter", "host", "user", "password", "config_xml", "expect_running_hash"):
        if getattr(args, attr, None) == "":
            setattr(args, attr, None)

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
    if op == "netconf-is-alive":
        return "true" if result.get("alive", False) else "false"

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
    print(formatted, end="" if args.op == "netconf-is-alive" else "\n")
    if not result.get("success"):
        print(formatted, file=sys.stderr)
    return 0 if result.get("success") else 1


if __name__ == "__main__":
    sys.exit(main())
