#!/usr/bin/env python3
"""Cisco NETCONF service for IAG5 — IOS XE and NX-OS.

Provides NETCONF-based operations for Cisco IOS XE (CSR1000v, ISR, ASR, Cat9k, etc.)
and Cisco NX-OS (Nexus 3K/7K/9K) devices via a single driver. The NETCONF transport
mechanics (connect, candidate datastore, lock, commit-confirm) are identical across
both platforms — only the device handler and exec/config payload shape differ.

Requires on the device:
    netconf-yang (IOS XE) / feature netconf (NX-OS)
    (optional) candidate-datastore support   ← enables candidate + commit

Actions: netconf-is-alive, netconf-run-command, netconf-get-config, netconf-get-config-clis,
netconf-preview-config, netconf-send-command, netconf-commit, netconf-discard, netconf-reboot

netconf-send-command's do_commit=false stages a change into candidate (validated, not
committed, not discarded) and returns — leaving it for a caller to render/diff separately
(e.g. via netconf-get-config-clis with datastore=candidate) and then finish with a later
netconf-commit or netconf-discard call. This driver does no rendering-format or diffing
itself for that path; that's left to the calling platform/workflow.

netconf-preview-config (IOS XE only) is the single-shot alternative: it stages, diffs
running vs candidate via difflib, and discards, all within one session, leaving zero
state on the device. Refuses to touch a dirty candidate (uncommitted work from another
session) unless force_discard is set. netconf-send-command's expect_running_hash lets a
caller guard against running config having drifted since a netconf-preview-config call
captured its hash.

Platform is resolved from (in order): --platform CLI flag, inventory attribute
"platform" (e.g. "IOS XE" / "NX-OS"), default "ios-xe" for backward compatibility.

Connection parameters are read from stdin as JSON in the gateway5 InventoryInfo format:

    {"inventory_nodes": [{"name": "...", "attributes": {
        "platform": "IOS XE",
        "itential_host": "...", "itential_user": "...",
        "itential_password": "...",
        "itential_driver_options": {"netconf": {"port": 830, ...}}
    }}]}

CLI flags for connection params override stdin values — useful for local testing.
"""

import argparse
import difflib
import hashlib
import json
import os
import sys
import time
from contextlib import contextmanager
from xml.sax.saxutils import escape as _xml_escape

import lxml.etree as _etree

from ncclient import manager
from ncclient.xml_ import to_ele
from ncclient.operations.rpc import RPCError
from ncclient.transport.errors import AuthenticationError, SSHError

# Cisco IOS XE exec-command RPC namespace (cisco-ia YANG module)
_CISCO_IA_NS = "http://cisco.com/yang/cisco-ia"

# Cisco IOS XE get-modelled-config-clis RPC namespace (Cisco-IOS-XE-cli-rpc YANG
# module, revision 2024-07-01). RPC-only module — not advertised in the NETCONF
# hello capability list even when present, so don't gate on capability checks;
# just call it and handle unknown-element the same way exec-command does.
_CLI_RPC_NS = "http://cisco.com/ns/yang/Cisco-IOS-XE-cli-rpc"

_PLATFORM_IOSXE = "ios-xe"
_PLATFORM_NXOS = "nx-os"

# ncclient device_params["name"] per platform — selects the ncclient device handler
# (iosxe: generic IETF-style handler; nexus: ncclient's built-in Nexus handler, which
# registers a native exec_command() RPC operation for Cisco-NXOS-namespaced exec-command).
_DEVICE_PARAMS = {
    _PLATFORM_IOSXE: {"name": "iosxe"},
    _PLATFORM_NXOS: {"name": "nexus"},
}


def _normalize_platform(raw) -> str:
    """Map a free-text platform string (from Netbox/inventory) to ios-xe or nx-os."""
    if not raw:
        return _PLATFORM_IOSXE
    val = str(raw).strip().lower().replace(" ", "").replace("_", "")
    if val in ("nxos", "nx-os", "nexus", "cisconxos"):
        return _PLATFORM_NXOS
    if val in ("iosxe", "ios-xe", "ciscoiosxe"):
        return _PLATFORM_IOSXE
    raise SystemExit(f"unsupported platform {raw!r}; expected 'IOS XE' or 'NX-OS'")


def _connect(conn):
    return manager.connect(
        host=conn["host"],
        port=conn["port"],
        username=conn["user"],
        password=conn["password"],
        hostkey_verify=False,
        device_params=_DEVICE_PARAMS[conn["platform"]],
        timeout=conn["timeout"],
        allow_agent=False,
        look_for_keys=False,
    )


@contextmanager
def _session(conn):
    """Wrap _connect() so a failure while gracefully closing the NETCONF session
    never clobbers a result already computed inside the `with` block. A device
    dropping the connection right after a commit, an exec RPC, or a reload is
    normal, not exceptional — but ncclient's Manager.__exit__() calls
    close_session() and lets any error from that RPC propagate, which would
    otherwise turn an operation that already succeeded on the device into a
    reported failure.
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


def _has_candidate(m) -> bool:
    """Return True if the device advertises the candidate datastore capability."""
    return ":candidate" in str(m.server_capabilities)


def _extract_exec_output(reply) -> str:
    """Best-effort extraction of exec output text from an RPC reply, regardless
    of which namespace/element names the device used (IOS XE cisco-ia vs
    NX-OS Cisco-NXOS exec-command reply shapes differ)."""
    xml_str = reply.xml if hasattr(reply, "xml") else str(reply)
    tree = _etree.fromstring(xml_str.encode() if isinstance(xml_str, str) else xml_str)
    for tag in ("result", "output", "cli-output", "msg"):
        nodes = tree.xpath(f".//{tag}") or tree.xpath(f".//*[local-name()='{tag}']")
        if nodes and nodes[0].text:
            return nodes[0].text
    return _etree.tostring(tree, pretty_print=True).decode().strip()


def _exec_command_iosxe(m, command: str) -> str:
    """Run a single exec-mode command via the Cisco IOS XE cisco-ia exec RPC."""
    rpc_xml = (
        f'<exec-command xmlns="{_CISCO_IA_NS}">'
        f"<ios-config-data>{_xml_escape(command)}</ios-config-data>"
        f"</exec-command>"
    )
    try:
        reply = m.dispatch(to_ele(rpc_xml))
    except RPCError as e:
        # unknown-element means the device does not have the cisco-ia YANG module
        tag = getattr(e, "tag", "") or ""
        if "unknown-element" in tag or "unknown-element" in str(e):
            raise RuntimeError(
                f"exec-command RPC not supported on this device — "
                f"enable 'netconf-yang' and ensure the Cisco-IOS-XE-ia YANG module is present. "
                f"Command: {command!r}"
            ) from e
        raise
    return _extract_exec_output(reply)


def _exec_command_nxos(m, command: str) -> str:
    """Run a single exec-mode command via ncclient's native Nexus exec_command()
    RPC (legacy Cisco-NXOS 1.0 namespace). Registered automatically by
    device_params {"name": "nexus"} — see ncclient.devices.nexus.NexusDeviceHandler.

    Confirmed against a live NX-OS 9.2(4) 9000v device (feature netconf enabled,
    candidate/confirmed-commit capabilities present) that this legacy RPC is simply
    not implemented — the device only advertises the native Cisco-NX-OS-device YANG
    model. So this is not universally available; treat failure here as "this
    platform/version needs structured native-YANG get/edit-config", not a config
    problem on the device.
    """
    try:
        reply = m.exec_command([command])
    except RPCError as e:
        raise RuntimeError(
            f"legacy exec-command RPC (nxos:1.0 namespace) not supported on this "
            f"NX-OS device — this device only supports the native Cisco-NX-OS-device "
            f"YANG model; show-command output needs a structured <get> instead. "
            f"Command: {command!r}. Detail: {e}"
        ) from e
    return _extract_exec_output(reply)


def _exec_command(m, platform: str, command: str, timeout: int = None) -> str:
    """Run a single exec-mode command, dispatched by platform.

    Returns the text output or raises RPCError/RuntimeError on failure.
    """
    original_timeout = m.timeout
    if timeout is not None:
        m.timeout = timeout
    try:
        if platform == _PLATFORM_NXOS:
            return _exec_command_nxos(m, command)
        return _exec_command_iosxe(m, command)
    finally:
        m.timeout = original_timeout


def is_alive(conn, args) -> dict:
    device_name = conn.get("device_name") or conn["host"]
    platform = conn["platform"]
    try:
        with _session(conn) as m:
            version = ""
            if platform == _PLATFORM_IOSXE:
                # Use standard NETCONF <get> with a minimal filter — works on all IOS XE
                # without requiring the cisco-ia YANG module.
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
            else:
                # NX-OS spans 8.2(6a) through 10.4(4) in scope — no single native YANG
                # container is guaranteed present across that whole range, so treat a
                # successful NETCONF capability exchange itself as the "alive" proof
                # rather than assuming a specific model.
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


def run_command(conn, args) -> dict:
    if not args.command:
        return {"success": False, "host": conn["host"], "error": "command is required for action=netconf-run-command"}
    results = []
    try:
        with _session(conn) as m:
            cmd_timeout = conn.get("command_timeout")
            for cmd in args.command:
                try:
                    output = _exec_command(m, conn["platform"], cmd, timeout=cmd_timeout)
                    results.append({"command": cmd, "output": output or "", "success": True})
                except RuntimeError as e:
                    # Clean message when exec RPC is unsupported
                    results.append({"command": cmd, "output": str(e), "success": False, "error": str(e)})
                except RPCError as e:
                    error_msg = getattr(e, "message", None) or f"RPC error: tag={getattr(e, 'tag', 'unknown')}"
                    results.append({"command": cmd, "output": error_msg, "success": False, "error": error_msg})
        return {"success": all(r["success"] for r in results), "host": conn["host"], "results": results}
    except Exception as e:
        return {"success": False, "host": conn["host"], "error": str(e), "error_type": type(e).__name__, "results": results}


_CONFIG_FORMATS = ("xml", "text", "set")


def get_config(conn, args) -> dict:
    fmt = conn.get("config_format") or "xml"
    if fmt not in _CONFIG_FORMATS:
        return {"success": False, "host": conn["host"],
                "error": f"unsupported config_format {fmt!r}; choose from {_CONFIG_FORMATS}"}
    try:
        with _session(conn) as m:
            if fmt == "xml":
                reply = m.get_config(
                    source=args.source,
                    filter=("subtree", args.filter) if args.filter else None,
                )
                try:
                    tree = _etree.fromstring(reply.data_xml.encode())
                    config_xml = _etree.tostring(tree, pretty_print=True).decode().strip()
                except Exception:
                    config_xml = reply.data_xml
                return {"success": True, "host": conn["host"], "source": args.source,
                        "config_format": fmt, "config": config_xml}

            # text: "show running-config"
            # set:  "show running-config | format"  (neither platform has a native
            #        set-style output; we return running config as text — callers
            #        should treat it as text)
            cmd = "show running-config"
            output = _exec_command(m, conn["platform"], cmd)
            return {"success": True, "host": conn["host"], "source": "running",
                    "config_format": fmt, "config": (output or "").strip()}
    except Exception as e:
        return {"success": False, "host": conn["host"], "error": str(e), "error_type": type(e).__name__}


def _get_modelled_config_clis(m, datastore: str = "running"):
    """Call get-modelled-config-clis and return (result_text, error_message).

    This is the RPC behind the operator CLI preview: it renders a whole datastore
    (running or candidate) as CLI text via the device's own modelled-config-to-CLI
    conversion — not a screen-scrape of an exec command, and not limited to
    running like the exec-based get-config text/set formats are.

    error_message is a normal *output leaf* on a successful RPC reply (the device
    telling us it couldn't render something, e.g. wireless/app-hosting/telemetry
    per Cisco's own docs) — distinct from an RPCError, which means the RPC itself
    failed at the transport/protocol level.
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
                "requires the Cisco-IOS-XE-cli-rpc YANG module."
            )
        raise
    xml_str = reply.xml if hasattr(reply, "xml") else str(reply)
    tree = _etree.fromstring(xml_str.encode() if isinstance(xml_str, str) else xml_str)
    result_nodes = tree.xpath(".//*[local-name()='result']")
    error_nodes = tree.xpath(".//*[local-name()='error-message']")
    result = result_nodes[0].text if result_nodes and result_nodes[0].text else None
    error = error_nodes[0].text if error_nodes and error_nodes[0].text else None
    return result, error


def get_config_clis(conn, args) -> dict:
    """Render a datastore as CLI text via get-modelled-config-clis — the actual
    mechanism behind the operator CLI preview (see netconf-driver-handoff doc §3).
    IOS XE only; NX-OS does not have this RPC."""
    datastore = args.source or "running"
    if conn["platform"] != _PLATFORM_IOSXE:
        return {
            "success": False,
            "host": conn["host"],
            "datastore": datastore,
            "error": "get-modelled-config-clis is IOS XE only — not available on NX-OS.",
            "error_type": "NotImplementedError",
        }
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
                # skipped rather than raising). Don't swallow it (§5.4 — whether
                # unsupported features error or silently omit is still unconfirmed
                # per-platform; this at least reports it when the device does tell us).
                "warning": error,
            }
    except Exception as e:
        return {"success": False, "host": conn["host"], "datastore": datastore,
                "error": str(e), "error_type": type(e).__name__}


def _build_cli_config_xml_iosxe(commands: list) -> str:
    """Build a NETCONF <config> payload using Cisco IOS XE cli-config-data.

    cli-config-data lets edit-config accept raw CLI text and have it parsed as if
    typed at the CLI — this is what lets IOS XE config push work generically across
    IOS versions without per-section native YANG modeling.
    """
    cmd_elements = "".join(f"<cmd>{_xml_escape(c)}</cmd>" for c in commands)
    return (
        f'<config>'
        f'<cli-config-data xmlns="{_CISCO_IA_NS}">'
        f"{cmd_elements}"
        f"</cli-config-data>"
        f"</config>"
    )


def _build_config_xml(platform: str, commands: list) -> str:
    """Build a NETCONF <config> payload for the candidate datastore, per platform."""
    if platform == _PLATFORM_NXOS:
        # CONFIRMED against live NX-ATL (NX-OS 9.2(4), 9000v): get-config returns a
        # single advertised model, the Cisco-NX-OS-device DME/MIT-style object tree
        # (class-based, e.g. <System><arp-items><inst-items>...), not a flat
        # CLI-mirrored native model like IOS XE's. There is no raw-CLI-text-in-
        # edit-config equivalent of cli-config-data here — real config push needs a
        # structured payload built against this exact DME tree, per config section
        # (port channel, SVI, OSPF, BGP, VPC, etc). That's template/workflow-layer
        # work (matches the spec's own risk mitigation: "separate Jinja2 XML
        # templates for Nexus"), not something this driver can generate generically
        # from a list of raw CLI strings.
        raise NotImplementedError(
            "NX-OS config push needs structured Cisco-NX-OS-device YANG per config "
            "section — raw CLI-text push (the IOS XE cli-config-data trick) is not "
            "supported on this platform. Confirmed live against NX-ATL 9.2(4)."
        )
    return _build_cli_config_xml_iosxe(commands)


def _acquire_candidate_lock(m, timeout: int, poll_interval: float) -> float:
    deadline = time.monotonic() + max(timeout, 0)
    start = time.monotonic()
    while True:
        try:
            m.lock(target="candidate")
            return time.monotonic() - start
        except RPCError as e:
            msg = str(e).lower()
            transient = (
                getattr(e, "tag", None) == "lock-denied"
                or "lock-denied" in msg
                or "lock denied" in msg
                or "in-use" in msg
                or "in use" in msg
                or "configuration database locked" in msg
            )
            if not transient or timeout == 0 or time.monotonic() >= deadline:
                raise
            time.sleep(poll_interval)


def _normalize_cli(text: str) -> str:
    """rstrip each line, drop blank lines, join with \\n. Used for both the
    dirty-candidate check and the diff inputs in netconf-preview-config, so
    trailing whitespace / blank-line noise from the renderer doesn't produce
    false differences."""
    if not text:
        return ""
    lines = (line.rstrip() for line in text.splitlines())
    return "\n".join(line for line in lines if line)


def _cli_hash(text: str) -> str:
    """sha256 of normalized CLI text, first 16 hex chars — short fingerprint
    used for netconf-preview-config's running_hash and netconf-send-command's
    expect_running_hash drift guard."""
    return hashlib.sha256(_normalize_cli(text).encode("utf-8")).hexdigest()[:16]


def preview_config(conn, args) -> dict:
    """Stage a proposed change, diff it against running, and leave zero state on
    the device — all in one session. IOS XE only (get-modelled-config-clis has
    no NX-OS equivalent).

    Sequence: lock candidate -> render running -> render candidate (dirty check:
    if it already differs from running, another session has uncommitted work
    there; refuse unless force_discard) -> discard_changes -> edit_config with
    the caller's payload -> validate (captured, not raised) -> re-render
    candidate -> diff running vs candidate -> discard_changes + unlock in a
    finally, discarding only if we actually edited.

    Never commits (committed is always False in the result) and never leaves
    the candidate populated or locked, on any exit path. This depends on
    `edited` being set to True immediately before the edit_config call, not
    after — a raising edit_config (e.g. cli-config-data applying commands
    sequentially and failing partway through) still needs the finally's
    discard. Don't reorder it back.
    """
    device_name = conn.get("device_name") or conn["host"]
    if conn["platform"] != _PLATFORM_IOSXE:
        return {
            "success": False,
            "host": conn["host"],
            "device_name": device_name,
            "error": "netconf-preview-config is IOS XE only — not available on NX-OS.",
            "error_type": "NotImplementedError",
        }

    raw_config_xml = getattr(args, "config_xml", None)
    if not args.command and not raw_config_xml:
        return {"success": False, "host": conn["host"], "device_name": device_name,
                "error": "command or config_xml is required for action=netconf-preview-config"}
    if raw_config_xml:
        config_xml = raw_config_xml
    else:
        try:
            config_xml = _build_config_xml(conn["platform"], args.command)
        except NotImplementedError as e:
            return {"success": False, "host": conn["host"], "device_name": device_name,
                    "error": str(e), "error_type": "NotImplementedError"}

    force_discard = getattr(args, "force_discard", False)
    include_diff = getattr(args, "diff", True)

    try:
        with _session(conn) as m:
            if not _has_candidate(m):
                return {"success": False, "host": conn["host"], "device_name": device_name,
                        "error": "device has no candidate datastore — netconf-preview-config requires it"}

            lock_wait = _acquire_candidate_lock(m, conn["lock_timeout"], conn["lock_poll_interval"])
            edited = False
            try:
                running_clis, running_err = _get_modelled_config_clis(m, "running")
                if running_clis is None:
                    return {
                        "success": False, "host": conn["host"], "device_name": device_name,
                        "commands": args.command, "lock_wait_seconds": round(lock_wait, 2),
                        "error": running_err or "CLI render of running returned no result",
                        "error_type": "RPCError", "committed": False,
                    }

                candidate_before, candidate_before_err = _get_modelled_config_clis(m, "candidate")
                if candidate_before is None:
                    return {
                        "success": False, "host": conn["host"], "device_name": device_name,
                        "commands": args.command, "lock_wait_seconds": round(lock_wait, 2),
                        "error": candidate_before_err or "CLI render of candidate returned no result",
                        "error_type": "RPCError", "committed": False,
                    }

                running_norm = _normalize_cli(running_clis)
                candidate_before_norm = _normalize_cli(candidate_before)
                if running_norm != candidate_before_norm and not force_discard:
                    return {
                        "success": False, "host": conn["host"], "device_name": device_name,
                        "commands": args.command, "lock_wait_seconds": round(lock_wait, 2),
                        "error": "candidate datastore is dirty (differs from running) — another "
                                 "session may have uncommitted work staged there. Pass "
                                 "force_discard=true to discard it and proceed.",
                        "error_type": "DirtyCandidate", "committed": False,
                    }

                # Clear candidate before staging our own edit — a no-op if it
                # already matched running; discards another session's stray
                # work if force_discard was needed to get past the check above.
                m.discard_changes()

                # Set before the call, not after: cli-config-data applies commands
                # sequentially, so a raising edit_config may have partially applied.
                # The discard in the finally is most needed on exactly that path.
                edited = True
                m.edit_config(target="candidate", config=config_xml)

                try:
                    m.validate(source="candidate")
                    valid = True
                    validate_result = "valid"
                except RPCError as e:
                    valid = False
                    validate_result = str(e)

                candidate_after, candidate_after_err = _get_modelled_config_clis(m, "candidate")
                candidate_after_norm = _normalize_cli(candidate_after)

                diff_text = None
                if include_diff:
                    diff_text = "\n".join(difflib.unified_diff(
                        running_norm.splitlines(), candidate_after_norm.splitlines(),
                        fromfile="running", tofile="candidate", lineterm="",
                    ))

                return {
                    "success": True,
                    "host": conn["host"],
                    "device_name": device_name,
                    "commands": args.command,
                    "lock_wait_seconds": round(lock_wait, 2),
                    "valid": valid,
                    "validate": validate_result,
                    "diff": diff_text,
                    "has_changes": running_norm != candidate_after_norm,
                    "candidate_config": candidate_after or "",
                    "running_config": running_clis or "",
                    "running_hash": _cli_hash(running_clis),
                    "warning": running_err or candidate_before_err or candidate_after_err,
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
                "commands": args.command, "committed": False,
                "error": str(e), "error_type": "RPCError",
                "rpc_tag": getattr(e, "tag", None),
                "rpc_type": getattr(e, "type", None),
                "rpc_severity": getattr(e, "severity", None),
                "rpc_info": getattr(e, "info", None),
                "rpc_path": getattr(e, "path", None)}
    except Exception as e:
        return {"success": False, "host": conn["host"], "device_name": device_name,
                "commands": args.command, "error": str(e), "error_type": type(e).__name__,
                "committed": False}


def send_command(conn, args) -> dict:
    device_name = conn.get("device_name") or conn["host"]
    raw_config_xml = getattr(args, "config_xml", None)
    if not args.command and not raw_config_xml:
        return {"success": False, "host": conn["host"], "device_name": device_name,
                "error": "command or config_xml is required for action=netconf-send-command"}
    dry_run = getattr(args, "dry_run", False)
    do_commit = getattr(args, "do_commit", True)
    confirmed = getattr(args, "confirmed", False)
    confirm_timeout = getattr(args, "confirm_timeout", None) or 10
    expect_running_hash = getattr(args, "expect_running_hash", None)

    if raw_config_xml:
        # Caller supplies an already-valid NETCONF <config> payload (e.g. generated
        # by a workflow's Jinja2 templates, per the spec's design). The driver's job
        # is just to push it — no CLI-to-XML conversion, no platform-specific
        # wrapping. This is the generic path: it works identically on any platform
        # as long as the XML is valid for that device's YANG model. Confirmed live
        # against NX-ATL (Cisco-NX-OS-device model) — edit_config/validate/commit
        # all succeeded with a hand-built native-YANG payload.
        config_xml = raw_config_xml
    else:
        try:
            config_xml = _build_config_xml(conn["platform"], args.command)
        except NotImplementedError as e:
            return {"success": False, "host": conn["host"], "device_name": device_name,
                    "error": str(e), "error_type": "NotImplementedError"}

    try:
        with _session(conn) as m:
            if expect_running_hash:
                # Drift guard: caller captured running_hash from an earlier
                # netconf-preview-config call and wants to be sure nothing else
                # changed running config in between. Re-render+hash before
                # touching candidate at all, and refuse to apply on a mismatch.
                if conn["platform"] != _PLATFORM_IOSXE:
                    return {
                        "success": False,
                        "host": conn["host"],
                        "device_name": device_name,
                        "error": "expect_running_hash drift guard is IOS XE only — not available on NX-OS.",
                        "error_type": "NotImplementedError",
                    }
                current_running, _current_running_err = _get_modelled_config_clis(m, "running")
                actual_hash = _cli_hash(current_running or "")
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

            use_candidate = _has_candidate(m)

            if use_candidate:
                lock_wait = _acquire_candidate_lock(m, conn["lock_timeout"], conn["lock_poll_interval"])
                try:
                    # IOS XE's candidate is a single global datastore, not per-session.
                    # The lock grants exclusive write access; it does NOT guarantee an
                    # empty candidate. Without this, edit_config stacks on top of
                    # whatever a prior or killed session left staged, and commit
                    # pushes all of it.
                    m.discard_changes()

                    m.edit_config(target="candidate", config=config_xml)

                    if dry_run:
                        try:
                            m.validate(source="candidate")
                            validate_result = "valid"
                        except RPCError as e:
                            validate_result = str(e)
                        m.discard_changes()
                        return {
                            "success": True,
                            "host": conn["host"],
                            "device_name": device_name,
                            "commands": args.command,
                            "lock_wait_seconds": round(lock_wait, 2),
                            "dry_run": True,
                            "committed": False,
                            "validate": validate_result,
                        }

                    if not do_commit:
                        # Stage and leave it in candidate — no discard, no commit.
                        # The candidate datastore is device-side state, not tied to
                        # this NETCONF session, so it's expected to still be there
                        # for a later, separate netconf-get-config-clis(candidate)
                        # render or a netconf-commit/netconf-discard call. Unlock
                        # here rather than holding it open across an operator's
                        # review — a long-held lock would block other automation
                        # touching this device for however long that review takes.
                        try:
                            m.validate(source="candidate")
                            validate_result = "valid"
                        except RPCError as e:
                            validate_result = str(e)
                        return {
                            "success": True,
                            "host": conn["host"],
                            "device_name": device_name,
                            "commands": args.command,
                            "lock_wait_seconds": round(lock_wait, 2),
                            "staged": True,
                            "committed": False,
                            "validate": validate_result,
                        }

                    commit_reply = m.commit(
                        confirmed=confirmed,
                        # ncclient's confirmed-commit builder requires timeout as a
                        # string — passing an int raises TypeError inside ncclient
                        # itself (confirmed live against NX-ATL 9.2(4); latent bug,
                        # not platform-specific — argparse gives us an int).
                        timeout=str(confirm_timeout) if confirmed else None,
                    )
                    result = {
                        "success": True,
                        "host": conn["host"],
                        "device_name": device_name,
                        "commands": args.command,
                        "lock_wait_seconds": round(lock_wait, 2),
                        "datastore": "candidate",
                        "commit": getattr(commit_reply, "xml", str(commit_reply)),
                    }
                    if confirmed:
                        result["confirmed"] = True
                        # NETCONF confirm-timeout is in seconds per RFC 6241 / ncclient's
                        # own Commit() docstring — this field was previously mislabeled
                        # "confirm_timeout_minutes", which would mislead an operator about
                        # how long they actually have to issue the confirming commit.
                        result["confirm_timeout_seconds"] = confirm_timeout
                    if hasattr(args, "_changes_list"):
                        result["_changes_list"] = args._changes_list
                    return result

                except Exception as inner:
                    try:
                        m.discard_changes()
                    except Exception:
                        pass
                    return {
                        "success": False,
                        "host": conn["host"],
                        "device_name": device_name,
                        "commands": args.command,
                        "error": str(inner),
                        "error_type": type(inner).__name__,
                    }
                finally:
                    try:
                        m.unlock(target="candidate")
                    except Exception:
                        pass
            else:
                # No candidate datastore — edit running directly (no lock, no commit)
                if dry_run or not do_commit:
                    return {
                        "success": False,
                        "host": conn["host"],
                        "device_name": device_name,
                        "error": "dry_run/do_commit=false requires candidate datastore (enable: netconf-yang feature candidate-datastore)",
                    }
                m.edit_config(target="running", config=config_xml)
                result = {
                    "success": True,
                    "host": conn["host"],
                    "device_name": device_name,
                    "commands": args.command,
                    "datastore": "running",
                    "lock_wait_seconds": 0,
                }
                if hasattr(args, "_changes_list"):
                    result["_changes_list"] = args._changes_list
                return result

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


def commit_only(conn, args) -> dict:
    """Commit whatever is already staged in the candidate datastore — the accept
    half of a stage (netconf-send-command with do_commit=false) -> render/diff on
    the platform -> commit-or-discard workflow. Takes its own lock; doesn't assume
    anything about who staged the candidate or when."""
    device_name = conn.get("device_name") or conn["host"]
    confirmed = getattr(args, "confirmed", False)
    confirm_timeout = getattr(args, "confirm_timeout", None) or 10
    try:
        with _session(conn) as m:
            if not _has_candidate(m):
                return {"success": False, "host": conn["host"], "device_name": device_name,
                        "error": "device has no candidate datastore — nothing to commit"}
            lock_wait = _acquire_candidate_lock(m, conn["lock_timeout"], conn["lock_poll_interval"])
            try:
                commit_reply = m.commit(
                    confirmed=confirmed,
                    timeout=str(confirm_timeout) if confirmed else None,
                )
                result = {
                    "success": True,
                    "host": conn["host"],
                    "device_name": device_name,
                    "lock_wait_seconds": round(lock_wait, 2),
                    "commit": getattr(commit_reply, "xml", str(commit_reply)),
                }
                if confirmed:
                    result["confirmed"] = True
                    result["confirm_timeout_seconds"] = confirm_timeout
                return result
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
    """Discard whatever is staged in the candidate datastore — the reject half of
    a stage (do_commit=false) -> render/diff on the platform -> commit-or-discard
    workflow."""
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


def reboot(conn, args) -> dict:
    """Schedule a reload via the exec RPC. Neither IOS XE nor NX-OS has a native
    NETCONF reboot RPC, so this goes through the same exec-command path as
    run-command. NX-OS 'reload' normally prompts for interactive confirmation on
    the CLI — untested whether exec_command() handles that prompt cleanly; treat
    reboot on NX-OS as unvalidated until confirmed against real hardware."""
    try:
        with _session(conn) as m:
            if args.at:
                command = f"reload in {args.at}"
            else:
                command = "reload in 0"
            if args.message:
                command += f" reason {args.message}"
            _exec_command(m, conn["platform"], command)
            return {
                "success": True,
                "host": conn["host"],
                "at": args.at or "now",
                "command": command,
            }
    except Exception as e:
        return {"success": False, "host": conn["host"], "error": str(e), "error_type": type(e).__name__}


_DISPATCH = {
    "netconf-is-alive": is_alive,
    "netconf-run-command": run_command,
    "netconf-get-config": get_config,
    "netconf-get-config-clis": get_config_clis,
    "netconf-preview-config": preview_config,
    "netconf-send-command": send_command,
    "netconf-set-config": send_command,
    "netconf-commit": commit_only,
    "netconf-discard": discard,
    "netconf-reboot": reboot,
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

    platform = _normalize_platform(pick(args.platform, ("platform",)))
    host = pick(args.host, ("itential_host",))
    user = pick(args.user, ("itential_user",))
    password = pick(args.password, ("itential_password",))
    port = pick(args.port, ("itential_driver_options", "netconf", "port"), default=830)
    timeout = pick(args.timeout, ("itential_driver_options", "netconf", "timeout"), default=90)
    command_timeout = pick(args.command_timeout, ("itential_driver_options", "netconf", "command_timeout"), default=None)
    config_format = pick(args.config_format, ("itential_driver_options", "netconf", "config_format"), default=None)
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
        "platform": platform,
        "timeout": int(timeout),
        "command_timeout": int(command_timeout) if command_timeout is not None else None,
        "config_format": str(config_format) if config_format is not None else None,
        "lock_timeout": int(lock_timeout),
        "lock_poll_interval": float(lock_poll_interval),
        "device_name": (node or {}).get("name") or host,
    }


def _optional_int(value):
    """argparse type= for int flags that may arrive as '' — IAG5 forwards every
    decorator-declared key as a CLI flag even when the caller didn't set it,
    using '' as the unset sentinel. Plain type=int crashes on that; treat '' as
    unset so downstream default logic (_resolve_connection / send_command) applies."""
    if value is None or value == "":
        return None
    return int(value)


def _optional_float(value):
    if value is None or value == "":
        return None
    return float(value)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Cisco NETCONF operations for IAG5 (IOS XE + NX-OS)")
    parser.add_argument("--op", default=os.environ.get("NETCONF_OP"),
                        choices=list(_DISPATCH.keys()),
                        help="Operation to perform. Defaults to NETCONF_OP env var.")
    parser.add_argument("--platform", default=None,
                        help="'IOS XE' or 'NX-OS'. Defaults to inventory attribute "
                             "'platform', then 'ios-xe' for backward compatibility.")
    parser.add_argument("--host", default=None)
    parser.add_argument("--port", type=_optional_int, default=None)
    parser.add_argument("--user", default=None)
    parser.add_argument("--password", default=None)
    parser.add_argument("--timeout", type=_optional_int, default=None)
    parser.add_argument("--command-timeout", type=_optional_int, default=None, dest="command_timeout")
    parser.add_argument("--config_format", "--config-format", dest="config_format", default=None,
                        choices=list(_CONFIG_FORMATS) + [""])
    parser.add_argument("--lock_timeout", "--lock-timeout", dest="lock_timeout", type=_optional_int, default=None)
    parser.add_argument("--lock-poll-interval", type=_optional_float, default=None, dest="lock_poll_interval")
    parser.add_argument("--command", action="append", default=None)
    parser.add_argument("--commands", default=None)
    parser.add_argument("--dry_run", "--dry-run", dest="dry_run", nargs="?", const=True, default=None)
    parser.add_argument("--do_commit", "--do-commit", dest="do_commit", nargs="?", const=True, default=None,
                        help="Default true. Set to false to stage the change into candidate and "
                             "leave it there (validated, not committed, not discarded) instead of "
                             "committing — for a workflow that renders/diffs candidate separately "
                             "(e.g. via netconf-get-config-clis) before a later netconf-commit or "
                             "netconf-discard call.")
    parser.add_argument("--diff", nargs="?", const=True, default=None,
                        help="Default true. netconf-preview-config only — include a unified diff "
                             "(running vs candidate) in the result.")
    parser.add_argument("--force_discard", "--force-discard", dest="force_discard", nargs="?",
                        const=True, default=None,
                        help="Default false. netconf-preview-config only — if the candidate "
                             "datastore is dirty (differs from running), discard it and proceed "
                             "instead of returning error_type=DirtyCandidate.")
    parser.add_argument("--confirmed", nargs="?", const=True, default=None)
    parser.add_argument("--confirm_timeout", "--confirm-timeout", dest="confirm_timeout", type=_optional_int, default=None)
    parser.add_argument("--expect_running_hash", "--expect-running-hash", dest="expect_running_hash", default=None,
                        help="netconf-send-command only — optional drift guard. If set, running "
                             "config is re-rendered and hashed before applying; a mismatch returns "
                             "error_type=ConfigDrift instead of applying. IOS XE only.")
    parser.add_argument("--config", default=None)
    parser.add_argument("--config_content", "--config-content", dest="config_content", default=None)
    parser.add_argument("--config_xml", "--config-xml", dest="config_xml", default=None,
                        help="Raw pre-built NETCONF <config> XML payload — pushed as-is via "
                             "edit-config, bypassing CLI-to-XML conversion. Works on any platform "
                             "as long as the XML is valid for that device's YANG model.")
    parser.add_argument("--changes", default=None)
    parser.add_argument("--options", default=None)
    parser.add_argument("--source", "--datastore", dest="source", default=None)
    parser.add_argument("--filter", default=None)
    parser.add_argument("--at", default=None, help="Minutes from now for reload (e.g. '5')")
    parser.add_argument("--message", default=None, help="Optional reason string for reload")
    return parser


def _normalize_args(args):
    for attr in ("source", "filter", "at", "message", "host", "user", "password", "platform",
                 "config", "config_content", "config_xml", "commands", "options",
                 "expect_running_hash"):
        if getattr(args, attr, None) == "":
            setattr(args, attr, None)

    # 'at'/'message' are concatenated directly into a single device-bound
    # "reload ..." command (main() -> reboot()), unlike 'command'/'config'
    # which get split into individual CLI lines before use. An embedded
    # newline here would let a caller (e.g. a change-ticket description
    # piped in from an upstream system) smuggle an extra CLI line into the
    # exec RPC payload. Reject rather than silently strip, so a bad caller
    # gets a clear error instead of a silently-altered command.
    for attr in ("at", "message"):
        val = getattr(args, attr, None)
        if val is not None and ("\n" in val or "\r" in val):
            raise SystemExit(f"--{attr} must not contain embedded newlines")

    for attr in ("dry_run", "confirmed", "force_discard"):
        val = getattr(args, attr, None)
        if val is None or val == "":
            setattr(args, attr, False)
        elif isinstance(val, str):
            setattr(args, attr, val.lower() in ("true", "1", "yes"))

    # do_commit defaults to True (commit) — opposite polarity from dry_run/confirmed,
    # which default to False. IAG5 forwards '' for an unset declared param same as
    # everywhere else in this file.
    val = getattr(args, "do_commit", None)
    if val is None or val == "":
        args.do_commit = True
    elif isinstance(val, str):
        args.do_commit = val.lower() in ("true", "1", "yes")

    # diff also defaults to True (netconf-preview-config includes the unified
    # diff unless explicitly turned off) — same opposite-polarity reasoning as
    # do_commit, kept as its own block rather than folded into that one.
    val = getattr(args, "diff", None)
    if val is None or val == "":
        args.diff = True
    elif isinstance(val, str):
        args.diff = val.lower() in ("true", "1", "yes")

    if args.commands and not args.command:
        raw = args.commands
        try:
            cmds = json.loads(raw) if isinstance(raw, str) else raw
            if isinstance(cmds, list):
                args.command = [str(c) for c in cmds if str(c).strip()]
            else:
                args.command = [str(cmds)] if str(cmds).strip() else None
        except (json.JSONDecodeError, TypeError):
            args.command = [raw] if raw.strip() else None
    args.commands = None

    if args.config and not args.command:
        config_val = args.config.strip()
        if config_val.startswith("["):
            try:
                changes_list = json.loads(config_val)
                lines = []
                for c in changes_list:
                    new_val = str(c.get("new", "")).strip()
                    old_val = str(c.get("old", "")).strip()
                    if new_val:
                        lines.append(new_val)
                    elif old_val:
                        lines.append(f"no {old_val}" if not old_val.startswith("no ") else old_val)
                if lines:
                    args.command = lines
                    args._changes_list = changes_list
            except (json.JSONDecodeError, TypeError, KeyError, AttributeError):
                args.command = [args.config]
        else:
            args.command = [args.config]
    args.config = None

    if args.config_content and not args.command:
        args.command = [args.config_content]
    args.config_content = None

    if args.changes and not args.command:
        raw = args.changes
        try:
            changes_list = json.loads(raw) if isinstance(raw, str) else raw
            lines = []
            for c in changes_list:
                new_val = str(c.get("new", "")).strip()
                old_val = str(c.get("old", "")).strip()
                if new_val:
                    lines.append(new_val)
                elif old_val:
                    lines.append(f"no {old_val}" if not old_val.startswith("no ") else old_val)
            if lines:
                args.command = lines
                args._changes_list = changes_list
        except (json.JSONDecodeError, TypeError, KeyError, AttributeError):
            pass
    args.changes = None

    if args.command:
        split = []
        for raw in args.command:
            if raw is None:
                continue
            for line in raw.splitlines():
                line = line.strip()
                if line:
                    split.append(line)
        args.command = split or None

    if args.source is None:
        args.source = "running"
    if args.source not in ("running", "candidate"):
        raise SystemExit(f"--source must be 'running' or 'candidate', got {args.source!r}")


def _format_for_humans(result, op):
    if op == "netconf-is-alive":
        return "true" if result.get("alive", False) else "false"

    if op == "netconf-run-command":
        results = result.get("results") or []
        if not results:
            return f"ERROR: {result.get('error', 'connection failed')}"
        if len(results) == 1:
            r = results[0]
            text = r.get("output", "")
            if not r.get("success"):
                text = f"ERROR: {r.get('error', 'unknown error')}\n{text}".rstrip()
            return text
        parts = []
        for r in results:
            parts.append(f"=== {r['command']} ===")
            if not r.get("success"):
                parts.append(f"ERROR: {r.get('error', 'unknown error')}")
            if r.get("output"):
                parts.append(r["output"])
        return "\n".join(parts)

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

    if op == "netconf-set-config":
        if result.get("success"):
            changes_list = result.get("_changes_list")
            if changes_list:
                output = [
                    {"result": True, "parents": c.get("parents", []),
                     "old": c.get("old", ""), "new": c.get("new", "")}
                    for c in changes_list
                ]
            else:
                output = [{"result": True, "parents": [], "old": "", "new": cmd}
                          for cmd in (result.get("commands") or [])]
            return json.dumps(output)
        else:
            print(result.get("error", "Configuration failed"), file=sys.stderr)
            return "[]"

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
